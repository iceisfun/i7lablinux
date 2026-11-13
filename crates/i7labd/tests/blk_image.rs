//! blk.image end to end, in process: the real client (`i7labctl::blkimage::flash`) against the real command
//! registry (stream mode, like the ether server drives it) and against the real HTTP server (batch mode), writing
//! to fixture disks (regular files behind a fake sysfs), with fault injection on the way.

use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

use i7labctl::blkimage::{flash, FlashError, Params, Progress, Tuning, Ui};
use i7labctl::{CallResult, ClientError, ClientIo, Input, Transport};
use i7labd::config::Config;
use i7labd::registry::{Ctx, Sink, Source};
use i7labd::Daemon;
use labprobe::block::parttable::{build_gpt, check_backup, parse_gpt_header};
use labproto::blkwire::RecordReader;
use labproto::catalog::CmdSpec;
use labproto::crypto::sha256;
use labproto::frame::Chan;
use labproto::keys::{Key, KeySet, Role};
use labproto::Status;

const MIB: u64 = 1 << 20;
const SER: &str = "SER-E2E";

struct Fx {
    root: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Fx {
    fn new(label: &str) -> Fx {
        let root = std::env::temp_dir().join(format!("i7bi-e2e-{}-{}", label, std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["sys/block", "dev", "proc/self", "run"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("proc/self/mountinfo"), "").unwrap();
        std::fs::write(root.join("proc/swaps"), "Filename Type Size Used Priority\n").unwrap();
        Fx { root }
    }
    fn disk(&self, name: &str, size: u64, minor: u32, serial: &str) {
        let real = self.root.join("sys/devices/pci0000:00/0000:00:03.0/virtio0/block").join(name);
        std::fs::create_dir_all(real.join("queue")).unwrap();
        std::fs::create_dir_all(real.join("holders")).unwrap();
        let w = |f: &str, c: String| std::fs::write(real.join(f), c).unwrap();
        w("dev", format!("252:{}\n", minor));
        w("size", format!("{}\n", size / 512));
        w("ro", "0\n".into());
        w("removable", "0\n".into());
        w("queue/logical_block_size", "4096\n".into());
        w("queue/physical_block_size", "4096\n".into());
        w("queue/rotational", "0\n".into());
        w("serial", serial.into());
        std::os::unix::fs::symlink(std::path::Path::new("../devices/pci0000:00/0000:00:03.0/virtio0/block").join(name), self.root.join("sys/block").join(name)).unwrap();
        std::fs::File::create(self.root.join("dev").join(name)).unwrap().set_len(size).unwrap();
    }
    fn get(&self, name: &str, off: u64, n: usize) -> Vec<u8> {
        let f = std::fs::File::open(self.root.join("dev").join(name)).unwrap();
        let mut b = vec![0u8; n];
        f.read_exact_at(&mut b, off).unwrap();
        b
    }
    fn daemon(&self, label: &str) -> Daemon {
        let run = self.root.join("run").join(label);
        std::fs::create_dir_all(&run).unwrap();
        let cfg = Config { audit_log: run.join("audit.log"), resolv_conf: run.join("resolv.conf"), run_dir: run, power_dry_run: true, dhcp: false, ..Config::default() };
        let mut d = Daemon::new(cfg).unwrap();
        d.probe = labprobe::ProbeCtx::fixture(&self.root);
        d
    }
}

fn image(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i as u32).wrapping_mul(2654435761).rotate_left(7) >> 3) as u8 | 1).collect()
}

fn tmpimg(label: &str, data: &[u8]) -> PathBuf {
    let p = std::env::temp_dir().join(format!("i7bi-img-{}-{}", label, std::process::id()));
    std::fs::write(&p, data).unwrap();
    p
}

#[derive(Default)]
struct TUi {
    said: Vec<String>,
    last: Option<Progress>,
}
impl Ui for TUi {
    fn say(&mut self, s: &str) {
        self.said.push(s.into());
    }
    fn confirm(&mut self, _s: &str) -> bool {
        true
    }
    fn progress(&mut self, p: &Progress) {
        self.last = Some(p.clone());
    }
}

fn params(p: &PathBuf, serial: &str) -> Params {
    Params { file: p.clone(), serial: serial.into(), verify: true, dest_offset: 0, resume: false, grow_last: false, no_relocate: false, tuning: None }
}

// ------------------------------------------------------------------ in-process "ether-style" transport

struct UpSink {
    rx: Option<Receiver<Vec<u8>>>,
    events: Sender<String>,
    queued: Arc<AtomicU64>,
}
impl Sink for UpSink {
    fn data(&mut self, _c: Chan, _b: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn event(&mut self, j: &str) -> std::io::Result<()> {
        self.events.send(j.to_string()).map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }
    fn input(&mut self) -> Option<Receiver<Vec<u8>>> {
        // account bytes as the handler takes them off the queue
        let (tx, rx2) = channel::<Vec<u8>>();
        let rx = self.rx.take()?;
        let queued = self.queued.clone();
        std::thread::spawn(move || {
            for c in rx {
                queued.fetch_sub(c.len() as u64, Ordering::SeqCst);
                if tx.send(c).is_err() {
                    break;
                }
            }
        });
        Some(rx2)
    }
}

/// Faults the fake link applies to the first transfer attempt only.
#[derive(Default)]
struct Faults {
    /// drop the n-th DATA record (0-based) of the first attempt
    drop_record: Option<usize>,
    /// flip a payload bit of the n-th DATA record of the first attempt
    corrupt_record: Option<usize>,
}

struct Local<'a> {
    d: &'a Daemon,
    faults: Faults,
    attempts: usize,
    max_queued: Arc<AtomicU64>,
}

impl Transport for Local<'_> {
    fn name(&self) -> &'static str {
        "ether"
    }
    fn call(&mut self, cmd: &CmdSpec, args: &[String], io: &mut dyn ClientIo) -> Result<CallResult, ClientError> {
        let is_transfer = !args.iter().any(|a| a == "--status" || a == "--abort");
        if is_transfer {
            self.attempts += 1;
        }
        let (tx, rx) = channel::<Vec<u8>>();
        let (etx, erx) = channel::<String>();
        let queued = Arc::new(AtomicU64::new(0));
        let mut sink = UpSink { rx: Some(rx), events: etx, queued: queued.clone() };
        let d = self.d;
        let argv = args.to_vec();
        let cname = cmd.name;
        let first = self.attempts == 1;
        let mut data_idx = 0usize;
        let mut rd = RecordReader::new();
        let result = std::thread::scope(|s| {
            let h = s.spawn(move || {
                let mut ctx = Ctx { daemon: d, source: Source::Local, role: Role::Admin, actor: "e2e".into(), args: argv, sink: &mut sink, cancel: Arc::new(AtomicBool::new(false)) };
                let cmd = d.registry.get(cname).unwrap();
                d.registry.dispatch(&mut ctx, cmd)
            });
            let mut input_done = !is_transfer;
            let mut tx = Some(tx);
            loop {
                while let Ok(e) = erx.try_recv() {
                    io.event(&e);
                }
                if h.is_finished() {
                    break;
                }
                if input_done {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                match io.input() {
                    Input::Data(_, mut bytes) => {
                        // fault injection works on whole records
                        rd.push(&bytes);
                        let mut keep = true;
                        if first {
                            let mut probe = RecordReader::new();
                            probe.push(&bytes);
                            if let Ok(Some(labproto::blkwire::Record::Data { .. })) = probe.next() {
                                if self.faults.drop_record == Some(data_idx) {
                                    keep = false;
                                }
                                if self.faults.corrupt_record == Some(data_idx) {
                                    let n = bytes.len();
                                    bytes[n - 1] ^= 0x10;
                                }
                                data_idx += 1;
                            }
                        }
                        while let Ok(Some(_)) = rd.next() {}
                        if keep {
                            let n = queued.fetch_add(bytes.len() as u64, Ordering::SeqCst) + bytes.len() as u64;
                            self.max_queued.fetch_max(n, Ordering::SeqCst);
                            let _ = tx.as_ref().unwrap().send(bytes);
                        }
                    }
                    Input::Pending => std::thread::sleep(Duration::from_micros(200)),
                    Input::End(_) | Input::None => {
                        input_done = true;
                        tx.take();
                    }
                }
            }
            h.join().unwrap()
        });
        while let Ok(e) = erx.try_recv() {
            io.event(&e);
        }
        Ok(CallResult { status: result.status, body: result.body, exit_code: None, rtt_ms: 0.0 })
    }
}

fn gpt_image(sectors: u64) -> Vec<u8> {
    let mut img = vec![0u8; (sectors * 4096) as usize];
    let g = build_gpt(4096, sectors, &[(34, 200, "root"), (201, sectors - 40, "data")]);
    img[..g.len()].copy_from_slice(&g);
    let x = image(200 * 4096);
    img[300 * 4096..300 * 4096 + x.len()].copy_from_slice(&x);
    img
}

#[test]
fn streams_a_sparse_gpt_image_through_the_registry_with_a_bounded_queue() {
    let fx = Fx::new("reg");
    fx.disk("vde1", 16 * MIB, 1, SER);
    let d = fx.daemon("a");
    let img = gpt_image(1024); // 4 MiB, mostly zero
    let p = tmpimg("reg", &img);
    let mut t = Local { d: &d, faults: Faults::default(), attempts: 0, max_queued: Arc::new(AtomicU64::new(0)) };
    let mut ui = TUi::default();
    let o = flash(&mut t, "vde1", &params(&p, SER), &mut ui).unwrap();
    assert_eq!(o.attempts, 1);
    assert!(o.verified);
    assert_eq!(o.sha256, labproto::crypto::hex(&sha256(&img)));
    assert_eq!(o.gpt_action, "moved");
    // blocks 0 (GPT) and 1 (data) are not zero; blocks 2 and 3 travel as one ZERO record
    assert_eq!((o.zero_sent, o.data_sent), (2 * MIB, 2 * MIB));
    // data and zeros as streamed
    assert_eq!(fx.get("vde1", 300 * 4096, 4096), img[300 * 4096..301 * 4096]);
    assert_eq!(fx.get("vde1", 2 * MIB, 4096), vec![0; 4096]);
    // GPT: backup at the last LBA of the 16 MiB disk (4096-byte sectors: LBA 4095)
    let hd = parse_gpt_header(&fx.get("vde1", 4096, 4096)).unwrap();
    assert!(hd.crc_ok && hd.alt_lba == 4095, "{:?}", hd);
    assert!(check_backup(&fx.get("vde1", 4095 * 4096, 4096), 4095));
    // the bound: never more than the window (+ record framing) queued towards the host
    let w = Tuning::for_transport("ether").window;
    assert!(t.max_queued.load(Ordering::SeqCst) <= w + 4 * 1024, "queued {} > window {}", t.max_queued.load(Ordering::SeqCst), w);
    assert!(ui.last.is_none() || ui.last.as_ref().unwrap().total == img.len() as u64);
    let _ = std::fs::remove_file(p);
}

#[test]
fn a_dropped_and_a_damaged_chunk_are_recovered_by_resuming() {
    for (label, faults) in [("drop", Faults { drop_record: Some(2), ..Default::default() }), ("corrupt", Faults { corrupt_record: Some(3), ..Default::default() })] {
        let fx = Fx::new(&format!("fault-{}", label));
        fx.disk("vde2", 16 * MIB, 2, SER);
        let d = fx.daemon("a");
        let img = image(3 * MIB as usize + 4096);
        let p = tmpimg(&format!("fault-{}", label), &img);
        let mut t = Local { d: &d, faults, attempts: 0, max_queued: Arc::new(AtomicU64::new(0)) };
        let mut ui = TUi::default();
        let mut pr = params(&p, SER);
        pr.no_relocate = true;
        let o = flash(&mut t, "vde2", &pr, &mut ui).unwrap();
        assert_eq!(o.attempts, 2, "{}: {:?}", label, ui.said);
        assert!(ui.said.iter().any(|s| s.contains("continuing at byte")), "{:?}", ui.said);
        assert_eq!(fx.get("vde2", 0, img.len()), img, "{}", label);
        assert!(o.verified);
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn refusals_reach_the_operator_and_write_nothing() {
    let fx = Fx::new("refuse");
    fx.disk("vde3", 16 * MIB, 3, SER);
    fx.disk("vde4", 16 * MIB, 4, SER);
    // vde4: a mounted partition
    std::fs::create_dir_all(fx.root.join("sys/block/vde4/vde4p1")).unwrap();
    std::fs::write(fx.root.join("sys/block/vde4/vde4p1/dev"), "252:5\n").unwrap();
    std::fs::write(fx.root.join("sys/block/vde4/vde4p1/partition"), "1\n").unwrap();
    std::fs::write(fx.root.join("proc/self/mountinfo"), "30 1 252:5 / /mnt rw - ext4 /dev/vde4p1 rw\n").unwrap();
    let d = fx.daemon("a");
    let img = image(2 * MIB as usize);
    let p = tmpimg("refuse", &img);
    let mut ui = TUi::default();
    let mut t = Local { d: &d, faults: Faults::default(), attempts: 0, max_queued: Arc::new(AtomicU64::new(0)) };
    // wrong serial: stopped on the client, nothing sent
    let e = flash(&mut t, "vde3", &params(&p, "NOPE"), &mut ui).unwrap_err();
    assert!(matches!(e, FlashError::Client(ClientError::Safety(ref m)) if m.contains("serial mismatch")), "{:?}", e);
    assert_eq!(t.attempts, 0);
    // mounted: the host's gate refuses, with the reason
    let e = flash(&mut t, "vde4", &params(&p, SER), &mut ui).unwrap_err();
    assert!(matches!(e, FlashError::Client(ClientError::Safety(ref m)) if m.contains("mounted")), "{:?}", e);
    assert_eq!(fx.get("vde4", 0, 16), vec![0; 16]);
    // image bigger than the disk
    let big = tmpimg("big", &image(17 * MIB as usize));
    let e = flash(&mut t, "vde3", &params(&big, SER), &mut ui).unwrap_err();
    assert!(matches!(e, FlashError::Client(ClientError::Safety(ref m)) if m.contains("larger than the disk")), "{:?}", e);
    assert_eq!(fx.get("vde3", 0, 16), vec![0; 16]);
    let _ = (std::fs::remove_file(p), std::fs::remove_file(big));
}

// ------------------------------------------------------------------ real HTTP server + real HTTP client

struct Http {
    addr: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<std::io::Result<()>>>,
}

impl Http {
    fn start(d: Daemon) -> Http {
        *d.keys.write().unwrap() = KeySet { admin: Some(Key { role: Role::Admin, bytes: [1; 32] }), ro: Some(Key { role: Role::Ro, bytes: [2; 32] }) };
        d.set_state("ready");
        let d = Arc::new(d);
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let s2 = stop.clone();
        let handle = Some(std::thread::spawn(move || i7labd::http::serve_listener(d, l, s2)));
        Http { addr, stop, handle }
    }
    fn client(&self, role: Role, byte: u8) -> i7labctl::http::HttpTransport {
        i7labctl::http::HttpTransport { addr: self.addr.to_string(), key: Key { role, bytes: [byte; 32] }, timeout: None, verbose: 0, trace: None }
    }
}

impl Drop for Http {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[test]
fn the_same_job_over_signed_http_batches() {
    let fx = Fx::new("http");
    fx.disk("vde5", 16 * MIB, 6, SER);
    let srv = Http::start(fx.daemon("h"));
    let img = gpt_image(1024);
    let p = tmpimg("http", &img);
    let mut t = srv.client(Role::Admin, 1);
    let mut ui = TUi::default();
    let o = flash(&mut t, "vde5", &params(&p, SER), &mut ui).unwrap();
    assert!(o.verified && o.gpt_action == "moved", "{:?}", o);
    assert_eq!(fx.get("vde5", 300 * 4096, 4096), img[300 * 4096..301 * 4096]);
    assert!(check_backup(&fx.get("vde5", 4095 * 4096, 4096), 4095));
    // the read-only key is refused by the host before any byte is read
    let mut ro = srv.client(Role::Ro, 2);
    let e = flash(&mut ro, "vde5", &params(&p, SER), &mut ui).unwrap_err();
    assert!(matches!(e, FlashError::Client(ClientError::Auth(_))), "{:?}", e);
    let _ = std::fs::remove_file(p);
}

#[test]
fn http_batches_continue_one_session_without_a_retry() {
    // several 1 MiB batches: each later batch must continue the host's paused session (found by a live QEMU run:
    // without `--resume` the host starts over and the second batch is a `gap`, healed by a wasted retry)
    let fx = Fx::new("http3");
    fx.disk("vde7", 16 * MIB, 8, SER);
    let srv = Http::start(fx.daemon("h"));
    let img = image(5 * MIB as usize);
    let p = tmpimg("http3", &img);
    let mut t = srv.client(Role::Admin, 1);
    let mut ui = TUi::default();
    let mut pr = params(&p, SER);
    pr.no_relocate = true;
    let o = flash(&mut t, "vde7", &pr, &mut ui).unwrap();
    assert_eq!(o.attempts, 1, "{:?}", o);
    assert_eq!(fx.get("vde7", 0, img.len()), img);
    let _ = std::fs::remove_file(p);
}

#[test]
fn http_resume_after_the_session_state_survives_a_failed_attempt() {
    let fx = Fx::new("http2");
    fx.disk("vde6", 16 * MIB, 7, SER);
    let srv = Http::start(fx.daemon("h"));
    let img = image(5 * MIB as usize);
    let p = tmpimg("http2", &img);
    let mut t = srv.client(Role::Admin, 1);
    // first half by hand through the raw record API: a session is left paused on the host
    let id = i7labctl::blkimage::image_id(&p, img.len() as u64, 0).unwrap();
    let spec = labproto::catalog::by_name("blk.image").unwrap();
    struct Once(Option<Vec<u8>>);
    impl ClientIo for Once {
        fn stdout(&mut self, _: &[u8]) {}
        fn stderr(&mut self, _: &[u8]) {}
        fn event(&mut self, _: &str) {}
        fn input(&mut self) -> Input {
            match self.0.take() {
                Some(b) => Input::Data(Chan::File, b),
                None => Input::End(Chan::File),
            }
        }
    }
    let mut first = Vec::new();
    for k in 0..4usize {
        first.extend(labproto::blkwire::encode_data((k * 256 << 10) as u64, &img[k * 256 << 10..(k + 1) * 256 << 10]));
    }
    let args: Vec<String> = ["vde6", "--size", &img.len().to_string(), "--image-id", &id, "--serial", SER, "--destructive", "--no-relocate"].iter().map(|s| s.to_string()).collect();
    let r = t.call(spec, &args, &mut Once(Some(first))).unwrap();
    assert_eq!(r.status, Status::Ok, "{}", String::from_utf8_lossy(&r.body));
    assert!(String::from_utf8_lossy(&r.body).contains("\"done\":false"));
    // now the real client with --resume picks up at 1 MiB
    let mut pr = params(&p, SER);
    pr.resume = true;
    pr.no_relocate = true;
    let mut ui = TUi::default();
    let o = flash(&mut t, "vde6", &pr, &mut ui).unwrap();
    assert_eq!(o.resumed_from, MIB);
    assert_eq!(fx.get("vde6", 0, img.len()), img);
    let _ = std::fs::remove_file(p);
    let _ = std::io::stdout().flush();
}
