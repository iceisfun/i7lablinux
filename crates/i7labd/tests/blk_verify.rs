//! Chunked verification of `blk image` (`--verify`, `--verify-only`), end to end in process: the real client
//! (`i7labctl::blkimage`) against the real command registry writing fixture disks (regular files behind a fake
//! sysfs). This file is its own test binary on purpose: one test lowers the session TTL (a process-wide setting).

use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use i7labctl::blkimage::{flash, verify_only, FlashError, Params, Progress, Tuning, Ui, VerifyParams, VerifyProgress};
use i7labctl::{CallResult, ClientError, ClientIo, Input, Transport};
use i7labd::config::Config;
use i7labd::registry::{Ctx, Sink, Source};
use i7labd::Daemon;
use labprobe::block::parttable::build_gpt;
use labproto::catalog::CmdSpec;
use labproto::crypto::{hex, sha256};
use labproto::frame::Chan;
use labproto::keys::Role;
use labproto::Status;

const MIB: u64 = 1 << 20;
const SER: &str = "SER-VFY";

/// The tests run one at a time: one of them lowers the process-wide session TTL.
static SERIAL: Mutex<()> = Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

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
        let root = std::env::temp_dir().join(format!("i7bv-{}-{}", label, std::process::id()));
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
    /// Change one byte of the fixture disk behind the daemon's back.
    fn flip(&self, name: &str, off: u64) {
        let f = std::fs::OpenOptions::new().read(true).write(true).open(self.root.join("dev").join(name)).unwrap();
        let mut b = [0u8; 1];
        f.read_exact_at(&mut b, off).unwrap();
        b[0] ^= 0x40;
        f.write_all_at(&b, off).unwrap();
        f.sync_all().unwrap();
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
    let p = std::env::temp_dir().join(format!("i7bv-img-{}-{}", label, std::process::id()));
    std::fs::write(&p, data).unwrap();
    p
}

#[derive(Default)]
struct TUi {
    said: Vec<String>,
    verify: Vec<VerifyProgress>,
}
impl Ui for TUi {
    fn say(&mut self, s: &str) {
        self.said.push(s.into());
    }
    fn confirm(&mut self, _s: &str) -> bool {
        true
    }
    fn progress(&mut self, _p: &Progress) {}
    fn verify_progress(&mut self, v: &VerifyProgress) {
        self.verify.push(v.clone());
    }
}

fn params(p: &PathBuf, verify: bool) -> Params {
    Params { file: p.clone(), serial: SER.into(), verify, dest_offset: 0, resume: false, grow_last: false, no_relocate: false, allow_boot_media: false, tuning: None, verify_chunk: MIB }
}

fn vparams(p: &PathBuf) -> VerifyParams {
    VerifyParams { file: p.clone(), serial: SER.into(), dest_offset: 0, from_range: 0, chunk: MIB, skip_gpt_head: false }
}

// ------------------------------------------------------------------ in-process transport

struct UpSink {
    rx: Option<Receiver<Vec<u8>>>,
    events: Sender<String>,
}
impl Sink for UpSink {
    fn data(&mut self, _c: Chan, _b: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn event(&mut self, j: &str) -> std::io::Result<()> {
        self.events.send(j.to_string()).map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }
    fn input(&mut self) -> Option<Receiver<Vec<u8>>> {
        self.rx.take()
    }
}

struct Local<'a> {
    d: &'a Daemon,
}

impl Transport for Local<'_> {
    fn name(&self) -> &'static str {
        "ether"
    }
    fn call(&mut self, cmd: &CmdSpec, args: &[String], io: &mut dyn ClientIo) -> Result<CallResult, ClientError> {
        let has = |f: &str| args.iter().any(|a| a == f);
        let is_transfer = has("--size") && !(has("--status") || has("--abort") || has("--finish") || has("--hash-range") || has("--hash-disk"));
        let (tx, rx) = channel::<Vec<u8>>();
        let (etx, erx) = channel::<String>();
        let mut sink = UpSink { rx: Some(rx), events: etx };
        let d = self.d;
        let argv = args.to_vec();
        let cname = cmd.name;
        let result = std::thread::scope(|s| {
            let h = s.spawn(move || {
                let mut ctx = Ctx { daemon: d, source: Source::Local, role: Role::Admin, actor: "e2e".into(), args: argv, sink: &mut sink, cancel: Arc::new(AtomicBool::new(false)) };
                let cmd = d.registry.get(cname).unwrap();
                d.registry.dispatch(&mut ctx, cmd)
            });
            let mut tx = Some(tx);
            let mut input_done = !is_transfer;
            if input_done {
                tx.take();
            }
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
                    Input::Data(_, bytes) => {
                        let _ = tx.as_ref().unwrap().send(bytes);
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

type Hook<'a> = Box<dyn FnMut(usize) + 'a>;

/// Wraps the transport: logs every call, delays hash calls, runs a hook before each, and can cut hash calls.
struct Spy<'a> {
    inner: Local<'a>,
    log: Arc<Mutex<Vec<Vec<String>>>>,
    hash_calls: usize,
    delay: Duration,
    hook: Option<Hook<'a>>,
    /// hash call indexes (0-based over this transport's life) that fail with a cut link
    cut: std::ops::Range<usize>,
}

impl<'a> Spy<'a> {
    fn new(d: &'a Daemon) -> Spy<'a> {
        Spy { inner: Local { d }, log: Arc::new(Mutex::new(Vec::new())), hash_calls: 0, delay: Duration::ZERO, hook: None, cut: 0..0 }
    }
    fn count(&self, flag: &str) -> usize {
        self.log.lock().unwrap().iter().filter(|a| a.iter().any(|x| x == flag)).count()
    }
}

impl Transport for Spy<'_> {
    fn name(&self) -> &'static str {
        "ether"
    }
    fn call(&mut self, cmd: &CmdSpec, args: &[String], io: &mut dyn ClientIo) -> Result<CallResult, ClientError> {
        let is_hash = args.iter().any(|a| a == "--hash-range" || a == "--hash-disk");
        if is_hash {
            let idx = self.hash_calls;
            self.hash_calls += 1;
            std::thread::sleep(self.delay);
            if let Some(h) = self.hook.as_mut() {
                h(idx);
            }
            if self.cut.contains(&idx) {
                return Err(ClientError::Transport("cut".into()));
            }
        }
        self.log.lock().unwrap().push(args.to_vec());
        self.inner.call(cmd, args, io)
    }
}

fn mismatch(r: Result<impl std::fmt::Debug, FlashError>) -> String {
    match r {
        Err(FlashError::Mismatch(m)) => m,
        other => panic!("expected a mismatch, got {:?}", other),
    }
}

// ------------------------------------------------------------------ tests

#[test]
fn a_multi_range_image_is_verified_in_bounded_requests() {
    let _serial = serial();
    let fx = Fx::new("multi");
    fx.disk("vdv1", 16 * MIB, 1, SER);
    let d = fx.daemon("a");
    let img = image(5 * MIB as usize + 12288); // 6 ranges of 1 MiB, the last one short
    let p = tmpimg("multi", &img);
    let mut t = Spy::new(&d);
    let mut ui = TUi::default();
    let o = flash(&mut t, "vdv1", &params(&p, true), &mut ui).unwrap();
    assert!(o.verified);
    assert_eq!(o.sha256, hex(&sha256(&img)));
    assert_eq!(t.hash_calls, 6, "one hash request per range");
    assert_eq!(t.count("--finish"), 1);
    // every range was asked with the session's own flags and nothing is longer than the chunk
    for a in t.log.lock().unwrap().iter().filter(|a| a.iter().any(|x| x == "--hash-range")) {
        let r = &a[a.iter().position(|x| x == "--hash-range").unwrap() + 1];
        let len: u64 = r.split(':').nth(1).unwrap().parse().unwrap();
        assert!(len <= MIB, "{}", r);
        assert!(a.iter().any(|x| x == "--destructive") && a.iter().any(|x| x == "--resume"));
    }
    assert_eq!(ui.verify.len(), 6);
    assert_eq!(ui.verify.last().unwrap().bytes_done, img.len() as u64);
    assert!(ui.verify.iter().all(|v| v.ranges == 6 && v.rate_mb > 0.0));
    assert_eq!(fx.get("vdv1", 0, img.len()), img);
    let _ = std::fs::remove_file(p);
}

#[test]
fn a_corrupted_byte_is_reported_with_the_offset_of_its_range() {
    let _serial = serial();
    let fx = Fx::new("bad");
    fx.disk("vdv2", 16 * MIB, 2, SER);
    let d = fx.daemon("a");
    let img = image(6 * MIB as usize);
    let p = tmpimg("bad", &img);
    let mut t = Spy::new(&d);
    // after the write, before the verify of range 3 (hash call 3): change one byte inside range 3
    let flip_fx = &fx;
    t.hook = Some(Box::new(move |i| {
        if i == 3 {
            flip_fx.flip("vdv2", 3 * MIB + 17);
        }
    }));
    let mut ui = TUi::default();
    let m = mismatch(flash(&mut t, "vdv2", &params(&p, true), &mut ui));
    assert!(m.contains("range 3 (offset 3145728, 1048576 bytes)"), "{}", m);
    assert!(!m.contains("range 2 ") && !m.contains("range 4 "), "only the damaged range is named: {}", m);
    assert!(ui.said.iter().any(|s| s.contains("reading it once more")), "a mismatch is read once more before it is reported: {:?}", ui.said);
    assert_eq!(t.count("--finish"), 0, "a failed verify does not finish the transfer");
    let _ = std::fs::remove_file(p);
}

#[test]
fn a_slow_host_outlives_the_session_ttl_because_every_request_refreshes_it() {
    let _serial = serial();
    // total verify time (6 x 0.8 s = ~5 s) is longer than the TTL set here, each request is far shorter
    i7labd::cmds::blkimage::IDLE_TTL_SECS.store(2, Ordering::Relaxed);
    let fx = Fx::new("slow");
    fx.disk("vdv3", 16 * MIB, 3, SER);
    let d = fx.daemon("a");
    let img = image(5 * MIB as usize + 4096);
    let p = tmpimg("slow", &img);
    let mut t = Spy::new(&d);
    t.delay = Duration::from_millis(800);
    let mut ui = TUi::default();
    let t0 = std::time::Instant::now();
    let o = flash(&mut t, "vdv3", &params(&p, true), &mut ui).unwrap();
    assert!(t0.elapsed() > Duration::from_secs(4), "the test really was slower than the TTL");
    assert!(o.verified);
    assert_eq!(t.count("--finish"), 1);
    i7labd::cmds::blkimage::IDLE_TTL_SECS.store(300, Ordering::Relaxed);
    let _ = std::fs::remove_file(p);
}

#[test]
fn verify_only_passes_on_a_good_disk_and_names_the_bad_range() {
    let _serial = serial();
    let fx = Fx::new("only");
    fx.disk("vdv4", 16 * MIB, 4, SER);
    let d = fx.daemon("a");
    let img = image(5 * MIB as usize);
    let p = tmpimg("only", &img);
    let mut ui = TUi::default();
    flash(&mut Spy::new(&d), "vdv4", &params(&p, false), &mut ui).unwrap();

    let mut t = Spy::new(&d);
    let o = verify_only(&mut t, "vdv4", &vparams(&p), &mut ui).unwrap();
    assert_eq!((o.ranges, o.bytes), (5, img.len() as u64));
    assert_eq!(o.sha256.as_deref(), Some(hex(&sha256(&img)).as_str()));
    assert_eq!(t.count("--hash-disk"), 5);
    assert_eq!(t.count("--destructive"), 0, "verify-only never asks for the write flags");
    assert_eq!(fx.get("vdv4", 0, img.len()), img, "nothing was written");

    // a bad disk: one byte in range 3 (the disk is also the thing that differs from the image)
    fx.flip("vdv4", 3 * MIB + 5);
    let m = mismatch(verify_only(&mut Spy::new(&d), "vdv4", &vparams(&p), &mut ui));
    assert!(m.contains("range 3 (offset 3145728") && m.contains("--from-range 3"), "{}", m);

    // resume by range: later ranges pass, the bad one is found again, an out-of-range start is a usage error
    let mut vp = vparams(&p);
    vp.from_range = 4;
    let mut t = Spy::new(&d);
    let o = verify_only(&mut t, "vdv4", &vp, &mut ui).unwrap();
    assert_eq!((o.ranges, o.sha256), (1, None));
    assert_eq!(t.hash_calls, 1);
    vp.from_range = 3;
    assert!(mismatch(verify_only(&mut Spy::new(&d), "vdv4", &vp, &mut ui)).contains("offset 3145728"));
    vp.from_range = 5;
    assert!(matches!(verify_only(&mut Spy::new(&d), "vdv4", &vp, &mut ui), Err(FlashError::Client(ClientError::Usage(_)))));

    // wrong serial: refused locally, and by the host when asked directly
    let mut vp = vparams(&p);
    vp.serial = "OTHER".into();
    assert!(matches!(verify_only(&mut Spy::new(&d), "vdv4", &vp, &mut ui), Err(FlashError::Client(ClientError::Safety(_)))));
    let mut t = Local { d: &d };
    let spec = labproto::catalog::by_name("blk.image").unwrap();
    let args: Vec<String> = ["vdv4", "--size", "5242880", "--serial", "OTHER", "--hash-disk", "0:4096"].iter().map(|s| s.to_string()).collect();
    let r = t.call(spec, &args, &mut i7labctl::NullIo).unwrap();
    assert_eq!(r.status, Status::Refused);
    let args: Vec<String> = ["vdv4", "--size", "5242880", "--hash-disk", "0:4096"].iter().map(|s| s.to_string()).collect();
    assert_eq!(t.call(spec, &args, &mut i7labctl::NullIo).unwrap().status, Status::Refused, "no serial");
    let _ = std::fs::remove_file(p);
}

#[test]
fn verify_only_after_a_gpt_flash_needs_skip_gpt_head() {
    let _serial = serial();
    let fx = Fx::new("gpt");
    fx.disk("vdv5", 16 * MIB, 5, SER);
    let d = fx.daemon("a");
    let sectors = 1024u64; // 4 MiB image on a 16 MiB disk: the flash moves the backup GPT, rewriting LBA 0 and 1
    let mut img = vec![0u8; (sectors * 4096) as usize];
    let g = build_gpt(4096, sectors, &[(34, 200, "root"), (201, sectors - 40, "data")]);
    img[..g.len()].copy_from_slice(&g);
    let x = image(200 * 4096);
    img[300 * 4096..300 * 4096 + x.len()].copy_from_slice(&x);
    let p = tmpimg("gpt", &img);
    let mut ui = TUi::default();
    let o = flash(&mut Spy::new(&d), "vdv5", &params(&p, true), &mut ui).unwrap();
    assert_eq!(o.gpt_action, "moved");
    let m = mismatch(verify_only(&mut Spy::new(&d), "vdv5", &vparams(&p), &mut ui));
    assert!(m.contains("range 0 (offset 0"), "{}", m);
    let mut vp = vparams(&p);
    vp.skip_gpt_head = true;
    let o = verify_only(&mut Spy::new(&d), "vdv5", &vp, &mut ui).unwrap();
    assert!(o.skipped_head);
    let _ = std::fs::remove_file(p);
}

#[test]
fn an_interrupted_verify_is_resumed_and_the_write_path_without_verify_is_unchanged() {
    let _serial = serial();
    let fx = Fx::new("res");
    fx.disk("vdv6", 16 * MIB, 6, SER);
    let d = fx.daemon("a");
    let img = image(4 * MIB as usize);
    let p = tmpimg("res", &img);
    let mut ui = TUi::default();
    // the link dies for good at hash call 2 (both the call and its retry)
    let mut t = Spy::new(&d);
    t.cut = 2..4;
    let e = flash(&mut t, "vdv6", &params(&p, true), &mut ui).unwrap_err();
    assert!(matches!(&e, FlashError::Client(ClientError::Failed(m)) if m.contains("failed twice")), "{:?}", e);
    assert_eq!(t.count("--finish"), 0);
    // the session is still on the host (verify phase): --resume sends only END and verifies again from range 0
    let mut t = Spy::new(&d);
    let mut pr = params(&p, true);
    pr.resume = true;
    let o = flash(&mut t, "vdv6", &pr, &mut ui).unwrap();
    assert!(o.verified && o.resumed_from == img.len() as u64, "resumed at {}", o.resumed_from);
    assert_eq!(t.hash_calls, 4);
    assert_eq!(t.count("--finish"), 1);
    assert_eq!(o.sha256, hex(&sha256(&img)));
    assert_eq!(fx.get("vdv6", 0, img.len()), img);

    // without --verify nothing changes: one request, no verify flag, no hash requests
    let mut t = Spy::new(&d);
    let o = flash(&mut t, "vdv6", &params(&p, false), &mut ui).unwrap();
    assert!(!o.verified);
    assert_eq!((t.hash_calls, t.count("--verify-ranges"), t.count("--finish")), (0, 0, 0));
    assert_eq!(fx.get("vdv6", 0, img.len()), img);
    let _ = (std::fs::remove_file(p), Tuning { chunk: 1, window: 1 });
}
