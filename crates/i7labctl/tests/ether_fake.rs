//! The ether client against the real session engine and a fake host built on `ServerSessions` over a MemLink.
//! Runs only once labproto::session is implemented (P1); until then each test reports SKIPPED.
mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use i7labctl::discover::LinkSet;
use i7labctl::ether::{EtherOpts, EtherTransport};
use i7labctl::opts::Global;
use i7labctl::{ClientError, Connect, Kind, Target, Transport};
use labproto::catalog;
use labproto::frame;
use labproto::keys::{Key, KeySet};
use labproto::link::{Link, MemLink};
use labproto::session::{Action, ClientSession, ServerSessions, SessionLimits};
use labproto::{Mac, Status};

const SERVER: Mac = Mac([0x02, 0, 0, 0, 0, 0x02]);
const CLIENT: Mac = Mac([0x02, 0, 0, 0, 0, 0x01]);

fn session_ready() -> bool {
    let k = Key::generate(labproto::keys::Role::Admin).unwrap();
    let mut c = ClientSession::new(CLIENT, SERVER, vec![], &k, SessionLimits::default(), Instant::now());
    let ready = c.poll(Instant::now()).iter().any(|a| matches!(a, Action::Send(_)));
    if !ready {
        eprintln!("SKIPPED: labproto::session is still a stub (P1)");
    }
    ready
}

struct FakeHost {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    pub executed: Arc<Mutex<Vec<u16>>>,
}

impl FakeHost {
    fn start(mut link: MemLink, keys: KeySet) -> FakeHost {
        let stop = Arc::new(AtomicBool::new(false));
        let executed: Arc<Mutex<Vec<u16>>> = Default::default();
        let (s2, e2) = (stop.clone(), executed.clone());
        let handle = std::thread::spawn(move || {
            let mut srv = ServerSessions::new(SERVER, SessionLimits::default()).unwrap();
            let mut buf = vec![0u8; 4096];
            while !s2.load(Ordering::SeqCst) {
                let mut acts = Vec::new();
                if let Ok(Some(m)) = link.recv(&mut buf, Duration::from_millis(5)) {
                    if let Some((eth, _)) = frame::eth_parse(&buf[..m.len]) {
                        if eth.ethertype == frame::ETHERTYPE_CTL {
                            acts.extend(srv.on_frame(&keys, &buf[..m.len], &eth.tags, Instant::now()));
                        }
                    }
                }
                acts.extend(srv.poll(Instant::now()));
                let mut queue = acts;
                while !queue.is_empty() {
                    let mut next = Vec::new();
                    for a in queue.drain(..) {
                        match a {
                            Action::Send(f) => {
                                let _ = link.send(1, &f);
                            }
                            Action::Request { req_id, cmd, .. } => {
                                e2.lock().unwrap().push(cmd);
                                let now = Instant::now();
                                match catalog::by_id(cmd).map(|c| c.name) {
                                    Some("ping") => next.extend(srv.respond(req_id, Status::Ok, b"{\"uptime_ms\":1,\"boot_id\":\"ab\"}", now)),
                                    Some("exec") => {
                                        let (_, o) = srv.stream_data(req_id, frame::Chan::Stdout, b"hello\n", true, now);
                                        next.extend(o);
                                        let mut body = 3i32.to_be_bytes().to_vec();
                                        body.extend_from_slice(b"{\"signal\":0}");
                                        next.extend(srv.respond(req_id, Status::Ok, &body, now));
                                    }
                                    Some("blk.write") => next.extend(srv.respond(req_id, Status::Refused, b"{\"error\":{\"code\":\"REFUSED\",\"message\":\"boot media\",\"reasons\":[\"BootMedia\"]}}", now)),
                                    _ => next.extend(srv.respond(req_id, Status::Unsupported, b"", now)),
                                }
                            }
                            _ => {}
                        }
                    }
                    queue = next;
                }
            }
        });
        FakeHost { stop, handle: Some(handle), executed }
    }
}

impl Drop for FakeHost {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

struct MemConnect {
    link: Mutex<Option<MemLink>>,
}

impl Connect for MemConnect {
    fn connect(&self, kind: Kind, t: &Target, g: &Global, key: &Key) -> Result<Box<dyn Transport>, ClientError> {
        assert_eq!(kind, Kind::Ether);
        let link = self.link.lock().unwrap().take().expect("one connect per test");
        let timeout = g.timeout.filter(|t| *t > 0.0).map(Duration::from_secs_f64);
        Ok(Box::new(EtherTransport::open(Box::new(link), 1, t.mac.unwrap(), t.vlan, key, EtherOpts { timeout, ..Default::default() })?))
    }
    fn open_link(&self, _g: &Global) -> Result<LinkSet, ClientError> {
        Err(ClientError::Transport("n/a".into()))
    }
}

fn run(t: &T, client: MemLink, args: &[&str]) -> (i32, String, String) {
    let mut env = t.env();
    env.connector = Box::new(MemConnect { link: Mutex::new(Some(client)) });
    let mut a: Vec<String> = vec!["--ether".into(), SERVER.to_string()];
    a.extend(args.iter().map(|s| s.to_string()));
    t.out.0.lock().unwrap().clear();
    t.err.0.lock().unwrap().clear();
    let code = i7labctl::cli::run_with(a, &mut env);
    (code, t.out.text(), t.err.text())
}

#[test]
fn ping_exec_and_refusal_over_the_real_session_engine() {
    if !session_ready() {
        return;
    }
    need_json!();
    let t = T::new("e1");
    let keys = KeySet::load_dir(&i7labctl::keys::default_key_dir(&t.home)).unwrap();
    let (a, b) = MemLink::pair(CLIENT, SERVER);
    let host = FakeHost::start(b, keys);
    let (code, o, e) = run(&t, a, &["ping", "-c", "1", "--timeout", "10"]);
    assert_eq!(code, 0, "{}", e);
    assert!(o.contains("1 received"), "{}", o);

    let (a, b2) = MemLink::pair(CLIENT, SERVER);
    drop(host);
    let keys = KeySet::load_dir(&i7labctl::keys::default_key_dir(&t.home)).unwrap();
    let host = FakeHost::start(b2, keys);
    let (code, o, e) = run(&t, a, &["exec", "--", "false"]);
    assert_eq!(code, 3, "{}", e);
    assert!(o.contains("hello"), "{}", o);

    let (a, b3) = MemLink::pair(CLIENT, SERVER);
    drop(host);
    let keys = KeySet::load_dir(&i7labctl::keys::default_key_dir(&t.home)).unwrap();
    let host = FakeHost::start(b3, keys);
    let (code, _, e) = run(&t, a, &["--cmd", "blk.write", "sda"]);
    assert_eq!(code, 7, "{}", e);
    assert!(e.contains("BootMedia"), "{}", e);
    assert!(host.executed.lock().unwrap().contains(&0x0016));
}

#[test]
fn a_host_with_another_key_set_never_answers_and_the_client_says_why() {
    if !session_ready() {
        return;
    }
    let t = T::new("e2");
    let other = KeySet { admin: Some(Key::generate(labproto::keys::Role::Admin).unwrap()), ro: Some(Key::generate(labproto::keys::Role::Ro).unwrap()) };
    let (a, b) = MemLink::pair(CLIENT, SERVER);
    let _host = FakeHost::start(b, other);
    let (code, _, e) = run(&t, a, &["ping", "-c", "1", "--timeout", "3"]);
    assert_eq!(code, 4, "{}", e);
    assert!(e.contains("no CHALLENGE: wrong key set or host unreachable"), "{}", e);
}
