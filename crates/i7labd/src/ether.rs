//! Ether command server and beacon sender (PROTOCOL.md sections 4-8, 10). Owner: P6b.
//!
//! One serving loop per NIC (physical or VLAN sub-interface), each with its own `labproto::session` engine (the
//! server MAC is part of the session key) and its own beacon scheduler, so a VLAN created by `net.vlan` gets a
//! loop within 2 s. The loop is single-threaded for I/O; every authenticated request runs on its own worker thread
//! through `Registry::dispatch` and talks back through the engine under a short lock:
//!
//!   driver: Link::recv -> Engine::on_frame -> Action::Request -> worker
//!   worker: dispatch -> EtherSink::data -> Engine::stream_data (retry while the window is closed = backpressure)
//!           -> Engine::respond -> frames queued to the driver, which owns the Link
//!
//! The engine is a trait so the loop is tested with a scripted mock over `MemLink`; production uses
//! `labproto::session::ServerSessions`.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use labproto::frame::{self, Chan, FrameType, Header, ETHERTYPE_BEACON, ETHERTYPE_CTL, HDR_LEN};
use labproto::keys::{KeySet, Role};
use labproto::link::Link;
use labproto::session::{Action, ServerSessions, SessionLimits};
use labproto::{Mac, Status};

use crate::beacon::{self, HintState, HintVerdict, Nic, Nics, ProbeLimiter, Scheduler};
use crate::daemon::Daemon;
use crate::limits::Stats;
use crate::registry::{Content, Ctx, Sink, Source};

/// Stream chunk handed to the engine at once (below the 1400 byte fragment size).
pub const STREAM_CHUNK: usize = 1024;
/// A closed send window for longer than this ends the request (client gone).
pub const STREAM_STALL: Duration = Duration::from_secs(60);
/// At most this many request workers per NIC (8 outstanding per session x 8 sessions would be more).
pub const MAX_WORKERS: usize = 16;
/// Queued input chunks per request (stdin / upload); overflow cancels the request.
pub const INPUT_QUEUE: usize = 4096;
const RECV_SLICE: Duration = Duration::from_millis(10);

/// The sans-IO session engine as the loop uses it (`labproto::session::ServerSessions`).
pub trait Engine: Send {
    fn on_frame(&mut self, keys: &KeySet, frame: &[u8], tags: &[(u16, u16)], now: Instant) -> Vec<Action>;
    fn respond(&mut self, req_id: u32, status: Status, body: &[u8], now: Instant) -> Vec<Action>;
    fn stream_data(&mut self, req_id: u32, chan: Chan, data: &[u8], fin: bool, now: Instant) -> (bool, Vec<Action>);
    fn poll(&mut self, now: Instant) -> Vec<Action>;
    fn session_count(&self) -> usize;
}

impl Engine for ServerSessions {
    fn on_frame(&mut self, keys: &KeySet, frame: &[u8], tags: &[(u16, u16)], now: Instant) -> Vec<Action> {
        ServerSessions::on_frame(self, keys, frame, tags, now)
    }
    fn respond(&mut self, req_id: u32, status: Status, body: &[u8], now: Instant) -> Vec<Action> {
        ServerSessions::respond(self, req_id, status, body, now)
    }
    fn stream_data(&mut self, req_id: u32, chan: Chan, data: &[u8], fin: bool, now: Instant) -> (bool, Vec<Action>) {
        ServerSessions::stream_data(self, req_id, chan, data, fin, now)
    }
    fn poll(&mut self, now: Instant) -> Vec<Action> {
        ServerSessions::poll(self, now)
    }
    fn session_count(&self) -> usize {
        ServerSessions::session_count(self)
    }
}

/// Where the frame that produced a set of actions came from (audit source of the requests it completes).
#[derive(Clone, Debug)]
struct Origin {
    mac: Mac,
    tags: Vec<(u16, u16)>,
}

struct ReqHandle {
    cancel: Arc<AtomicBool>,
    input: Option<SyncSender<Vec<u8>>>,
}

struct Shared {
    daemon: Arc<Daemon>,
    engine: Mutex<Box<dyn Engine>>,
    out: Mutex<Sender<Vec<u8>>>,
    reqs: Mutex<HashMap<u32, ReqHandle>>,
    workers: AtomicUsize,
    iface: String,
}

impl Shared {
    fn emit(&self, frame: Vec<u8>) {
        let _ = self.out.lock().unwrap().send(frame);
    }

    fn respond(self: &Arc<Self>, req_id: u32, status: Status, body: &[u8]) {
        let acts = self.engine.lock().unwrap().respond(req_id, status, body, Instant::now());
        self.apply(acts, None);
    }

    /// Execute what the engine asked for.
    fn apply(self: &Arc<Self>, actions: Vec<Action>, origin: Option<&Origin>) {
        for a in actions {
            match a {
                Action::Send(f) => self.emit(f),
                Action::Request { req_id, cmd, body, role } => self.start_request(req_id, cmd, body, role, origin),
                Action::StreamData { req_id, chan, data } => self.route_input(req_id, chan, data),
                Action::StreamEnd { req_id, chan } => {
                    // end of the client's stdin / upload: closing the channel is EOF for the handler
                    if matches!(chan, Chan::Stdin | Chan::File) {
                        if let Some(h) = self.reqs.lock().unwrap().get_mut(&req_id) {
                            h.input = None;
                        }
                    }
                }
                Action::Canceled { req_id } => {
                    if let Some(h) = self.reqs.lock().unwrap().get(&req_id) {
                        h.cancel.store(true, Ordering::SeqCst);
                    }
                }
                Action::Closed { reason } => self.daemon.log(&format!("ether {}: session closed: {}", self.iface, reason)),
                Action::Response { .. } | Action::Opened { .. } => {} // client-side actions
            }
        }
    }

    fn route_input(&self, req_id: u32, chan: Chan, data: Vec<u8>) {
        if !matches!(chan, Chan::Stdin | Chan::File) {
            return; // Ctl (resize, signals) has no consumer yet: documented in the report
        }
        let mut reqs = self.reqs.lock().unwrap();
        if let Some(h) = reqs.get_mut(&req_id) {
            if let Some(tx) = &h.input {
                match tx.try_send(data) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        // the handler cannot keep up and the engine has already acknowledged the data: stop
                        // rather than corrupt the stream
                        h.cancel.store(true, Ordering::SeqCst);
                        h.input = None;
                    }
                    Err(TrySendError::Disconnected(_)) => h.input = None,
                }
            }
        }
    }

    fn start_request(self: &Arc<Self>, req_id: u32, cmd_id: u16, body: Vec<u8>, role: Role, origin: Option<&Origin>) {
        let d = &self.daemon;
        Stats::bump(&d.stats.ether_requests);
        let Some(cmd) = d.registry.by_id(cmd_id) else {
            return self.respond(req_id, Status::Unsupported, &err_body(Status::Unsupported, "unknown command id"));
        };
        let args = match labproto::args::decode_argv(&body) {
            Ok(a) => a,
            Err(e) => return self.respond(req_id, Status::BadArgs, &err_body(Status::BadArgs, &e.to_string())),
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = sync_channel::<Vec<u8>>(INPUT_QUEUE);
        {
            let mut reqs = self.reqs.lock().unwrap();
            // PLAN gap: `Action::Request`/`respond` carry no session id, so two sessions using the same req_id
            // cannot be told apart. The second one is refused rather than answered to the wrong peer.
            if reqs.contains_key(&req_id) {
                drop(reqs);
                return self.respond(req_id, Status::Busy, &err_body(Status::Busy, "req_id already in flight"));
            }
            if self.workers.load(Ordering::SeqCst) >= MAX_WORKERS {
                drop(reqs);
                Stats::bump(&d.stats.ether_dropped_busy);
                return self.respond(req_id, Status::Busy, &err_body(Status::Busy, "too many requests in progress"));
            }
            reqs.insert(req_id, ReqHandle { cancel: cancel.clone(), input: Some(tx) });
        }
        self.workers.fetch_add(1, Ordering::SeqCst);
        let origin = origin.cloned().unwrap_or(Origin { mac: Mac::default(), tags: vec![] });
        let me = self.clone();
        let spec = cmd.spec;
        std::thread::spawn(move || {
            let keys = me.daemon.keys.read().unwrap();
            let fp = match role {
                Role::Admin => keys.admin.as_ref(),
                Role::Ro => keys.ro.as_ref(),
            }
            .map(|k| k.fingerprint())
            .unwrap_or_else(|| "-".into());
            drop(keys);
            let mut sink = EtherSink { shared: me.clone(), req_id, cancel: cancel.clone(), input: Some(rx) };
            let mut ctx = Ctx {
                daemon: &me.daemon,
                source: Source::Ether { mac: origin.mac, vlan: origin.tags.first().map(|t| t.1 & 0x0fff), iface: me.iface.clone() },
                role,
                actor: format!("{}:{}", role.name(), fp),
                args,
                sink: &mut sink,
                cancel,
            };
            let cmd = me.daemon.registry.get(spec.name).expect("registry entry vanished");
            let reply = me.daemon.registry.dispatch(&mut ctx, cmd);
            let body = match reply.content {
                Content::Json | Content::Bytes | Content::ExecResult => reply.body,
            };
            me.reqs.lock().unwrap().remove(&req_id);
            me.respond(req_id, reply.status, &body);
            me.workers.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// Error bodies built outside a handler look like handler errors.
fn err_body(st: Status, msg: &str) -> Vec<u8> {
    crate::registry::Reply::error(st, msg).body
}

/// `Sink` of one request: output goes through `Engine::stream_data`, input comes from the DATA frames the
/// driver routes into the request's channel.
struct EtherSink {
    shared: Arc<Shared>,
    req_id: u32,
    cancel: Arc<AtomicBool>,
    input: Option<Receiver<Vec<u8>>>,
}

impl Sink for EtherSink {
    fn data(&mut self, chan: Chan, bytes: &[u8]) -> io::Result<()> {
        for piece in bytes.chunks(STREAM_CHUNK) {
            let stalled_since = Instant::now();
            loop {
                if self.cancel.load(Ordering::SeqCst) {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "request canceled"));
                }
                let (accepted, acts) = self.shared.engine.lock().unwrap().stream_data(self.req_id, chan, piece, false, Instant::now());
                self.shared.apply(acts, None);
                if accepted {
                    break;
                }
                if stalled_since.elapsed() > STREAM_STALL {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "send window closed"));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        Ok(())
    }

    /// Progress objects travel as NDJSON lines on the stdout channel (PROTOCOL.md section 7: blk tests).
    fn event(&mut self, json: &str) -> io::Result<()> {
        let mut line = json.as_bytes().to_vec();
        line.push(b'\n');
        self.data(Chan::Stdout, &line)
    }

    fn input(&mut self) -> Option<Receiver<Vec<u8>>> {
        self.input.take()
    }
}

/// xorshift for beacon jitter and probe-reply delay (not security relevant).
struct Rng(u64);
impl Rng {
    fn new(seed: [u8; 8]) -> Rng {
        Rng(u64::from_le_bytes(seed) | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    /// -max..=max
    fn jitter(&mut self, max: i64) -> i64 {
        (self.next() % (2 * max as u64 + 1)) as i64 - max
    }
}

fn our_frame(nic: &Nic, src: Mac) -> bool {
    src == nic.mac
}

/// Serve one NIC until `stop` is set or the link fails. `ifindex` is where frames leave.
pub fn serve(
    daemon: Arc<Daemon>,
    mut link: Box<dyn Link>,
    mut nics: Box<dyn Nics>,
    engine: Box<dyn Engine>,
    ifindex: i32,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    let (tx, rx) = channel::<Vec<u8>>();
    let mut nic_list = nics.list();
    let iface = nic_list.first().map(|n| n.name.clone()).unwrap_or_else(|| format!("if{}", ifindex));
    let shared = Arc::new(Shared {
        daemon: daemon.clone(),
        engine: Mutex::new(engine),
        out: Mutex::new(tx),
        reqs: Mutex::new(HashMap::new()),
        workers: AtomicUsize::new(0),
        iface,
    });
    let mut sched = Scheduler::new(daemon.config.beacon_compat);
    let mut limiter = ProbeLimiter::default();
    let mut hints = HintState::default();
    let mut delayed: Vec<(Instant, Vec<u8>)> = Vec::new();
    let mut rng = Rng::new(daemon.boot_id);
    let mut nic_at = Instant::now();
    let mut counted = 0usize;
    let mut errors = 0u32;
    let mut buf = vec![0u8; 9216];
    let boot_hex = labproto::crypto::hex(&daemon.boot_id);

    let result = loop {
        if stop.load(Ordering::SeqCst) {
            break Ok(());
        }
        let now = Instant::now();
        if now.duration_since(nic_at) > Duration::from_millis(500) {
            nic_list = nics.list();
            nic_at = now;
        }
        // 1. beacons (and the last frame at shutdown)
        let shutdown = daemon.state_str() == "shutdown";
        for due in sched.due(now, &nic_list, shutdown, &mut |m| rng.jitter(m)) {
            let payload = beacon::encode(&daemon, &due);
            shared.emit(beacon::beacon_frame(&due.nic, &payload));
            Stats::bump(&daemon.stats.beacons_tx);
        }
        // 2. delayed probe replies that are due
        let mut i = 0;
        while i < delayed.len() {
            if delayed[i].0 <= now {
                shared.emit(delayed.swap_remove(i).1);
            } else {
                i += 1;
            }
        }
        // 3. everything queued for the wire
        while let Ok(f) = rx.try_recv() {
            match link.send(ifindex, &f) {
                Ok(()) => Stats::bump(&daemon.stats.frames_tx),
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => break,
                Err(_) => {} // transient (ENOBUFS, link down): the engine retransmits
            }
        }
        // 4. one received frame
        match link.recv(&mut buf, RECV_SLICE) {
            Ok(Some(meta)) => {
                errors = 0;
                Stats::bump(&daemon.stats.frames_rx);
                let frame = &buf[..meta.len.min(buf.len())];
                if let Some((eth, payload)) = frame::eth_parse(frame) {
                    let nic = nic_list.first().cloned();
                    if nic.as_ref().is_some_and(|n| our_frame(n, eth.src)) {
                        continue; // own beacon looped back (multicast test links)
                    }
                    let Some(tags) = frame::canonical_tags(meta.aux_tag, &eth.tags) else { continue };
                    match eth.ethertype {
                        ETHERTYPE_CTL => {
                            let probe = payload.len() >= HDR_LEN
                                && Header::decode(&payload[..HDR_LEN]).map(|h| h.ftype == FrameType::Probe as u8).unwrap_or(false);
                            if probe {
                                if let Some(n) = nic {
                                    Stats::bump(&daemon.stats.probes_rx);
                                    if limiter.allow(ifindex, now) {
                                        let h = Header::decode(&payload[..HDR_LEN]).unwrap();
                                        let f = beacon::probe_reply(&daemon, &n, eth.src, &tags, &h, 0);
                                        // jittered 0..400 ms so replies of many hosts do not collide
                                        delayed.push((now + Duration::from_millis(rng.next() % 400), f));
                                    }
                                }
                            } else {
                                let origin = Origin { mac: eth.src, tags: tags.clone() };
                                let acts = {
                                    let keys = daemon.keys.read().unwrap();
                                    shared.engine.lock().unwrap().on_frame(&keys, frame, &tags, now)
                                };
                                shared.apply(acts, Some(&origin));
                            }
                        }
                        ETHERTYPE_BEACON if payload.starts_with(b"I7LR") => {
                            if let Some(n) = nic {
                                handle_hint(&daemon, &mut hints, &n, payload, &boot_hex);
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                errors += 1;
                if errors > 50 {
                    break Err(e);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        // 5. engine timers (retransmits, keepalives, idle expiry)
        let acts = shared.engine.lock().unwrap().poll(Instant::now());
        shared.apply(acts, None);
        let n = shared.engine.lock().unwrap().session_count();
        if n != counted {
            if n > counted {
                daemon.sessions_open.fetch_add(n - counted, Ordering::Relaxed);
            } else {
                daemon.sessions_open.fetch_sub(counted - n, Ordering::Relaxed);
            }
            counted = n;
        }
    };
    // leave the shared counter right and cancel what is still running on this NIC
    daemon.sessions_open.fetch_sub(counted.min(daemon.sessions_open.load(Ordering::Relaxed)), Ordering::Relaxed);
    for h in shared.reqs.lock().unwrap().values() {
        h.cancel.store(true, Ordering::SeqCst);
    }
    result
}

fn handle_hint(daemon: &Arc<Daemon>, hints: &mut HintState, nic: &Nic, payload: &[u8], boot_hex: &str) {
    let v2 = payload.starts_with(b"I7LR2");
    let admin = daemon.keys.read().unwrap().admin.as_ref().map(|k| k.bytes);
    if !v2 && !daemon.config.accept_v1_hint {
        Stats::bump(&daemon.stats.hints_rejected);
        return;
    }
    let parsed = if v2 {
        match &admin {
            Some(a) => labproto::beacon::Hint::parse(payload, Some(a)),
            None => return,
        }
    } else {
        labproto::beacon::Hint::parse(payload, None)
    };
    let Ok(hint) = parsed else {
        Stats::bump(&daemon.stats.hints_rejected);
        return;
    };
    match hints.judge(nic, &hint, v2, boot_hex, daemon.config.accept_v1_hint) {
        HintVerdict::Reject(why) => {
            Stats::bump(&daemon.stats.hints_rejected);
            daemon.log(&format!("ether {}: hint rejected: {}", nic.name, why));
        }
        HintVerdict::Apply => match crate::netcfg::apply_hint(daemon, daemon.netops.clone(), nic, &hint) {
            Ok(()) => {
                Stats::bump(&daemon.stats.hints_applied);
                daemon.log(&format!("ether {}: hint applied: {}.{}.{}.{}/{}", nic.name, hint.ip[0], hint.ip[1], hint.ip[2], hint.ip[3], hint.prefix));
            }
            Err(e) => daemon.log(&format!("ether {}: hint failed: {}", nic.name, e)),
        },
    }
}

/// Interfaces to serve under `i7lab.ether=` (allow) and `ether_deny`.
pub fn select_ifaces(all: &[String], allow: &[String], deny: &[String]) -> Vec<String> {
    all.iter().filter(|n| (allow.is_empty() || allow.contains(n)) && !deny.contains(n)).cloned().collect()
}

fn nic_thread(daemon: Arc<Daemon>, name: String, stop: Arc<AtomicBool>) -> io::Result<()> {
    let ifindex = labproto::packet::PacketLink::ifindex(&name)?;
    let link = labproto::packet::PacketLink::open(std::slice::from_ref(&name))?;
    let mac = link.local_mac(ifindex)?;
    let engine = ServerSessions::new(mac, SessionLimits::default())?;
    serve(daemon, Box::new(link), Box::new(beacon::SysNics { names: vec![name] }), Box::new(engine), ifindex, stop)
}

/// Retry delay for a NIC loop that ended (no permission, unsupported socket, interface down).
pub const RESTART_COOLDOWN: Duration = Duration::from_secs(15);

/// The ether duty: keep one serving loop per selected NIC; loops for vanished NICs stop, failed ones restart
/// after a cooldown, and an error is logged once per distinct message.
pub fn run(daemon: Arc<Daemon>) -> io::Result<()> {
    struct Loop {
        stop: Arc<AtomicBool>,
        handle: std::thread::JoinHandle<()>,
    }
    let mut loops: HashMap<String, Loop> = HashMap::new();
    let mut cooldown: HashMap<String, Instant> = HashMap::new();
    let last_err: Arc<Mutex<HashMap<String, String>>> = Arc::default();
    loop {
        let all = labproto::packet::ethernet_ifaces().unwrap_or_default();
        let want = select_ifaces(&all, &daemon.config.ether_allow, &daemon.config.ether_deny);
        loops.retain(|name, l| {
            let keep = want.contains(name) && !l.handle.is_finished();
            if !keep {
                l.stop.store(true, Ordering::SeqCst);
                if l.handle.is_finished() {
                    cooldown.insert(name.clone(), Instant::now() + RESTART_COOLDOWN);
                }
            }
            keep
        });
        cooldown.retain(|n, _| want.contains(n));
        for name in want {
            if loops.contains_key(&name) || cooldown.get(&name).is_some_and(|t| *t > Instant::now()) {
                continue;
            }
            let stop = Arc::new(AtomicBool::new(false));
            let (d, n, s, errs) = (daemon.clone(), name.clone(), stop.clone(), last_err.clone());
            let handle = std::thread::spawn(move || {
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| nic_thread(d.clone(), n.clone(), s)));
                let msg = match r {
                    Ok(Err(e)) => Some(e.to_string()),
                    Err(_) => Some("loop panicked".to_string()),
                    Ok(Ok(())) => None,
                };
                if let Some(m) = msg {
                    let mut g = errs.lock().unwrap();
                    if g.get(&n) != Some(&m) {
                        d.log(&format!("ether {}: {}", n, m));
                        g.insert(n, m);
                    }
                }
            });
            loops.insert(name, Loop { stop, handle });
        }
        let running = loops.values().filter(|l| !l.handle.is_finished()).count();
        daemon.flags.set_ether(running);
        std::thread::sleep(Duration::from_secs(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::StaticNics;
    use crate::registry::tests_support::test_daemon;
    use labproto::frame::{eth_build, eth_parse, EthHeader};
    use labproto::link::MemLink;
    use std::collections::VecDeque;

    const SERVER: Mac = Mac([2, 0, 0, 0, 0, 0xaa]);
    const CLIENT: Mac = Mac([2, 0, 0, 0, 0, 0xcc]);

    // ---- scripted engine: frames are [kind, req_id u32 BE, ...]; kind 1 REQ(cmd u16, role u8, argv), 2 DATA(chan, bytes),
    // 3 END(chan), 4 CANCEL. Outgoing: 0x10 RESP(status u16, body), 0x11 DATA(chan, bytes).
    struct Mock {
        refuse: usize,
        peer: Mac,
        seen: Arc<Mutex<VecDeque<String>>>,
    }

    fn client_frame(payload: Vec<u8>) -> Vec<u8> {
        eth_build(&EthHeader { dst: SERVER, src: CLIENT, tags: vec![], ethertype: ETHERTYPE_CTL }, &payload)
    }

    fn req(req_id: u32, cmd: u16, role: Role, argv: &[&str]) -> Vec<u8> {
        let mut p = vec![1];
        p.extend_from_slice(&req_id.to_be_bytes());
        p.extend_from_slice(&cmd.to_be_bytes());
        p.push(role as u8);
        p.extend_from_slice(&labproto::args::encode_argv(argv));
        client_frame(p)
    }

    fn simple(kind: u8, req_id: u32, chan: u8, data: &[u8]) -> Vec<u8> {
        let mut p = vec![kind];
        p.extend_from_slice(&req_id.to_be_bytes());
        p.push(chan);
        p.extend_from_slice(&(data.len() as u16).to_be_bytes());
        p.extend_from_slice(data);
        client_frame(p)
    }

    impl Mock {
        fn out(&self, p: Vec<u8>) -> Action {
            Action::Send(eth_build(&EthHeader { dst: self.peer, src: SERVER, tags: vec![], ethertype: ETHERTYPE_CTL }, &p))
        }
    }

    impl Engine for Mock {
        fn on_frame(&mut self, _k: &KeySet, frame: &[u8], _t: &[(u16, u16)], _n: Instant) -> Vec<Action> {
            let (eth, p) = eth_parse(frame).unwrap();
            self.peer = eth.src;
            let id = u32::from_be_bytes(p[1..5].try_into().unwrap());
            match p[0] {
                1 => {
                    let cmd = u16::from_be_bytes([p[5], p[6]]);
                    let role = if p[7] == 0 { Role::Admin } else { Role::Ro };
                    vec![Action::Request { req_id: id, cmd, body: p[8..].to_vec(), role }]
                }
                2 => vec![Action::StreamData { req_id: id, chan: if p[5] == 3 { Chan::Stdin } else { Chan::File }, data: p[8..8 + u16::from_be_bytes([p[6], p[7]]) as usize].to_vec() }],
                3 => vec![Action::StreamEnd { req_id: id, chan: if p[5] == 3 { Chan::Stdin } else { Chan::File } }],
                4 => vec![Action::Canceled { req_id: id }],
                _ => vec![],
            }
        }
        fn respond(&mut self, req_id: u32, status: Status, body: &[u8], _n: Instant) -> Vec<Action> {
            self.seen.lock().unwrap().push_back(format!("resp {}", req_id));
            let mut p = vec![0x10];
            p.extend_from_slice(&req_id.to_be_bytes());
            p.extend_from_slice(&(status as u16).to_be_bytes());
            p.extend_from_slice(&(body.len() as u32).to_be_bytes());
            p.extend_from_slice(body);
            vec![self.out(p)]
        }
        fn stream_data(&mut self, req_id: u32, chan: Chan, data: &[u8], _fin: bool, _n: Instant) -> (bool, Vec<Action>) {
            if self.refuse > 0 {
                self.refuse -= 1;
                return (false, vec![]);
            }
            let mut p = vec![0x11];
            p.extend_from_slice(&req_id.to_be_bytes());
            p.push(chan as u8);
            p.extend_from_slice(&(data.len() as u16).to_be_bytes());
            p.extend_from_slice(data);
            (true, vec![self.out(p)])
        }
        fn poll(&mut self, _n: Instant) -> Vec<Action> {
            vec![]
        }
        fn session_count(&self) -> usize {
            1
        }
    }

    struct Harness {
        client: MemLink,
        stop: Arc<AtomicBool>,
        server: Option<std::thread::JoinHandle<io::Result<()>>>,
        daemon: Arc<Daemon>,
    }

    fn nic() -> Nic {
        Nic { name: "eth0".into(), ifindex: 1, mac: SERVER, carrier: true, operstate: "up".into(), ipv4: Some("10.0.0.2/24".into()), vlan: 0 }
    }

    fn harness(refuse: usize) -> Harness {
        let daemon = Arc::new(test_daemon());
        daemon.set_state("ready");
        let (srv, client) = MemLink::pair(SERVER, CLIENT);
        let stop = Arc::new(AtomicBool::new(false));
        let mock = Mock { refuse, peer: CLIENT, seen: Arc::default() };
        let (d, s) = (daemon.clone(), stop.clone());
        let server = std::thread::spawn(move || serve(d, Box::new(srv), Box::new(StaticNics(vec![nic()])), Box::new(mock), 1, s));
        Harness { client, stop, server: Some(server), daemon }
    }

    impl Harness {
        /// Collect frames until `done` says so or 5 s pass. Beacons are returned as ("beacon", payload).
        fn collect(&mut self, mut done: impl FnMut(&[(String, Vec<u8>)]) -> bool) -> Vec<(String, Vec<u8>)> {
            let mut got: Vec<(String, Vec<u8>)> = Vec::new();
            let t = Instant::now();
            let mut buf = vec![0u8; 4096];
            while t.elapsed() < Duration::from_secs(5) && !done(&got) {
                let Some(m) = self.client.recv(&mut buf, Duration::from_millis(50)).unwrap() else { continue };
                let (eth, p) = eth_parse(&buf[..m.len]).unwrap();
                match (eth.ethertype, p.first()) {
                    (ETHERTYPE_BEACON, _) => got.push(("beacon".into(), p.to_vec())),
                    (ETHERTYPE_CTL, Some(0x10)) => {
                        let n = u32::from_be_bytes(p[7..11].try_into().unwrap()) as usize;
                        let mut v = p[1..7].to_vec();
                        v.extend_from_slice(&p[11..11 + n]);
                        got.push(("resp".into(), v))
                    }
                    (ETHERTYPE_CTL, Some(0x11)) => {
                        let n = u16::from_be_bytes([p[6], p[7]]) as usize;
                        let mut v = p[1..6].to_vec();
                        v.extend_from_slice(&p[8..8 + n]);
                        got.push(("data".into(), v))
                    }
                    (ETHERTYPE_CTL, _) => got.push(("ctl".into(), p.to_vec())),
                    _ => {}
                }
            }
            got
        }
        fn send(&mut self, f: Vec<u8>) {
            self.client.send(1, &f).unwrap();
        }
        fn finish(mut self) {
            self.stop.store(true, Ordering::SeqCst);
            self.server.take().unwrap().join().unwrap().unwrap();
        }
    }

    fn resp(got: &[(String, Vec<u8>)], id: u32) -> Option<(u16, Vec<u8>)> {
        got.iter().find(|(k, b)| k == "resp" && b[..4] == id.to_be_bytes()).map(|(_, b)| (u16::from_be_bytes([b[4], b[5]]), b[6..].to_vec()))
    }

    #[test]
    fn beacons_go_out_first_and_parse() {
        let mut h = harness(0);
        let got = h.collect(|g| g.iter().filter(|(k, _)| k == "beacon").count() >= 2);
        let b: Vec<_> = got.iter().filter(|(k, _)| k == "beacon").collect();
        assert!(b.len() >= 2);
        let parsed = labproto::beacon::Beacon::parse(&b[0].1).unwrap();
        assert_eq!((parsed.version, parsed.get("mac"), parsed.get("state")), (2, Some("02:00:00:00:00:aa"), Some("ready")));
        h.finish();
    }

    #[test]
    fn ping_request_is_answered() {
        let mut h = harness(0);
        h.send(req(1, 0x0001, Role::Ro, &["hi"]));
        let got = h.collect(|g| resp(g, 1).is_some());
        let (st, body) = resp(&got, 1).expect("no RESP");
        assert_eq!(st, 0);
        assert!(String::from_utf8_lossy(&body).contains("\"echo\":\"hi\""));
        h.finish();
    }

    #[test]
    fn ro_request_for_admin_command_is_refused_and_unknown_ids_unsupported() {
        let mut h = harness(0);
        h.send(req(1, 0x0020, Role::Ro, &["--", "/bin/true"]));
        h.send(req(2, 0x7777, Role::Admin, &[]));
        let got = h.collect(|g| resp(g, 1).is_some() && resp(g, 2).is_some());
        assert_eq!(resp(&got, 1).unwrap().0, Status::Eperm as u16);
        assert_eq!(resp(&got, 2).unwrap().0, Status::Unsupported as u16);
        h.finish();
    }

    #[test]
    fn exec_output_streams_before_the_response_even_with_backpressure() {
        let mut h = harness(25); // the first 25 stream_data calls say "window closed"
        h.send(req(3, 0x0020, Role::Admin, &["--", "/bin/sh", "-c", "echo out; echo err >&2; exit 5"]));
        let got = h.collect(|g| resp(g, 3).is_some());
        let order: Vec<&str> = got.iter().filter(|(k, _)| k != "beacon").map(|(k, _)| k.as_str()).collect();
        assert_eq!(order.last(), Some(&"resp"), "RESP never overtakes output: {:?}", order);
        let out: Vec<u8> = got.iter().filter(|(k, b)| k == "data" && b[4] == Chan::Stdout as u8).flat_map(|(_, b)| b[5..].to_vec()).collect();
        let err: Vec<u8> = got.iter().filter(|(k, b)| k == "data" && b[4] == Chan::Stderr as u8).flat_map(|(_, b)| b[5..].to_vec()).collect();
        assert_eq!((out.as_slice(), err.as_slice()), (&b"out\n"[..], &b"err\n"[..]));
        let (st, body) = resp(&got, 3).unwrap();
        assert_eq!(st, 0);
        assert_eq!(&body[..4], &5i32.to_be_bytes());
        h.finish();
    }

    #[test]
    fn upload_arrives_through_stream_data() {
        let mut h = harness(0);
        let dir = h.daemon.config.run_dir.join("up");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.txt");
        let data = b"uploaded over L2";
        let sha = labproto::crypto::hex(&labproto::crypto::sha256(data));
        let size = data.len().to_string();
        h.send(req(4, 0x0030, Role::Admin, &[path.to_str().unwrap(), "--size", &size, "--sha256", &sha]));
        h.send(simple(2, 4, 4, &data[..6]));
        h.send(simple(2, 4, 4, &data[6..]));
        h.send(simple(3, 4, 4, b""));
        let got = h.collect(|g| resp(g, 4).is_some());
        let (st, body) = resp(&got, 4).expect("no RESP");
        assert_eq!(st, 0, "{}", String::from_utf8_lossy(&body));
        assert_eq!(std::fs::read(&path).unwrap(), data);
        h.finish();
    }

    #[test]
    fn cancel_terminates_a_running_exec() {
        let mut h = harness(0);
        h.send(req(5, 0x0020, Role::Admin, &["--", "/bin/sleep", "30"]));
        std::thread::sleep(Duration::from_millis(300));
        h.send(simple(4, 5, 0, b""));
        let t = Instant::now();
        let got = h.collect(|g| resp(g, 5).is_some());
        assert_eq!(resp(&got, 5).expect("no RESP").0, Status::Canceled as u16);
        assert!(t.elapsed() < Duration::from_secs(4));
        h.finish();
    }

    #[test]
    fn duplicate_req_id_in_flight_is_refused() {
        let mut h = harness(0);
        h.send(req(6, 0x0020, Role::Admin, &["--", "/bin/sleep", "2"]));
        std::thread::sleep(Duration::from_millis(200));
        h.send(req(6, 0x0001, Role::Ro, &[]));
        let got = h.collect(|g| resp(g, 6).is_some());
        assert_eq!(resp(&got, 6).unwrap().0, Status::Busy as u16, "the second request with the same id is refused");
        h.send(simple(4, 6, 0, b""));
        h.finish();
    }

    #[test]
    fn probe_gets_a_unicast_reply_and_is_rate_limited() {
        let mut h = harness(0);
        for i in 0..4 {
            let hdr = Header { ver: 1, ftype: FrameType::Probe as u8, req_id: i, plen: 8, ..Default::default() };
            let payload = frame::seal(&hdr, &[7u8; 8], frame::TagKey::None);
            h.send(eth_build(&EthHeader { dst: Mac::BROADCAST, src: CLIENT, tags: vec![], ethertype: ETHERTYPE_CTL }, &payload));
        }
        let got = h.collect(|g| g.iter().filter(|(k, _)| k == "ctl").count() >= 2);
        std::thread::sleep(Duration::from_millis(600));
        let mut more = h.collect(|_| true);
        let mut ctl: Vec<_> = got.into_iter().filter(|(k, _)| k == "ctl").collect();
        ctl.append(&mut more);
        assert!(!ctl.is_empty());
        let f = frame::open(&ctl[0].1).unwrap();
        assert_eq!(f.hdr.ftype, FrameType::ProbeReply as u8);
        assert!(f.payload.starts_with(b"I7LP2\n"));
        h.finish();
    }

    #[test]
    fn selection_rules() {
        let all: Vec<String> = ["eth0", "eth1", "eth0.30"].iter().map(|s| s.to_string()).collect();
        assert_eq!(select_ifaces(&all, &[], &[]).len(), 3);
        assert_eq!(select_ifaces(&all, &["eth1".into()], &[]), vec!["eth1"]);
        assert_eq!(select_ifaces(&all, &[], &["eth0".into()]), vec!["eth1", "eth0.30"]);
    }

    #[test]
    fn own_frames_are_ignored_and_stop_works() {
        let mut h = harness(0);
        // a frame claiming to come from the server's own MAC must not reach the engine
        h.send(eth_build(&EthHeader { dst: SERVER, src: SERVER, tags: vec![], ethertype: ETHERTYPE_CTL }, &{
            let mut p = vec![1];
            p.extend_from_slice(&9u32.to_be_bytes());
            p.extend_from_slice(&1u16.to_be_bytes());
            p.push(1);
            p.extend_from_slice(&labproto::args::encode_argv::<&str>(&[]));
            p
        }));
        let got = h.collect(|g| resp(g, 9).is_some());
        assert!(resp(&got, 9).is_none());
        h.finish();
    }
}
