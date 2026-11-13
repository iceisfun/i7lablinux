//! Ether client: drives `labproto::session::ClientSession` (via the `Engine` trait, so tests can script it) over a
//! `labproto::link::Link` (PacketLink on a real NIC, UdpLink for QEMU dgram/multicast, MemLink in tests).
//! It contains no protocol logic: handshake, fragmentation, ACKs and retransmission live in the session engine;
//! this file moves frames, applies timeouts, routes stream data to the caller's `ClientIo` and feeds it stdin.

use std::time::{Duration, Instant};

use labproto::args::{encode_argv, MAX_BODY};
use labproto::catalog::CmdSpec;
use labproto::frame::{self, Chan, FrameError};
use labproto::keys::{Key, Role};
use labproto::link::Link;
use labproto::session::{Action, ClientSession, SessionLimits};
use labproto::status::Status;
use labproto::Mac;

use crate::{CallResult, ClientError, ClientIo, Input, Transport};

/// The client half of the session engine, as a trait.
pub trait Engine {
    fn send_req(&mut self, cmd: u16, body: &[u8], now: Instant) -> Result<u32, FrameError>;
    fn send_data(&mut self, req_id: u32, chan: Chan, data: &[u8], fin: bool, now: Instant) -> bool;
    fn cancel(&mut self, req_id: u32, now: Instant);
    fn on_frame(&mut self, frame: &[u8], tags: &[(u16, u16)], now: Instant) -> Vec<Action>;
    fn poll(&mut self, now: Instant) -> Vec<Action>;
    fn next_deadline(&self) -> Option<Instant>;
}

impl Engine for ClientSession {
    fn send_req(&mut self, cmd: u16, body: &[u8], now: Instant) -> Result<u32, FrameError> {
        ClientSession::send_req(self, cmd, body, now)
    }
    fn send_data(&mut self, req_id: u32, chan: Chan, data: &[u8], fin: bool, now: Instant) -> bool {
        ClientSession::send_data(self, req_id, chan, data, fin, now)
    }
    fn cancel(&mut self, req_id: u32, now: Instant) {
        ClientSession::cancel(self, req_id, now)
    }
    fn on_frame(&mut self, frame: &[u8], tags: &[(u16, u16)], now: Instant) -> Vec<Action> {
        ClientSession::on_frame(self, frame, tags, now)
    }
    fn poll(&mut self, now: Instant) -> Vec<Action> {
        ClientSession::poll(self, now)
    }
    fn next_deadline(&self) -> Option<Instant> {
        ClientSession::next_deadline(self)
    }
}

pub type EngineFactory = Box<dyn FnMut(Instant) -> Box<dyn Engine>>;

#[derive(Clone, Debug, Default)]
pub struct EtherOpts {
    /// whole-call timeout; None = none (streaming commands)
    pub timeout: Option<Duration>,
    /// extra full handshake attempts after the engine's own retries
    pub retries: u32,
    /// resend the captured REQ frames verbatim right after the first send (I7LABCTL_TEST_REPLAY, F-F26)
    pub replay: bool,
    /// 0 off, 1 summary lines, 2 per frame
    pub verbose: u8,
}

pub struct EtherTransport {
    link: Box<dyn Link>,
    ifindex: i32,
    target: Mac,
    tags: Vec<(u16, u16)>,
    factory: EngineFactory,
    engine: Option<Box<dyn Engine>>,
    opened: Option<(Role, String)>,
    pub opts: EtherOpts,
    trace: Option<Box<dyn FnMut(&str)>>,
}

/// 802.1Q tag stack for `--vlan`.
pub fn vlan_tags(vlan: Option<u16>) -> Vec<(u16, u16)> {
    vlan.map(|v| vec![(frame::TPID_8021Q, v)]).unwrap_or_default()
}

impl EtherTransport {
    /// With the real session engine.
    pub fn open(link: Box<dyn Link>, ifindex: i32, target: Mac, vlan: Option<u16>, key: &Key, opts: EtherOpts) -> Result<EtherTransport, ClientError> {
        let client = link.local_mac(ifindex).map_err(|e| ClientError::Transport(format!("cannot read the MAC of the lab-side interface: {}", e)))?;
        let tags = vlan_tags(vlan);
        let key = key.clone();
        let t2 = tags.clone();
        let factory: EngineFactory = Box::new(move |now| Box::new(ClientSession::new(client, target, t2.clone(), &key, SessionLimits::default(), now)));
        Ok(EtherTransport::with_engine(link, ifindex, target, tags, factory, opts))
    }

    pub fn with_engine(link: Box<dyn Link>, ifindex: i32, target: Mac, tags: Vec<(u16, u16)>, factory: EngineFactory, opts: EtherOpts) -> EtherTransport {
        EtherTransport { link, ifindex, target, tags, factory, engine: None, opened: None, opts, trace: None }
    }

    pub fn set_trace(&mut self, f: Box<dyn FnMut(&str)>) {
        self.trace = Some(f);
    }

    fn tr(&mut self, s: &str) {
        if let Some(t) = self.trace.as_mut() {
            t(s);
        }
    }

    fn send_frame(&mut self, f: &[u8]) -> Result<(), ClientError> {
        if self.opts.verbose >= 2 {
            let desc = frame::eth_parse(f).and_then(|(_, p)| frame::open(p).ok().map(|fr| format!("type={} req={} len={}", fr.hdr.ftype, fr.hdr.req_id, fr.hdr.plen))).unwrap_or_default();
            self.tr(&format!("tx {}B {}", f.len(), desc));
        }
        self.link.send(self.ifindex, f).map_err(|e| ClientError::Transport(format!("send failed: {}", e)))
    }

    /// Execute the engine's actions that concern the link and session state; returns the rest.
    fn dispatch(&mut self, acts: Vec<Action>, rest: &mut Vec<Action>) -> Result<(), ClientError> {
        for a in acts {
            match a {
                Action::Send(f) => self.send_frame(&f)?,
                Action::Opened { role, hostname } => {
                    self.tr(&format!("session open: role {} host {}", role.name(), hostname));
                    self.opened = Some((role, hostname));
                }
                other => rest.push(other),
            }
        }
        Ok(())
    }

    fn handshake_error(reason: &str) -> ClientError {
        let r = reason.to_ascii_lowercase();
        if ["auth", "tag", "proof", "key"].iter().any(|k| r.contains(k)) {
            ClientError::Auth(format!("{}: the host's proof did not verify (wrong key set?)", reason))
        } else {
            ClientError::Transport(format!("no CHALLENGE: wrong key set or host unreachable ({})", reason))
        }
    }

    fn recv_one(&mut self, wait: Duration, buf: &mut [u8], now: Instant) -> Result<Vec<Action>, ClientError> {
        let meta = match self.link.recv(buf, wait) {
            Ok(Some(m)) => m,
            Ok(None) => return Ok(Vec::new()),
            Err(e) => return Err(ClientError::Transport(format!("receive failed: {}", e))),
        };
        let f = &buf[..meta.len];
        let Some((eth, _)) = frame::eth_parse(f) else { return Ok(Vec::new()) };
        if eth.ethertype != frame::ETHERTYPE_CTL || eth.src != self.target {
            return Ok(Vec::new());
        }
        let Some(tags) = frame::canonical_tags(meta.aux_tag, &eth.tags) else { return Ok(Vec::new()) };
        if tags != self.tags {
            return Ok(Vec::new());
        }
        if self.opts.verbose >= 2 {
            self.tr(&format!("rx {}B", f.len()));
        }
        let eng = self.engine.as_mut().expect("engine");
        Ok(eng.on_frame(f, &tags, now))
    }

    fn call_once(&mut self, cmd: &CmdSpec, args: &[String], io: &mut dyn ClientIo, deadline: Option<Instant>) -> Result<CallResult, ClientError> {
        let body = encode_argv(args);
        if body.len() > MAX_BODY {
            return Err(ClientError::Usage(format!("arguments too long ({} bytes, limit {})", body.len(), MAX_BODY)));
        }
        if self.engine.is_none() {
            let now = Instant::now();
            self.engine = Some((self.factory)(now));
            self.opened = None;
        }
        let _sigint = crate::ffi::InterruptGuard::install();
        let mut buf = vec![0u8; 4096];
        let mut req: Option<u32> = None;
        let mut sent_at = Instant::now();
        let mut rest: Vec<Action> = Vec::new();
        let mut outq = Outgoing::default();
        let mut lines = LineSplit::new(event_stream(cmd));

        loop {
            let now = Instant::now();
            // 1. timers
            let acts = self.engine.as_mut().unwrap().poll(now);
            self.dispatch(acts, &mut rest)?;

            // 2. session open: send the request
            if self.opened.is_some() && req.is_none() {
                let eng = self.engine.as_mut().unwrap();
                let id = eng.send_req(cmd.id, &body, now).map_err(|e| ClientError::Usage(format!("request refused locally: {:?}", e)))?;
                req = Some(id);
                sent_at = now;
                let acts = eng.poll(now);
                let mut first: Vec<Vec<u8>> = Vec::new();
                if self.opts.replay {
                    first = acts.iter().filter_map(|a| if let Action::Send(f) = a { Some(f.clone()) } else { None }).collect();
                }
                self.dispatch(acts, &mut rest)?;
                for f in first {
                    self.tr("replaying captured REQ frame");
                    self.send_frame(&f)?;
                }
            }

            // 3. what the engine told us
            for a in std::mem::take(&mut rest) {
                match a {
                    Action::Response { req_id, status, body } if Some(req_id) == req => {
                        lines.flush(io);
                        return Ok(finish(cmd, status, body, sent_at));
                    }
                    Action::Response { .. } => {}
                    Action::StreamData { req_id, chan, data } if Some(req_id) == req => match chan {
                        Chan::Stdout => lines.feed(&data, io),
                        Chan::Stderr => io.stderr(&data),
                        Chan::File => io.file(&data),
                        _ => {}
                    },
                    Action::StreamData { .. } | Action::StreamEnd { .. } => {}
                    Action::Canceled { req_id } if Some(req_id) == req => {
                        lines.flush(io);
                        return Ok(CallResult { status: Status::Canceled, body: Vec::new(), exit_code: None, rtt_ms: ms(sent_at) });
                    }
                    Action::Canceled { .. } => {}
                    Action::Closed { reason } => {
                        self.engine = None;
                        let was_open = self.opened.take().is_some();
                        return Err(if was_open {
                            ClientError::Transport(format!("session closed by the host ({}); it may have rebooted, retry", reason))
                        } else {
                            Self::handshake_error(reason)
                        });
                    }
                    Action::Send(_) | Action::Opened { .. } | Action::Request { .. } => {}
                }
            }

            // 4. client -> server stream data
            if let Some(id) = req {
                let acts = self.pump_input(id, &mut outq, io);
                self.dispatch(acts, &mut rest)?;
            }

            // 4b. Ctrl-C: cancel the remote command, exit 130
            if crate::ffi::interrupted() {
                if let Some(id) = req {
                    self.engine.as_mut().unwrap().cancel(id, Instant::now());
                    let acts = self.engine.as_mut().unwrap().poll(Instant::now());
                    let _ = self.dispatch(acts, &mut Vec::new());
                }
                self.engine = None;
                self.opened = None;
                return Err(ClientError::Interrupted);
            }

            // 5. overall timeout
            if let Some(d) = deadline {
                if Instant::now() >= d {
                    if let Some(id) = req {
                        self.engine.as_mut().unwrap().cancel(id, Instant::now());
                        let acts = self.engine.as_mut().unwrap().poll(Instant::now());
                        let _ = self.dispatch(acts, &mut Vec::new());
                    }
                    self.engine = None;
                    self.opened = None;
                    return Err(if req.is_none() { Self::handshake_error("timeout") } else { ClientError::Timeout });
                }
            }

            // 6. wait for a frame
            let mut wait = Duration::from_millis(100);
            if outq.active() || outq.had_input {
                wait = Duration::from_millis(10);
            }
            if let Some(nd) = self.engine.as_ref().unwrap().next_deadline() {
                wait = wait.min(nd.saturating_duration_since(Instant::now()));
            }
            if let Some(d) = deadline {
                wait = wait.min(d.saturating_duration_since(Instant::now()));
            }
            let wait = wait.max(Duration::from_millis(1));
            let acts = self.recv_one(wait, &mut buf, Instant::now())?;
            self.dispatch(acts, &mut rest)?;
        }
    }

    fn pump_input(&mut self, id: u32, q: &mut Outgoing, io: &mut dyn ClientIo) -> Vec<Action> {
        let now = Instant::now();
        let mut sent_any = false;
        for _ in 0..64 {
            if let Some(o) = q.pending.take() {
                let ok = match &o {
                    Out::Data(c, d) => self.engine.as_mut().unwrap().send_data(id, *c, d, false, now),
                    Out::End(c) => self.engine.as_mut().unwrap().send_data(id, *c, &[], true, now),
                };
                if !ok {
                    q.pending = Some(o);
                    break;
                }
                sent_any = true;
                continue;
            }
            if q.no_input {
                break;
            }
            match io.input() {
                Input::None => {
                    q.no_input = true;
                    break;
                }
                Input::Pending => break,
                Input::Data(c, d) => {
                    if !d.is_empty() {
                        q.pending = Some(Out::Data(c, d));
                    }
                    q.had_input = true;
                }
                Input::End(c) => {
                    q.pending = Some(Out::End(c));
                    q.had_input = true;
                }
            }
        }
        // flush frames produced by send_data; anything else the engine says is handed back to the caller
        if sent_any {
            self.engine.as_mut().unwrap().poll(Instant::now())
        } else {
            Vec::new()
        }
    }
}

#[derive(Default)]
struct Outgoing {
    pending: Option<Out>,
    no_input: bool,
    had_input: bool,
}

impl Outgoing {
    fn active(&self) -> bool {
        self.pending.is_some()
    }
}

enum Out {
    Data(Chan, Vec<u8>),
    End(Chan),
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

fn finish(cmd: &CmdSpec, status: Status, body: Vec<u8>, sent_at: Instant) -> CallResult {
    // exec/shell answer with a 4-byte big-endian exit status then JSON; `exec --detach` answers with plain JSON
    // (`{"v":1,"job":N}`), whose first bytes must not be read as an exit status (it used to give exit 254)
    let (exit_code, body) = if matches!(cmd.name, "exec" | "shell") && status == Status::Ok && body.len() >= 4 && body[0] != b'{' {
        (Some(i32::from_be_bytes([body[0], body[1], body[2], body[3]])), body[4..].to_vec())
    } else {
        (None, body)
    };
    CallResult { status, body, exit_code, rtt_ms: ms(sent_at) }
}

/// Commands whose stdout channel carries NDJSON progress lines (PLAN: blk tests, thermal --follow).
pub fn event_stream(cmd: &CmdSpec) -> bool {
    cmd.name.starts_with("blk.") || cmd.name == "thermal"
}

/// Splits the stdout channel into NDJSON events (lines starting with `{`) and plain output.
struct LineSplit {
    on: bool,
    buf: Vec<u8>,
}

impl LineSplit {
    fn new(on: bool) -> LineSplit {
        LineSplit { on, buf: Vec::new() }
    }
    fn feed(&mut self, data: &[u8], io: &mut dyn ClientIo) {
        if !self.on {
            io.stdout(data);
            return;
        }
        self.buf.extend_from_slice(data);
        while let Some(i) = self.buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=i).collect();
            self.emit(&line[..line.len() - 1], true, io);
        }
        if self.buf.len() > 1 << 20 {
            let l = std::mem::take(&mut self.buf);
            self.emit(&l, false, io);
        }
    }
    fn emit(&mut self, line: &[u8], nl: bool, io: &mut dyn ClientIo) {
        match std::str::from_utf8(line) {
            Ok(s) if s.starts_with('{') => io.event(s),
            _ => {
                io.stdout(line);
                if nl {
                    io.stdout(b"\n");
                }
            }
        }
    }
    fn flush(&mut self, io: &mut dyn ClientIo) {
        if !self.buf.is_empty() {
            let l = std::mem::take(&mut self.buf);
            self.emit(&l, false, io);
        }
    }
}

impl Transport for EtherTransport {
    fn call(&mut self, cmd: &CmdSpec, args: &[String], io: &mut dyn ClientIo) -> Result<CallResult, ClientError> {
        let deadline = self.opts.timeout.map(|t| Instant::now() + t);
        let mut attempt = 0;
        loop {
            match self.call_once(cmd, args, io, deadline) {
                Err(ClientError::Transport(m)) if m.starts_with("no CHALLENGE") && attempt < self.opts.retries => {
                    attempt += 1;
                    self.tr(&format!("handshake failed, retry {}", attempt));
                }
                other => return other,
            }
        }
    }
    fn name(&self) -> &'static str {
        "ether"
    }
    fn role(&self) -> Option<Role> {
        self.opened.as_ref().map(|(r, _)| *r)
    }
}

/// Raw wire command without a catalogue entry (`--cmd 0x00ff`): leaks a tiny spec so the server gate can be
/// exercised with ids the client does not know (raw `--cmd` never pre-validates, F-F26).
pub fn raw_spec(name_or_id: &str) -> Result<&'static CmdSpec, ClientError> {
    if let Some(c) = labproto::catalog::by_name(name_or_id) {
        return Ok(c);
    }
    let id = name_or_id
        .strip_prefix("0x")
        .map(|h| u16::from_str_radix(h, 16))
        .unwrap_or_else(|| name_or_id.parse::<u16>())
        .map_err(|_| ClientError::Usage(format!("unknown wire command '{}' (try: i7labctl help ether; or a numeric id like 0x0001)", name_or_id)))?;
    if let Some(c) = labproto::catalog::by_id(id) {
        return Ok(c);
    }
    let spec = CmdSpec { id, name: "raw", group: 0, access: labproto::catalog::Access::Admin, streams: true, usage: "", summary: "raw wire command", since: labproto::catalog::CURRENT_RELEASE };
    Ok(Box::leak(Box::new(spec)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use labproto::catalog::by_name;
    use labproto::link::MemLink;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    /// Scripted engine: each `poll` pops one batch of actions.
    #[derive(Default)]
    struct Script {
        polls: VecDeque<Vec<Action>>,
        sent: Vec<(u32, Chan, Vec<u8>, bool)>,
        reqs: Vec<(u16, Vec<u8>)>,
        cancels: Vec<u32>,
        accept_data: bool,
    }
    struct Mock(Rc<RefCell<Script>>);
    impl Engine for Mock {
        fn send_req(&mut self, cmd: u16, body: &[u8], _: Instant) -> Result<u32, FrameError> {
            self.0.borrow_mut().reqs.push((cmd, body.to_vec()));
            Ok(1)
        }
        fn send_data(&mut self, r: u32, c: Chan, d: &[u8], fin: bool, _: Instant) -> bool {
            let mut s = self.0.borrow_mut();
            if !s.accept_data {
                return false;
            }
            s.sent.push((r, c, d.to_vec(), fin));
            true
        }
        fn cancel(&mut self, r: u32, _: Instant) {
            self.0.borrow_mut().cancels.push(r);
        }
        fn on_frame(&mut self, _: &[u8], _: &[(u16, u16)], _: Instant) -> Vec<Action> {
            Vec::new()
        }
        fn poll(&mut self, _: Instant) -> Vec<Action> {
            self.0.borrow_mut().polls.pop_front().unwrap_or_default()
        }
        fn next_deadline(&self) -> Option<Instant> {
            None
        }
    }

    fn transport(script: Rc<RefCell<Script>>, timeout_ms: u64) -> EtherTransport {
        let (a, _b) = MemLink::pair(Mac([2, 0, 0, 0, 0, 1]), Mac([2, 0, 0, 0, 0, 2]));
        let s2 = script.clone();
        let f: EngineFactory = Box::new(move |_| Box::new(Mock(s2.clone())));
        EtherTransport::with_engine(Box::new(a), 1, Mac([2, 0, 0, 0, 0, 2]), vec![], f, EtherOpts { timeout: Some(Duration::from_millis(timeout_ms)), ..Default::default() })
    }

    #[derive(Default)]
    struct Cap {
        out: Vec<u8>,
        err: Vec<u8>,
        events: Vec<String>,
        input: VecDeque<Input>,
    }
    impl ClientIo for Cap {
        fn stdout(&mut self, b: &[u8]) {
            self.out.extend_from_slice(b)
        }
        fn stderr(&mut self, b: &[u8]) {
            self.err.extend_from_slice(b)
        }
        fn event(&mut self, j: &str) {
            self.events.push(j.to_string())
        }
        fn input(&mut self) -> Input {
            self.input.pop_front().unwrap_or(Input::None)
        }
    }

    fn opened() -> Action {
        Action::Opened { role: Role::Admin, hostname: "lab".into() }
    }

    #[test]
    fn simple_call_returns_body_and_sends_argv() {
        let s = Rc::new(RefCell::new(Script::default()));
        s.borrow_mut().polls.push_back(vec![opened()]);
        s.borrow_mut().polls.push_back(vec![]);
        s.borrow_mut().polls.push_back(vec![Action::Response { req_id: 1, status: Status::Ok, body: b"{\"pong\":1}".to_vec() }]);
        let mut t = transport(s.clone(), 2000);
        let r = t.call(by_name("ping").unwrap(), &["hello".into()], &mut Cap::default()).unwrap();
        assert_eq!(r.status, Status::Ok);
        assert_eq!(r.body, b"{\"pong\":1}");
        assert_eq!(s.borrow().reqs[0].0, 0x0001);
        assert_eq!(labproto::args::decode_argv(&s.borrow().reqs[0].1).unwrap(), vec!["hello"]);
        assert_eq!(t.role(), Some(Role::Admin));
    }

    #[test]
    fn detached_exec_reply_is_json_not_an_exit_status() {
        let r = finish(by_name("exec").unwrap(), Status::Ok, b"{\"v\":1,\"job\":7}".to_vec(), Instant::now());
        assert_eq!(r.exit_code, None);
        assert_eq!(r.body, b"{\"v\":1,\"job\":7}");
        let mut with_code = 3i32.to_be_bytes().to_vec();
        with_code.extend_from_slice(b"{}");
        assert_eq!(finish(by_name("exec").unwrap(), Status::Ok, with_code, Instant::now()).exit_code, Some(3));
    }

    #[test]
    fn exec_parses_exit_code_and_streams() {
        let s = Rc::new(RefCell::new(Script::default()));
        let mut resp = 3i32.to_be_bytes().to_vec();
        resp.extend_from_slice(b"{\"signal\":0}");
        s.borrow_mut().polls.push_back(vec![opened()]);
        s.borrow_mut().polls.push_back(vec![]);
        s.borrow_mut().polls.push_back(vec![
            Action::StreamData { req_id: 1, chan: Chan::Stdout, data: b"out".to_vec() },
            Action::StreamData { req_id: 1, chan: Chan::Stderr, data: b"err".to_vec() },
            Action::StreamData { req_id: 9, chan: Chan::Stdout, data: b"other request".to_vec() },
            Action::Response { req_id: 1, status: Status::Ok, body: resp },
        ]);
        let mut t = transport(s, 2000);
        let mut io = Cap::default();
        let r = t.call(by_name("exec").unwrap(), &["--".into(), "false".into()], &mut io).unwrap();
        assert_eq!(r.exit_code, Some(3));
        assert_eq!(r.body, b"{\"signal\":0}");
        assert_eq!(io.out, b"out");
        assert_eq!(io.err, b"err");
    }

    #[test]
    fn blk_progress_lines_become_events() {
        let s = Rc::new(RefCell::new(Script::default()));
        s.borrow_mut().polls.push_back(vec![opened()]);
        s.borrow_mut().polls.push_back(vec![]);
        s.borrow_mut().polls.push_back(vec![
            Action::StreamData { req_id: 1, chan: Chan::Stdout, data: b"{\"event\":\"progress\",\"done\":0.5}\nplain".to_vec() },
            Action::StreamData { req_id: 1, chan: Chan::Stdout, data: b" text\n{\"event\":\"progress\",".to_vec() },
            Action::StreamData { req_id: 1, chan: Chan::Stdout, data: b"\"done\":1}\n".to_vec() },
            Action::Response { req_id: 1, status: Status::Ok, body: b"{}".to_vec() },
        ]);
        let mut t = transport(s, 2000);
        let mut io = Cap::default();
        t.call(by_name("blk.read").unwrap(), &["sda".into()], &mut io).unwrap();
        assert_eq!(io.events, vec!["{\"event\":\"progress\",\"done\":0.5}", "{\"event\":\"progress\",\"done\":1}"]);
        assert_eq!(String::from_utf8(io.out).unwrap(), "plain text\n");
    }

    #[test]
    fn handshake_failure_is_exit_4_with_hint_and_auth_is_5() {
        let s = Rc::new(RefCell::new(Script::default()));
        s.borrow_mut().polls.push_back(vec![Action::Closed { reason: "handshake timeout" }]);
        let mut t = transport(s, 2000);
        let e = t.call(by_name("ping").unwrap(), &[], &mut NullIoLocal).unwrap_err();
        assert_eq!(e.exit_code(), 4);
        assert!(e.to_string().contains("no CHALLENGE: wrong key set or host unreachable"), "{}", e);

        let s = Rc::new(RefCell::new(Script::default()));
        s.borrow_mut().polls.push_back(vec![Action::Closed { reason: "server proof: bad tag" }]);
        let mut t = transport(s, 2000);
        assert_eq!(t.call(by_name("ping").unwrap(), &[], &mut NullIoLocal).unwrap_err().exit_code(), 5);
    }

    struct NullIoLocal;
    impl ClientIo for NullIoLocal {
        fn stdout(&mut self, _: &[u8]) {}
        fn stderr(&mut self, _: &[u8]) {}
        fn event(&mut self, _: &str) {}
    }

    #[test]
    fn timeout_cancels_and_reports_4() {
        let s = Rc::new(RefCell::new(Script::default()));
        s.borrow_mut().polls.push_back(vec![opened()]);
        let mut t = transport(s.clone(), 60);
        let e = t.call(by_name("ping").unwrap(), &[], &mut NullIoLocal).unwrap_err();
        assert!(matches!(e, ClientError::Timeout));
        assert_eq!(e.exit_code(), 4);
        assert_eq!(s.borrow().cancels, vec![1]);
    }

    #[test]
    fn stdin_is_pumped_with_backpressure_and_end() {
        let s = Rc::new(RefCell::new(Script::default()));
        s.borrow_mut().polls.push_back(vec![opened()]);
        let mut t = transport(s.clone(), 3000);
        let mut io = Cap::default();
        io.input.push_back(Input::Data(Chan::Stdin, b"abc".to_vec()));
        io.input.push_back(Input::End(Chan::Stdin));
        // window open from the start; the response arrives after a few polls
        s.borrow_mut().accept_data = true;
        s.borrow_mut().polls.push_back(vec![]);
        for _ in 0..6 {
            s.borrow_mut().polls.push_back(vec![]);
        }
        s.borrow_mut().polls.push_back(vec![Action::Response { req_id: 1, status: Status::Ok, body: vec![0, 0, 0, 0] }]);
        t.call(by_name("exec").unwrap(), &["--stdin".into(), "--".into(), "cat".into()], &mut io).unwrap();
        let sent = s.borrow().sent.clone();
        assert_eq!(sent[0], (1, Chan::Stdin, b"abc".to_vec(), false));
        assert_eq!(sent[1], (1, Chan::Stdin, vec![], true));
    }

    #[test]
    fn oversized_args_are_a_local_usage_error() {
        let s = Rc::new(RefCell::new(Script::default()));
        let mut t = transport(s.clone(), 500);
        let big = "x".repeat(60_000);
        let e = t.call(by_name("exec").unwrap(), &[big.clone(), big], &mut NullIoLocal).unwrap_err();
        assert_eq!(e.exit_code(), 2);
        assert!(s.borrow().reqs.is_empty());
    }

    #[test]
    fn raw_spec_accepts_names_and_ids() {
        assert_eq!(raw_spec("ping").unwrap().id, 1);
        assert_eq!(raw_spec("0x0001").unwrap().name, "ping");
        assert_eq!(raw_spec("0x7777").unwrap().id, 0x7777);
        assert_eq!(raw_spec("4660").unwrap().id, 4660);
        assert!(raw_spec("frobnicate").is_err());
    }

    #[test]
    fn vlan_stack() {
        assert_eq!(vlan_tags(Some(13)), vec![(0x8100, 13)]);
        assert!(vlan_tags(None).is_empty());
    }
}
