//! Sans-IO session state machines for the ether control protocol (PROTOCOL.md sections 4-6). Owner: P1.
//!
//! One implementation of handshake + REQ/RESP + reliability + streams + idempotence, used by BOTH the server
//! (`i7labd::ether`, P6b) and the client (`i7labctl::ether`, P9) (review feasibility F6). No sockets, no
//! threads, no clock reads: the driver feeds received frames and the current time in, and executes the
//! returned `Action`s (send a frame, deliver a request, deliver stream data, ...). That makes acceptance test 2
//! (10 % loss + reordering over `MemLink`) a pure unit test owned by P1.
//!
//! Frames here are full Ethernet frames (as `Link` sends/receives them); `tags` is the canonical stack
//! (`frame::canonical_tags`) of the frame, which is part of the session binding. Replies carry the same stack
//! in their bytes.
//!
//! Driver contract (both sides): after any call that queues work (`send_req`, `send_data`, `cancel`,
//! `respond`, `stream_data`) frames leave with the returned actions or with the next `poll`; call `poll` at
//! least every `next_deadline` (and again right after `send_req`/`send_data`/`cancel` on the client).
//!
//! Choices where PROTOCOL.md left room (all reported to the architect):
//! * Server side, `Action::Request::req_id` (and the `req_id` of the other server actions, and the first
//!   argument of `respond`/`stream_data`) is a server-unique *handle*: client req ids are only unique per
//!   session. `ServerSessions::request_info(handle)` gives session, source MAC, VLAN stack, role and the
//!   client's own id for audit. Session lifecycle goes through `take_events`, not through `Action`.
//! * OPEN payload is `cn | sn | frag(2)`; the 2-byte tail is the fragment size the client picked, so the
//!   stateless server learns it without keeping HELLO state (older 32-byte OPENs are accepted: server default).
//! * Retransmitted OPENs carry a fresh `ctr`; an OPEN for an existing session whose tag verifies is answered
//!   with the cached OPEN_OK again (idempotent) without touching the replay window.
//! * NO_SESSION carries session id and boot id in header fields (see `frame::nosession_header`), `plen` 0, so
//!   it is exactly as small as the smallest authenticated frame. One is sent per loaded key (the server cannot
//!   know which key the unknown client holds): at most 2 frames per rate-limited trigger.
//! * An ACK with the FIN flag means "stream complete, FIN received".
//! * The client does not re-handshake itself: on `Closed` the driver makes a new `ClientSession` (it learns the
//!   new boot id from `boot_id()`).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::crypto::random_bytes;
use crate::frame::{self, flags, Chan, Dir, EthHeader, FrameError, FrameType, Header, TagKey, ETHERTYPE_CTL, VERSION};
use crate::handshake::{session_id, session_key, Challenge, CookieJar, Hello, OpenOk, COOKIE_BUCKET_MS, HELLO_LEN};
use crate::keys::{Key, KeySet, Role};
use crate::mac::Mac;
use crate::reliable::{StreamRx, TxStream, MAX_WINDOW};
use crate::replay::ReplayWindow;
use crate::status::Status;

/// What the driver must do after feeding the state machine.
#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    /// Send this complete Ethernet frame.
    Send(Vec<u8>),
    /// Server: a complete, authenticated, not-yet-executed request. The driver dispatches it and answers with
    /// `ServerSessions::respond` (and `stream_data` for streaming commands). Delivered exactly once per
    /// request. `req_id` is the server-unique handle (see module doc).
    Request { req_id: u32, cmd: u16, body: Vec<u8>, role: Role },
    /// Client: final response of `req_id`.
    Response { req_id: u32, status: Status, body: Vec<u8> },
    /// Stream data for `req_id` on `chan` (stdout/stderr/file to the client; stdin/file upload/ctl to the
    /// server), in order, without gaps.
    StreamData { req_id: u32, chan: Chan, data: Vec<u8> },
    /// The stream ended (FIN received, all bytes delivered).
    StreamEnd { req_id: u32, chan: Chan },
    /// Server: the peer canceled the request (or its session ended): kill the command and then `respond`.
    Canceled { req_id: u32 },
    /// Client: handshake finished.
    Opened { role: Role, hostname: String },
    /// Client: session closed (idle timeout, CLOSE, NO_SESSION, retransmit limit, handshake timeout).
    Closed { reason: &'static str },
}

/// Session lifecycle events of the server engine (audit log, console, stats), drained with
/// `ServerSessions::take_events`. Kept out of `Action` so drivers can match `Action` exhaustively.
#[derive(Clone, Debug, PartialEq)]
pub enum ServerEvent {
    /// a session was created
    SessionOpened { session: u32, src: Mac, tags: Vec<(u16, u16)>, role: Role },
    /// a session ended (idle, lifetime, CLOSE, evicted, retransmit limit). Its running requests were reported
    /// with `Action::Canceled` first.
    SessionEnded { session: u32, src: Mac, reason: &'static str },
}

/// Where a delivered request came from (audit: time, session, source MAC, VLAN, command).
#[derive(Clone, Debug, PartialEq)]
pub struct RequestInfo {
    pub session: u32,
    pub src: Mac,
    pub tags: Vec<(u16, u16)>,
    pub role: Role,
    /// the id the client gave the request (unique per session only)
    pub client_req_id: u32,
}

#[derive(Clone, Debug)]
pub struct SessionLimits {
    pub frag: u16,
    pub window: u16,
    pub idle: Duration,
    /// REQ body cap (64 KiB) and RESP cap (16 MiB), PROTOCOL 6.1
    pub max_req: u32,
    pub max_resp: u32,
    /// out-of-order bytes held per stream never exceed `window * frag`; fragments beyond
    /// `next_expected + window*frag` are dropped, not buffered (review security F13)
    pub per_session_bytes: usize,
}

impl Default for SessionLimits {
    fn default() -> Self {
        SessionLimits {
            frag: crate::frame::DEFAULT_FRAG,
            window: 16,
            idle: Duration::from_secs(120),
            max_req: 64 * 1024,
            max_resp: 16 * 1024 * 1024,
            per_session_bytes: 2 * 1024 * 1024,
        }
    }
}

pub const MIN_FRAG: u16 = 256;
const MAX_OUTSTANDING: usize = 8;
const REQ_RETAIN: usize = 16;
const MAX_SESSIONS: usize = 8;
const MAX_PER_MAC: usize = 2;
const CACHE_TOTAL: usize = 1024 * 1024;
const LIFETIME: Duration = Duration::from_secs(3600);
const CTR_LIMIT: u64 = 1 << 40;
const DELAYED_ACK: Duration = Duration::from_millis(20);
const ACK_EVERY: u32 = 8;
const KEEPALIVE_IDLE: Duration = Duration::from_secs(20);
const KEEPALIVE_RETRY: Duration = Duration::from_secs(2);
const KEEPALIVE_TRIES: u32 = 3;
const HANDSHAKE_DELAYS_MS: [u64; 5] = [250, 500, 1000, 1000, 1000];
const VIOLATION_LIMIT: u32 = 20;
const NO_LEN: u32 = u32::MAX;
/// Cookies (`sn`) of OPENs that already started a session, kept for longer than a cookie lives (2 buckets).
const SPENT_TTL: Duration = Duration::from_millis(2 * COOKIE_BUCKET_MS + 1000);
/// Only verified OPENs enter the list, so it cannot be filled without a key; full => new OPENs wait (fail closed).
const SPENT_CAP: usize = 4096;

fn clamp_frag(f: u16, max: u16) -> u16 {
    f.clamp(MIN_FRAG, max.max(MIN_FRAG))
}

fn eth_wrap(src: Mac, dst: Mac, tags: &[(u16, u16)], sealed: &[u8]) -> Vec<u8> {
    frame::eth_build(&EthHeader { dst, src, tags: tags.to_vec(), ethertype: ETHERTYPE_CTL }, sealed)
}

// ---------------------------------------------------------------------------------------------------------
// shared per-session transport state
// ---------------------------------------------------------------------------------------------------------

enum OutKind {
    Req { cmd: u16 },
    Resp { cmd: u16, status: u16 },
    Data,
}

struct Out {
    s: TxStream,
    kind: OutKind,
    msg_len: u32,
    /// RESP waits until every other stream of the request is acknowledged (RESP never overtakes output)
    gated: bool,
}

struct In {
    rx: StreamRx,
    buf: Vec<u8>,
    is_msg: bool,
    status: u16,
    unacked: u32,
    ack_at: Option<Instant>,
    delivered: bool,
}

struct Incoming {
    data: Vec<u8>,
    newly_complete: bool,
    status: u16,
}

#[derive(PartialEq, Eq)]
enum RxCheck {
    Ok,
    Replay,
    BadTag,
}

struct Conn {
    me: Mac,
    peer: Mac,
    tags: Vec<(u16, u16)>,
    sk: [u8; 32],
    send_dir: Dir,
    recv_dir: Dir,
    session: u32,
    ctr: u64,
    rx_win: ReplayWindow,
    frag: u16,
    window: u16,
    out: BTreeMap<(u32, u8), Out>,
    inn: BTreeMap<(u32, u8), In>,
    last_rx: Instant,
    retransmits: u64,
}

impl Conn {
    #[allow(clippy::too_many_arguments)]
    fn new(me: Mac, peer: Mac, tags: Vec<(u16, u16)>, sk: [u8; 32], session: u32, send_dir: Dir, frag: u16, window: u16, now: Instant) -> Conn {
        let recv_dir = if send_dir == Dir::ClientToServer { Dir::ServerToClient } else { Dir::ClientToServer };
        Conn {
            me,
            peer,
            tags,
            sk,
            send_dir,
            recv_dir,
            session,
            ctr: 0,
            rx_win: ReplayWindow::new(),
            frag,
            window: window.clamp(1, MAX_WINDOW),
            out: BTreeMap::new(),
            inn: BTreeMap::new(),
            last_rx: now,
            retransmits: 0,
        }
    }

    /// Build one authenticated frame; `ctr` increases per transmitted frame, retransmissions included.
    fn seal(&mut self, mut h: Header, payload: &[u8]) -> Vec<u8> {
        self.ctr += 1;
        h.ver = VERSION;
        h.session = self.session;
        h.ctr = self.ctr;
        h.plen = payload.len() as u16;
        let sealed = frame::seal(&h, payload, TagKey::Session { sk: &self.sk, dir: self.send_dir });
        eth_wrap(self.me, self.peer, &self.tags, &sealed)
    }

    fn simple(&mut self, ftype: FrameType, fl: u8, req_id: u32, status: u16) -> Vec<u8> {
        self.seal(Header { ftype: ftype as u8, flags: fl, req_id, status, ..Default::default() }, &[])
    }

    fn check_rx(&mut self, f: &frame::Frame) -> RxCheck {
        if !self.rx_win.check(f.hdr.ctr) {
            return RxCheck::Replay;
        }
        if !frame::verify(f, TagKey::Session { sk: &self.sk, dir: self.recv_dir }) {
            return RxCheck::BadTag;
        }
        self.rx_win.commit(f.hdr.ctr);
        RxCheck::Ok
    }

    fn exhausted(&self) -> bool {
        self.ctr >= CTR_LIMIT
    }

    fn ack_frame(&mut self, req_id: u32, chan: u8) -> Option<Vec<u8>> {
        let i = self.inn.get(&(req_id, chan))?;
        let (next, win, sack, done) = (i.rx.next_expected(), i.rx.advertised_window(), i.rx.sack_bitmap(), i.rx.complete());
        let h = Header { ftype: FrameType::Ack as u8, flags: if done { flags::FIN } else { 0 }, chan, req_id, off: next, win, ..Default::default() };
        let f = self.seal(h, &sack.to_be_bytes());
        if let Some(i) = self.inn.get_mut(&(req_id, chan)) {
            i.unacked = 0;
            i.ack_at = None;
        }
        Some(f)
    }

    /// Feed a REQ/RESP/DATA fragment into its receive stream (created on first sight). ACKs that the receive
    /// policy calls for are appended to `frames`.
    fn on_incoming(&mut self, h: &Header, payload: &[u8], now: Instant, msg_limit: u32, frames: &mut Vec<Vec<u8>>) -> Result<Incoming, FrameError> {
        let key = (h.req_id, h.chan);
        let is_msg = h.chan == Chan::Msg as u8;
        if payload.len() > self.frag as usize {
            return Err(FrameError::BadLength);
        }
        if !self.inn.contains_key(&key) {
            let rx = if is_msg {
                if h.msg_len == NO_LEN {
                    return Err(FrameError::BadLength);
                }
                StreamRx::new(self.frag, self.window, msg_limit, Some(h.msg_len), true)?
            } else {
                StreamRx::new(self.frag, self.window, u32::MAX, None, false)?
            };
            self.inn.insert(key, In { rx, buf: Vec::new(), is_msg, status: h.status, unacked: 0, ack_at: None, delivered: false });
        }
        let i = self.inn.get_mut(&key).unwrap();
        if is_msg && Some(h.msg_len) != i.rx_msg_len() {
            return Err(FrameError::BadLength);
        }
        let fin = h.flags & flags::FIN != 0;
        let r = i.rx.insert(h.off, payload, fin)?;
        i.unacked += 1;
        let mut data = Vec::new();
        let mut newly_complete = false;
        if i.is_msg {
            i.buf.extend_from_slice(&r.data);
            if i.rx.complete() && !i.delivered {
                i.delivered = true;
                newly_complete = true;
                data = std::mem::take(&mut i.buf);
            }
        } else {
            data = r.data;
            if i.rx.complete() && !i.delivered {
                i.delivered = true;
                newly_complete = true;
            }
        }
        let ack_now = h.flags & flags::ACK_REQ != 0 || fin || r.out_of_order || r.duplicate || i.unacked >= ACK_EVERY;
        if !ack_now && i.ack_at.is_none() {
            i.ack_at = Some(now + DELAYED_ACK);
        }
        let status = i.status;
        if ack_now {
            if let Some(f) = self.ack_frame(h.req_id, h.chan) {
                frames.push(f);
            }
        }
        Ok(Incoming { data, newly_complete, status })
    }

    fn on_ack(&mut self, h: &Header, payload: &[u8], now: Instant) {
        let key = (h.req_id, h.chan);
        let sack = if payload.len() >= 8 { u64::from_be_bytes(payload[..8].try_into().unwrap()) } else { 0 };
        if let Some(o) = self.out.get_mut(&key) {
            o.s.on_ack(h.off, sack, h.win, h.flags & flags::FIN != 0, now);
        }
    }

    fn flush_acks(&mut self, now: Instant, frames: &mut Vec<Vec<u8>>) {
        let due: Vec<(u32, u8)> = self.inn.iter().filter(|(_, i)| i.ack_at.is_some_and(|t| t <= now)).map(|(k, _)| *k).collect();
        for (r, c) in due {
            if let Some(f) = self.ack_frame(r, c) {
                frames.push(f);
            }
        }
    }

    /// Emit due and new fragments of every unblocked outgoing stream; drop finished ones.
    fn pump(&mut self, now: Instant, frames: &mut Vec<Vec<u8>>) {
        let keys: Vec<(u32, u8)> = self.out.keys().copied().collect();
        for k in keys {
            let blocked = {
                let o = &self.out[&k];
                o.gated && self.out.iter().any(|(k2, o2)| k2.0 == k.0 && k2.1 != 0 && !o2.s.done())
            };
            if blocked {
                continue;
            }
            let mut o = self.out.remove(&k).unwrap();
            let segs = o.s.poll(now);
            let n = segs.len();
            for (idx, seg) in segs.into_iter().enumerate() {
                if seg.retransmit {
                    self.retransmits += 1;
                }
                let mut fl = 0;
                if seg.fin {
                    fl |= flags::FIN;
                }
                if idx + 1 == n || seg.fin {
                    fl |= flags::ACK_REQ;
                }
                let mut h = Header { flags: fl, chan: k.1, req_id: k.0, off: seg.off, msg_len: o.msg_len, ..Default::default() };
                match o.kind {
                    OutKind::Req { cmd } => {
                        h.ftype = FrameType::Req as u8;
                        h.cmd = cmd;
                    }
                    OutKind::Resp { cmd, status } => {
                        h.ftype = FrameType::Resp as u8;
                        h.cmd = cmd;
                        h.status = status;
                    }
                    OutKind::Data => h.ftype = FrameType::Data as u8,
                }
                frames.push(self.seal(h, &seg.data));
            }
            if !o.s.done() {
                self.out.insert(k, o);
            }
        }
    }

    fn any_dead(&self) -> bool {
        self.out.values().any(|o| o.s.dead())
    }

    fn next_deadline(&self, now: Instant) -> Option<Instant> {
        let a = self.out.values().filter_map(|o| o.s.next_deadline(now)).min();
        let b = self.inn.values().filter_map(|i| i.ack_at).min();
        match (a, b) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    fn queue_out(&mut self, req_id: u32, chan: u8, kind: OutKind, msg_len: u32, gated: bool) -> &mut Out {
        self.out.entry((req_id, chan)).or_insert_with(|| Out { s: TxStream::new(self.frag, self.window), kind, msg_len, gated })
    }

    fn forget_req(&mut self, req_id: u32) {
        self.out.retain(|k, _| k.0 != req_id);
        self.inn.retain(|k, _| k.0 != req_id);
    }
}

impl In {
    fn rx_msg_len(&self) -> Option<u32> {
        self.rx.declared_len()
    }
}

/// Everything addressed to the engine arrives as an Ethernet frame; validate the outer shape.
fn parse_ctl<'a>(frame: &'a [u8]) -> Option<(EthHeader, frame::Frame<'a>)> {
    let (eth, payload) = frame::eth_parse(frame)?;
    if eth.ethertype != ETHERTYPE_CTL {
        return None;
    }
    let f = frame::open(payload).ok()?;
    if f.hdr.flags & flags::ENC != 0 {
        return None;
    }
    Some((eth, f))
}

fn emit(frames: Vec<Vec<u8>>, acts: &mut Vec<Action>) {
    acts.extend(frames.into_iter().map(Action::Send));
}

fn status_of(e: &FrameError) -> Status {
    match e {
        FrameError::TooBig => Status::TooBig,
        _ => Status::BadArgs,
    }
}

// ---------------------------------------------------------------------------------------------------------
// client
// ---------------------------------------------------------------------------------------------------------

#[derive(PartialEq, Eq)]
enum CState {
    Hello,
    Opening,
    Open,
    Dead,
}

struct HandshakeTimer {
    sent: usize,
    next: Instant,
}

/// Client half (i7labctl).
pub struct ClientSession {
    me: Mac,
    server: Mac,
    tags: Vec<(u16, u16)>,
    key: [u8; 32],
    key_id: [u8; 4],
    limits: SessionLimits,
    state: CState,
    cn: [u8; 16],
    sn: [u8; 16],
    hs: HandshakeTimer,
    conn: Option<Conn>,
    boot_id: Option<[u8; 8]>,
    role: Option<Role>,
    hostname: String,
    server_caps: u32,
    next_req: u32,
    outstanding: BTreeSet<u32>,
    retired: VecDeque<u32>,
    queued: Vec<(u32, u16, Vec<u8>)>,
    ctl: VecDeque<(FrameType, u32)>,
    ka_sent: u32,
    ka_next: Option<Instant>,
    random_failed: bool,
}

impl ClientSession {
    /// Starts the handshake; the first `poll` returns the HELLO frame.
    pub fn new(client: Mac, server: Mac, tags: Vec<(u16, u16)>, key: &Key, limits: SessionLimits, now: Instant) -> ClientSession {
        let mut cn = [0u8; 16];
        let random_failed = random_bytes(&mut cn).is_err();
        ClientSession {
            me: client,
            server,
            tags,
            key: key.bytes,
            key_id: key.key_id(),
            limits,
            state: if random_failed { CState::Dead } else { CState::Hello },
            cn,
            sn: [0; 16],
            hs: HandshakeTimer { sent: 0, next: now },
            conn: None,
            boot_id: None,
            role: None,
            hostname: String::new(),
            server_caps: 0,
            next_req: 1,
            outstanding: BTreeSet::new(),
            retired: VecDeque::new(),
            queued: Vec::new(),
            ctl: VecDeque::new(),
            ka_sent: 0,
            ka_next: None,
            random_failed,
        }
    }

    /// Like `new` with a caller supplied client nonce (deterministic tests, golden vectors).
    pub fn with_nonce(client: Mac, server: Mac, tags: Vec<(u16, u16)>, key: &Key, limits: SessionLimits, now: Instant, cn: [u8; 16]) -> ClientSession {
        let mut s = ClientSession::new(client, server, tags, key, limits, now);
        s.cn = cn;
        s.state = CState::Hello;
        s.random_failed = false;
        s
    }

    pub fn is_open(&self) -> bool {
        self.state == CState::Open
    }
    pub fn is_dead(&self) -> bool {
        self.state == CState::Dead
    }
    /// Boot id the server announced in its CHALLENGE (a change between sessions means the host rebooted).
    pub fn boot_id(&self) -> Option<[u8; 8]> {
        self.boot_id
    }
    pub fn role(&self) -> Option<Role> {
        self.role
    }
    pub fn server_caps(&self) -> u32 {
        self.server_caps
    }
    pub fn session_id(&self) -> Option<u32> {
        self.conn.as_ref().map(|c| c.session)
    }
    /// Negotiated fragment size (after OPEN_OK), else the configured one.
    pub fn frag(&self) -> u16 {
        self.conn.as_ref().map_or(self.limits.frag, |c| c.frag)
    }

    /// Queue a request; returns its req_id. Body = `args::encode_argv` of the argv words. The frames leave with
    /// the next `poll`.
    pub fn send_req(&mut self, cmd: u16, body: &[u8], now: Instant) -> Result<u32, FrameError> {
        let _ = now;
        if self.state == CState::Dead {
            return Err(FrameError::BadPayload("session closed"));
        }
        if body.len() > self.limits.max_req as usize {
            return Err(FrameError::TooBig);
        }
        if self.outstanding.len() >= MAX_OUTSTANDING {
            return Err(FrameError::BadPayload("too many outstanding requests"));
        }
        let id = self.next_req;
        self.next_req += 1;
        self.outstanding.insert(id);
        match &mut self.conn {
            Some(c) if self.state == CState::Open => {
                let o = c.queue_out(id, 0, OutKind::Req { cmd }, body.len() as u32, false);
                o.s.push(body);
                o.s.finish();
            }
            _ => self.queued.push((id, cmd, body.to_vec())),
        }
        Ok(id)
    }

    /// Client to server stream data (exec --stdin, put, ctl). Returns false while the send buffer is full
    /// (backpressure) or the request is unknown.
    pub fn send_data(&mut self, req_id: u32, chan: Chan, data: &[u8], fin: bool, now: Instant) -> bool {
        let _ = now;
        if !matches!(chan, Chan::Stdin | Chan::File | Chan::Ctl) || !self.outstanding.contains(&req_id) || self.state != CState::Open {
            return false;
        }
        let Some(c) = self.conn.as_mut() else { return false };
        let cap = c.window as usize * c.frag as usize * 2;
        let o = c.queue_out(req_id, chan as u8, OutKind::Data, NO_LEN, false);
        if o.s.is_finished_queued() {
            return false;
        }
        if o.s.buffered() > 0 && o.s.buffered() + data.len() > cap {
            return false;
        }
        o.s.push(data);
        if fin {
            o.s.finish();
        }
        true
    }

    pub fn cancel(&mut self, req_id: u32, now: Instant) {
        let _ = now;
        if self.outstanding.contains(&req_id) {
            self.ctl.push_back((FrameType::Cancel, req_id));
        }
    }

    /// Orderly close: sends CLOSE with the next `poll`.
    pub fn close(&mut self) {
        if self.state == CState::Open {
            self.ctl.push_back((FrameType::Close, 0));
        }
    }

    fn build_hello(&mut self) -> Vec<u8> {
        let h = Hello { cn: self.cn, key_id: self.key_id, ver_min: VERSION, ver_max: VERSION, max_frag: self.limits.frag, caps: 1 };
        let hdr = Header { ver: VERSION, ftype: FrameType::Hello as u8, plen: HELLO_LEN as u16, ..Default::default() };
        let sealed = frame::seal(&hdr, &h.encode(), TagKey::Hello(&self.key));
        eth_wrap(self.me, self.server, &self.tags, &sealed)
    }

    fn build_open(&mut self) -> Vec<u8> {
        let frag = self.conn.as_ref().map_or(self.limits.frag, |c| c.frag);
        let mut p = Vec::with_capacity(34);
        p.extend_from_slice(&self.cn);
        p.extend_from_slice(&self.sn);
        p.extend_from_slice(&frag.to_be_bytes());
        let h = Header { ftype: FrameType::Open as u8, ..Default::default() };
        self.conn.as_mut().unwrap().seal(h, &p)
    }

    fn die(&mut self, reason: &'static str, acts: &mut Vec<Action>) {
        if self.state != CState::Dead {
            self.state = CState::Dead;
            acts.push(Action::Closed { reason });
        }
    }

    /// Feed one received Ethernet frame (already filtered to our ethertype and peer).
    pub fn on_frame(&mut self, frame: &[u8], tags: &[(u16, u16)], now: Instant) -> Vec<Action> {
        let mut acts = Vec::new();
        if self.state == CState::Dead || tags != self.tags.as_slice() {
            return acts;
        }
        let Some((eth, f)) = parse_ctl(frame) else { return acts };
        if eth.src != self.server || eth.dst != self.me {
            return acts;
        }
        let ft = FrameType::from_u8(f.hdr.ftype);
        match (&self.state, ft) {
            (CState::Hello, Some(FrameType::Challenge)) => self.on_challenge(&f, now, &mut acts),
            (_, Some(FrameType::NoSession)) => self.on_nosession(&f, &mut acts),
            (CState::Opening | CState::Open, Some(t)) => self.on_session_frame(t, &f, now, &mut acts),
            _ => {}
        }
        acts
    }

    fn on_challenge(&mut self, f: &frame::Frame, now: Instant, acts: &mut Vec<Action>) {
        if !frame::verify(f, TagKey::Challenge { k: &self.key, cn: &self.cn }) || f.payload.len() < crate::handshake::CHALLENGE_LEN {
            return;
        }
        let Ok(ch) = Challenge::decode(f.payload) else { return };
        if ch.ver != VERSION {
            return;
        }
        let frag = clamp_frag(ch.max_frag.min(self.limits.frag), self.limits.frag);
        let sk = session_key(&self.key, &self.cn, &ch.sn, &self.me, &self.server, ch.ver);
        self.sn = ch.sn;
        self.boot_id = Some(ch.boot_id);
        self.server_caps = ch.caps;
        self.conn = Some(Conn::new(self.me, self.server, self.tags.clone(), sk, session_id(&ch.sn), Dir::ClientToServer, frag, self.limits.window, now));
        self.state = CState::Opening;
        self.hs = HandshakeTimer { sent: 1, next: now + Duration::from_millis(HANDSHAKE_DELAYS_MS[0]) };
        let open = self.build_open();
        acts.push(Action::Send(open));
    }

    fn on_nosession(&mut self, f: &frame::Frame, acts: &mut Vec<Action>) {
        let Some(c) = &self.conn else { return };
        if f.hdr.session == c.session && frame::verify(f, TagKey::NoSession(&self.key)) {
            self.die("no session (server restarted or forgot us)", acts);
        }
    }

    fn on_session_frame(&mut self, t: FrameType, f: &frame::Frame, now: Instant, acts: &mut Vec<Action>) {
        let Some(c) = self.conn.as_mut() else { return };
        if f.hdr.session != c.session {
            return;
        }
        if c.check_rx(f) != RxCheck::Ok {
            return;
        }
        c.last_rx = now;
        self.ka_sent = 0;
        self.ka_next = None;
        let h = &f.hdr;
        let mut frames = Vec::new();
        match t {
            FrameType::OpenOk => {
                if self.state == CState::Opening {
                    if let Ok(ok) = OpenOk::decode(f.payload) {
                        c.frag = clamp_frag(ok.frag.min(c.frag), c.frag);
                        c.window = ok.window.clamp(1, MAX_WINDOW);
                        self.role = Some(ok.role);
                        self.hostname = ok.hostname.clone();
                        self.server_caps = ok.caps;
                        self.state = CState::Open;
                        acts.push(Action::Opened { role: ok.role, hostname: ok.hostname });
                        let queued = std::mem::take(&mut self.queued);
                        let c = self.conn.as_mut().unwrap();
                        for (id, cmd, body) in queued {
                            let o = c.queue_out(id, 0, OutKind::Req { cmd }, body.len() as u32, false);
                            o.s.push(&body);
                            o.s.finish();
                        }
                    }
                }
            }
            FrameType::Resp if self.state == CState::Open => {
                if self.outstanding.contains(&h.req_id) || self.retired.contains(&h.req_id) {
                    let limit = self.limits.max_resp;
                    match c.on_incoming(h, f.payload, now, limit, &mut frames) {
                        Ok(inc) if inc.newly_complete => {
                            let status = Status::from_u16(inc.status).unwrap_or(Status::Internal);
                            acts.push(Action::Response { req_id: h.req_id, status, body: inc.data });
                            // a RESP implies the REQ arrived
                            c.out.remove(&(h.req_id, 0));
                            self.outstanding.remove(&h.req_id);
                            self.retire(h.req_id);
                        }
                        _ => {}
                    }
                }
            }
            FrameType::Data if self.state == CState::Open => {
                let chan = match h.chan {
                    1 => Chan::Stdout,
                    2 => Chan::Stderr,
                    4 => Chan::File,
                    _ => return emit(frames, acts),
                };
                if self.outstanding.contains(&h.req_id) || self.retired.contains(&h.req_id) {
                    if let Ok(inc) = c.on_incoming(h, f.payload, now, 0, &mut frames) {
                        if !inc.data.is_empty() {
                            acts.push(Action::StreamData { req_id: h.req_id, chan, data: inc.data });
                        }
                        if inc.newly_complete {
                            acts.push(Action::StreamEnd { req_id: h.req_id, chan });
                        }
                    }
                }
            }
            FrameType::Ack if self.state == CState::Open => c.on_ack(h, f.payload, now),
            FrameType::Keepalive if h.flags & flags::REPLY == 0 => {
                let fr = c.simple(FrameType::Keepalive, flags::REPLY, 0, 0);
                frames.push(fr);
            }
            FrameType::Close => self.die("closed by peer", acts),
            FrameType::Err => {
                if self.outstanding.remove(&h.req_id) {
                    let status = Status::from_u16(h.status).unwrap_or(Status::Internal);
                    c.forget_req(h.req_id);
                    acts.push(Action::Response { req_id: h.req_id, status, body: Vec::new() });
                } else {
                    self.die("protocol error from server", acts);
                }
            }
            _ => {}
        }
        emit(frames, acts);
    }

    fn retire(&mut self, id: u32) {
        self.retired.push_back(id);
        while self.retired.len() > REQ_RETAIN {
            if let (Some(old), Some(c)) = (self.retired.pop_front(), self.conn.as_mut()) {
                c.forget_req(old);
            }
        }
    }

    /// Timers: retransmits, handshake retry, delayed ACKs, keepalive. Call at least every `next_deadline`.
    pub fn poll(&mut self, now: Instant) -> Vec<Action> {
        let mut acts = Vec::new();
        match self.state {
            CState::Dead => {
                if self.random_failed {
                    self.random_failed = false;
                    acts.push(Action::Closed { reason: "no randomness available" });
                }
            }
            CState::Hello => {
                if now >= self.hs.next {
                    if self.hs.sent > HANDSHAKE_DELAYS_MS.len() {
                        self.die("handshake timeout (no CHALLENGE: host down, wrong key, or not on this segment)", &mut acts);
                    } else {
                        let hello = self.build_hello();
                        let d = HANDSHAKE_DELAYS_MS[(self.hs.sent).min(HANDSHAKE_DELAYS_MS.len() - 1)];
                        self.hs.sent += 1;
                        self.hs.next = now + Duration::from_millis(d);
                        acts.push(Action::Send(hello));
                    }
                }
            }
            CState::Opening => {
                if now >= self.hs.next {
                    if self.hs.sent > HANDSHAKE_DELAYS_MS.len() {
                        self.die("handshake timeout (no OPEN_OK)", &mut acts);
                    } else {
                        let open = self.build_open();
                        let d = HANDSHAKE_DELAYS_MS[(self.hs.sent).min(HANDSHAKE_DELAYS_MS.len() - 1)];
                        self.hs.sent += 1;
                        self.hs.next = now + Duration::from_millis(d);
                        acts.push(Action::Send(open));
                    }
                }
            }
            CState::Open => self.poll_open(now, &mut acts),
        }
        acts
    }

    fn poll_open(&mut self, now: Instant, acts: &mut Vec<Action>) {
        let mut frames = Vec::new();
        let c = self.conn.as_mut().unwrap();
        while let Some((t, id)) = self.ctl.pop_front() {
            let fr = c.simple(t, 0, id, 0);
            frames.push(fr);
            if t == FrameType::Close {
                self.state = CState::Dead;
                acts.push(Action::Closed { reason: "closed locally" });
            }
        }
        if self.state == CState::Dead {
            emit(frames, acts);
            return;
        }
        c.flush_acks(now, &mut frames);
        c.pump(now, &mut frames);
        let dead = c.any_dead() || c.exhausted();
        let idle = now.saturating_duration_since(c.last_rx);
        let busy = !c.out.is_empty() || !self.outstanding.is_empty();
        if dead {
            let fr = c.simple(FrameType::Close, 0, 0, 0);
            frames.push(fr);
            self.state = CState::Dead;
            acts.push(Action::Closed { reason: "retransmit limit reached (no answer from host)" });
        } else if !busy && idle >= KEEPALIVE_IDLE && self.ka_next.map_or(true, |t| now >= t) {
            if self.ka_sent >= KEEPALIVE_TRIES {
                self.state = CState::Dead;
                acts.push(Action::Closed { reason: "keepalive timeout" });
            } else {
                let fr = c.simple(FrameType::Keepalive, 0, 0, 0);
                frames.push(fr);
                self.ka_sent += 1;
                self.ka_next = Some(now + KEEPALIVE_RETRY);
            }
        }
        emit(frames, acts);
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        match self.state {
            CState::Dead => None,
            CState::Hello | CState::Opening => Some(self.hs.next),
            CState::Open => {
                let c = self.conn.as_ref()?;
                let now = c.last_rx;
                let mut d = c.next_deadline(now);
                let ka = self.ka_next.unwrap_or(c.last_rx + KEEPALIVE_IDLE);
                d = Some(d.map_or(ka, |x| x.min(ka)));
                if !self.ctl.is_empty() {
                    d = Some(now);
                }
                d
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------
// server
// ---------------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ReqState {
    Receiving,
    Running,
    Canceled,
    Responded,
}

struct SReq {
    handle: u32,
    state: ReqState,
    cmd: u16,
    cached: Option<(Status, Vec<u8>)>,
}

struct SSession {
    conn: Conn,
    role: Role,
    created: Instant,
    open_ok: Vec<u8>,
    reqs: BTreeMap<u32, SReq>,
    order: VecDeque<u32>,
    violations: u32,
}

#[derive(Clone, Debug, Default)]
pub struct ServerStats {
    pub frames_rx: u64,
    pub frames_tx: u64,
    pub bad_tags: u64,
    pub drops: u64,
    pub replays: u64,
    pub rate_limited: u64,
    pub penalized: u64,
    pub sessions_opened: u64,
    pub sessions_ended: u64,
    pub requests: u64,
    pub retransmits: u64,
    pub no_session_sent: u64,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(burst: f64, now: Instant) -> Bucket {
        Bucket { tokens: burst, last: now }
    }
    fn take(&mut self, now: Instant, rate: f64, burst: f64) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * rate).min(burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct MacState {
    hello: Bucket,
    unauth: Bucket,
    nosess: Bucket,
    bad: VecDeque<Instant>,
    penalty_until: Option<Instant>,
    penalty_len: Duration,
    last_bad: Option<Instant>,
    last_seen: Instant,
}

impl MacState {
    fn new(now: Instant) -> MacState {
        MacState {
            hello: Bucket::new(20.0, now),
            unauth: Bucket::new(100.0, now),
            nosess: Bucket::new(4.0, now),
            bad: VecDeque::new(),
            penalty_until: None,
            penalty_len: Duration::from_secs(10),
            last_bad: None,
            last_seen: now,
        }
    }
    fn penalized(&self, now: Instant) -> bool {
        self.penalty_until.is_some_and(|t| now < t)
    }
    /// 5 bad tags within 10 s start a penalty (10 s, doubling to 5 min, reset after a quiet hour).
    fn record_bad(&mut self, now: Instant) -> bool {
        if self.last_bad.is_some_and(|t| now.saturating_duration_since(t) > Duration::from_secs(3600)) {
            self.penalty_len = Duration::from_secs(10);
        }
        self.last_bad = Some(now);
        self.bad.push_back(now);
        while self.bad.front().is_some_and(|t| now.saturating_duration_since(*t) > Duration::from_secs(10)) {
            self.bad.pop_front();
        }
        if self.bad.len() >= 5 {
            self.penalty_until = Some(now + self.penalty_len);
            self.penalty_len = (self.penalty_len * 2).min(Duration::from_secs(300));
            self.bad.clear();
            return true;
        }
        false
    }
}

/// Server half (i7labd): all sessions of one host (one per (client MAC, tag stack, session id)).
pub struct ServerSessions {
    mac: Mac,
    limits: SessionLimits,
    jar: CookieJar,
    boot_id: [u8; 8],
    epoch: Option<Instant>,
    base_ms: u64,
    caps: u32,
    hostname: String,
    sessions: Vec<SSession>,
    macs: HashMap<Mac, MacState>,
    g_hello: Option<Bucket>,
    g_unauth: Option<Bucket>,
    next_handle: u32,
    stats: ServerStats,
    events: Vec<ServerEvent>,
    /// (sn, when) of every OPEN that started a session, oldest first (code security review: OPEN replay)
    spent: VecDeque<([u8; 16], Instant)>,
}

impl ServerSessions {
    pub fn new(server_mac: Mac, limits: SessionLimits) -> std::io::Result<ServerSessions> {
        let mut boot_id = [0u8; 8];
        random_bytes(&mut boot_id)?;
        Ok(ServerSessions::with_parts(server_mac, limits, CookieJar::new()?, boot_id))
    }

    /// Deterministic construction for tests and golden vectors.
    pub fn with_parts(server_mac: Mac, limits: SessionLimits, jar: CookieJar, boot_id: [u8; 8]) -> ServerSessions {
        ServerSessions {
            mac: server_mac,
            limits,
            jar,
            boot_id,
            epoch: None,
            base_ms: 60_000,
            caps: crate::catalog::caps_bits(),
            hostname: String::new(),
            sessions: Vec::new(),
            macs: HashMap::new(),
            g_hello: None,
            g_unauth: None,
            next_handle: 1,
            stats: ServerStats::default(),
            events: Vec::new(),
            spent: VecDeque::new(),
        }
    }

    pub fn boot_id(&self) -> [u8; 8] {
        self.boot_id
    }
    pub fn set_caps(&mut self, caps: u32) {
        self.caps = caps;
    }
    pub fn set_hostname(&mut self, h: &str) {
        self.hostname = h.chars().take(63).collect();
    }
    /// Uptime of the host at the first `now` the engine sees (CHALLENGE `uptime_ms`).
    pub fn set_uptime_base(&mut self, ms: u64) {
        self.base_ms = ms;
    }
    /// Drain the session lifecycle events accumulated since the last call.
    pub fn take_events(&mut self) -> Vec<ServerEvent> {
        std::mem::take(&mut self.events)
    }
    /// Origin of the request with this handle (valid while the request is retained, 16 per session).
    pub fn request_info(&self, handle: u32) -> Option<RequestInfo> {
        let (i, rid) = self.find_handle(handle)?;
        let s = &self.sessions[i];
        Some(RequestInfo { session: s.conn.session, src: s.conn.peer, tags: s.conn.tags.clone(), role: s.role, client_req_id: rid })
    }
    pub fn stats(&self) -> &ServerStats {
        &self.stats
    }
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
    /// Out-of-order bytes currently held over all sessions (bounded by `window * frag` per stream).
    pub fn held_bytes(&self) -> usize {
        self.sessions.iter().flat_map(|s| s.conn.inn.values()).map(|i| i.rx.held_bytes()).sum()
    }
    /// Number of outstanding (received, not yet answered) requests over all sessions.
    pub fn outstanding_requests(&self) -> usize {
        self.sessions.iter().map(|s| s.outstanding()).sum()
    }

    fn uptime_ms(&mut self, now: Instant) -> u64 {
        let e = *self.epoch.get_or_insert(now);
        self.base_ms + now.saturating_duration_since(e).as_millis() as u64
    }

    fn mac_state(&mut self, m: Mac, now: Instant) -> &mut MacState {
        let s = self.macs.entry(m).or_insert_with(|| MacState::new(now));
        s.last_seen = now;
        s
    }

    fn global_ok(&mut self, hello: bool, now: Instant) -> bool {
        let (slot, rate, burst) = if hello { (&mut self.g_hello, 200.0, 400.0) } else { (&mut self.g_unauth, 500.0, 1000.0) };
        slot.get_or_insert_with(|| Bucket::new(burst, now)).take(now, rate, burst)
    }

    fn event(&mut self, e: ServerEvent) {
        if self.events.len() >= 1024 {
            self.events.remove(0);
        }
        self.events.push(e);
    }

    fn drop_frame(&mut self) -> Vec<Action> {
        self.stats.drops += 1;
        Vec::new()
    }

    fn send(&mut self, v: Vec<u8>, acts: &mut Vec<Action>) {
        self.stats.frames_tx += 1;
        acts.push(Action::Send(v));
    }

    /// Feed one received frame. Pre-crypto penalties apply to the HELLO/OPEN/unknown-session path only; frames
    /// that pass the session-id + ctr-window + tag check are never dropped by a per-MAC penalty (review
    /// security F7).
    pub fn on_frame(&mut self, keys: &KeySet, frame: &[u8], tags: &[(u16, u16)], now: Instant) -> Vec<Action> {
        self.stats.frames_rx += 1;
        self.uptime_ms(now);
        let Some((eth, f)) = parse_ctl(frame) else { return self.drop_frame() };
        if eth.dst != self.mac || !eth.src.is_unicast() {
            return self.drop_frame();
        }
        let Some(t) = FrameType::from_u8(f.hdr.ftype) else { return self.drop_frame() };
        let mut acts = match t {
            FrameType::Hello => self.on_hello(keys, &eth, &f, tags, now),
            FrameType::Open => self.on_open(keys, &eth, &f, tags, now),
            FrameType::Req | FrameType::Data | FrameType::Ack | FrameType::Cancel | FrameType::Close | FrameType::Keepalive => {
                self.on_session_frame(keys, t, &eth, &f, tags, now)
            }
            _ => self.drop_frame(),
        };
        self.after(now, &mut acts);
        acts
    }

    fn after(&mut self, now: Instant, acts: &mut Vec<Action>) {
        // frames that became sendable (window opened by an ACK, delayed ACKs due) leave with this call
        let mut frames = Vec::new();
        for s in self.sessions.iter_mut() {
            s.conn.flush_acks(now, &mut frames);
            s.conn.pump(now, &mut frames);
        }
        for f in frames {
            self.send(f, acts);
        }
    }

    fn on_hello(&mut self, keys: &KeySet, eth: &EthHeader, f: &frame::Frame, tags: &[(u16, u16)], now: Instant) -> Vec<Action> {
        if f.payload.len() < HELLO_LEN || f.hdr.session != 0 {
            return self.drop_frame();
        }
        if !self.global_ok(true, now) {
            self.stats.rate_limited += 1;
            return Vec::new();
        }
        let ms = self.mac_state(eth.src, now);
        if ms.penalized(now) {
            self.stats.penalized += 1;
            return Vec::new();
        }
        if !ms.hello.take(now, 5.0, 20.0) {
            self.stats.rate_limited += 1;
            return Vec::new();
        }
        let Ok(h) = Hello::decode(f.payload) else { return self.drop_frame() };
        let Some(key) = keys.by_id(&h.key_id) else { return self.drop_frame() };
        if !frame::verify(f, TagKey::Hello(&key.bytes)) {
            self.stats.bad_tags += 1;
            self.mac_state(eth.src, now).record_bad(now);
            return Vec::new();
        }
        if h.ver_min > VERSION || h.ver_max < VERSION {
            return self.drop_frame();
        }
        let up = self.uptime_ms(now);
        let sn = self.jar.make(up, &eth.src, &self.mac, &h.cn, tags);
        let ch = Challenge {
            sn,
            boot_id: self.boot_id,
            uptime_ms: up as u32,
            ver: VERSION,
            max_frag: clamp_frag(h.max_frag.min(self.limits.frag), self.limits.frag),
            caps: self.caps,
        };
        let hdr = Header { ver: VERSION, ftype: FrameType::Challenge as u8, plen: crate::handshake::CHALLENGE_LEN as u16, ..Default::default() };
        let sealed = frame::seal(&hdr, &ch.encode(), TagKey::Challenge { k: &key.bytes, cn: &h.cn });
        let mut acts = Vec::new();
        let out = eth_wrap(self.mac, eth.src, tags, &sealed);
        self.send(out, &mut acts);
        acts
    }

    fn find(&self, src: Mac, tags: &[(u16, u16)], id: u32) -> Option<usize> {
        self.sessions.iter().position(|s| s.conn.session == id && s.conn.peer == src && s.conn.tags == tags)
    }

    fn on_open(&mut self, keys: &KeySet, eth: &EthHeader, f: &frame::Frame, tags: &[(u16, u16)], now: Instant) -> Vec<Action> {
        if f.payload.len() < 32 || f.hdr.ctr == 0 {
            return self.drop_frame();
        }
        if !self.global_ok(false, now) {
            self.stats.rate_limited += 1;
            return Vec::new();
        }
        let ms = self.mac_state(eth.src, now);
        if ms.penalized(now) {
            self.stats.penalized += 1;
            return Vec::new();
        }
        if !ms.unauth.take(now, 50.0, 100.0) {
            self.stats.rate_limited += 1;
            return Vec::new();
        }
        let id = f.hdr.session;
        let mut acts = Vec::new();
        // duplicate OPEN of an existing session: same OPEN_OK again
        if let Some(i) = self.find(eth.src, tags, id) {
            let s = &mut self.sessions[i];
            if frame::verify(f, TagKey::Session { sk: &s.conn.sk, dir: Dir::ClientToServer }) {
                let ok = s.open_ok.clone();
                let fr = s.conn.seal(Header { ftype: FrameType::OpenOk as u8, ..Default::default() }, &ok);
                s.conn.last_rx = now;
                self.send(fr, &mut acts);
            } else {
                self.stats.bad_tags += 1;
                self.mac_state(eth.src, now).record_bad(now);
            }
            return acts;
        }
        let cn: [u8; 16] = f.payload[0..16].try_into().unwrap();
        let sn: [u8; 16] = f.payload[16..32].try_into().unwrap();
        if session_id(&sn) != id {
            return self.drop_frame();
        }
        let up = self.uptime_ms(now);
        if !self.jar.check(up, &eth.src, &self.mac, &cn, tags, &sn) {
            return self.drop_frame();
        }
        let frag_req = if f.payload.len() >= 34 { u16::from_be_bytes([f.payload[32], f.payload[33]]) } else { self.limits.frag };
        let frag = clamp_frag(frag_req.min(self.limits.frag), self.limits.frag);
        let mut found: Option<([u8; 32], Role)> = None;
        for k in [keys.admin.as_ref(), keys.ro.as_ref()].into_iter().flatten() {
            let sk = session_key(&k.bytes, &cn, &sn, &eth.src, &self.mac, f.hdr.ver);
            if frame::verify(f, TagKey::Session { sk: &sk, dir: Dir::ClientToServer }) {
                found = Some((sk, k.role));
                break;
            }
        }
        let Some((sk, role)) = found else {
            self.stats.bad_tags += 1;
            self.mac_state(eth.src, now).record_bad(now);
            return acts;
        };
        // One OPEN, one session. The cookie stays valid for up to 30 s, so without this a captured HELLO/OPEN
        // replayed after that session ended would open a NEW session with the same SK and a fresh replay window,
        // and the captured REQ frames of the old session (reboot, exec, put, blk.write) would run a second time.
        while self.spent.front().is_some_and(|(_, t)| now.saturating_duration_since(*t) > SPENT_TTL) {
            self.spent.pop_front();
        }
        if self.spent.iter().any(|(s, _)| *s == sn) {
            self.stats.replays += 1;
            return acts;
        }
        if self.spent.len() >= SPENT_CAP {
            self.stats.rate_limited += 1;
            return acts;
        }
        self.spent.push_back((sn, now));
        // make room: 2 per MAC, 8 total, oldest closed first
        while self.sessions.iter().filter(|s| s.conn.peer == eth.src).count() >= MAX_PER_MAC {
            let i = self.sessions.iter().enumerate().filter(|(_, s)| s.conn.peer == eth.src).min_by_key(|(_, s)| s.created).map(|(i, _)| i).unwrap();
            self.end_session(i, "evicted (per-MAC session limit)", true, &mut acts);
        }
        while self.sessions.len() >= MAX_SESSIONS {
            let i = self.sessions.iter().enumerate().min_by_key(|(_, s)| s.created).map(|(i, _)| i).unwrap();
            self.end_session(i, "evicted (session limit)", true, &mut acts);
        }
        let mut conn = Conn::new(self.mac, eth.src, tags.to_vec(), sk, id, Dir::ServerToClient, frag, self.limits.window, now);
        conn.rx_win.commit(f.hdr.ctr);
        let ok = OpenOk { role, idle_s: self.limits.idle.as_secs().min(u16::MAX as u64) as u16, frag, window: self.limits.window, caps: self.caps, hostname: self.hostname.clone() }.encode();
        let fr = conn.seal(Header { ftype: FrameType::OpenOk as u8, ..Default::default() }, &ok);
        self.sessions.push(SSession { conn, role, created: now, open_ok: ok, reqs: BTreeMap::new(), order: VecDeque::new(), violations: 0 });
        self.stats.sessions_opened += 1;
        self.event(ServerEvent::SessionOpened { session: id, src: eth.src, tags: tags.to_vec(), role });
        self.send(fr, &mut acts);
        acts
    }

    fn on_session_frame(&mut self, keys: &KeySet, t: FrameType, eth: &EthHeader, f: &frame::Frame, tags: &[(u16, u16)], now: Instant) -> Vec<Action> {
        let id = f.hdr.session;
        let Some(i) = self.find(eth.src, tags, id) else {
            // same MAC and id but another tag stack: dropped silently (cross-VLAN confusion)
            if self.sessions.iter().any(|s| s.conn.session == id && s.conn.peer == eth.src) {
                return self.drop_frame();
            }
            return self.no_session(keys, eth, tags, id, now);
        };
        match self.sessions[i].conn.check_rx(f) {
            RxCheck::Replay => {
                self.stats.replays += 1;
                return Vec::new();
            }
            RxCheck::BadTag => {
                self.stats.bad_tags += 1;
                self.mac_state(eth.src, now).record_bad(now);
                return Vec::new();
            }
            RxCheck::Ok => {}
        }
        let mut acts = Vec::new();
        self.sessions[i].conn.last_rx = now;
        let mut frames = Vec::new();
        let mut end: Option<&'static str> = None;
        let mut violation: Option<(u32, Status)> = None;
        let h = &f.hdr;
        {
            let handle_base = &mut self.next_handle;
            let s = &mut self.sessions[i];
            match t {
                FrameType::Req => match s.on_req(h, f.payload, now, self.limits.max_req, handle_base, &mut frames, &mut acts) {
                    Ok(()) => {}
                    Err(e) => violation = Some((h.req_id, status_of(&e))),
                },
                FrameType::Data => {
                    if let Err(e) = s.on_data(h, f.payload, now, &mut frames, &mut acts) {
                        violation = Some((h.req_id, status_of(&e)));
                    }
                }
                FrameType::Ack => s.conn.on_ack(h, f.payload, now),
                FrameType::Cancel => {
                    if let Some(r) = s.reqs.get_mut(&h.req_id) {
                        if matches!(r.state, ReqState::Receiving | ReqState::Running) {
                            r.state = ReqState::Canceled;
                            acts.push(Action::Canceled { req_id: r.handle });
                        }
                    }
                }
                FrameType::Keepalive => {
                    if h.flags & flags::REPLY == 0 {
                        frames.push(s.conn.simple(FrameType::Keepalive, flags::REPLY, 0, 0));
                    }
                }
                FrameType::Close => end = Some("closed by client"),
                _ => {}
            }
            if let Some((rid, st)) = violation {
                s.violations += 1;
                frames.push(s.conn.simple(FrameType::Err, 0, rid, st as u16));
                if s.violations >= VIOLATION_LIMIT {
                    end = Some("too many protocol violations");
                }
            }
        }
        for fr in frames {
            self.send(fr, &mut acts);
        }
        if let Some(reason) = end {
            self.end_session(i, reason, reason != "closed by client", &mut acts);
        }
        acts
    }

    fn no_session(&mut self, keys: &KeySet, eth: &EthHeader, tags: &[(u16, u16)], id: u32, now: Instant) -> Vec<Action> {
        let mut acts = Vec::new();
        if !self.global_ok(false, now) {
            self.stats.rate_limited += 1;
            return acts;
        }
        let ms = self.mac_state(eth.src, now);
        if ms.penalized(now) {
            self.stats.penalized += 1;
            return acts;
        }
        if !ms.unauth.take(now, 50.0, 100.0) || !ms.nosess.take(now, 2.0, 4.0) {
            self.stats.rate_limited += 1;
            return acts;
        }
        let hdr = frame::nosession_header(id, &self.boot_id);
        for k in [keys.admin.as_ref(), keys.ro.as_ref()].into_iter().flatten() {
            let sealed = frame::seal(&hdr, &[], TagKey::NoSession(&k.bytes));
            let out = eth_wrap(self.mac, eth.src, tags, &sealed);
            self.stats.no_session_sent += 1;
            self.send(out, &mut acts);
        }
        acts
    }

    fn end_session(&mut self, i: usize, reason: &'static str, send_close: bool, acts: &mut Vec<Action>) {
        let mut s = self.sessions.remove(i);
        for r in s.reqs.values() {
            if matches!(r.state, ReqState::Running | ReqState::Canceled) {
                acts.push(Action::Canceled { req_id: r.handle });
            }
        }
        if send_close {
            let fr = s.conn.simple(FrameType::Close, 0, 0, 0);
            self.send(fr, acts);
        }
        self.stats.retransmits += s.conn.retransmits;
        self.stats.sessions_ended += 1;
        self.event(ServerEvent::SessionEnded { session: s.conn.session, src: s.conn.peer, reason });
    }

    /// Close every session (reboot/poweroff/service stop): CLOSE frames and the usual actions.
    pub fn close_all(&mut self, reason: &'static str) -> Vec<Action> {
        let mut acts = Vec::new();
        while !self.sessions.is_empty() {
            self.end_session(0, reason, true, &mut acts);
        }
        acts
    }

    fn find_handle(&self, handle: u32) -> Option<(usize, u32)> {
        for (i, s) in self.sessions.iter().enumerate() {
            for (rid, r) in &s.reqs {
                if r.handle == handle {
                    return Some((i, *rid));
                }
            }
        }
        None
    }

    /// Final response for a delivered `Action::Request`. Cached for idempotent retransmit of the REQ. Any
    /// stream of the request still open is finished first; the RESP leaves only after all of them are
    /// acknowledged (RESP never overtakes output).
    pub fn respond(&mut self, req_id: u32, status: Status, body: &[u8], now: Instant) -> Vec<Action> {
        let mut acts = Vec::new();
        let Some((i, rid)) = self.find_handle(req_id) else { return acts };
        let max_resp = self.limits.max_resp as usize;
        let s = &mut self.sessions[i];
        let (status, body): (Status, &[u8]) = if body.len() > max_resp { (Status::TooBig, &[]) } else { (status, body) };
        let r = s.reqs.get_mut(&rid).unwrap();
        if r.state == ReqState::Responded || r.state == ReqState::Receiving {
            return acts;
        }
        r.state = ReqState::Responded;
        let cmd = r.cmd;
        if body.len() <= CACHE_TOTAL {
            r.cached = Some((status, body.to_vec()));
        }
        s.trim_cache();
        s.start_resp(rid, cmd, status, body);
        self.after(now, &mut acts);
        acts
    }

    /// Server to client stream data; returns false while the window is closed (driver blocks: backpressure).
    pub fn stream_data(&mut self, req_id: u32, chan: Chan, data: &[u8], fin: bool, now: Instant) -> (bool, Vec<Action>) {
        let mut acts = Vec::new();
        let Some((i, rid)) = self.find_handle(req_id) else { return (false, acts) };
        if !matches!(chan, Chan::Stdout | Chan::Stderr | Chan::File) {
            return (false, acts);
        }
        let s = &mut self.sessions[i];
        if !matches!(s.reqs[&rid].state, ReqState::Running | ReqState::Canceled) {
            return (false, acts);
        }
        let cap = s.conn.window as usize * s.conn.frag as usize * 2;
        let o = s.conn.queue_out(rid, chan as u8, OutKind::Data, NO_LEN, false);
        if o.s.is_finished_queued() {
            return (false, acts);
        }
        if o.s.buffered() > 0 && o.s.buffered() + data.len() > cap {
            return (false, acts);
        }
        o.s.push(data);
        if fin {
            o.s.finish();
        }
        self.after(now, &mut acts);
        (true, acts)
    }

    /// Timers: retransmits, delayed ACKs, idle/lifetime expiry. Call at least every `next_deadline`.
    pub fn poll(&mut self, now: Instant) -> Vec<Action> {
        self.uptime_ms(now);
        let mut acts = Vec::new();
        let mut i = 0;
        while i < self.sessions.len() {
            let s = &self.sessions[i];
            let idle = now.saturating_duration_since(s.conn.last_rx);
            let reason = if s.conn.any_dead() {
                Some("retransmit limit reached")
            } else if idle >= self.limits.idle {
                Some("idle timeout")
            } else if now.saturating_duration_since(s.created) >= LIFETIME {
                Some("session lifetime reached")
            } else if s.conn.exhausted() {
                Some("frame counter exhausted")
            } else {
                None
            };
            match reason {
                Some(r) => self.end_session(i, r, true, &mut acts),
                None => i += 1,
            }
        }
        self.after(now, &mut acts);
        if self.macs.len() > 4096 {
            self.macs.retain(|_, m| now.saturating_duration_since(m.last_seen) < Duration::from_secs(60) || m.penalized(now));
        }
        acts
    }

    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        self.sessions
            .iter()
            .flat_map(|s| [s.conn.next_deadline(now), Some(s.conn.last_rx + self.limits.idle)])
            .flatten()
            .min()
    }
}

impl SSession {
    fn outstanding(&self) -> usize {
        self.reqs.values().filter(|r| matches!(r.state, ReqState::Receiving | ReqState::Running | ReqState::Canceled)).count()
    }

    fn trim_cache(&mut self) {
        let mut total: usize = self.reqs.values().filter_map(|r| r.cached.as_ref()).map(|c| c.1.len()).sum();
        if total <= CACHE_TOTAL {
            return;
        }
        let ids: Vec<u32> = self.order.iter().copied().collect();
        for id in ids {
            if total <= CACHE_TOTAL {
                break;
            }
            if let Some(r) = self.reqs.get_mut(&id) {
                if let Some(c) = r.cached.take() {
                    total -= c.1.len();
                }
            }
        }
    }

    fn start_resp(&mut self, rid: u32, cmd: u16, status: Status, body: &[u8]) {
        for (k, o) in self.conn.out.iter_mut() {
            if k.0 == rid && k.1 != 0 {
                o.s.finish();
            }
        }
        self.conn.out.remove(&(rid, 0));
        let o = self.conn.queue_out(rid, 0, OutKind::Resp { cmd, status: status as u16 }, body.len() as u32, true);
        o.s.push(body);
        o.s.finish();
    }

    fn retire_old(&mut self) {
        while self.order.len() > REQ_RETAIN {
            // never drop a request that is still in progress
            let pos = self.order.iter().position(|id| self.reqs.get(id).is_some_and(|r| r.state == ReqState::Responded));
            let Some(p) = pos else { break };
            let id = self.order.remove(p).unwrap();
            self.reqs.remove(&id);
            self.conn.forget_req(id);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn on_req(&mut self, h: &Header, payload: &[u8], now: Instant, max_req: u32, handle: &mut u32, frames: &mut Vec<Vec<u8>>, acts: &mut Vec<Action>) -> Result<(), FrameError> {
        let rid = h.req_id;
        if rid == 0 {
            return Err(FrameError::BadPayload("req_id 0"));
        }
        match self.reqs.get(&rid).map(|r| r.state) {
            Some(ReqState::Receiving) => {}
            Some(ReqState::Running | ReqState::Canceled) => {
                // retransmitted fragment of a request that is already executing: just acknowledge
                if let Some(f) = self.conn.ack_frame(rid, 0) {
                    frames.push(f);
                }
                return Ok(());
            }
            Some(ReqState::Responded) => {
                if let Some(f) = self.conn.ack_frame(rid, 0) {
                    frames.push(f);
                }
                if !self.conn.out.contains_key(&(rid, 0)) {
                    let cmd = self.reqs[&rid].cmd;
                    match self.reqs[&rid].cached.clone() {
                        Some((st, body)) => self.start_resp(rid, cmd, st, &body),
                        None => self.start_resp(rid, cmd, Status::StreamGone, &[]),
                    }
                }
                return Ok(());
            }
            None => {
                // unknown id: older than everything retained => stale retransmit, ignore
                if self.reqs.len() >= REQ_RETAIN && self.order.front().is_some_and(|f| rid < *f) {
                    return Ok(());
                }
                if h.msg_len > max_req {
                    return Err(FrameError::TooBig);
                }
                let busy = self.outstanding() >= MAX_OUTSTANDING;
                let hd = *handle;
                *handle = handle.wrapping_add(1).max(1);
                self.reqs.insert(rid, SReq { handle: hd, state: if busy { ReqState::Responded } else { ReqState::Receiving }, cmd: h.cmd, cached: None });
                self.order.push_back(rid);
                if busy {
                    self.start_resp(rid, h.cmd, Status::Busy, &[]);
                    self.reqs.get_mut(&rid).unwrap().cached = Some((Status::Busy, Vec::new()));
                    self.retire_old();
                    return Ok(());
                }
                self.retire_old();
            }
        }
        let inc = self.conn.on_incoming(h, payload, now, max_req, frames);
        let inc = match inc {
            Ok(i) => i,
            Err(e) => return Err(e),
        };
        if inc.newly_complete {
            let r = self.reqs.get_mut(&rid).unwrap();
            r.state = ReqState::Running;
            r.cmd = h.cmd;
            acts.push(Action::Request { req_id: r.handle, cmd: h.cmd, body: inc.data, role: self.role });
        }
        Ok(())
    }

    fn on_data(&mut self, h: &Header, payload: &[u8], now: Instant, frames: &mut Vec<Vec<u8>>, acts: &mut Vec<Action>) -> Result<(), FrameError> {
        let chan = match h.chan {
            3 => Chan::Stdin,
            4 => Chan::File,
            5 => Chan::Ctl,
            _ => return Err(FrameError::BadPayload("bad channel")),
        };
        let Some(r) = self.reqs.get(&h.req_id) else { return Ok(()) };
        if !matches!(r.state, ReqState::Running | ReqState::Canceled) {
            return Ok(()); // body not complete yet or already answered: dropped, the client retransmits
        }
        let handle = r.handle;
        let inc = self.conn.on_incoming(h, payload, now, 0, frames)?;
        if !inc.data.is_empty() {
            acts.push(Action::StreamData { req_id: handle, chan, data: inc.data });
        }
        if inc.newly_complete {
            acts.push(Action::StreamEnd { req_id: handle, chan });
        }
        Ok(())
    }
}
