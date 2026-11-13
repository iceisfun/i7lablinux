//! Shared test scaffolding: seeded RNG, keys, a virtual-time lossy network between a `ClientSession` and a
//! `ServerSessions`, and a tiny server application (ping, get, put, exec) driving the engine like i7labd will.
#![allow(dead_code)]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use labproto::args::{decode_argv, encode_argv};
use labproto::crypto::{hex, sha256};
use labproto::frame::Chan;
use labproto::keys::{Key, KeySet, Role};
use labproto::mac::Mac;
use labproto::session::{Action, ClientSession, ServerSessions, SessionLimits};
use labproto::status::Status;

/// xorshift64*, seeded.
pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

pub const CLIENT: Mac = Mac([2, 0, 0, 0, 0, 1]);
pub const SERVER: Mac = Mac([2, 0, 0, 0, 0, 2]);

pub const CMD_PING: u16 = 0x0001;
pub const CMD_EXEC: u16 = 0x0020;
pub const CMD_PUT: u16 = 0x0030;
pub const CMD_GET: u16 = 0x0031;

pub fn admin_key() -> Key {
    Key { role: Role::Admin, bytes: std::array::from_fn(|i| i as u8) }
}
pub fn ro_key() -> Key {
    Key { role: Role::Ro, bytes: std::array::from_fn(|i| 0x80 + i as u8) }
}
pub fn keyset() -> KeySet {
    KeySet { admin: Some(admin_key()), ro: Some(ro_key()) }
}

/// Deterministic content served by `get`.
pub fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8).collect()
}

struct Getter {
    handle: u32,
    data: Vec<u8>,
    pos: usize,
    finished: bool,
}

pub struct Sim {
    pub t0: Instant,
    pub now: Instant,
    pub rng: Rng,
    pub loss: u64,
    pub jitter_ms: u64,
    pub tags: Vec<(u16, u16)>,
    pub server: ServerSessions,
    pub keys: KeySet,
    pub client: ClientSession,
    c2s: Vec<(Instant, Vec<u8>)>,
    s2c: Vec<(Instant, Vec<u8>)>,
    /// every frame the client sent (for replay tests)
    pub captured_c2s: Vec<Vec<u8>>,
    getters: Vec<Getter>,
    puts: HashMap<u32, Vec<u8>>,
    // observations
    pub requests: Vec<(u32, u16, Vec<u8>, Role)>,
    pub responses: HashMap<u32, (Status, Vec<u8>)>,
    pub streams: HashMap<(u32, u8), Vec<u8>>,
    pub stream_ends: Vec<(u32, u8)>,
    pub opened: Option<(Role, String)>,
    pub closed: Option<&'static str>,
    pub server_events: Vec<Action>,
    pub max_held: usize,
    /// order of client-visible events: ('D'ata, req), ('E'nd, req), ('R'esponse, req)
    pub order: Vec<(char, u32)>,
    pub drop_c2s: Box<dyn FnMut(&[u8]) -> bool>,
}

impl Sim {
    pub fn new(seed: u64, loss: u64, jitter_ms: u64, tags: Vec<(u16, u16)>, key: &Key) -> Sim {
        let t0 = Instant::now();
        let limits = SessionLimits::default();
        let mut server = ServerSessions::new(SERVER, limits.clone()).unwrap();
        server.set_hostname("labhost");
        let client = ClientSession::new(CLIENT, SERVER, tags.clone(), key, limits, t0);
        Sim {
            t0,
            now: t0,
            rng: Rng(seed | 1),
            loss,
            jitter_ms,
            tags,
            server,
            keys: keyset(),
            client,
            c2s: Vec::new(),
            s2c: Vec::new(),
            captured_c2s: Vec::new(),
            getters: Vec::new(),
            puts: HashMap::new(),
            requests: Vec::new(),
            responses: HashMap::new(),
            streams: HashMap::new(),
            stream_ends: Vec::new(),
            opened: None,
            closed: None,
            server_events: Vec::new(),
            max_held: 0,
            order: Vec::new(),
            drop_c2s: Box::new(|_| false),
        }
    }

    fn enqueue(&mut self, to_server: bool, f: Vec<u8>) {
        if to_server {
            self.captured_c2s.push(f.clone());
            if (self.drop_c2s)(&f) {
                return;
            }
        }
        if self.rng.below(100) < self.loss {
            return;
        }
        let at = self.now + Duration::from_millis(1 + self.rng.below(self.jitter_ms + 1));
        if to_server {
            self.c2s.push((at, f));
        } else {
            self.s2c.push((at, f));
        }
    }

    fn server_actions(&mut self, acts: Vec<Action>) {
        for a in acts {
            match a {
                Action::Send(f) => self.enqueue(false, f),
                Action::Request { req_id, cmd, body, role, .. } => {
                    self.requests.push((req_id, cmd, body.clone(), role));
                    let argv = decode_argv(&body).unwrap_or_default();
                    match cmd {
                        CMD_PING => {
                            let echo = argv.first().cloned().unwrap_or_default();
                            let out = self.server.respond(req_id, Status::Ok, echo.as_bytes(), self.now);
                            self.server_actions(out);
                        }
                        CMD_GET => {
                            let n: usize = argv[0].parse().unwrap();
                            self.getters.push(Getter { handle: req_id, data: pattern(n), pos: 0, finished: false });
                        }
                        CMD_PUT => {
                            self.puts.insert(req_id, Vec::new());
                        }
                        CMD_EXEC => {}
                        _ => {
                            let out = self.server.respond(req_id, Status::Unsupported, b"", self.now);
                            self.server_actions(out);
                        }
                    }
                }
                Action::StreamData { req_id, chan: Chan::File, data } => {
                    self.puts.entry(req_id).or_default().extend_from_slice(&data);
                }
                Action::StreamData { .. } => {}
                Action::StreamEnd { req_id, chan: Chan::File } => {
                    let d = self.puts.remove(&req_id).unwrap_or_default();
                    let out = self.server.respond(req_id, Status::Ok, hex(&sha256(&d)).as_bytes(), self.now);
                    self.server_actions(out);
                }
                Action::Canceled { req_id } => {
                    let out = self.server.respond(req_id, Status::Canceled, b"", self.now);
                    self.server_actions(out);
                }
                other => self.server_events.push(other),
            }
        }
    }

    fn client_actions(&mut self, acts: Vec<Action>) {
        for a in acts {
            match a {
                Action::Send(f) => self.enqueue(true, f),
                Action::Response { req_id, status, body } => {
                    self.order.push(('R', req_id));
                    assert!(self.responses.insert(req_id, (status, body)).is_none(), "response {} delivered twice", req_id);
                }
                Action::StreamData { req_id, chan, data } => {
                    self.order.push(('D', req_id));
                    self.streams.entry((req_id, chan as u8)).or_default().extend_from_slice(&data)
                }
                Action::StreamEnd { req_id, chan } => {
                    self.order.push(('E', req_id));
                    self.stream_ends.push((req_id, chan as u8))
                }
                Action::Opened { role, hostname } => self.opened = Some((role, hostname)),
                Action::Closed { reason } => self.closed = Some(reason),
                _ => {}
            }
        }
    }

    fn feed_getters(&mut self) {
        let now = self.now;
        let mut i = 0;
        while i < self.getters.len() {
            let handle = self.getters[i].handle;
            loop {
                let g = &mut self.getters[i];
                if g.finished {
                    break;
                }
                let end = (g.pos + 16 * 1024).min(g.data.len());
                let chunk = g.data[g.pos..end].to_vec();
                let fin = end == g.data.len();
                let (ok, acts) = self.server.stream_data(handle, Chan::File, &chunk, fin, now);
                self.server_actions(acts);
                if !ok {
                    break;
                }
                let g = &mut self.getters[i];
                g.pos = end;
                if fin {
                    g.finished = true;
                    let acts = self.server.respond(handle, Status::Ok, b"{\"ok\":true}", now);
                    self.server_actions(acts);
                    break;
                }
            }
            i += 1;
        }
        self.getters.retain(|g| !g.finished);
    }

    pub fn step(&mut self) {
        self.now += Duration::from_millis(2);
        let now = self.now;
        // deliveries
        let mut due: Vec<Vec<u8>> = Vec::new();
        let mut i = 0;
        while i < self.c2s.len() {
            if self.c2s[i].0 <= now {
                due.push(self.c2s.swap_remove(i).1);
            } else {
                i += 1;
            }
        }
        for f in due {
            let tags = self.tags.clone();
            let acts = self.server.on_frame(&self.keys, &f, &tags, now);
            self.server_actions(acts);
            self.max_held = self.max_held.max(self.server.held_bytes());
        }
        let mut due: Vec<Vec<u8>> = Vec::new();
        let mut i = 0;
        while i < self.s2c.len() {
            if self.s2c[i].0 <= now {
                due.push(self.s2c.swap_remove(i).1);
            } else {
                i += 1;
            }
        }
        for f in due {
            let tags = self.tags.clone();
            let acts = self.client.on_frame(&f, &tags, now);
            self.client_actions(acts);
        }
        let acts = self.server.poll(now);
        self.server_actions(acts);
        self.feed_getters();
        let acts = self.client.poll(now);
        self.client_actions(acts);
    }

    /// Run until `cond` holds or `max_steps` pass.
    pub fn run_until(&mut self, max_steps: usize, cond: impl Fn(&Sim) -> bool) -> bool {
        for _ in 0..max_steps {
            if cond(self) {
                return true;
            }
            self.step();
        }
        cond(self)
    }

    pub fn open(&mut self) {
        assert!(self.run_until(5000, |s| s.opened.is_some()), "handshake did not finish: {:?}", self.closed);
    }

    pub fn req(&mut self, cmd: u16, argv: &[&str]) -> u32 {
        let id = self.client.send_req(cmd, &encode_argv(argv), self.now).unwrap();
        let acts = self.client.poll(self.now);
        self.client_actions(acts);
        id
    }
}

// ---------------------------------------------------------------------------------------------------------
// An independent, hand-rolled client written from PROTOCOL.md (not from the engine's code), so that attack
// tests can craft arbitrary frames with a valid session key.
// ---------------------------------------------------------------------------------------------------------

use labproto::frame::{self, Dir, EthHeader, FrameType, Header, TagKey, ETHERTYPE_CTL};
use labproto::handshake::{session_id, session_key, Challenge, Hello};

pub struct Raw {
    pub mac: Mac,
    pub tags: Vec<(u16, u16)>,
    pub key: Key,
    pub cn: [u8; 16],
    pub sk: [u8; 32],
    pub sn: [u8; 16],
    pub session: u32,
    pub ctr: u64,
    pub boot: [u8; 8],
    pub frag: u16,
}

pub fn sends(acts: &[Action]) -> Vec<Vec<u8>> {
    acts.iter().filter_map(|a| if let Action::Send(f) = a { Some(f.clone()) } else { None }).collect()
}

pub fn requests(acts: &[Action]) -> Vec<&Action> {
    acts.iter().filter(|a| matches!(a, Action::Request { .. })).collect()
}

/// (ethernet header, protocol header, payload)
pub fn parse(frame_bytes: &[u8]) -> Option<(EthHeader, Header, Vec<u8>)> {
    let (eth, p) = frame::eth_parse(frame_bytes)?;
    let f = frame::open(p).ok()?;
    Some((eth, f.hdr.clone(), f.payload.to_vec()))
}

impl Raw {
    pub fn new(mac: Mac, tags: Vec<(u16, u16)>, key: Key, cn_seed: u8) -> Raw {
        Raw { mac, tags, key, cn: [cn_seed; 16], sk: [0; 32], sn: [0; 16], session: 0, ctr: 0, boot: [0; 8], frag: 1400 }
    }

    fn wrap(&self, sealed: &[u8]) -> Vec<u8> {
        frame::eth_build(&EthHeader { dst: SERVER, src: self.mac, tags: self.tags.clone(), ethertype: ETHERTYPE_CTL }, sealed)
    }

    pub fn hello(&self) -> Vec<u8> {
        let h = Hello { cn: self.cn, key_id: self.key.key_id(), ver_min: 1, ver_max: 1, max_frag: 1400, caps: 1 };
        let hdr = Header { ver: 1, ftype: 1, plen: 48, ..Default::default() };
        self.wrap(&frame::seal(&hdr, &h.encode(), TagKey::Hello(&self.key.bytes)))
    }

    pub fn bad_hello(&self) -> Vec<u8> {
        let wrong = [0x55u8; 32];
        let h = Hello { cn: self.cn, key_id: self.key.key_id(), ver_min: 1, ver_max: 1, max_frag: 1400, caps: 1 };
        let hdr = Header { ver: 1, ftype: 1, plen: 48, ..Default::default() };
        self.wrap(&frame::seal(&hdr, &h.encode(), TagKey::Hello(&wrong)))
    }

    /// Verify a CHALLENGE as a client must and derive SK.
    pub fn take_challenge(&mut self, f: &[u8]) -> bool {
        let Some((eth, p)) = frame::eth_parse(f) else { return false };
        let Ok(fr) = frame::open(p) else { return false };
        if eth.src != SERVER || fr.hdr.ftype != FrameType::Challenge as u8 {
            return false;
        }
        if !frame::verify(&fr, TagKey::Challenge { k: &self.key.bytes, cn: &self.cn }) {
            return false;
        }
        let ch = Challenge::decode(fr.payload).unwrap();
        self.sn = ch.sn;
        self.boot = ch.boot_id;
        self.session = session_id(&ch.sn);
        self.sk = session_key(&self.key.bytes, &self.cn, &ch.sn, &self.mac, &SERVER, ch.ver);
        true
    }

    pub fn open(&mut self) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&self.cn);
        p.extend_from_slice(&self.sn);
        p.extend_from_slice(&self.frag.to_be_bytes());
        self.frame(FrameType::Open, 0, 0, 0, 0, 0, 0, 0, 0, &p)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn frame(&mut self, t: FrameType, fl: u8, chan: u8, cmd: u16, req: u32, msg_len: u32, off: u32, win: u16, status: u16, payload: &[u8]) -> Vec<u8> {
        self.ctr += 1;
        let c = self.ctr;
        self.frame_ctr(c, t, fl, chan, cmd, req, msg_len, off, win, status, payload)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn frame_ctr(&self, ctr: u64, t: FrameType, fl: u8, chan: u8, cmd: u16, req: u32, msg_len: u32, off: u32, win: u16, status: u16, payload: &[u8]) -> Vec<u8> {
        let h = Header { ver: 1, ftype: t as u8, flags: fl, chan, cmd, session: self.session, req_id: req, ctr, msg_len, off, plen: payload.len() as u16, win, status };
        self.wrap(&frame::seal(&h, payload, TagKey::Session { sk: &self.sk, dir: Dir::ClientToServer }))
    }

    /// A whole single-fragment REQ.
    pub fn req(&mut self, cmd: u16, id: u32, argv: &[&str]) -> Vec<u8> {
        let body = encode_argv(argv);
        self.frame(FrameType::Req, 1, 0, cmd, id, body.len() as u32, 0, 0, 0, &body)
    }

    /// Handshake against `server`; returns false if any step failed.
    pub fn handshake(&mut self, server: &mut ServerSessions, keys: &KeySet, now: Instant) -> bool {
        let tags = self.tags.clone();
        let acts = server.on_frame(keys, &self.hello(), &tags, now);
        let s = sends(&acts);
        let Some(ch) = s.iter().find(|f| parse(f).is_some_and(|(_, h, _)| h.ftype == FrameType::Challenge as u8)) else { return false };
        if !self.take_challenge(ch) {
            return false;
        }
        let acts = server.on_frame(keys, &self.open(), &tags, now);
        let s = sends(&acts);
        let Some(ok) = s.iter().find_map(|f| parse(f).filter(|(_, h, _)| h.ftype == FrameType::OpenOk as u8)) else { return false };
        let (_, h, _) = ok;
        h.session == self.session
    }
}
