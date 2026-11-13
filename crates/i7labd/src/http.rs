//! HTTP/1.1 server (std `TcpListener`, one bounded thread per connection) with the JSON API and the SPA.
//! Owner: P7. Spec: PLAN.md C3/C4/C17/C22, WEB.md. Wire helpers: `httpwire.rs`.
//!
//! Authentication is the lab-proxy nonce HMAC of `labproto::httpauth`, keyed by the same admin/ro keys as the
//! ether protocol: no secret crosses the wire, requests are bound to nonce + method + target + body hash, and
//! every response carries `X-Lab-Proof`. Streams (NDJSON, SSE) carry `seq` + `mac` per event; raw file bodies use
//! the `_hashed` MAC forms (header `X-Lab-Body-Sha256` declares the upload digest up front so the MAC can be
//! checked BEFORE the first byte is written; downloads end with the proof as a chunked trailer).
//!
//! Routes (all under /api/v1 unless noted):
//!   open:    GET /  GET /api/v1/hello  GET /api/v1/nonce  GET /api/v1/openapi.json  (aliases GET /health /nonce)
//!   signed:  POST cmd/<name>[?stream=1]  GET probe[/<section>]  GET overview  GET events (SSE)
//!            GET|PUT file?path=..  GET inventory|pcie|blk|usb|net|thermal|log (?a=ARG..)

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use labproto::catalog::{Access, CATALOG};
use labproto::crypto::{hex, unhex, Sha256};
use labproto::frame::Chan;
use labproto::httpauth::{self, NonceStore, H_AUTH, H_KEYID, H_NONCE, H_PROOF};
use labproto::json::JsonWriter;
use labproto::keys::Role;
use labproto::Status;

use crate::daemon::Daemon;
use crate::events::Event;
use crate::httpwire::*;
use crate::limits::Stats;
use crate::registry::{Content, Ctx, Reply, Sink, Source};

pub const MAX_WORKERS: usize = 16;
pub const MAX_SSE: usize = 4;
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_BODY: usize = 1 << 20;
pub const NONCE_TTL: Duration = Duration::from_secs(30);
pub const NONCE_CAP: usize = 256;
pub const FAIL_LIMIT: u32 = 20;
pub const FAIL_WINDOW: Duration = Duration::from_secs(60);
pub const FAIL_DELAY: Duration = Duration::from_millis(200);
pub const KEEPALIVE_MAX: usize = 100;
/// Collected output of a non-streaming command (exec, logs ...) is cut here: the handler is cancelled.
pub const COLLECT_MAX: usize = 8 << 20;
pub const SNAPSHOT_PERIOD: Duration = Duration::from_secs(2);

/// Routes (v1) for docs and the SPA.
pub const ROUTES: &[(&str, &str, &str)] = &[
    ("GET", "/", "SPA (open)"),
    ("GET", "/api/v1/hello", "identity (open)"),
    ("GET", "/api/v1/nonce", "single-use nonce, 30 s (open)"),
    ("POST", "/api/v1/cmd/<name>", "{\"args\":[..]} -> command result; ?stream=1 for sealed NDJSON"),
    ("GET", "/api/v1/probe/<section>", "inv --section <section>"),
    ("GET", "/api/v1/overview", "snapshot overview JSON"),
    ("GET", "/api/v1/events", "SSE: snapshot every 2 s, audit/job/link events"),
    ("GET", "/api/v1/file?path=P[&offset=N&len=N]", "raw download, proof as trailer"),
    ("PUT", "/api/v1/file?path=P[&mode=0644&mkdirs=1&offset=N]", "raw upload, X-Lab-Body-Sha256 required"),
    ("GET", "/api/v1/openapi.json", "generated from the catalogue (open)"),
];

/// Per-address failure tracking: 20 failures within a minute lock the address for 60 s.
#[derive(Default)]
pub struct FailTable {
    inner: HashMap<IpAddr, (u32, Instant)>,
}

impl FailTable {
    pub fn locked(&mut self, ip: IpAddr, now: Instant) -> bool {
        match self.inner.get(&ip) {
            Some((n, since)) if *n >= FAIL_LIMIT => {
                if now.duration_since(*since) < FAIL_WINDOW {
                    true
                } else {
                    self.inner.remove(&ip);
                    false
                }
            }
            _ => false,
        }
    }
    pub fn failed(&mut self, ip: IpAddr, now: Instant) {
        if self.inner.len() > 4096 {
            self.inner.retain(|_, (_, t)| now.duration_since(*t) < FAIL_WINDOW);
        }
        let e = self.inner.entry(ip).or_insert((0, now));
        if now.duration_since(e.1) > FAIL_WINDOW && e.0 < FAIL_LIMIT {
            *e = (0, now);
        }
        e.0 += 1;
        if e.0 == FAIL_LIMIT {
            e.1 = now; // the lock runs from the failure that tripped it
        }
    }
    pub fn ok(&mut self, ip: IpAddr) {
        if self.inner.get(&ip).is_some_and(|(n, _)| *n < FAIL_LIMIT) {
            self.inner.remove(&ip);
        }
    }
}

/// Shared server state.
pub struct HttpState {
    pub daemon: Arc<Daemon>,
    nonces: Mutex<NonceStore>,
    fails: Mutex<FailTable>,
    csp_nonce: String,
    active: AtomicUsize,
    sse: AtomicUsize,
}

impl HttpState {
    pub fn new(daemon: Arc<Daemon>) -> io::Result<HttpState> {
        let mut b = [0u8; 16];
        labproto::crypto::random_bytes(&mut b)?;
        Ok(HttpState {
            daemon,
            nonces: Mutex::new(NonceStore::new(NONCE_CAP, NONCE_TTL)),
            fails: Mutex::new(FailTable::default()),
            csp_nonce: hex(&b),
            active: AtomicUsize::new(0),
            sse: AtomicUsize::new(0),
        })
    }
}

/// A request that passed authentication.
pub struct Authed {
    pub role: Role,
    key: [u8; 32],
    pub fp: String,
    pub nonce: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    Missing,
    BadKey,
    BadNonce,
    BadMac,
    Locked,
}

fn hello_json(d: &Daemon) -> String {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_u64("v", 1);
    w.field_str("name", "i7labd");
    w.field_str("version", labproto::VERSION);
    w.field_str("build", &d.config.image_build);
    w.field_str("hostname", &d.config.hostname);
    w.field_str("boot_id", &hex(&d.boot_id));
    w.field_str("kid", &d.kid());
    w.field_u64("proto", labproto::frame::VERSION as u64);
    w.field_str("state", &d.state_str());
    w.field_u64("caps", labproto::catalog::caps_bits() as u64);
    w.end_object();
    w.finish()
}

impl HttpState {
    /// Check key id, single-use nonce and request MAC. `body_sha` is the digest the MAC covers (the real body
    /// hash for ordinary requests, the declared one for raw uploads).
    pub fn authenticate(&self, head: &Head, body_sha: &[u8; 32], peer: IpAddr) -> Result<Authed, AuthError> {
        let now = Instant::now();
        if self.fails.lock().unwrap().locked(peer, now) {
            return Err(AuthError::Locked);
        }
        let (Some(kid), Some(nonce), Some(auth)) = (head.header(&H_KEYID.to_ascii_lowercase()), head.header(&H_NONCE.to_ascii_lowercase()), head.header(&H_AUTH.to_ascii_lowercase())) else {
            return Err(self.fail(peer, AuthError::Missing));
        };
        let keyid: [u8; 4] = match unhex(kid).and_then(|v| v.try_into().ok()) {
            Some(k) => k,
            None => return Err(self.fail(peer, AuthError::BadKey)),
        };
        let key = {
            let ks = self.daemon.keys.read().unwrap();
            ks.by_id(&keyid).map(|k| (k.role, k.bytes, k.fingerprint()))
        };
        let Some((role, bytes, fp)) = key else { return Err(self.fail(peer, AuthError::BadKey)) };
        // the nonce is consumed whether or not the MAC is right: a captured request cannot be retried
        if !self.nonces.lock().unwrap().take(nonce, now) {
            return Err(self.fail(peer, AuthError::BadNonce));
        }
        let want = httpauth::request_mac_hashed(&bytes, nonce, &head.method, &head.target, body_sha);
        if !httpauth::check_hex_mac(&want, auth) {
            return Err(self.fail(peer, AuthError::BadMac));
        }
        self.fails.lock().unwrap().ok(peer);
        Ok(Authed { role, key: bytes, fp, nonce: nonce.to_string() })
    }

    fn fail(&self, peer: IpAddr, e: AuthError) -> AuthError {
        Stats::bump(&self.daemon.stats.http_auth_fail);
        self.fails.lock().unwrap().failed(peer, Instant::now());
        e
    }
}

// ------------------------------------------------------------------------------------------------ responses

type W = BufWriter<TcpStream>;

fn json_error(status: Status, msg: &str) -> Vec<u8> {
    Reply::error(status, msg).body
}

fn proof(a: &Authed, status: u16, body: &[u8]) -> (&'static str, String) {
    (H_PROOF, hex(&httpauth::response_mac(&a.key, &a.nonce, status, body)))
}

fn send_json(w: &mut W, status: u16, body: &[u8], auth: Option<&Authed>, keep: bool) -> io::Result<()> {
    let mut h = vec![("Content-Type", "application/json".to_string())];
    if let Some(a) = auth {
        h.push(proof(a, status, body));
    }
    write_response(w, status, &h, body, keep)
}

/// Unauthenticated failure answers (401/403/404/...): JSON error, no proof.
fn send_error(w: &mut W, status: u16, code: Status, msg: &str, keep: bool) -> io::Result<()> {
    send_json(w, status, &json_error(code, msg), None, keep)
}

fn reply_http_status(r: &Reply) -> u16 {
    r.status.http_status()
}

// ------------------------------------------------------------------------------------------------ sinks

/// Buffers output of a non-streaming call; refuses to grow past `COLLECT_MAX` (which cancels the handler).
#[derive(Default)]
struct Collect {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    file: Vec<u8>,
}

impl Collect {
    fn total(&self) -> usize {
        self.stdout.len() + self.stderr.len() + self.file.len()
    }
    fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

impl Sink for Collect {
    fn data(&mut self, chan: Chan, b: &[u8]) -> io::Result<()> {
        if self.total() + b.len() > COLLECT_MAX {
            return Err(io::Error::new(io::ErrorKind::Other, "output limit"));
        }
        match chan {
            Chan::Stderr => self.stderr.extend_from_slice(b),
            Chan::File => self.file.extend_from_slice(b),
            _ => self.stdout.extend_from_slice(b),
        }
        Ok(())
    }
    fn event(&mut self, _j: &str) -> io::Result<()> {
        Ok(()) // progress is only interesting to streaming callers
    }
    fn streaming(&self) -> bool {
        false
    }
}

fn text_or_b64(w: &mut JsonWriter, name: &str, b: &[u8]) {
    match std::str::from_utf8(b) {
        Ok(s) => w.field_str(name, s),
        Err(_) => w.field_str(&format!("{}_b64", name), &base64(b)),
    }
}

/// JSON of a finished non-streaming command: the reply body itself when nothing else was produced, otherwise an
/// envelope carrying exit/stdout/stderr/data.
fn envelope(r: &Reply, out: &Collect) -> Vec<u8> {
    if out.is_empty() && r.content == Content::Json {
        return r.body.clone();
    }
    if r.content == Content::Bytes && out.is_empty() {
        return r.body.clone();
    }
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_u64("v", 1);
    w.field_str("status", r.status.name());
    if r.content == Content::ExecResult && r.body.len() >= 4 {
        w.field_i64("exit", i32::from_be_bytes(r.body[..4].try_into().unwrap()) as i64);
        w.key("info");
        w.raw(std::str::from_utf8(&r.body[4..]).unwrap_or("{}"));
    } else if r.content == Content::Json {
        w.key("result");
        w.raw(std::str::from_utf8(&r.body).unwrap_or("null"));
    }
    if !out.stdout.is_empty() {
        text_or_b64(&mut w, "stdout", &out.stdout);
    }
    if !out.stderr.is_empty() {
        text_or_b64(&mut w, "stderr", &out.stderr);
    }
    if !out.file.is_empty() {
        w.field_str("data_b64", &base64(&out.file));
    }
    w.end_object();
    w.finish().into_bytes()
}

fn content_type(r: &Reply, out: &Collect) -> &'static str {
    if r.content == Content::Bytes && out.is_empty() {
        "application/octet-stream"
    } else {
        "application/json"
    }
}

/// Streams NDJSON: every event is sealed (`seq`, `mac`) and sent as one chunk.
pub struct NdjsonSink<Wr: Write + Send> {
    w: Wr,
    sealer: EventSealer,
    failed: bool,
}

impl<Wr: Write + Send> NdjsonSink<Wr> {
    pub fn new(w: Wr, key: [u8; 32], nonce: String) -> Self {
        NdjsonSink { w, sealer: EventSealer::new(key, nonce), failed: false }
    }

    fn line(&mut self, json: &str) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        let mut s = self.sealer.seal(json);
        s.push('\n');
        write_chunk(&mut self.w, s.as_bytes()).map_err(|e| {
            self.failed = true;
            e
        })
    }

    fn chan_event(&mut self, name: &str, b: &[u8]) -> io::Result<()> {
        let mut w = JsonWriter::new();
        w.begin_object();
        w.field_str("event", name);
        match std::str::from_utf8(b) {
            Ok(s) if name != "file" => w.field_str("data", s),
            _ => w.field_str("b64", &base64(b)),
        }
        w.end_object();
        self.line(&w.finish())
    }

    /// The closing `result` event and the last chunk. Shape (read by i7labctl and the SPA):
    /// `{"event":"result","ok":bool,"status":<u16 code>,"status_name":"IO",["exit":N,"info":{..},]
    ///   "data":<result json> | "error":{code,message[,reasons]}, "report":<alias of data, <= 64 KiB>}`
    pub fn finish(mut self, r: &Reply) -> io::Result<()> {
        let mut w = JsonWriter::new();
        w.begin_object();
        w.field_str("event", "result");
        w.field_bool("ok", r.status == Status::Ok);
        w.field_u64("status", r.status as u64);
        w.field_str("status_name", r.status.name());
        match r.content {
            Content::Json => {
                let text = std::str::from_utf8(&r.body).unwrap_or("null");
                if let Some(inner) = text.strip_prefix("{\"error\":").and_then(|t| t.strip_suffix('}')) {
                    w.key("error");
                    w.raw(inner);
                } else {
                    w.key("data");
                    w.raw(text);
                    if text.len() <= 64 * 1024 {
                        // alias read by the SPA's test-result view (`last.report`)
                        w.key("report");
                        w.raw(text);
                    }
                }
            }
            Content::ExecResult if r.body.len() >= 4 => {
                w.field_i64("exit", i32::from_be_bytes(r.body[..4].try_into().unwrap()) as i64);
                w.key("info");
                w.raw(std::str::from_utf8(&r.body[4..]).unwrap_or("{}"));
            }
            Content::Bytes => w.field_str("data_b64", &base64(&r.body)),
            _ => {}
        }
        w.end_object();
        self.line(&w.finish())?;
        write_last_chunk(&mut self.w, &[])
    }
}

impl<Wr: Write + Send> Sink for NdjsonSink<Wr> {
    fn data(&mut self, chan: Chan, b: &[u8]) -> io::Result<()> {
        let name = match chan {
            Chan::Stderr => "stderr",
            Chan::File => "file",
            _ => "stdout",
        };
        for piece in b.chunks(16 * 1024) {
            self.chan_event(name, piece)?;
        }
        Ok(())
    }
    fn event(&mut self, json: &str) -> io::Result<()> {
        self.line(json)
    }
}

/// Download sink: raw bytes as chunks with a running SHA-256; headers go out with the first byte so an error
/// before any data can still be a normal JSON error response.
struct FileSink {
    w: W,
    auth_key: [u8; 32],
    started: bool,
    hasher: Sha256,
    failed: bool,
}

impl Sink for FileSink {
    fn data(&mut self, _chan: Chan, b: &[u8]) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        let r = (|| {
            if !self.started {
                write_chunked_head(&mut self.w, 200, &[("Content-Type", "application/octet-stream".into()), ("Trailer", H_PROOF.into())])?;
                self.started = true;
            }
            self.hasher.update(b);
            write_chunk(&mut self.w, b)
        })();
        if r.is_err() {
            self.failed = true;
        }
        r
    }
    fn event(&mut self, _j: &str) -> io::Result<()> {
        Ok(())
    }
}

/// Upload source: a thread reads exactly `len` body bytes off the socket into the request's input channel.
fn feed_body(r: &mut BufReader<TcpStream>, len: u64, tx: &std::sync::mpsc::SyncSender<Vec<u8>>, done: &AtomicBool) -> bool {
    let mut left = len;
    let mut buf = vec![0u8; 64 * 1024];
    while left > 0 {
        let want = left.min(buf.len() as u64) as usize;
        match r.read(&mut buf[..want]) {
            Ok(0) => return false,
            Ok(n) => {
                left -= n as u64;
                let mut chunk = Some(buf[..n].to_vec());
                while let Some(c) = chunk.take() {
                    match tx.try_send(c) {
                        Ok(()) => {}
                        Err(std::sync::mpsc::TrySendError::Full(c)) => {
                            if done.load(Ordering::SeqCst) {
                                return false;
                            }
                            std::thread::sleep(Duration::from_millis(2));
                            chunk = Some(c);
                        }
                        Err(_) => return false,
                    }
                }
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                if done.load(Ordering::SeqCst) {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    true
}

// ------------------------------------------------------------------------------------------------ dispatch helper

/// Run `name args..` as the authenticated caller with `sink`.
fn run_cmd(st: &HttpState, peer: SocketAddr, a: &Authed, name: &str, args: Vec<String>, sink: &mut dyn Sink, cancel: Arc<AtomicBool>) -> Option<Reply> {
    let d = &st.daemon;
    let cmd = d.registry.get(name)?;
    let mut ctx = Ctx { daemon: d, source: Source::Http { peer }, role: a.role, actor: format!("http {}:{}", a.role.name(), a.fp), args, sink, cancel };
    Some(d.registry.dispatch(&mut ctx, cmd))
}

/// Minimal JSON reader for the one request shape the API takes, `{"args":["a","b"]}`: other keys are skipped,
/// nesting is bounded. (Independent of `labproto::json::parse`, which only serves bounded documents.)
struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn ws(&mut self) {
        while self.b.get(self.i).is_some_and(|c| c.is_ascii_whitespace()) {
            self.i += 1;
        }
    }
    fn eat(&mut self, c: u8) -> Option<()> {
        self.ws();
        (self.b.get(self.i) == Some(&c)).then(|| self.i += 1)
    }
    fn peek(&mut self) -> Option<u8> {
        self.ws();
        self.b.get(self.i).copied()
    }
    fn hex4(&mut self) -> Option<u32> {
        let h = std::str::from_utf8(self.b.get(self.i..self.i + 4)?).ok()?;
        self.i += 4;
        u32::from_str_radix(h, 16).ok()
    }
    fn string(&mut self) -> Option<String> {
        self.eat(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = *self.b.get(self.i)?;
            self.i += 1;
            match c {
                b'"' => return String::from_utf8(out).ok(),
                0..=0x1f => return None,
                b'\\' => {
                    let e = *self.b.get(self.i)?;
                    self.i += 1;
                    let ch = match e {
                        b'"' | b'\\' | b'/' => e as char,
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let mut u = self.hex4()?;
                            if (0xd800..0xdc00).contains(&u) {
                                if self.b.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return None;
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&lo) {
                                    return None;
                                }
                                u = 0x10000 + ((u - 0xd800) << 10) + (lo - 0xdc00);
                            }
                            char::from_u32(u)?
                        }
                        _ => return None,
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                c => out.push(c),
            }
        }
    }
    fn skip(&mut self, depth: u8) -> Option<()> {
        if depth > 8 {
            return None;
        }
        match self.peek()? {
            b'"' => self.string().map(|_| ()),
            b'{' => {
                self.i += 1;
                if self.peek()? == b'}' {
                    self.i += 1;
                    return Some(());
                }
                loop {
                    self.string()?;
                    self.eat(b':')?;
                    self.skip(depth + 1)?;
                    match self.peek()? {
                        b',' => self.i += 1,
                        b'}' => {
                            self.i += 1;
                            return Some(());
                        }
                        _ => return None,
                    }
                }
            }
            b'[' => {
                self.i += 1;
                if self.peek()? == b']' {
                    self.i += 1;
                    return Some(());
                }
                loop {
                    self.skip(depth + 1)?;
                    match self.peek()? {
                        b',' => self.i += 1,
                        b']' => {
                            self.i += 1;
                            return Some(());
                        }
                        _ => return None,
                    }
                }
            }
            _ => {
                // number, true, false, null
                let start = self.i;
                while self.b.get(self.i).is_some_and(|c| c.is_ascii_alphanumeric() || b"+-.".contains(c)) {
                    self.i += 1;
                }
                (self.i > start).then_some(())
            }
        }
    }
}

/// `{"args":["a","b"]}` (or an empty body) -> argv.
pub fn parse_cmd_body(body: &[u8]) -> Result<Vec<String>, &'static str> {
    if body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(vec![]);
    }
    let mut r = Reader { b: body, i: 0 };
    let bad = "body is not a JSON object like {\"args\":[..]}";
    r.eat(b'{').ok_or(bad)?;
    let mut args = Vec::new();
    if r.peek() == Some(b'}') {
        return Ok(args);
    }
    loop {
        let key = r.string().ok_or(bad)?;
        r.eat(b':').ok_or(bad)?;
        if key == "args" {
            r.eat(b'[').ok_or("args must be an array of strings")?;
            args.clear();
            if r.peek() == Some(b']') {
                r.i += 1;
            } else {
                loop {
                    args.push(r.string().ok_or("args must be an array of strings")?);
                    match r.peek() {
                        Some(b',') => r.i += 1,
                        Some(b']') => {
                            r.i += 1;
                            break;
                        }
                        _ => return Err(bad),
                    }
                }
            }
        } else {
            r.skip(0).ok_or(bad)?;
        }
        match r.peek() {
            Some(b',') => r.i += 1,
            Some(b'}') => {
                r.i += 1;
                break;
            }
            _ => return Err(bad),
        }
    }
    r.ws();
    if r.i != body.len() {
        return Err(bad);
    }
    if args.len() > 4096 || args.iter().any(|a| a.len() > 16 * 1024) {
        return Err("too many or too long arguments");
    }
    Ok(args)
}

/// OpenAPI-ish description generated from the catalogue.
pub fn openapi(d: &Daemon) -> String {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_str("openapi", "3.0.3");
    w.key("info");
    w.begin_object();
    w.field_str("title", "i7lablinux agent");
    w.field_str("version", labproto::VERSION);
    w.field_str("description", "Auth: X-Lab-Key / X-Lab-Nonce / X-Lab-Auth (HMAC, see docs/WEB.md). Arguments are argv word lists.");
    w.end_object();
    w.key("paths");
    w.begin_object();
    for c in CATALOG {
        w.key(&format!("/api/v1/cmd/{}", c.name));
        w.begin_object();
        w.key("post");
        w.begin_object();
        w.field_str("summary", c.summary);
        w.field_str("description", &format!("usage: {} {}", c.name, c.usage));
        w.field_str("x-access", match c.access { Access::Ro => "ro", Access::Admin => "admin", Access::RoLimitedPaths => "ro-limited-paths" });
        w.field_bool("x-streams", c.streams);
        w.field_bool("x-planned", c.planned());
        w.end_object();
        w.end_object();
    }
    w.end_object();
    w.field_str("x-build", &d.config.image_build);
    w.end_object();
    w.finish()
}

// ------------------------------------------------------------------------------------------------ routing

enum Next {
    KeepAlive,
    Close,
}

struct Conn {
    r: BufReader<TcpStream>,
    w: W,
    peer: SocketAddr,
}

/// GET alias routes -> (command, fixed argv prefix).
fn alias(name: &str) -> Option<(&'static str, &'static [&'static str])> {
    Some(match name {
        "inventory" => ("inv", &[]),
        "pcie" => ("pcie", &[]),
        "blk" => ("blk.ls", &[]),
        "usb" => ("usb", &[]),
        "net" => ("net.ls", &[]),
        "thermal" => ("thermal", &[]),
        "log" => ("logs", &[]),
        _ => return None,
    })
}

fn log_access(st: &HttpState, c: &Conn, head: &Head, status: u16, who: &str) {
    let path = labproto::text::sanitize(&head.path);
    st.daemon.http_log.push(format!("{} {} {} {} {}", c.peer.ip(), head.method, path, status, who));
}

fn handle_one(st: &Arc<HttpState>, c: &mut Conn, served: usize) -> Result<Next, HttpError> {
    let head = read_head(&mut c.r)?;
    Stats::bump(&st.daemon.stats.http_requests);
    let keep = !head.wants_close() && served + 1 < KEEPALIVE_MAX;
    let peer_ip = c.peer.ip();
    let path = head.path.trim_end_matches('/').to_string();
    let path = if path.is_empty() { "/".to_string() } else { path };

    // ---- open endpoints
    match (head.method.as_str(), path.as_str()) {
        ("GET" | "HEAD", "/") => {
            let html = crate::web::INDEX_HTML.replace(crate::web::NONCE_TOKEN, &st.csp_nonce);
            let csp = format!("default-src 'self'; script-src 'nonce-{}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'", st.csp_nonce);
            let body = if head.method == "HEAD" { &[][..] } else { html.as_bytes() };
            let etag = format!("\"{}\"", st.daemon.config.image_build);
            write_response(&mut c.w, 200, &[("Content-Type", "text/html; charset=utf-8".into()), ("Content-Security-Policy", csp), ("ETag", etag), ("X-Frame-Options", "DENY".into())], body, keep)?;
            log_access(st, c, &head, 200, "-");
            return Ok(if keep { Next::KeepAlive } else { Next::Close });
        }
        ("GET", "/api/v1/hello" | "/api/v1/health" | "/health") => {
            send_json(&mut c.w, 200, hello_json(&st.daemon).as_bytes(), None, keep)?;
            log_access(st, c, &head, 200, "-");
            return Ok(if keep { Next::KeepAlive } else { Next::Close });
        }
        ("GET", "/api/v1/openapi.json") => {
            // the command catalogue is public (it is in the source tree); the SPA links to it as a plain href
            send_json(&mut c.w, 200, openapi(&st.daemon).as_bytes(), None, keep)?;
            return Ok(if keep { Next::KeepAlive } else { Next::Close });
        }
        ("GET", "/api/v1/nonce" | "/nonce") => {
            let n = st.nonces.lock().unwrap().issue(Instant::now());
            let (code, body) = match n {
                Ok(n) => (200, format!("{{\"nonce\":\"{}\",\"ttl_s\":{}}}", n, NONCE_TTL.as_secs()).into_bytes()),
                Err(_) => (500, json_error(Status::Internal, "no randomness")),
            };
            send_json(&mut c.w, code, &body, None, keep)?;
            return Ok(if keep { Next::KeepAlive } else { Next::Close });
        }
        _ => {}
    }
    if !path.starts_with("/api/v1/") {
        send_error(&mut c.w, 404, Status::NotFound, "not found", keep)?;
        log_access(st, c, &head, 404, "-");
        return Ok(if keep { Next::KeepAlive } else { Next::Close });
    }
    let route = path["/api/v1/".len()..].to_string();

    // ---- raw file upload: authenticated against the DECLARED body digest before any byte is read
    if head.method == "PUT" && route == "file" {
        return put_file(st, c, &head);
    }

    // ---- ordinary signed requests: body (bounded) first, then the MAC over its hash
    let body = match head.content_length {
        Some(n) => read_body(&mut c.r, n, MAX_BODY)?,
        None => Vec::new(),
    };
    let sha = labproto::crypto::sha256(&body);
    let auth = match st.authenticate(&head, &sha, peer_ip) {
        Ok(a) => a,
        Err(e) => return auth_failed(st, c, &head, e),
    };
    let who = format!("{}:{}", auth.role.name(), auth.fp);
    let mut status_logged = 200;

    let result = (|| -> io::Result<Next> {
        match (head.method.as_str(), route.as_str()) {
            ("GET", "overview") => {
                let snap = st.daemon.snapshot.get();
                let body = if snap.overview_json.is_empty() { b"{\"v\":1,\"pending\":true}".to_vec() } else { snap.overview_json.clone().into_bytes() };
                send_json(&mut c.w, 200, &body, Some(&auth), keep)?;
            }
            ("GET", "events") => {
                sse(st, c, &auth)?;
                return Ok(Next::Close);
            }
            ("GET", "file") => return get_file(st, c, &head, &auth),
            ("GET", "probe") => {
                let mut w = JsonWriter::new();
                w.begin_object();
                w.field_u64("v", 1);
                w.key("sections");
                w.begin_array();
                for s in labprobe::Section::ALL {
                    w.str(s.name());
                }
                w.end_array();
                w.end_object();
                send_json(&mut c.w, 200, w.finish().as_bytes(), Some(&auth), keep)?;
            }
            ("GET", r) if r.starts_with("probe/") => {
                let section = &r["probe/".len()..];
                let args = vec!["--section".to_string(), section.to_string()];
                return simple_cmd(st, c, &auth, "inv", args, keep, &mut status_logged);
            }
            ("GET", r) if alias(r).is_some() => {
                let (cmd, _) = alias(r).unwrap();
                let args: Vec<String> = head.q_all("a").into_iter().map(str::to_string).collect();
                return simple_cmd(st, c, &auth, cmd, args, keep, &mut status_logged);
            }
            ("POST", r) if r.starts_with("cmd/") => {
                let name = r["cmd/".len()..].to_string();
                let args = match parse_cmd_body(&body) {
                    Ok(a) => a,
                    Err(m) => {
                        status_logged = 400;
                        send_json(&mut c.w, 400, &json_error(Status::BadArgs, m), Some(&auth), keep)?;
                        return Ok(if keep { Next::KeepAlive } else { Next::Close });
                    }
                };
                if head.q("stream") == Some("1") {
                    return stream_cmd(st, c, &auth, &name, args);
                }
                return simple_cmd(st, c, &auth, &name, args, keep, &mut status_logged);
            }
            ("POST", "exec") => {
                let args = match parse_cmd_body(&body) {
                    Ok(a) => a,
                    Err(m) => {
                        status_logged = 400;
                        send_json(&mut c.w, 400, &json_error(Status::BadArgs, m), Some(&auth), keep)?;
                        return Ok(if keep { Next::KeepAlive } else { Next::Close });
                    }
                };
                return simple_cmd(st, c, &auth, "exec", args, keep, &mut status_logged);
            }
            _ => {
                status_logged = 404;
                send_json(&mut c.w, 404, &json_error(Status::NotFound, "no such route"), Some(&auth), keep)?;
            }
        }
        Ok(if keep { Next::KeepAlive } else { Next::Close })
    })();
    log_access(st, c, &head, status_logged, &who);
    result.map_err(HttpError::from)
}

fn auth_failed(st: &Arc<HttpState>, c: &mut Conn, head: &Head, e: AuthError) -> Result<Next, HttpError> {
    let (code, status, msg) = match e {
        AuthError::Locked => (429, Status::Busy, "too many failed attempts: address locked for 60 s"),
        AuthError::Missing => (401, Status::Eperm, "authentication required (X-Lab-Key, X-Lab-Nonce, X-Lab-Auth)"),
        AuthError::BadKey => (401, Status::Eperm, "unknown key id"),
        AuthError::BadNonce => (401, Status::Eperm, "nonce unknown, expired or already used"),
        AuthError::BadMac => (401, Status::Eperm, "bad request signature"),
    };
    if e != AuthError::Locked {
        std::thread::sleep(FAIL_DELAY); // constant delay on every failure
    }
    send_error(&mut c.w, code, status, msg, false)?;
    log_access(st, c, head, code, "unauth");
    Ok(Next::Close)
}

fn simple_cmd(st: &Arc<HttpState>, c: &mut Conn, a: &Authed, name: &str, args: Vec<String>, keep: bool, logged: &mut u16) -> io::Result<Next> {
    let mut out = Collect::default();
    let cancel = Arc::new(AtomicBool::new(false));
    let Some(reply) = run_cmd(st, c.peer, a, name, args, &mut out, cancel) else {
        *logged = 404;
        send_json(&mut c.w, 404, &json_error(Status::NotFound, "no such command"), Some(a), keep)?;
        return Ok(if keep { Next::KeepAlive } else { Next::Close });
    };
    let code = reply_http_status(&reply);
    *logged = code;
    let body = envelope(&reply, &out);
    let h = vec![("Content-Type", content_type(&reply, &out).to_string()), proof(a, code, &body)];
    write_response(&mut c.w, code, &h, &body, keep)?;
    Ok(if keep { Next::KeepAlive } else { Next::Close })
}

fn stream_cmd(st: &Arc<HttpState>, c: &mut Conn, a: &Authed, name: &str, args: Vec<String>) -> io::Result<Next> {
    if st.daemon.registry.get(name).is_none() {
        send_json(&mut c.w, 404, &json_error(Status::NotFound, "no such command"), Some(a), false)?;
        return Ok(Next::Close);
    }
    write_chunked_head(&mut c.w, 200, &[("Content-Type", "application/x-ndjson".into()), ("X-Lab-Stream", "1".into())])?;
    // the sink owns its own writer (a clone of the socket); the BufWriter is flushed first so ordering holds
    c.w.flush()?;
    let sock = c.w.get_ref().try_clone()?;
    let mut sink = NdjsonSink::new(BufWriter::new(sock), a.key, a.nonce.clone());
    let cancel = Arc::new(AtomicBool::new(false));
    let reply = run_cmd(st, c.peer, a, name, args, &mut sink, cancel).unwrap_or_else(|| Reply::error(Status::NotFound, "no such command"));
    st.daemon.http_log.push(format!("{} stream {} -> {}", c.peer.ip(), name, reply.status.name()));
    let _ = sink.finish(&reply);
    Ok(Next::Close)
}

fn sse(st: &Arc<HttpState>, c: &mut Conn, a: &Authed) -> io::Result<()> {
    if st.sse.fetch_add(1, Ordering::SeqCst) >= MAX_SSE {
        st.sse.fetch_sub(1, Ordering::SeqCst);
        return send_json(&mut c.w, 503, &json_error(Status::Busy, "too many event streams"), Some(a), false);
    }
    let r = sse_loop(st, c, a);
    st.sse.fetch_sub(1, Ordering::SeqCst);
    r
}

fn sse_loop(st: &Arc<HttpState>, c: &mut Conn, a: &Authed) -> io::Result<()> {
    c.w.get_ref().set_write_timeout(Some(Duration::from_secs(10)))?;
    write!(c.w, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nX-Lab-Stream: 1\r\n\r\n")?;
    c.w.flush()?;
    let rx = st.daemon.events.subscribe();
    let mut sealer = EventSealer::new(a.key, a.nonce.clone());
    let mut next_snapshot = Instant::now();
    loop {
        if Instant::now() >= next_snapshot {
            let snap = st.daemon.snapshot.get();
            let mut w = JsonWriter::new();
            w.begin_object();
            w.field_str("event", "snapshot");
            w.field_u64("taken_ms", snap.taken_ms);
            w.field_str("state", &st.daemon.state_str());
            w.key("attention");
            w.value(&snap.attention);
            w.key("links");
            w.begin_array();
            for (n, m, ips) in &snap.links {
                w.begin_object();
                w.field_str("name", n);
                w.field_str("mac", m);
                w.key("ipv4");
                w.value(ips);
                w.end_object();
            }
            w.end_array();
            w.key("sessions");
            w.value(&snap.sessions);
            w.key("stats");
            w.raw(if snap.stats_json.is_empty() { "null" } else { &snap.stats_json });
            w.key("overview");
            w.raw(if snap.overview_json.is_empty() { "null" } else { &snap.overview_json });
            w.end_object();
            write!(c.w, "event: snapshot\ndata: {}\n\n", sealer.seal(&w.finish()))?;
            c.w.flush()?;
            next_snapshot = Instant::now() + SNAPSHOT_PERIOD;
        }
        let wait = next_snapshot.saturating_duration_since(Instant::now()).min(Duration::from_millis(500));
        match rx.recv_timeout(wait) {
            Ok(ev) => {
                let (name, mut w) = (event_name(&ev), JsonWriter::new());
                w.begin_object();
                w.field_str("event", name);
                match &ev {
                    Event::Audit(l) => w.field_str("line", l),
                    Event::Job { id, json } => {
                        w.field_u64("id", *id as u64);
                        w.key("job");
                        w.raw(json);
                    }
                    Event::Msg(t) => w.field_str("text", t),
                    Event::TuiTab(t) => w.field_opt_str("tab", t.as_deref()),
                    Event::Identify(d) => w.field_u64("seconds", d.as_secs()),
                    Event::Link(n) => w.field_str("iface", n),
                }
                w.end_object();
                write!(c.w, "event: {}\ndata: {}\n\n", name, sealer.seal(&w.finish()))?;
                c.w.flush()?;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // comment keep-alive also detects a dead client through the write
                if next_snapshot > Instant::now() + Duration::from_millis(1500) {
                    write!(c.w, ": ping\n\n")?;
                    c.w.flush()?;
                }
            }
            Err(_) => return Ok(()),
        }
    }
}

fn event_name(e: &Event) -> &'static str {
    match e {
        Event::Audit(_) => "audit",
        Event::Job { .. } => "job",
        Event::Msg(_) => "msg",
        Event::TuiTab(_) => "tui",
        Event::Identify(_) => "identify",
        Event::Link(_) => "link",
    }
}

fn get_file(st: &Arc<HttpState>, c: &mut Conn, head: &Head, a: &Authed) -> io::Result<Next> {
    let Some(path) = head.q("path") else {
        send_json(&mut c.w, 400, &json_error(Status::BadArgs, "path is required"), Some(a), false)?;
        return Ok(Next::Close);
    };
    let mut args = vec![path.to_string()];
    for k in ["offset", "len"] {
        if let Some(v) = head.q(k) {
            args.push(format!("--{}", k));
            args.push(v.to_string());
        }
    }
    let sock = c.w.get_ref().try_clone()?;
    let mut sink = FileSink { w: BufWriter::new(sock), auth_key: a.key, started: false, hasher: Sha256::new(), failed: false };
    let cancel = Arc::new(AtomicBool::new(false));
    let reply = run_cmd(st, c.peer, a, "get", args, &mut sink, cancel).unwrap_or_else(|| Reply::error(Status::Internal, "get missing"));
    let key = sink.auth_key;
    if sink.started {
        if reply.status == Status::Ok && !sink.failed {
            let digest = sink.hasher.finish();
            let p = hex(&httpauth::response_mac_hashed(&key, &a.nonce, 200, &digest));
            let _ = write_last_chunk(&mut sink.w, &[(H_PROOF, p)]);
        } // else: the connection is cut without the terminating chunk, the client sees a truncated body
        return Ok(Next::Close);
    }
    drop(sink);
    if reply.status == Status::Ok {
        // empty file: a well-formed empty body with its proof
        let h = vec![("Content-Type", "application/octet-stream".to_string()), proof(a, 200, b"")];
        write_response(&mut c.w, 200, &h, b"", false)?;
    } else {
        send_json(&mut c.w, reply_http_status(&reply), &reply.body, Some(a), false)?;
    }
    Ok(Next::Close)
}

fn put_file(st: &Arc<HttpState>, c: &mut Conn, head: &Head) -> Result<Next, HttpError> {
    let peer_ip = c.peer.ip();
    let declared = head.header("x-lab-body-sha256").or(head.header("x-sha256")).and_then(unhex).and_then(|v| <[u8; 32]>::try_from(v).ok());
    let (Some(len), Some(sha)) = (head.content_length, declared) else {
        send_error(&mut c.w, 400, Status::BadArgs, "PUT file needs Content-Length and X-Lab-Body-Sha256", false)?;
        return Ok(Next::Close);
    };
    let auth = match st.authenticate(head, &sha, peer_ip) {
        Ok(a) => a,
        Err(e) => return auth_failed(st, c, head, e),
    };
    let Some(path) = head.q("path") else {
        send_json(&mut c.w, 400, &json_error(Status::BadArgs, "path is required"), Some(&auth), false)?;
        return Ok(Next::Close);
    };
    let offset: u64 = head.q("offset").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut args = vec![path.to_string(), "--size".into(), (offset + len).to_string(), "--sha256".into(), hex(&sha)];
    if offset > 0 {
        args.push("--offset".into());
        args.push(offset.to_string());
    }
    if let Some(m) = head.q("mode") {
        args.push("--mode".into());
        args.push(m.to_string());
    }
    if head.q("mkdirs") == Some("1") {
        args.push("--mkdirs".into());
    }
    let (tx, rx) = sync_channel::<Vec<u8>>(64);
    struct UpSink(Option<std::sync::mpsc::Receiver<Vec<u8>>>);
    impl Sink for UpSink {
        fn data(&mut self, _c: Chan, _b: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn event(&mut self, _j: &str) -> io::Result<()> {
            Ok(())
        }
        fn input(&mut self) -> Option<std::sync::mpsc::Receiver<Vec<u8>>> {
            self.0.take()
        }
    }
    let mut sink = UpSink(Some(rx));
    let done = AtomicBool::new(false);
    let cancel = Arc::new(AtomicBool::new(false));
    let reader = &mut c.r;
    let done_ref = &done;
    let (reply, body_ok) = std::thread::scope(|s| {
        // the feeder owns `tx`: when it ends (body done or socket dead) the handler sees end-of-input
        let feeder = s.spawn(move || feed_body(reader, len, &tx, done_ref));
        let reply = run_cmd(st, c.peer, &auth, "put", args, &mut sink, cancel.clone()).unwrap_or_else(|| Reply::error(Status::Internal, "put missing"));
        done.store(true, Ordering::SeqCst);
        drop(sink.0.take());
        (reply, feeder.join().unwrap_or(false))
    });
    let code = reply_http_status(&reply);
    log_access(st, c, head, code, &format!("{}:{}", auth.role.name(), auth.fp));
    send_json(&mut c.w, code, &reply.body, Some(&auth), false)?;
    let _ = body_ok; // an unread rest of the body is why the connection closes
    Ok(Next::Close)
}

fn serve_conn(st: Arc<HttpState>, stream: TcpStream, peer: SocketAddr) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_nodelay(true);
    let Ok(w) = stream.try_clone() else { return };
    let mut c = Conn { r: BufReader::new(stream), w: BufWriter::new(w), peer };
    let mut served = 0;
    loop {
        match handle_one(&st, &mut c, served) {
            Ok(Next::KeepAlive) => {
                served += 1;
                // wait for the next request without logging an idle close
                if c.r.fill_buf().map(|b| b.is_empty()).unwrap_or(true) {
                    return;
                }
            }
            Ok(Next::Close) => return,
            Err(HttpError::Closed) | Err(HttpError::Io(_)) => return,
            Err(e) => {
                let (code, msg) = e.status();
                Stats::bump(&st.daemon.stats.http_rejected);
                let _ = send_error(&mut c.w, code, Status::BadArgs, msg, false);
                return;
            }
        }
    }
}

/// Bind address from `i7lab.http_bind=` (None = every IPv4 address; an IPv4 literal; or an interface name).
pub fn resolve_bind(bind: &Option<String>, ops: &dyn crate::netcfg::NetOps) -> io::Result<Ipv4Addr> {
    let Some(b) = bind else { return Ok(Ipv4Addr::UNSPECIFIED) };
    if let Ok(ip) = b.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    let idx = crate::netcfg::ifindex_of(b)?;
    crate::netcfg::current_addrs(ops, idx)
        .first()
        .map(|(a, _)| Ipv4Addr::from(*a))
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, format!("interface {} has no IPv4 address yet", b)))
}

/// Accept loop on an existing listener until `stop`.
pub fn serve_listener(daemon: Arc<Daemon>, listener: TcpListener, stop: Arc<AtomicBool>) -> io::Result<()> {
    let st = Arc::new(HttpState::new(daemon)?);
    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let _ = stream.set_nonblocking(false);
                if st.active.fetch_add(1, Ordering::SeqCst) >= MAX_WORKERS {
                    st.active.fetch_sub(1, Ordering::SeqCst);
                    Stats::bump(&st.daemon.stats.http_rejected);
                    let mut w = BufWriter::new(stream);
                    let _ = send_error(&mut w, 503, Status::Busy, "too many connections", false);
                    continue;
                }
                let st2 = st.clone();
                std::thread::spawn(move || {
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| serve_conn(st2.clone(), stream, peer)));
                    let _ = r;
                    st2.active.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(10)),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Serve forever on `port` (the duty body).
pub fn serve(daemon: Arc<Daemon>, port: u16) -> io::Result<()> {
    let ip = resolve_bind(&daemon.config.http_bind, &*daemon.netops)?;
    let l = TcpListener::bind(SocketAddr::new(IpAddr::V4(ip), port))?;
    let actual = l.local_addr()?.port();
    daemon.flags.set_http(Some(actual));
    daemon.log(&format!("http listening on {}:{}", ip, actual));
    let r = serve_listener(daemon.clone(), l, Arc::new(AtomicBool::new(false)));
    daemon.flags.set_http(None);
    r
}

#[cfg(test)]
mod tests;
