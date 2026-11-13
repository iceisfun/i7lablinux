//! Web terminal: a PTY running i7labsh, driven over plain signed HTTP (no WebSocket).
//!
//!   POST /api/v1/shell/open[?cols=N&rows=N]  -> {"v":1,"id":"<32 hex>"}
//!   GET  /api/v1/shell/<id>/out              -> sealed SSE: {"event":"out","b64":..} ... {"event":"exit",..}
//!   POST /api/v1/shell/<id>/in               -> keystrokes: base64 text body, or raw bytes with
//!                                               Content-Type: application/octet-stream
//!   POST /api/v1/shell/<id>/resize?cols=&rows=  (or JSON body {"cols":N,"rows":N})
//!   POST /api/v1/shell/<id>/close
//!
//! Every request is signed like all others (the MAC covers method + target incl. query + body hash); every
//! response carries the proof and every out event carries seq + mac. Admin key only. Limits: `MAX_SHELLS`
//! concurrent sessions, `IDLE_MS` without input, a session whose out stream never attaches is dropped after
//! `UNATTACHED_MS`, a closed out stream closes the session, buffered output is capped at `OUT_CAP` (the child
//! blocks on the pty when the browser is slow: backpressure, never loss), one input request at most `IN_MAX`.
//! Open and close are audited (`shell.open`, `shell.close`).

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

use super::*;

pub const MAX_SHELLS: usize = 2;
pub const IDLE_MS: u64 = 10 * 60 * 1000;
pub const UNATTACHED_MS: u64 = 60 * 1000;
pub const OUT_CAP: usize = 256 * 1024;
pub const IN_MAX: usize = 64 * 1024;
const OUT_CHUNK: usize = 8 * 1024;
const PING_EVERY: Duration = Duration::from_secs(1);

/// Monotonic milliseconds; injectable so tests can age sessions without sleeping.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

pub struct SysClock(Instant);
impl SysClock {
    pub fn new() -> SysClock {
        SysClock(Instant::now())
    }
}
impl Clock for SysClock {
    fn now_ms(&self) -> u64 {
        self.0.elapsed().as_millis() as u64
    }
}

/// What the daemon wires in; tests replace the clock and the program.
#[derive(Clone)]
pub struct ShellCfg {
    pub clock: Arc<dyn Clock>,
    /// replaces the in-image shell (tests); None = `exec::SHELL`
    pub argv: Option<Vec<String>>,
    pub max: usize,
    pub idle_ms: u64,
}

impl Default for ShellCfg {
    fn default() -> Self {
        ShellCfg { clock: Arc::new(SysClock::new()), argv: None, max: MAX_SHELLS, idle_ms: IDLE_MS }
    }
}

/// One audit-worthy moment: (command, session, detail, status).
pub type AuditHook = Arc<dyn Fn(&'static str, &Session, &str, Status) + Send + Sync>;

#[derive(Default)]
struct OutBuf {
    data: VecDeque<u8>,
    /// pty master hit EOF/EIO
    eof: bool,
}

pub struct Session {
    pub id: String,
    pub peer: SocketAddr,
    pub actor: String,
    pid: i32,
    master: Mutex<File>,
    out: Mutex<OutBuf>,
    cv: Condvar,
    opened_ms: u64,
    last_in_ms: AtomicU64,
    attached: AtomicBool,
    exited: Mutex<Option<(i32, Instant)>>,
    closed: Mutex<Option<&'static str>>,
    audited: AtomicBool,
}

impl Session {
    pub fn buffered(&self) -> usize {
        self.out.lock().unwrap().data.len()
    }
    pub fn close_reason(&self) -> Option<&'static str> {
        *self.closed.lock().unwrap()
    }
    fn is_exited(&self) -> bool {
        self.exited.lock().unwrap().is_some()
    }
    fn touch(&self, now: u64) {
        self.last_in_ms.store(now, Ordering::SeqCst);
    }

    pub fn write_input(&self, now: u64, bytes: &[u8]) -> io::Result<()> {
        if self.close_reason().is_some() {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        self.touch(now);
        let mut m = self.master.lock().unwrap();
        m.write_all(bytes)?;
        m.flush()
    }

    pub fn resize(&self, now: u64, cols: u16, rows: u16) -> io::Result<()> {
        self.touch(now);
        crate::ffi::set_winsize(self.master.lock().unwrap().as_raw_fd(), cols, rows)
    }
}

pub struct ShellTable {
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    cfg: ShellCfg,
    hook: AuditHook,
    me: Mutex<Weak<ShellTable>>,
}

#[derive(Debug)]
pub enum OpenError {
    Busy,
    Start(io::Error),
}

pub fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn valid_dims(cols: u32, rows: u32) -> Option<(u16, u16)> {
    (1..=1000).contains(&cols).then_some(()).and((1..=1000).contains(&rows).then_some(())).map(|_| (cols as u16, rows as u16))
}

/// Standard base64, padding optional, ASCII whitespace ignored. None on any other byte.
pub fn unbase64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    let mut pad = false;
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                pad = true;
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        if pad {
            return None;
        }
        acc = acc << 6 | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (bits < 6).then_some(out)
}

impl ShellTable {
    pub fn new(cfg: ShellCfg, hook: AuditHook) -> Arc<ShellTable> {
        let t = Arc::new(ShellTable { sessions: Mutex::new(HashMap::new()), cfg, hook, me: Mutex::new(Weak::new()) });
        *t.me.lock().unwrap() = Arc::downgrade(&t);
        t
    }

    pub fn clock(&self) -> u64 {
        self.cfg.clock.now_ms()
    }
    pub fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
    pub fn get(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions.lock().unwrap().get(id).cloned()
    }

    pub fn open(&self, cols: u16, rows: u16, peer: SocketAddr, actor: &str) -> Result<Arc<Session>, OpenError> {
        self.reap();
        let mut map = self.sessions.lock().unwrap();
        if map.len() >= self.cfg.max {
            return Err(OpenError::Busy);
        }
        let (mut spec, _) = crate::exec::parse_shell_args(&["--cols".to_string(), cols.to_string(), "--rows".to_string(), rows.to_string()]).map_err(|e| OpenError::Start(io::Error::new(io::ErrorKind::InvalidInput, e)))?;
        if let Some(a) = &self.cfg.argv {
            spec.argv = a.clone();
        }
        let (child, master) = crate::exec::spawn_tty(crate::exec::build_command(&spec), cols, rows).map_err(OpenError::Start)?;
        let mut idb = [0u8; 16];
        labproto::crypto::random_bytes(&mut idb).map_err(OpenError::Start)?;
        let now = self.clock();
        let reader = master.try_clone().map_err(OpenError::Start)?;
        let s = Arc::new(Session {
            id: hex(&idb),
            peer,
            actor: actor.to_string(),
            pid: child.id() as i32,
            master: Mutex::new(master),
            out: Mutex::new(OutBuf::default()),
            cv: Condvar::new(),
            opened_ms: now,
            last_in_ms: AtomicU64::new(now),
            attached: AtomicBool::new(false),
            exited: Mutex::new(None),
            closed: Mutex::new(None),
            audited: AtomicBool::new(false),
        });
        map.insert(s.id.clone(), s.clone());
        drop(map);
        spawn_reader(s.clone(), reader);
        spawn_waiter(s.clone(), child, self.me.lock().unwrap().clone());
        (self.hook)("shell.open", &s, &format!("{}x{}", cols, rows), Status::Ok);
        Ok(s)
    }

    /// Close once (first reason wins): SIGTERM now, SIGKILL after 2 s, slot freed, audited.
    pub fn close(&self, s: &Arc<Session>, reason: &'static str) -> bool {
        {
            let mut c = s.closed.lock().unwrap();
            if c.is_some() {
                return false;
            }
            *c = Some(reason);
        }
        self.sessions.lock().unwrap().remove(&s.id);
        if !s.is_exited() {
            let _ = crate::ffi::killpg(s.pid, 15);
            let s2 = s.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(2));
                if !s2.is_exited() {
                    let _ = crate::ffi::killpg(s2.pid, crate::ffi::SIGKILL);
                }
            });
        }
        s.cv.notify_all();
        if !s.audited.swap(true, Ordering::SeqCst) {
            (self.hook)("shell.close", s, reason, Status::Ok);
        }
        true
    }

    /// Is this session past its idle or attach deadline? Closes it when so.
    pub fn check(&self, s: &Arc<Session>) {
        let now = self.clock();
        if now.saturating_sub(s.last_in_ms.load(Ordering::SeqCst)) > self.cfg.idle_ms {
            self.close(s, "idle");
        } else if !s.attached.load(Ordering::SeqCst) && now.saturating_sub(s.opened_ms) > UNATTACHED_MS {
            self.close(s, "unattached");
        }
    }

    pub fn reap(&self) {
        let all: Vec<Arc<Session>> = self.sessions.lock().unwrap().values().cloned().collect();
        for s in all {
            self.check(&s);
        }
    }

    pub fn close_all(&self, reason: &'static str) {
        let all: Vec<Arc<Session>> = self.sessions.lock().unwrap().values().cloned().collect();
        for s in all {
            self.close(&s, reason);
        }
    }
}

impl Drop for ShellTable {
    fn drop(&mut self) {
        let all: Vec<Arc<Session>> = self.sessions.lock().unwrap().values().cloned().collect();
        for s in all {
            *s.closed.lock().unwrap() = Some("shutdown");
            if !s.is_exited() {
                let _ = crate::ffi::killpg(s.pid, crate::ffi::SIGKILL);
            }
            s.cv.notify_all();
        }
    }
}

/// Background reaper for idle / unattached sessions; ends when the table is gone.
pub fn spawn_reaper(t: &Arc<ShellTable>) {
    let w = Arc::downgrade(t);
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(500));
        match w.upgrade() {
            Some(t) => t.reap(),
            None => return,
        }
    });
}

fn spawn_reader(s: Arc<Session>, mut master: File) {
    std::thread::spawn(move || {
        let mut buf = vec![0u8; OUT_CHUNK];
        loop {
            let n = match master.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break, // EIO when the slave side is gone
            };
            let mut o = s.out.lock().unwrap();
            // backpressure: wait for room (never drop, never grow past the cap)
            while o.data.len() + n > OUT_CAP && s.close_reason().is_none() {
                o = s.cv.wait_timeout(o, Duration::from_millis(200)).unwrap().0;
            }
            if s.close_reason().is_some() {
                break;
            }
            o.data.extend(&buf[..n]);
            drop(o);
            s.cv.notify_all();
        }
        s.out.lock().unwrap().eof = true;
        s.cv.notify_all();
    });
}

fn spawn_waiter(s: Arc<Session>, mut child: std::process::Child, table: Weak<ShellTable>) {
    std::thread::spawn(move || {
        let code = match child.wait() {
            Ok(st) => std::os::unix::process::ExitStatusExt::signal(&st).map(|x| 128 + x).or(st.code()).unwrap_or(-1),
            Err(_) => -1,
        };
        *s.exited.lock().unwrap() = Some((code, Instant::now()));
        // the slot is free as soon as the shell is gone; the out stream still drains what is buffered
        // (so the session is NOT marked closed here, only audited)
        if let Some(t) = table.upgrade() {
            t.sessions.lock().unwrap().remove(&s.id);
            if !s.audited.swap(true, Ordering::SeqCst) {
                (t.hook)("shell.close", &s, &format!("exit {}", code), Status::Ok);
            }
        }
        s.cv.notify_all();
    });
}

/// Embedded xterm.js assets: (content type, body) by file name.
pub fn vendor(name: &str) -> Option<(&'static str, &'static str)> {
    Some(match name {
        "xterm.js" => ("text/javascript; charset=utf-8", XTERM_JS),
        "addon-fit.js" => ("text/javascript; charset=utf-8", FIT_JS),
        "xterm.css" => ("text/css; charset=utf-8", XTERM_CSS),
        _ => return None,
    })
}
const XTERM_JS: &str = include_str!("../../web/vendor/xterm.js");
const FIT_JS: &str = include_str!("../../web/vendor/addon-fit.js");
const XTERM_CSS: &str = include_str!("../../web/vendor/xterm.css");

// ------------------------------------------------------------------------------------------------ routes

fn reject(c: &mut Conn, a: &Authed, status: Status, msg: &str, logged: &mut u16) -> io::Result<Next> {
    let code = status.http_status();
    *logged = code;
    send_json(&mut c.w, code, &json_error(status, msg), Some(a), false)?;
    Ok(Next::Close)
}

fn ok_json(c: &mut Conn, a: &Authed, body: String, keep: bool) -> io::Result<Next> {
    send_json(&mut c.w, 200, body.as_bytes(), Some(a), keep)?;
    Ok(if keep { Next::KeepAlive } else { Next::Close })
}

fn dims(head: &Head, body: &[u8]) -> Result<(u16, u16), &'static str> {
    let (mut cols, mut rows) = (head.q("cols").and_then(|v| v.parse::<u32>().ok()), head.q("rows").and_then(|v| v.parse::<u32>().ok()));
    if cols.is_none() && rows.is_none() && !body.iter().all(|b| b.is_ascii_whitespace()) {
        if let Ok(txt) = std::str::from_utf8(body) {
            if let Ok(v) = labproto::json::parse(txt, &labproto::json::Limits::default()) {
                cols = v.get("cols").and_then(|x| x.as_u64()).map(|x| x.min(u32::MAX as u64) as u32);
                rows = v.get("rows").and_then(|x| x.as_u64()).map(|x| x.min(u32::MAX as u64) as u32);
            }
        }
    }
    valid_dims(cols.unwrap_or(80), rows.unwrap_or(24)).ok_or("cols and rows must be 1..1000")
}

/// Dispatch of `shell/...` routes (already authenticated).
pub fn route(st: &Arc<HttpState>, c: &mut Conn, head: &Head, a: &Authed, body: &[u8], route: &str, keep: bool, logged: &mut u16) -> io::Result<Next> {
    let parts: Vec<&str> = route.split('/').collect();
    let (id, action) = match (head.method.as_str(), parts.as_slice()) {
        ("POST", ["shell", "open"]) => ("", "open"),
        ("GET", ["shell", id, "out"]) => (*id, "out"),
        ("POST", ["shell", id, act @ ("in" | "resize" | "close")]) => (*id, *act),
        _ => return reject(c, a, Status::NotFound, "no such route", logged),
    };
    let t = &st.shells;
    if a.role != Role::Admin {
        // audited as a refusal: somebody tried the terminal with the read-only key
        let (n, actor) = (&st.daemon, format!("http {}:{}", a.role.name(), a.fp));
        let line = n.audit.record(&Source::Http { peer: c.peer }, &actor, "shell.open", &[format!("denied:{}", action)], Status::Eperm);
        n.events.publish(Event::Audit(line));
        return reject(c, a, Status::Eperm, "the terminal needs the admin key", logged);
    }
    if action == "open" {
        let (cols, rows) = match dims(head, body) {
            Ok(d) => d,
            Err(m) => return reject(c, a, Status::BadArgs, m, logged),
        };
        let actor = format!("http {}:{}", a.role.name(), a.fp);
        return match t.open(cols, rows, c.peer, &actor) {
            Ok(s) => ok_json(c, a, format!("{{\"v\":1,\"id\":\"{}\",\"idle_s\":{},\"max\":{}}}", s.id, t.cfg.idle_ms / 1000, t.cfg.max), keep),
            Err(OpenError::Busy) => {
                let line = st.daemon.audit.record(&Source::Http { peer: c.peer }, &actor, "shell.open", &["busy".to_string()], Status::Busy);
                st.daemon.events.publish(Event::Audit(line));
                reject(c, a, Status::Busy, "too many open shells", logged)
            }
            Err(OpenError::Start(e)) => {
                let (st2, msg) = match e.kind() {
                    io::ErrorKind::NotFound => (Status::NotFound, "cannot start the shell (not found)".to_string()),
                    _ => (Status::Io, format!("cannot start the shell: {}", e)),
                };
                let line = st.daemon.audit.record(&Source::Http { peer: c.peer }, &actor, "shell.open", &["start-failed".to_string()], st2);
                st.daemon.events.publish(Event::Audit(line));
                reject(c, a, st2, &msg, logged)
            }
        };
    }
    if !valid_id(id) {
        return reject(c, a, Status::NotFound, "no such shell", logged);
    }
    let Some(s) = t.get(id).filter(|s| s.close_reason().is_none()) else {
        // a shell that exited is still readable by its attached out stream; everything else is gone
        return reject(c, a, Status::NotFound, "no such shell", logged);
    };
    match action {
        "out" => out_stream(st, c, a, &s, logged),
        "in" => {
            if body.len() > IN_MAX * 4 / 3 + 4 {
                return reject(c, a, Status::TooBig, "input chunk too large", logged);
            }
            let raw = head.header("content-type").is_some_and(|v| v.starts_with("application/octet-stream"));
            let bytes = if raw {
                body.to_vec()
            } else {
                match std::str::from_utf8(body).ok().and_then(unbase64) {
                    Some(b) => b,
                    None => return reject(c, a, Status::BadArgs, "body is not base64", logged),
                }
            };
            if bytes.len() > IN_MAX {
                return reject(c, a, Status::TooBig, "input chunk too large", logged);
            }
            match s.write_input(t.clock(), &bytes) {
                Ok(()) => ok_json(c, a, format!("{{\"v\":1,\"n\":{}}}", bytes.len()), keep),
                Err(_) => reject(c, a, Status::Io, "shell input closed", logged),
            }
        }
        "resize" => match dims(head, body) {
            Ok((cols, rows)) => match s.resize(t.clock(), cols, rows) {
                Ok(()) => ok_json(c, a, "{\"v\":1}".into(), keep),
                Err(e) => reject(c, a, Status::Io, &format!("resize failed: {}", e), logged),
            },
            Err(m) => reject(c, a, Status::BadArgs, m, logged),
        },
        _ => {
            t.close(&s, "closed");
            ok_json(c, a, "{\"v\":1}".into(), keep)
        }
    }
}

fn event(sealer: &mut EventSealer, w: &mut W, name: &str, fill: impl FnOnce(&mut JsonWriter)) -> io::Result<()> {
    let mut j = JsonWriter::new();
    j.begin_object();
    j.field_str("event", name);
    fill(&mut j);
    j.end_object();
    write!(w, "event: {}\ndata: {}\n\n", name, sealer.seal(&j.finish()))?;
    w.flush()
}

fn out_stream(st: &Arc<HttpState>, c: &mut Conn, a: &Authed, s: &Arc<Session>, logged: &mut u16) -> io::Result<Next> {
    if s.attached.swap(true, Ordering::SeqCst) {
        return reject(c, a, Status::Busy, "this shell already has an output stream", logged);
    }
    let t = st.shells.clone();
    c.w.get_ref().set_write_timeout(Some(Duration::from_secs(10)))?;
    let r = out_loop(&t, c, a, s);
    // whatever ended the stream, the session ends with it
    t.close(s, if r.is_err() { "disconnect" } else { "closed" });
    Ok(Next::Close)
}

fn out_loop(t: &Arc<ShellTable>, c: &mut Conn, a: &Authed, s: &Arc<Session>) -> io::Result<()> {
    write!(c.w, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nX-Lab-Stream: 1\r\n\r\n")?;
    c.w.flush()?;
    let mut sealer = EventSealer::new(a.key, a.nonce.clone());
    let mut last_write = Instant::now();
    loop {
        let (chunk, finished) = {
            let mut o = s.out.lock().unwrap();
            if o.data.is_empty() && !o.eof && s.close_reason().is_none() {
                o = s.cv.wait_timeout(o, Duration::from_millis(300)).unwrap().0;
            }
            let n = o.data.len().min(OUT_CHUNK);
            let chunk: Vec<u8> = o.data.drain(..n).collect();
            let gone = s.exited.lock().unwrap().is_some_and(|(_, at)| at.elapsed() > Duration::from_millis(400));
            let finished = s.close_reason().is_some() || (o.data.is_empty() && (o.eof || gone));
            (chunk, finished)
        };
        if !chunk.is_empty() {
            s.cv.notify_all(); // room for the reader
            event(&mut sealer, &mut c.w, "out", |j| j.field_str("b64", &base64(&chunk)))?;
            last_write = Instant::now();
        }
        t.check(s);
        if finished || s.close_reason().is_some() {
            break;
        }
        if chunk.is_empty() && last_write.elapsed() >= PING_EVERY {
            write!(c.w, ": ping\n\n")?;
            c.w.flush()?;
            last_write = Instant::now();
        }
    }
    // the pty may hit EOF a moment before the waiter thread has the exit status
    if s.close_reason().is_none() {
        for _ in 0..40 {
            if s.is_exited() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    let code = s.exited.lock().unwrap().map(|(c, _)| c);
    let reason = s.close_reason().unwrap_or("exit");
    event(&mut sealer, &mut c.w, "exit", |j| {
        j.field_str("reason", reason);
        match code {
            Some(x) => j.field_i64("code", x as i64),
            None => {
                j.key("code");
                j.null();
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decoder() {
        assert_eq!(unbase64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(unbase64("aGVsbG8").unwrap(), b"hello");
        assert_eq!(unbase64(" aGVs\nbG8= ").unwrap(), b"hello");
        assert_eq!(unbase64("").unwrap(), b"");
        assert!(unbase64("a$b=").is_none());
        assert!(unbase64("aG=VsbG8").is_none(), "data after padding");
        assert!(unbase64("a").is_none(), "dangling sextet");
        for n in 0..20usize {
            let data: Vec<u8> = (0..n as u8).map(|i| i.wrapping_mul(37)).collect();
            assert_eq!(unbase64(&base64(&data)).unwrap(), data);
        }
    }

    #[test]
    fn vendored_files_match_the_recorded_hashes() {
        let readme = include_str!("../../web/vendor/README.md");
        for (name, body) in [("xterm.js", XTERM_JS), ("addon-fit.js", FIT_JS), ("xterm.css", XTERM_CSS)] {
            let h = hex(&labproto::crypto::sha256(body.as_bytes()));
            assert!(readme.contains(&h), "{} sha256 {} is not recorded in web/vendor/README.md", name, h);
            assert!(vendor(name).is_some());
        }
        assert!(vendor("../index.html").is_none());
    }

    #[test]
    fn ids_and_dims() {
        assert!(valid_id(&"a1".repeat(16)));
        assert!(!valid_id("../etc"));
        assert!(!valid_id(&"A1".repeat(16)));
        assert_eq!(valid_dims(80, 24), Some((80, 24)));
        assert_eq!(valid_dims(0, 24), None);
        assert_eq!(valid_dims(80, 1001), None);
    }
}
