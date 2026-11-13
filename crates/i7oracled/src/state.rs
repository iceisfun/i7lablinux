//! Shared daemon state and the single entry point for recording events.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use crate::auth::{self, AuthGuard};
use crate::config::Config;
use crate::evlog::{self, EventLog};
use crate::httpauth::NonceStore;
use crate::keys::KeySet;
use crate::stamp::Stamp;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Windows service (session 0, LocalSystem): API, beacon, recorder (service control handler + hidden window).
    Service,
    /// Everything in the foreground (testing, or the logon task that gives probes a real desktop).
    Console,
    /// Interactive-session recorder only: forwards window events to the service on loopback.
    Agent,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::Service => "service",
            Mode::Console => "console",
            Mode::Agent => "agent",
        }
    }
}

pub enum Sink {
    /// This process owns the durable log.
    Log(Mutex<EventLog>),
    /// Agent: records go to the service over loopback; unsent ones are spooled to a file and replayed.
    Forward { addr: SocketAddr, spool: std::path::PathBuf, lock: Mutex<()> },
}

#[derive(Default)]
pub struct Counters {
    pub suspends: AtomicU64,
    pub resumes: AtomicU64,
    pub events: AtomicU64,
    pub runs: AtomicU64,
}

pub struct Shared {
    pub cfg: Config,
    pub keys: KeySet,
    pub sink: Sink,
    pub nonces: Mutex<NonceStore>,
    pub guard: Mutex<AuthGuard>,
    pub stop: AtomicBool,
    pub started: Instant,
    pub boot_id: String,
    pub mode: Mode,
    pub counters: Counters,
    pub last_stamp: Mutex<Option<Stamp>>,
}

/// The one instance the C callbacks (window procedure, service handler, power callback) reach.
pub static GLOBAL: OnceLock<Arc<Shared>> = OnceLock::new();

pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Shared {
    pub fn new(cfg: Config, keys: KeySet, mode: Mode) -> Result<Shared, String> {
        let sink = match mode {
            Mode::Agent => Sink::Forward {
                addr: SocketAddr::from(([127, 0, 0, 1], cfg.agent_port)),
                spool: cfg.spool_path(),
                lock: Mutex::new(()),
            },
            _ => Sink::Log(Mutex::new(EventLog::open(&cfg.events_path()).map_err(|e| format!("{}: {}", cfg.events_path().display(), e))?)),
        };
        let mut b = [0u8; 8];
        crate::crypto::random_bytes(&mut b).map_err(|e| e.to_string())?;
        Ok(Shared {
            cfg,
            keys,
            sink,
            nonces: Mutex::new(auth::new_nonces()),
            guard: Mutex::new(AuthGuard::default()),
            stop: AtomicBool::new(false),
            started: Instant::now(),
            boot_id: crate::crypto::hex(&b),
            mode,
            counters: Counters::default(),
            last_stamp: Mutex::new(None),
        })
    }

    pub fn last_seq(&self) -> u64 {
        match &self.sink {
            Sink::Log(l) => lock(l).last_seq(),
            Sink::Forward { .. } => 0,
        }
    }

    /// Record one event now. `data_json` must be one valid JSON value. Returns the seq (0 when forwarded).
    pub fn emit(&self, src: &str, kind: &str, data_json: &str) -> u64 {
        self.emit_at(src, kind, &Stamp::now(), data_json)
    }

    pub fn emit_at(&self, src: &str, kind: &str, stamp: &Stamp, data_json: &str) -> u64 {
        self.counters.events.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let body = evlog::record(src, kind, stamp, data_json);
        self.emit_body(&body)
    }

    /// `body` is a complete record object without seq (what `evlog::record` produces).
    pub fn emit_body(&self, body: &str) -> u64 {
        match &self.sink {
            Sink::Log(l) => match lock(l).append(body) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("i7oracled: event log write failed: {}", e);
                    0
                }
            },
            Sink::Forward { addr, spool, lock: lk } => {
                let _g = lock(lk);
                forward(*addr, spool, body);
                0
            }
        }
    }
}

/// Agent side: replay the spool, then send this record; on any failure append it to the spool.
fn forward(addr: SocketAddr, spool: &std::path::Path, body: &str) {
    let mut pending = std::fs::read_to_string(spool).unwrap_or_default();
    pending.push_str(body);
    pending.push('\n');
    let sent = TcpStream::connect_timeout(&addr, Duration::from_millis(500)).and_then(|mut s| {
        s.set_write_timeout(Some(Duration::from_secs(2)))?;
        s.write_all(pending.as_bytes())?;
        s.flush()
    });
    match sent {
        Ok(()) => {
            let _ = std::fs::remove_file(spool);
        }
        Err(_) => {
            if let Some(p) = spool.parent() {
                let _ = std::fs::create_dir_all(p);
            }
            let _ = std::fs::write(spool, pending);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn agent_forward_and_spool() {
        let dir = std::env::temp_dir().join(format!("i7oracled-fwd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let spool = dir.join("spool.jsonl");
        // nobody listening: spooled
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = dead.local_addr().unwrap();
        drop(dead);
        forward(addr, &spool, "{\"a\":1}");
        forward(addr, &spool, "{\"a\":2}");
        assert_eq!(std::fs::read_to_string(&spool).unwrap(), "{\"a\":1}\n{\"a\":2}\n");
        // listener appears: spool is replayed in order, then removed
        let l = std::net::TcpListener::bind(addr).unwrap();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut v = String::new();
            s.read_to_string(&mut v).unwrap();
            v
        });
        forward(addr, &spool, "{\"a\":3}");
        assert_eq!(t.join().unwrap(), "{\"a\":1}\n{\"a\":2}\n{\"a\":3}\n");
        assert!(!spool.exists());
    }
}
