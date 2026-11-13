//! Daemon state and the duty threads. Owner: P6a.

use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use labproto::keys::KeySet;

use crate::audit::Audit;
use crate::beacon::Identity;
use crate::config::Config;
use crate::events::{EventBus, Snapshots};
use crate::jobs::Jobs;
use crate::limits::{Limits, Stats};
use crate::logring::LogRing;
use crate::netcfg::NetState;
use crate::registry::Registry;

/// Live state shown by beacon, TUI and `id`.
#[derive(Clone, Debug, Default)]
pub struct HostState {
    /// "booting" | "ready" | "busy" | "degraded" | "shutdown"
    pub state: String,
    pub console_message: Option<String>,
    pub tui_tab: Option<String>,
}

/// Which services are up (beacon keys `ctl` and `http`, `svc ... status`).
#[derive(Default)]
pub struct Flags {
    ether: AtomicUsize,
    http: AtomicU16,
}

impl Flags {
    pub fn ether_up(&self) -> bool {
        self.ether.load(Ordering::SeqCst) > 0
    }
    /// Number of NIC loops currently serving.
    pub fn set_ether(&self, n: usize) {
        self.ether.store(n, Ordering::SeqCst);
    }
    pub fn http_port(&self) -> Option<u16> {
        match self.http.load(Ordering::SeqCst) {
            0 => None,
            p => Some(p),
        }
    }
    pub fn set_http(&self, port: Option<u16>) {
        self.http.store(port.unwrap_or(0), Ordering::SeqCst);
    }
}

pub struct Daemon {
    pub registry: Registry,
    pub keys: RwLock<KeySet>,
    pub config: Config,
    pub boot_id: [u8; 8],
    pub audit: Audit,
    pub jobs: Jobs,
    pub state: RwLock<HostState>,
    pub snapshot: Snapshots,
    pub events: EventBus,
    // additions inside the agent (P6a/P6b/P7)
    pub limits: Limits,
    pub stats: Stats,
    pub flags: Flags,
    pub ident: Identity,
    /// probe context with the boot media identity resolved ONCE at start (PLAN D4); every handler uses it
    pub probe: labprobe::ProbeCtx,
    pub logs: LogRing,
    pub http_log: LogRing,
    pub net: NetState,
    /// kernel network operations (rtnetlink); replaced by a mock in tests
    pub netops: Arc<dyn crate::netcfg::NetOps>,
    pub sessions_open: AtomicUsize,
}

impl Daemon {
    pub fn new(config: Config) -> std::io::Result<Daemon> {
        let keys = KeySet::load_dir(&config.key_dir).unwrap_or_default();
        let mut boot_id = [0u8; 8];
        labproto::crypto::random_bytes(&mut boot_id)?;
        let mut probe = labprobe::ProbeCtx::live();
        if let Some(pu) = &config.boot_partuuid {
            probe.boot_partuuid = Some(pu.clone());
            probe.boot_disk = labprobe::block::resolve_boot_disk(&probe, pu);
        }
        Ok(Daemon {
            snapshot: Snapshots::default(),
            events: EventBus::default(),
            registry: Registry::standard(),
            keys: RwLock::new(keys),
            audit: Audit::new(&config.audit_log),
            jobs: Jobs::default(),
            state: RwLock::new(HostState { state: "booting".into(), ..Default::default() }),
            limits: Limits::default(),
            stats: Stats::default(),
            flags: Flags::default(),
            ident: Identity::load(),
            probe,
            logs: LogRing::new(1000),
            http_log: LogRing::new(1000),
            net: NetState::default(),
            netops: Arc::new(crate::netcfg::Netlink),
            sessions_open: AtomicUsize::new(0),
            boot_id,
            config,
        })
    }

    /// `a:<8hex>,r:<8hex>` as in beacon key `kid` (`-` for a missing key).
    pub fn kid(&self) -> String {
        let k = self.keys.read().unwrap();
        let fp = |o: &Option<labproto::keys::Key>| o.as_ref().map(|k| k.fingerprint()).unwrap_or_else(|| "-".into());
        format!("a:{},r:{}", fp(&k.admin), fp(&k.ro))
    }

    pub fn key_summary(&self) -> String {
        self.kid().replace(',', " ")
    }

    pub fn state_str(&self) -> String {
        let s = self.state.read().unwrap().state.clone();
        if s == "ready" && self.limits.busy() {
            "busy".into()
        } else {
            s
        }
    }

    pub fn set_state(&self, s: &str) {
        self.state.write().unwrap().state = s.to_string();
    }

    /// Daemon log line: stderr (init captures it into /run/i7lab/init.log) and the `logs --daemon` ring.
    pub fn log(&self, msg: &str) {
        let line = format!("[{:>8.3}] {}", labproto::sys::uptime_ms() as f64 / 1000.0, labproto::text::sanitize(msg));
        eprintln!("i7labd: {}", line);
        self.logs.push(line);
    }
}

/// Run `f` forever with panic isolation and 1 s -> 30 s backoff; a clean `Ok`/`Unsupported` return ends the duty.
fn supervise(daemon: Arc<Daemon>, name: &'static str, f: fn(Arc<Daemon>) -> std::io::Result<()>) {
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let mut backoff = std::time::Duration::from_secs(1);
            loop {
                let d = daemon.clone();
                let started = std::time::Instant::now();
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(d))) {
                    Ok(Ok(())) => {
                        daemon.log(&format!("duty {} finished", name));
                        return;
                    }
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::Unsupported => {
                        daemon.log(&format!("duty {} not available in this build: {}", name, e));
                        return;
                    }
                    Ok(Err(e)) => daemon.log(&format!("duty {} failed: {}", name, e)),
                    Err(_) => daemon.log(&format!("duty {} panicked", name)),
                }
                if started.elapsed() > std::time::Duration::from_secs(60) {
                    backoff = std::time::Duration::from_secs(1);
                }
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(std::time::Duration::from_secs(30));
            }
        })
        .expect("spawn duty thread");
}

/// Start every duty (net config + DHCP, snapshot, ether server + beacon, http, local socket, console TUI) and
/// supervise them. Never returns.
pub fn run(daemon: Arc<Daemon>) -> ! {
    let _ = std::fs::create_dir_all(&daemon.config.run_dir);
    let _ = std::fs::write(daemon.config.run_dir.join("i7labd.pid"), std::process::id().to_string());
    daemon.log(&format!("i7labd {} build {} starting; keys {}", labproto::VERSION, daemon.config.image_build, daemon.key_summary()));
    supervise(daemon.clone(), "snapshot", crate::snapshot::run);
    supervise(daemon.clone(), "net", crate::netcfg::run);
    supervise(daemon.clone(), "ether", crate::ether::run);
    supervise(daemon.clone(), "http", |d| {
        let ports = d.config.http_ports();
        if ports.is_empty() {
            Ok(())
        } else {
            crate::http::serve_ports(d, &ports)
        }
    });
    supervise(daemon.clone(), "localsock", crate::localsock::serve);
    if daemon.config.tui && daemon.config.console != crate::config::ConsoleMode::Off {
        supervise(daemon.clone(), "console", |d| crate::console::run(d, "/dev/tty1"));
        if let Some(tty) = daemon.config.serial_tty.clone() {
            // second console on the serial line (`i7lab.serial=ttyS0`); same UI, own thread
            let d = daemon.clone();
            std::thread::Builder::new()
                .name("console-serial".into())
                .spawn(move || {
                    if let Err(e) = crate::console::run(d.clone(), &tty) {
                        d.log(&format!("serial console {} ended: {}", tty, e));
                    }
                })
                .expect("spawn serial console thread");
        }
    }
    daemon.set_state("ready");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kid_and_state() {
        let d = crate::registry::tests_support::test_daemon();
        assert_eq!(d.kid(), "a:-,r:-");
        d.set_state("ready");
        assert_eq!(d.state_str(), "ready");
        let _g = d.limits.blk_write.try_acquire().unwrap();
        assert_eq!(d.state_str(), "busy");
        d.set_state("shutdown");
        assert_eq!(d.state_str(), "shutdown");
        d.flags.set_http(Some(8080));
        assert_eq!(d.flags.http_port(), Some(8080));
    }
}
