//! Start-up wiring shared by service, console and agent modes.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::evlog::json_str;
use crate::keys::KeySet;
use crate::state::{Mode, Shared, GLOBAL};

#[derive(Default, Clone)]
pub struct Overrides {
    pub root: Option<PathBuf>,
    pub data: Option<PathBuf>,
    pub port: Option<u16>,
    pub collector: Option<String>,
}

impl Overrides {
    pub fn default_for_service() -> Overrides {
        Overrides::default()
    }
}

/// Config (defaults, config.json, flags) and keys, then the shared state. Missing keys are not fatal:
/// the daemon runs, records, and answers /health, but every authenticated route is 401 until keys are installed.
pub fn build(mode: Mode, ov: &Overrides) -> Result<Arc<Shared>, String> {
    let mut cfg = Config::defaults();
    if ov.root.is_some() || ov.data.is_some() {
        let d = Config::defaults();
        cfg = Config::with_dirs(ov.root.clone().unwrap_or(d.oracle_dir), ov.data.clone().unwrap_or(d.data_dir));
    }
    let cfg_path = cfg.config_path();
    let loaded = cfg.load_file(&cfg_path)?;
    if let Some(p) = ov.port {
        cfg.port = p;
    }
    if let Some(c) = &ov.collector {
        cfg.collector = Some(crate::config::normalise_collector(c)?);
    }
    let keys = KeySet::load_dir(&cfg.keys_dir)?;
    let sh = Shared::new(cfg, keys, mode)?;
    let _ = loaded;
    Ok(Arc::new(sh))
}

pub fn start(sh: &Arc<Shared>) {
    let _ = GLOBAL.set(sh.clone());
    let cfg = &sh.cfg;
    for d in [cfg.probes_dir(), cfg.results_dir()] {
        let _ = std::fs::create_dir_all(d);
    }
    sh.emit(
        &format!("{}", sh.mode.name()),
        "start",
        &format!(
            "{{\"version\":{},\"mode\":{},\"boot\":{},\"host\":{},\"os\":{},\"pid\":{},\"api_port\":{},\"keys\":{},\"keys_missing\":{},\"collector\":{},\"info\":{}}}",
            json_str(env!("CARGO_PKG_VERSION")),
            json_str(sh.mode.name()),
            json_str(&sh.boot_id),
            json_str(&crate::plat::hostname()),
            json_str(&crate::plat::os_short()),
            std::process::id(),
            cfg.port,
            json_str(&sh.keys.kid_summary()),
            sh.keys.is_empty(),
            cfg.collector.as_deref().map(json_str).unwrap_or_else(|| "null".into()),
            crate::plat::info_json()
        ),
    );
    if sh.keys.is_empty() {
        eprintln!("i7oracled: no keys in {} (admin.key / ro.key): authenticated API routes will refuse everything", cfg.keys_dir.display());
    }
    crate::plat::start_recorders(sh);
    if sh.mode == Mode::Agent {
        return;
    }
    spawn("api", sh, serve_api);
    spawn("beacon", sh, crate::beacon::run);
    spawn("agent-listener", sh, agent_listener);
    spawn("first-boot", sh, |s| crate::jobs::first_boot(&s));
    spawn("prev-shutdown", sh, |s| previous_shutdown(&s));
}

fn spawn<F: FnOnce(Arc<Shared>) + Send + 'static>(name: &str, sh: &Arc<Shared>, f: F) {
    let s = sh.clone();
    let _ = std::thread::Builder::new().name(name.into()).spawn(move || f(s));
}

fn serve_api(sh: Arc<Shared>) {
    let addr = format!("{}:{}", sh.cfg.bind, sh.cfg.port);
    match TcpListener::bind(&addr) {
        Ok(l) => {
            sh.emit("daemon", "api_listening", &format!("{{\"addr\":{}}}", json_str(&addr)));
            crate::httpd::serve(l, sh.clone(), crate::api::handle);
        }
        Err(e) => {
            eprintln!("i7oracled: cannot listen on {}: {}", addr, e);
            sh.emit("daemon", "error", &format!("{{\"what\":\"api bind\",\"addr\":{},\"error\":{}}}", json_str(&addr), json_str(&e.to_string())));
        }
    }
}

/// Loopback TCP port where the interactive agent sends complete record bodies, one JSON object per line.
fn agent_listener(sh: Arc<Shared>) {
    let l = match TcpListener::bind(("127.0.0.1", sh.cfg.agent_port)) {
        Ok(l) => l,
        Err(e) => {
            sh.emit("daemon", "error", &format!("{{\"what\":\"agent listener bind\",\"error\":{}}}", json_str(&e.to_string())));
            return;
        }
    };
    let _ = l.set_nonblocking(true);
    while !sh.stop.load(Ordering::SeqCst) {
        match l.accept() {
            Ok((s, _)) => {
                let _ = s.set_nonblocking(false);
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                for line in BufReader::new(s.take(4 << 20)).lines() {
                    let Ok(line) = line else { break };
                    if accept_agent_line(&sh, &line) {
                        continue;
                    }
                }
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

use std::io::Read;

/// Only well-formed one-line records that claim an agent source are appended (the sequence number is ours).
pub fn accept_agent_line(sh: &Shared, line: &str) -> bool {
    let ok = line.starts_with("{\"src\":\"agent-") && line.len() < 64 << 10 && crate::json::parse(line, &crate::json::Limits::default()).is_ok();
    if ok {
        sh.emit_body(line);
    }
    ok
}

fn previous_shutdown(sh: &Arc<Shared>) {
    if !cfg!(windows) {
        return;
    }
    let args: Vec<String> = ["qe", "System", &format!("/q:{}", crate::evtparse::QUERY), "/c:30", "/rd:true", "/f:text"].iter().map(|s| s.to_string()).collect();
    let r = crate::exec::exec_capture("wevtutil.exe", &args, None, Duration::from_secs(60), 1 << 20);
    let text = crate::exec::lossy(&r.stdout);
    let ev = crate::evtparse::parse(&text);
    sh.emit("daemon", "previous_shutdown", &crate::evtparse::summary_json(&ev, &text));
}

/// Foreground run: prints where it listens, runs until Ctrl-C (Windows console) or a kill.
pub fn run_console(mode: Mode, ov: &Overrides) -> Result<(), String> {
    let sh = build(mode, ov)?;
    start(&sh);
    eprintln!("i7oracled {} ({} mode) api http://{}:{}/ events {}", env!("CARGO_PKG_VERSION"), mode.name(), sh.cfg.bind, sh.cfg.port, sh.cfg.events_path().display());
    while !sh.stop.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(500));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_lines_are_filtered() {
        let d = std::env::temp_dir().join(format!("i7oracled-agent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let cfg = Config::with_dirs(d.join("o"), d.join("d"));
        let sh = Shared::new(cfg, KeySet::default(), Mode::Console).unwrap();
        let st = crate::stamp::Stamp::now();
        let good = crate::evlog::record("agent-win", "pbt", &st, "{}");
        assert!(accept_agent_line(&sh, &good));
        assert!(!accept_agent_line(&sh, "{\"src\":\"evil\"}"));
        assert!(!accept_agent_line(&sh, "{\"src\":\"agent-x\",broken"));
        assert!(!accept_agent_line(&sh, "garbage"));
        assert_eq!(sh.last_seq(), 1);
    }
}
