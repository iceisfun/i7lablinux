//! Probe runs and the first-boot sweep.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::evlog::json_str;
use crate::exec::{self, ExecResult};
use crate::json::JsonWriter;
use crate::stamp::{filetime_compact, Stamp};
use crate::state::Shared;

pub struct Outcome {
    pub name: String,
    pub args: Vec<String>,
    pub started_utc: String,
    pub saved_as: Option<String>,
    pub res: ExecResult,
}

impl Outcome {
    pub fn json(&self, include_output: bool) -> String {
        let mut w = JsonWriter::new();
        w.begin_object();
        w.field_bool("ok", self.res.spawn_error.is_none());
        w.field_str("name", &self.name);
        w.key("args");
        w.begin_array();
        for a in &self.args {
            w.str(a);
        }
        w.end_array();
        w.field_str("started_utc", &self.started_utc);
        match self.res.exit {
            Some(c) => w.field_i64("exit_code", c as i64),
            None => w.field_opt_u64("exit_code", None),
        }
        w.field_bool("timed_out", self.res.timed_out);
        w.field_u64("duration_ms", self.res.duration_ms);
        w.field_bool("truncated", self.res.truncated);
        w.field_opt_str("spawn_error", self.res.spawn_error.as_deref());
        w.field_opt_str("saved_as", self.saved_as.as_deref());
        if include_output {
            w.field_str("stdout", &exec::lossy(&self.res.stdout));
            w.field_str("stderr", &exec::lossy(&self.res.stderr));
        }
        w.end_object();
        w.finish()
    }

    /// One short line for the sweep summary.
    pub fn line(&self) -> String {
        match (&self.res.spawn_error, self.res.timed_out, self.res.exit) {
            (Some(e), _, _) => format!("{} spawn-error({})", self.name, e),
            (_, true, _) => format!("{} TIMEOUT {}ms", self.name, self.res.duration_ms),
            (_, _, Some(c)) => format!("{} exit={} {}ms", self.name, c, self.res.duration_ms),
            _ => format!("{} killed {}ms", self.name, self.res.duration_ms),
        }
    }
}

pub fn run_probe(sh: &Shared, src: &str, name: &str, args: &[String], timeout: Duration) -> Result<Outcome, String> {
    if !exec::valid_probe_name(name) {
        return Err("bad probe name (plain file name in the probes directory, .exe/.bat/.cmd/.ps1)".into());
    }
    if args.len() > 64 || args.iter().any(|a| a.len() > 2048 || a.contains('\0')) {
        return Err("too many or too long arguments".into());
    }
    let dir = sh.cfg.probes_dir();
    let path = dir.join(name);
    if !path.is_file() {
        return Err(format!("no such probe: {}", name));
    }
    let started = Stamp::now();
    let started_utc = crate::stamp::filetime_to_utc(started.wall_100ns);
    sh.counters.runs.fetch_add(1, Ordering::Relaxed);
    sh.emit_at(src, "run_start", &started, &format!("{{\"name\":{},\"timeout_s\":{}}}", json_str(name), timeout.as_secs()));
    let (prog, argv) = exec::command_for(&path, args);
    let res = exec::exec_capture(&prog, &argv, Some(&dir), timeout, exec::OUT_CAP);
    let header = format!(
        "# i7oracled result\nname: {}\nargs: {}\nstarted_utc: {}\nexit_code: {}\ntimed_out: {}\nduration_ms: {}\ntruncated: {}\nspawn_error: {}\n",
        name,
        args.join(" "),
        started_utc,
        res.exit.map(|c| c.to_string()).unwrap_or_else(|| "none".into()),
        res.timed_out,
        res.duration_ms,
        res.truncated,
        res.spawn_error.as_deref().unwrap_or("none")
    );
    let saved_as = exec::save_result(&sh.cfg.results_dir(), &filetime_compact(started.wall_100ns), name, &header, &res.stdout, &res.stderr).ok();
    let out = Outcome { name: name.to_string(), args: args.to_vec(), started_utc, saved_as, res };
    sh.emit(src, "run_end", &out.json(false));
    Ok(out)
}

/// Run every *.exe in the probes directory in sorted order. Returns the summary JSON.
pub fn sweep(sh: &Shared, reason: &str, timeout: Duration) -> String {
    let names = exec::list_probes(&sh.cfg.probes_dir(), true);
    sh.emit("sweep", "sweep_start", &format!("{{\"reason\":{},\"count\":{}}}", json_str(reason), names.len()));
    let t0 = Instant::now();
    let (mut ok, mut failed, mut timed_out) = (0u32, 0u32, 0u32);
    let mut lines = Vec::new();
    for n in &names {
        if sh.stop.load(Ordering::SeqCst) {
            break;
        }
        match run_probe(sh, "sweep", n, &[], timeout) {
            Ok(o) => {
                if o.res.timed_out {
                    timed_out += 1;
                } else if o.res.exit == Some(0) {
                    ok += 1;
                } else {
                    failed += 1;
                }
                lines.push(o.line());
            }
            Err(e) => {
                failed += 1;
                lines.push(format!("{} error({})", n, e));
            }
        }
    }
    let line = format!("{} probes: {} ok, {} failed, {} timeout in {}s", names.len(), ok, failed, timed_out, t0.elapsed().as_secs());
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_str("host", &crate::plat::hostname());
    w.field_str("reason", reason);
    w.field_str("summary", &line);
    w.field_u64("probes", names.len() as u64);
    w.field_u64("ok", ok as u64);
    w.field_u64("failed", failed as u64);
    w.field_u64("timed_out", timed_out as u64);
    w.key("lines");
    w.begin_array();
    for l in &lines {
        w.str(l);
    }
    w.end_array();
    w.end_object();
    let json = w.finish();
    sh.emit("sweep", "sweep_end", &json);
    json
}

/// Post the sweep summary to the optional collector; the outcome is recorded as an event either way.
pub fn hello_collector(sh: &Shared, summary_json: &str) {
    let Some(c) = &sh.cfg.collector else { return };
    let r = exec::http_post(c, "/oracle-hello", summary_json, Duration::from_secs(5));
    sh.emit("sweep", "collector_post", &format!("{{\"collector\":{},\"result\":{}}}", json_str(c), json_str(&match r {
        Ok(code) => format!("http {}", code),
        Err(e) => format!("error: {}", e),
    })));
}

/// First-boot behaviour: wait for the network to settle, sweep once (marker file), tell the collector.
pub fn first_boot(sh: &Shared) {
    if !sh.cfg.sweep_on_first_boot || sh.cfg.sweep_marker().exists() {
        return;
    }
    for _ in 0..sh.cfg.sweep_delay_s * 5 {
        if sh.stop.load(Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    if exec::list_probes(&sh.cfg.probes_dir(), true).is_empty() {
        return; // nothing to sweep yet: the operator may not have copied the probes; try again at the next start
    }
    let summary = sweep(sh, "first-boot", Duration::from_secs(sh.cfg.sweep_timeout_s));
    let _ = std::fs::write(sh.cfg.sweep_marker(), format!("{}\n", crate::stamp::filetime_to_utc(Stamp::now().wall_100ns)));
    hello_collector(sh, &summary);
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::keys::KeySet;
    use crate::state::Mode;
    use std::os::unix::fs::PermissionsExt;

    pub fn shared(tag: &str) -> Shared {
        let d = std::env::temp_dir().join(format!("i7oracled-jobs-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("o/probes")).unwrap();
        let cfg = Config::with_dirs(d.join("o"), d.join("d"));
        Shared::new(cfg, KeySet::default(), Mode::Console).unwrap()
    }

    #[test]
    fn run_probe_saves_and_logs() {
        let sh = shared("run");
        let p = sh.cfg.probes_dir().join("echo_probe.exe"); // a shell script with an .exe name
        std::fs::write(&p, "#!/bin/sh\necho \"args:$*\"\nexit 4\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        let o = run_probe(&sh, "api", "echo_probe.exe", &["a".into(), "b".into()], Duration::from_secs(10)).unwrap();
        assert_eq!(o.res.exit, Some(4));
        let saved = o.saved_as.clone().unwrap();
        let text = String::from_utf8(exec::read_result(&sh.cfg.results_dir(), &saved).unwrap()).unwrap();
        assert!(text.contains("exit_code: 4") && text.contains("args:a b"), "{}", text);
        assert!(crate::json::parse(&o.json(true), &crate::json::Limits::default()).is_ok());
        assert_eq!(sh.last_seq(), 2); // run_start + run_end
        assert!(run_probe(&sh, "api", "../x.exe", &[], Duration::from_secs(1)).is_err());
        assert!(run_probe(&sh, "api", "missing.exe", &[], Duration::from_secs(1)).is_err());
    }

    #[test]
    fn sweep_runs_sorted_and_summarises() {
        let sh = shared("sweep");
        for (n, code) in [("b_probe.exe", 0), ("a_probe.exe", 1)] {
            let p = sh.cfg.probes_dir().join(n);
            std::fs::write(&p, format!("#!/bin/sh\nexit {}\n", code)).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let j = sweep(&sh, "test", Duration::from_secs(10));
        let v = crate::json::parse(&j, &crate::json::Limits::default()).unwrap();
        assert_eq!(v.get("ok").unwrap().as_u64(), Some(1));
        assert_eq!(v.get("failed").unwrap().as_u64(), Some(1));
        let lines = v.get("lines").unwrap().as_array().unwrap();
        assert!(lines[0].as_str().unwrap().starts_with("a_probe.exe"));
        let (ev, _) = crate::evlog::read_since(&sh.cfg.events_path(), 0, 100, 1 << 20).unwrap();
        assert!(ev.first().unwrap().contains("sweep_start") && ev.last().unwrap().contains("sweep_end"));
    }
}
