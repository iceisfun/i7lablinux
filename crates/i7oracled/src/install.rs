//! install / uninstall: service registration (sc.exe), logon task for the interactive agent, firewall rule,
//! key directory ACL. Command lines are built by pure functions (tested); executing them needs Windows and elevation.

use std::path::Path;
use std::time::Duration;

use crate::config::Config;
use crate::exec::{exec_capture, lossy};

pub const SERVICE: &str = "i7oracled";
pub const TASK_AGENT: &str = "i7oracled-agent";
pub const FW_API: &str = "i7oracled API";

pub type CmdLine = (&'static str, Vec<String>);

fn c(prog: &'static str, args: &[&str]) -> CmdLine {
    (prog, args.iter().map(|s| s.to_string()).collect())
}

pub fn install_commands(exe: &Path, cfg: &Config, exists: bool) -> Vec<CmdLine> {
    let bin = format!("\"{}\" run", exe.display());
    let mut v = Vec::new();
    // (re)create the service: sc has no "create or update", so configure when it already exists
    if exists {
        v.push(("sc.exe", vec!["stop".into(), SERVICE.into()]));
        v.push(("sc.exe", vec!["config".into(), SERVICE.into(), "binPath=".into(), bin.clone(), "start=".into(), "auto".into(), "obj=".into(), "LocalSystem".into(), "DisplayName=".into(), "i7oracled oracle daemon".into()]));
    } else {
        v.push(("sc.exe", vec!["create".into(), SERVICE.into(), "binPath=".into(), bin, "start=".into(), "auto".into(), "obj=".into(), "LocalSystem".into(), "DisplayName=".into(), "i7oracled oracle daemon".into()]));
    }
    v.push(c("sc.exe", &["description", SERVICE, "Lab oracle: power-event recorder and probe runner (i7lablinux)"]));
    // restart on crash: 5 s, 5 s, 30 s; counter resets after a day; also act on non-crash failure exits
    v.push(c("sc.exe", &["failure", SERVICE, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/30000"]));
    v.push(c("sc.exe", &["failureflag", SERVICE, "1"]));
    v.push(c("netsh.exe", &["advfirewall", "firewall", "delete", "rule", &format!("name={}", FW_API)]));
    v.push(("netsh.exe", vec!["advfirewall".into(), "firewall".into(), "add".into(), "rule".into(), format!("name={}", FW_API), "dir=in".into(), "action=allow".into(), "protocol=TCP".into(), format!("localport={}", cfg.port), "profile=any".into()]));
    v.push(("icacls.exe", vec![cfg.keys_dir.display().to_string(), "/inheritance:r".into(), "/grant".into(), "*S-1-5-18:(OI)(CI)F".into(), "/grant".into(), "*S-1-5-32-544:(OI)(CI)F".into()]));
    v.push(c("sc.exe", &["start", SERVICE]));
    v
}

pub fn uninstall_commands() -> Vec<CmdLine> {
    vec![
        c("sc.exe", &["stop", SERVICE]),
        c("sc.exe", &["delete", SERVICE]),
        c("schtasks.exe", &["/delete", "/tn", TASK_AGENT, "/f"]),
        c("schtasks.exe", &["/delete", "/tn", "i7oracled-wake", "/f"]),
        ("netsh.exe", vec!["advfirewall".into(), "firewall".into(), "delete".into(), "rule".into(), format!("name={}", FW_API)]),
    ]
}

/// Logon task for the interactive agent (run from the account that logs on, elevated).
pub fn agent_task_commands(exe: &Path) -> Vec<CmdLine> {
    vec![
        ("schtasks.exe", vec!["/create".into(), "/tn".into(), TASK_AGENT.into(), "/sc".into(), "onlogon".into(), "/rl".into(), "highest".into(), "/tr".into(), format!("\"{}\" agent", exe.display()), "/f".into()]),
        c("schtasks.exe", &["/run", "/tn", TASK_AGENT]),
    ]
}

fn run_all(cmds: &[CmdLine], tolerate: &[&str]) -> Result<(), String> {
    let mut failures = 0;
    for (prog, args) in cmds {
        let r = exec_capture(prog, args, None, Duration::from_secs(60), 1 << 16);
        let line = format!("{} {}", prog, args.join(" "));
        match (r.spawn_error, r.exit) {
            (Some(e), _) => {
                println!("FAIL  {}  ({})", line, e);
                failures += 1;
            }
            (None, Some(0)) => println!("ok    {}", line),
            (None, code) => {
                let benign = tolerate.iter().any(|t| line.contains(t));
                println!("{}  {}  exit={:?} {}", if benign { "skip " } else { "FAIL " }, line, code, lossy(&r.stdout).trim().replace('\n', " "));
                if !benign {
                    failures += 1;
                }
            }
        }
    }
    if failures == 0 {
        Ok(())
    } else {
        Err(format!("{} step(s) failed (run from an elevated prompt)", failures))
    }
}

pub fn install(cfg: &Config) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    for d in [&cfg.oracle_dir, &cfg.probes_dir(), &cfg.results_dir(), &cfg.data_dir, &cfg.keys_dir] {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {}", d.display(), e))?;
    }
    let exists = exec_capture("sc.exe", &["query".to_string(), SERVICE.to_string()], None, Duration::from_secs(20), 1 << 14).exit == Some(0);
    run_all(&install_commands(&exe, cfg, exists), &["sc.exe stop", "delete rule"])?;
    if cfg.keys_dir.join("admin.key").exists() || cfg.keys_dir.join("ro.key").exists() {
        println!("keys found in {}", cfg.keys_dir.display());
    } else {
        println!("NOTE: no keys in {}: copy admin.key and ro.key there, then `sc stop i7oracled & sc start i7oracled`", cfg.keys_dir.display());
    }
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    run_all(&uninstall_commands(), &["sc.exe stop", "sc.exe delete", "schtasks.exe", "delete rule"])
}

pub fn install_agent() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    run_all(&agent_task_commands(&exe), &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn service_commands() {
        let cfg = Config::defaults();
        let exe = PathBuf::from("C:\\oracle\\i7oracled.exe");
        let v = install_commands(&exe, &cfg, false);
        assert_eq!(v[0].1[0], "create");
        assert!(v[0].1.contains(&"\"C:\\oracle\\i7oracled.exe\" run".to_string()));
        assert!(v[0].1.contains(&"LocalSystem".to_string()));
        assert!(v.iter().any(|(p, a)| *p == "sc.exe" && a[0] == "failure" && a.contains(&"restart/5000/restart/5000/restart/30000".to_string())));
        assert!(v.iter().any(|(p, a)| *p == "netsh.exe" && a.contains(&"localport=8765".to_string())));
        assert_eq!(v.last().unwrap().1, ["start", "i7oracled"]);
        let v = install_commands(&exe, &cfg, true);
        assert_eq!(v[0].1[0], "stop");
        assert_eq!(v[1].1[0], "config");
    }

    #[test]
    fn agent_and_uninstall() {
        let t = agent_task_commands(Path::new("C:\\oracle\\i7oracled.exe"));
        assert!(t[0].1.contains(&"onlogon".to_string()) && t[0].1.contains(&"\"C:\\oracle\\i7oracled.exe\" agent".to_string()));
        assert!(uninstall_commands().iter().any(|(_, a)| a.first().map(|s| s == "delete").unwrap_or(false)));
    }
}
