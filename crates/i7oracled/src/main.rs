//! i7oracled: oracle daemon for a real Windows 10 machine (docs/ORACLED.md).
//!
//! The pure logic (event log, auth, HTTP parsing, JSON, request validation) builds and tests on Linux; the Windows
//! layer is `win/` (cross-built for x86_64-pc-windows-gnu). `crypto.rs`, `json.rs`, `httpauth.rs` are compiled from
//! crates/labproto/src so the bytes on the wire are exactly the lab's.

// labproto modules are compiled whole; the parts this daemon never calls are expected dead code
#![allow(dead_code)]

#[path = "../../labproto/src/crypto.rs"]
mod crypto;
#[path = "../../labproto/src/httpauth.rs"]
mod httpauth;
#[path = "../../labproto/src/json.rs"]
mod json;

mod api;
mod auth;
mod beacon;
mod config;
mod daemon;
mod evlog;
mod evtparse;
mod exec;
mod httpd;
mod install;
mod jobs;
mod keys;
mod power;
mod powercfg;
mod pstruct;
mod stamp;
mod state;
mod sys;

#[cfg(windows)]
mod win;
#[cfg(windows)]
use win as plat;

#[cfg(not(windows))]
mod stub;
#[cfg(not(windows))]
use stub as plat;

use daemon::Overrides;
use state::Mode;

const USAGE: &str = "i7oracled [--root DIR] [--data DIR] [--port N] [--collector HOST:PORT] <command>

commands:
  run             service entry point (started by the service control manager)
  console         run everything in the foreground (testing; also the interactive-desktop mode)
  agent           interactive-session recorder: window events forwarded to the service on loopback
  install         register the service (auto start, LocalSystem, restart on failure), firewall rule, key ACL, start it
  install-agent   scheduled task: run `agent` at every logon (run elevated, as the user who logs on)
  uninstall       stop and remove the service, the logon task and the firewall rule
  version

defaults: --root C:\\oracle   --data C:\\ProgramData\\i7oracled (keys\\, config.json)   port 8765   beacon UDP 8766";

fn parse_args(args: &[String]) -> Result<(Overrides, String), String> {
    let mut ov = Overrides::default();
    let mut cmd = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let mut val = |name: &str| -> Result<String, String> {
            i += 1;
            args.get(i).cloned().ok_or_else(|| format!("{} needs a value", name))
        };
        match a {
            "--root" => ov.root = Some(val("--root")?.into()),
            "--data" => ov.data = Some(val("--data")?.into()),
            "--port" => ov.port = Some(val("--port")?.parse().map_err(|_| "bad --port")?),
            "--collector" => ov.collector = Some(val("--collector")?),
            "-h" | "--help" | "help" => cmd = Some("help".to_string()),
            "-V" | "--version" | "version" => cmd = Some("version".to_string()),
            c if !c.starts_with('-') && cmd.is_none() => cmd = Some(c.to_string()),
            other => return Err(format!("unknown argument {:?}", other)),
        }
        i += 1;
    }
    Ok((ov, cmd.unwrap_or_else(|| "help".into())))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (ov, cmd) = match parse_args(&args) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("i7oracled: {}\n\n{}", e, USAGE);
            std::process::exit(2);
        }
    };
    let cfg_for_install = || {
        let mut c = config::Config::defaults();
        if ov.root.is_some() || ov.data.is_some() {
            c = config::Config::with_dirs(ov.root.clone().unwrap_or_else(|| c.oracle_dir.clone()), ov.data.clone().unwrap_or_else(|| c.data_dir.clone()));
        }
        let p = c.config_path();
        let _ = c.load_file(&p);
        if let Some(p) = ov.port {
            c.port = p;
        }
        c
    };
    let r = match cmd.as_str() {
        "run" => plat::run_service(),
        "console" => daemon::run_console(Mode::Console, &ov),
        "agent" => daemon::run_console(Mode::Agent, &ov),
        "install" => install::install(&cfg_for_install()),
        "install-agent" => install::install_agent(),
        "uninstall" => install::uninstall(),
        "version" => {
            println!("i7oracled {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "help" => {
            println!("{}", USAGE);
            Ok(())
        }
        other => Err(format!("unknown command {:?}\n\n{}", other, USAGE)),
    };
    if let Err(e) = r {
        eprintln!("i7oracled: {}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn arg_parsing() {
        let (ov, c) = parse_args(&a(&["--root", "/r", "--port", "9", "console"])).unwrap();
        assert_eq!((c.as_str(), ov.port), ("console", Some(9)));
        assert_eq!(ov.root.unwrap().to_str(), Some("/r"));
        assert_eq!(parse_args(&a(&[])).unwrap().1, "help");
        assert_eq!(parse_args(&a(&["--version"])).unwrap().1, "version");
        assert!(parse_args(&a(&["--port"])).is_err());
        assert!(parse_args(&a(&["--port", "x", "run"])).is_err());
        assert!(parse_args(&a(&["--bogus"])).is_err());
    }
}
