//! i7labd binary. No arguments: run the agent. `--check`: load config and keys, print a summary, exit 0/1.
//! Test and bring-up options: `--etc DIR` (default /etc/i7lab), `--run DIR` (default /run/i7lab),
//! `--cmdline STR` (instead of /proc/cmdline, e.g. "i7lab.http=18080 i7lab.tui=off").

use std::path::PathBuf;
use std::sync::Arc;

fn main() {
    let mut etc = PathBuf::from("/etc/i7lab");
    let mut run_dir: Option<PathBuf> = None;
    let mut cmdline: Option<String> = None;
    let mut check = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--check" => check = true,
            "--etc" => etc = args.next().map(PathBuf::from).unwrap_or(etc),
            "--run" => run_dir = args.next().map(PathBuf::from),
            "--cmdline" => cmdline = args.next(),
            "-h" | "--help" => {
                println!("usage: i7labd [--check] [--etc DIR] [--run DIR] [--cmdline STR]");
                return;
            }
            other => {
                eprintln!("i7labd: unknown argument {:?}", other);
                std::process::exit(2);
            }
        }
    }
    let cmdline = cmdline.unwrap_or_else(|| std::fs::read_to_string("/proc/cmdline").unwrap_or_default());
    let mut config = i7labd::config::Config::load(&etc, &cmdline);
    if let Some(r) = run_dir {
        config.audit_log = r.join("audit.log");
        config.run_dir = r;
    }
    let _ = std::fs::create_dir_all(&config.run_dir);
    let daemon = match i7labd::Daemon::new(config) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("i7labd: {}", e);
            std::process::exit(1);
        }
    };
    if check {
        println!("i7labd {} ok: {} commands, keys: {}", labproto::VERSION, daemon.registry.commands().count(), daemon.key_summary());
        return;
    }
    i7labd::run(Arc::new(daemon));
}
