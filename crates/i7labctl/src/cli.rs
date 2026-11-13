//! Subcommand table (drives parsing hints, `help`, `help --all`, completions) and top-level dispatch. Owner: P9.

use std::io::Write;

use labproto::catalog;

use crate::opts::{split_global, Global};
use crate::output::{err_envelope, ErrInfo, Paint};
use crate::{ClientError, Env};

pub struct Sub {
    pub name: &'static str,
    /// transports: E ether, H http, S ssh, L local
    pub transports: &'static str,
    /// "R", "W", "R/W" or "-"
    pub role: &'static str,
    pub synopsis: &'static str,
    pub summary: &'static str,
    /// options of this command (completion and docs; parsing is per handler)
    pub opts: &'static [&'static str],
    /// second words (`net ls`, `key init`, ...)
    pub verbs: &'static [&'static str],
    /// `Some("v0.2")` for commands this tree does not serve yet; answered locally with exit 10
    pub planned: Option<&'static str>,
    /// wire command it fronts (planned status follows the catalogue), if one
    pub wire: Option<&'static str>,
}

macro_rules! s {
    ($n:expr, $t:expr, $r:expr, $syn:expr, $sum:expr, $opts:expr, $verbs:expr, $planned:expr, $wire:expr) => {
        Sub { name: $n, transports: $t, role: $r, synopsis: $syn, summary: $sum, opts: $opts, verbs: $verbs, planned: $planned, wire: $wire }
    };
}

/// I7LABCTL.md section 3 (v1 surface of PLAN.md 4.7).
pub static SUBS: &[Sub] = &[
    s!("discover", "E", "-", "discover [--listen S] [--active] [--watch] [--all] [--assign MAC=IP/PFX[/GW]].. [-i IF].. [--vlan IDS]", "listen for L2 beacons, fill the registry", &["--listen", "--active", "--watch", "--all", "--assign", "--daemon"], &[], None, None),
    s!("ls", "L", "-", "ls [--all] [--sort mac|ip|age|board] [--state live|stale|any]", "list known hosts", &["--all", "--sort", "--state"], &[], None, None),
    s!("ping", "EH", "R", "ping <host> [-c N] [-W S] [ECHO]", "round trip, uptime, boot id", &["-c", "-W"], &[], None, Some("ping")),
    s!("id", "EH", "R", "id <host>", "identity, versions, key fingerprints", &[], &[], None, Some("id")),
    s!("inv", "EH", "R", "inv <host> [--section S,..] [--raw]", "system inventory", &["--section", "--raw"], &[], None, Some("inv")),
    s!("pcie", "EH", "R", "pcie <host> [--tree] [--id VVVV:DDDD] [--class CC] [--verbose]", "PCIe devices", &["--tree", "--id", "--class", "--verbose"], &[], None, Some("pcie")),
    s!("usb", "EH", "R", "usb <host> [--tree] [--id VVVV:PPPP]", "USB devices", &["--tree", "--id"], &[], None, Some("usb")),
    s!("thermal", "EH", "R", "thermal <host> [--follow] [--interval S]", "temperatures, fans", &["--follow", "--interval"], &[], None, Some("thermal")),
    s!("logs", "EH", "R", "logs <host> [--dmesg|--init|--daemon|--http|--audit] [-n N] [-f]", "logs", &["--dmesg", "--init", "--daemon", "--http", "--audit", "-n", "-f"], &[], None, Some("logs")),
    s!("net", "EH", "R/W", "net ls|set|vlan|link|confirm <host> ...", "NICs and configuration", &["--dhcp", "--ip", "--gw", "--dns", "--mtu", "--confirm"], &["ls", "set", "vlan", "link", "confirm"], None, Some("net.ls")),
    s!("blk", "EH", "R/W", "blk ls|smart|read|write|verify <host> ...", "block devices and tests (write: --destructive --serial S)", &["--all", "--attrs", "--selftest", "--mb", "--regions", "--offset", "--len", "--bs", "--direct", "--destructive", "--serial", "--seed"], &["ls", "smart", "read", "write", "verify"], None, Some("blk.ls")),
    s!("exec", "EHS", "W", "exec <host> [--timeout S] [--env K=V].. [--cwd D] [--stdin F|-] [--tty] [--detach] -- CMD..", "run a program (no shell)", &["--timeout", "--env", "--cwd", "--stdin", "--tty", "--detach"], &[], None, Some("exec")),
    s!("sh", "EHS", "W", "sh <host> '<command line>'", "run a command line through i7labsh (alias of exec -- i7labsh -c)", &["--timeout", "--env", "--cwd"], &[], None, Some("exec")),
    s!("shell", "ES", "W", "shell <host> [--term T] [--escape C] [--via ether|ssh]", "interactive i7labsh on a pty", &["--term", "--escape", "--via"], &[], None, Some("shell")),
    s!("put", "EH", "W", "put <host> <local> <remote> [--mode 0644] [--resume] [--mkdirs]", "upload a file", &["--mode", "--resume", "--mkdirs"], &[], None, Some("put")),
    s!("get", "EH", "R/W", "get <host> <remote> <local> [--resume]", "download a file", &["--resume"], &[], None, Some("get")),
    s!("fs", "EH", "R/W", "fs ls|stat|rm <host> <path> ...", "remote files", &["-l", "-r"], &["ls", "stat", "rm"], None, Some("fs.ls")),
    s!("jobs", "EH", "W", "jobs <host> [ls] | kill ID | out ID [-f]", "detached jobs", &["-f"], &["ls", "kill", "out"], None, Some("jobs")),
    s!("reboot", "EH", "W", "reboot <host> [--force] [--delay S] [--uefi] [--to-os] [--wait [S]]", "reboot", &["--force", "--delay", "--uefi", "--to-os", "--wait"], &[], None, Some("reboot")),
    s!("poweroff", "EH", "W", "poweroff <host> [--delay S]", "power off", &["--delay"], &[], None, Some("poweroff")),
    s!("kexec", "EH", "W", "kexec <host> --kernel P [--initrd P] [--cmdline S] [--wait [S]]", "boot another kernel", &["--kernel", "--initrd", "--cmdline", "--wait"], &[], None, Some("kexec")),
    s!("wait", "E", "-", "wait <host> [--timeout S] [--state up|down|ready|reboot] [--boot-id ID]", "wait for a host state (beacons)", &["--timeout", "--state", "--boot-id"], &[], None, None),
    s!("identify", "EH", "W", "identify <host> [--seconds N] [--stop]", "blink LEDs, banner on the console", &["--seconds", "--stop"], &[], None, Some("identify")),
    s!("msg", "EH", "W", "msg <host> <text..>", "message on the host console", &[], &[], None, Some("msg")),
    s!("time-set", "EH", "W", "time-set <host> [UNIX_SECONDS|now]", "set the host clock", &[], &[], None, Some("time.set")),
    s!("svc", "EH", "W", "svc <host> http|beacon|ether start|stop|status [--port N] [--force]", "agent services", &["--port", "--force"], &[], None, Some("svc")),
    s!("tui", "EH", "R/W", "tui tab NAME|reset|dump <host>", "console TUI of the host: switch tab, text screenshot", &[], &["tab", "reset", "dump"], None, Some("tui")),
    s!("key", "L", "-", "key init|show|verify|import|export ...", "key management", &["--dir", "--force", "--demo", "--secret", "--file"], &["init", "show", "verify", "import", "export", "rotate"], None, None),
    s!("ether", "E", "-", "ether cmds|probe|hello|sniff|frame|replay ...", "raw protocol tools", &["--decode", "--count"], &["cmds", "probe", "hello", "sniff", "frame", "replay"], None, None),
    s!("api", "H", "-", "api <host> METHOD PATH [--data JSON|@file]", "raw authenticated HTTP request", &["--data"], &[], None, None),
    s!("ssh", "S", "W", "ssh <host> [--user U] [--no-start] [-- ssh-args..]", "ssh to a host that runs sshd (system ssh, pinned host keys)", &["--user", "--no-start"], &[], None, None),
    s!("lab-boot", "L", "-", "lab-boot --jetkvm HOST --image PATH [--mode cdrom|disk] [--wait S]", "boot a host from lab linux via JetKVM virtual media (through hwlabd)", &["--jetkvm", "--image", "--mode", "--wait", "--dry-run"], &[], None, None),
    s!("image", "L", "-", "image build|write|bake|keys|test|info|verify ...", "wrappers around scripts/ (build, write a stick, bake keys)", &[], &["build", "write", "bake", "keys", "test", "info", "verify"], None, None),
    s!("web", "L", "R/W", "web [--listen 127.0.0.1:8081]", "local web UI gateway", &["--listen", "--open"], &[], Some("v0.5"), None),
    s!("completions", "L", "-", "completions bash|zsh|fish", "shell completion script", &[], &["bash", "zsh", "fish"], None, None),
    s!("help", "L", "-", "help [CMD|--all|ether|exit-codes|boot-keys|json]", "help", &["--all"], &["ether", "exit-codes", "boot-keys", "json"], None, None),
    s!("version", "L", "-", "version", "versions", &[], &[], None, None),
];

pub fn find(name: &str) -> Option<&'static Sub> {
    SUBS.iter().find(|s| s.name == name)
}

/// `Some("vX.Y")` if the command is planned (table or catalogue).
pub fn planned(s: &Sub) -> Option<&'static str> {
    s.planned.or_else(|| s.wire.and_then(catalog::by_name).filter(|c| c.planned()).map(|c| c.since))
}

pub fn real_env() -> Env {
    use std::io::IsTerminal;
    let home = crate::keys::real_home().unwrap_or_default();
    let out_tty = std::io::stdout().is_terminal();
    Env {
        out: Box::new(std::io::stdout()),
        err: Box::new(std::io::stderr()),
        keyenv: crate::keys::KeyEnv::from_process(None),
        home,
        cwd: std::env::current_dir().unwrap_or_default(),
        connector: Box::new(crate::cmds::RealConnect),
        out_tty,
        in_tty: std::io::stdin().is_terminal(),
        color: out_tty && std::env::var_os("NO_COLOR").is_none(),
        scripts_dir: crate::wrap::find_scripts_dir(),
        fake_now: None,
        fake_answer: None,
        ssh_bin: std::env::var_os("I7LABCTL_SSH").map(std::path::PathBuf::from),
        hwlab: std::env::var("HWLAB").ok(),
    }
}

pub const EXIT_CODES_TEXT: &str = "\
exit codes
  0    success
  1    generic failure (the command ran but reported failure)
  2    usage error (bad option or arguments), nothing was sent
  3    a test or probe found a problem: blk read/write/verify errors or mismatches, SMART verdict FAILED
  4    no response or timeout (transport, handshake without CHALLENGE, wait timeout, ping without reply)
  5    authentication failure (server proof invalid, key unknown to the host, no key file, role too low)
  6    host not found in the registry / not reachable at L2
  7    refused by a safety rule (REFUSED from the host, or a local refusal in blk write / image write)
  8    ambiguous host selector (candidates are listed)
  9    host busy (BUSY, NOT_READY)
  10   unsupported command or version mismatch (UNSUPPORTED, planned commands)
  130  interrupted (Ctrl-C)
  255  exec, sh, shell, ssh only: i7labctl's own error (1..254 are then the remote command's exit status)
";

/// Parse, dispatch, return the process exit status.
pub fn run_with(args: Vec<String>, env: &mut Env) -> i32 {
    let (mut g, rest) = match split_global(&args) {
        Ok(x) => x,
        Err(e) => {
            let _ = writeln!(env.err, "i7labctl: {}\ntry: i7labctl help", e);
            return 2;
        }
    };
    if !env.color {
        g.no_color = true;
    }
    let paint = Paint { on: !g.no_color && env.out_tty };

    if g.version {
        let _ = writeln!(env.out, "{}", crate::help::version_text());
        return 0;
    }

    if rest.first().map(String::as_str) == Some("__hosts") {
        return crate::cmds::hosts_for_completion(env, &g);
    }
    // raw form: --ether MAC --cmd NAME [params..]
    if g.cmd.is_some() {
        return crate::cmds::run_raw(env, &g, &rest, paint);
    }
    let Some(first) = rest.first().cloned() else {
        // no command: `i7labctl --help` or nothing at all
        let _ = write!(env.out, "{}", crate::help::top(false, paint));
        return if g.help { 0 } else { 2 };
    };
    if g.help {
        return crate::help::run_cmd_help(env, &first, paint);
    }
    let Some(sub) = find(&first) else {
        let hint = suggest(&first).map(|s| format!(" (did you mean '{}'?)", s)).unwrap_or_default();
        let msg = format!("unknown command '{}'{}", first, hint);
        if g.json {
            let e = err_envelope(None, None, &first, &ErrInfo { code: "E_USAGE", status: None, exit: 2, message: &msg, reasons: &[] });
            let _ = writeln!(env.out, "{}", e);
        } else {
            let _ = writeln!(env.err, "i7labctl: {}\ntry: i7labctl help", msg);
        }
        return 2;
    };
    let args = &rest[1..];
    if args.iter().any(|a| a == "-h" || a == "--help") {
        return crate::help::run_cmd_help(env, &first, paint);
    }
    if let Some(v) = planned(sub) {
        return planned_exit(env, &g, sub.name, v);
    }
    crate::cmds::dispatch(env, &g, sub, args, paint)
}

pub fn planned_exit(env: &mut Env, g: &Global, name: &str, since: &str) -> i32 {
    let msg = format!("'{}' is planned for {} and is not served by this build (UNSUPPORTED)", name, since);
    emit_error(env, g, name, &ClientError::Unsupported(msg.clone()), 10)
}

/// Print a client-side error (human on stderr, or the JSON envelope on stdout) and return `exit`.
pub fn emit_error(env: &mut Env, g: &Global, cmd: &str, e: &ClientError, exit: i32) -> i32 {
    if g.json {
        let msg = e.to_string();
        let reasons: Vec<String> = match e {
            ClientError::Ambiguous(c) => c.clone(),
            _ => Vec::new(),
        };
        let env_json = err_envelope(None, None, cmd, &ErrInfo { code: e.code(), status: None, exit, message: &msg, reasons: &reasons });
        let _ = writeln!(env.out, "{}", env_json);
    } else if !g.quiet || exit != 0 {
        let _ = writeln!(env.err, "i7labctl: {}: {}", cmd, e);
    }
    exit
}

fn suggest(word: &str) -> Option<&'static str> {
    SUBS.iter().map(|s| (edit_distance(word, s.name), s.name)).filter(|(d, _)| *d <= 2).min().map(|(_, n)| n)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i];
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur.push((prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost));
        }
        prev = cur;
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sane() {
        let mut seen = std::collections::HashSet::new();
        for s in SUBS {
            assert!(seen.insert(s.name), "duplicate {}", s.name);
            assert!(s.synopsis.starts_with(s.name), "{}", s.name);
            if let Some(w) = s.wire {
                assert!(catalog::by_name(w).is_some(), "{} fronts unknown wire command {}", s.name, w);
            }
        }
        // planned commands follow the catalogue
        assert!(planned(find("kexec").unwrap()).is_some());
        assert!(planned(find("svc").unwrap()).is_some());
        assert!(planned(find("web").unwrap()).is_some());
        assert!(planned(find("inv").unwrap()).is_none());
        assert!(planned(find("blk").unwrap()).is_none());
    }

    #[test]
    fn suggestions() {
        assert_eq!(suggest("discove"), Some("discover"));
        assert_eq!(suggest("pign"), Some("ping"));
        assert_eq!(suggest("zzzzzzzz"), None);
    }
}
