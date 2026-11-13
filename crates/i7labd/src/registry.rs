//! Command registry: key policy, role check, path policy, concurrency, audit, panic isolation, then the
//! handler. Owner: P6a.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Receiver;
use std::sync::Arc;

use labproto::catalog::{Access, CmdSpec, PathOp, CATALOG};
use labproto::frame::Chan;
use labproto::keys::Role;
use labproto::json::JsonWriter;
use labproto::{Mac, Status};

use crate::daemon::Daemon;

#[derive(Clone, Debug)]
pub enum Source {
    Ether { mac: Mac, vlan: Option<u16>, iface: String },
    Http { peer: SocketAddr },
    Console { tty: String },
    Local,
}

impl Source {
    pub fn describe(&self) -> String {
        match self {
            Source::Ether { mac, vlan, iface } => match vlan {
                Some(v) => format!("ether {} {} vlan {}", iface, mac, v),
                None => format!("ether {} {}", iface, mac),
            },
            Source::Http { peer } => format!("http {}", peer),
            Source::Console { tty } => format!("console {}", tty),
            Source::Local => "local".into(),
        }
    }
}

/// Streaming side channel of the current request (stdout/stderr/file data, progress events, input).
pub trait Sink: Send {
    /// Blocks while the transport window is closed (backpressure).
    fn data(&mut self, chan: Chan, bytes: &[u8]) -> io::Result<()>;
    /// One NDJSON event object, e.g. `{"event":"progress",...}`.
    fn event(&mut self, json: &str) -> io::Result<()>;
    /// Stdin / file upload / Ctl channel for exec, shell and put; `None` if the transport has none.
    fn input(&mut self) -> Option<Receiver<Vec<u8>>> {
        None
    }
    /// false for sinks that buffer in memory: handlers then cap their output (exec: 64 MiB).
    fn streaming(&self) -> bool {
        true
    }
}

/// Discards everything (non-streaming callers).
pub struct NullSink;
impl Sink for NullSink {
    fn data(&mut self, _c: Chan, _b: &[u8]) -> io::Result<()> {
        Ok(())
    }
    fn event(&mut self, _j: &str) -> io::Result<()> {
        Ok(())
    }
    fn streaming(&self) -> bool {
        false
    }
}

/// Collects output in memory (tests, console TUI actions).
#[derive(Default)]
pub struct CollectSink {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub file: Vec<u8>,
    pub events: Vec<String>,
}
impl Sink for CollectSink {
    fn data(&mut self, c: Chan, b: &[u8]) -> io::Result<()> {
        match c {
            Chan::Stderr => self.stderr.extend_from_slice(b),
            Chan::File => self.file.extend_from_slice(b),
            _ => self.stdout.extend_from_slice(b),
        }
        Ok(())
    }
    fn event(&mut self, j: &str) -> io::Result<()> {
        self.events.push(j.to_string());
        Ok(())
    }
    fn streaming(&self) -> bool {
        false
    }
}

pub struct Ctx<'a> {
    pub daemon: &'a Daemon,
    pub source: Source,
    pub role: Role,
    /// key fingerprint + source, for audit
    pub actor: String,
    /// argv words after the command name
    pub args: Vec<String>,
    pub sink: &'a mut dyn Sink,
    pub cancel: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Content {
    Json,
    Bytes,
    /// i32 big-endian exit code followed by JSON `{signal,duration_ms}`
    ExecResult,
}

#[derive(Clone, Debug)]
pub struct Reply {
    pub status: Status,
    pub body: Vec<u8>,
    pub content: Content,
}

impl Reply {
    pub fn json(s: String) -> Reply {
        Reply { status: Status::Ok, body: s.into_bytes(), content: Content::Json }
    }
    pub fn ok_empty() -> Reply {
        Reply::json("{}".into())
    }
    /// `{"error":{"code":"..","message":".."}}`
    pub fn error(status: Status, msg: &str) -> Reply {
        let mut w = JsonWriter::new();
        w.begin_object();
        w.key("error");
        w.begin_object();
        w.field_str("code", status.name());
        w.field_str("message", msg);
        w.end_object();
        w.end_object();
        Reply { status, body: w.finish().into_bytes(), content: Content::Json }
    }
    /// REFUSED with the safety reasons listed (blk.write etc).
    pub fn refused(reasons_json: &str, msg: &str) -> Reply {
        let mut w = JsonWriter::new();
        w.begin_object();
        w.key("error");
        w.begin_object();
        w.field_str("code", Status::Refused.name());
        w.field_str("message", msg);
        w.key("reasons");
        w.raw(reasons_json);
        w.end_object();
        w.end_object();
        Reply { status: Status::Refused, body: w.finish().into_bytes(), content: Content::Json }
    }
}

pub type Handler = fn(&mut Ctx) -> Reply;

pub struct Command {
    pub spec: &'static CmdSpec,
    pub handler: Handler,
}

pub struct Registry {
    cmds: Vec<Command>,
}

fn unsupported(_ctx: &mut Ctx) -> Reply {
    Reply::error(Status::Unsupported, "not implemented in this build")
}

/// Roots a read-only key may read with get / fs.ls / fs.stat (PLAN.md C22).
pub const RO_ROOTS: &[&str] = &["/var/log", "/run/i7lab", "/proc", "/sys", "/etc/os-release"];

/// Denied for EVERY role over get/put/fs.* (admin included: keys are never served as files; rotate by
/// rewriting keys.cpio on the stick). Read and write.
pub const DENY_ALL: &[&str] = &["/etc/i7lab/keys"];
/// Denied for writes (put, fs.rm) for every role: daemon control files, audit log, locks, baked config.
pub const DENY_WRITE: &[&str] = &["/run/i7lab", "/etc/i7lab"];
/// Under /proc, path components a ro key may never traverse (magic links, other processes' memory/env).
pub const PROC_DENY: &[&str] =
    &["root", "cwd", "exe", "fd", "fdinfo", "map_files", "environ", "mem", "pagemap", "kcore", "kmem", "auxv", "syscall", "kmsg"];
/// Under /sys, ro denies these subtrees.
pub const SYS_DENY: &[&str] = &["/sys/firmware/efi/efivars", "/sys/kernel/debug", "/sys/kernel/tracing"];

/// Lexical normal form: absolute, no "..", "." or empty components, no NUL. `None` = rejected.
pub fn normalize(path: &str) -> Option<String> {
    if !path.starts_with('/') || path.contains('\0') {
        return None;
    }
    let mut out = Vec::new();
    for c in path.split('/') {
        match c {
            "" => {}
            "." | ".." => return None,
            c => out.push(c),
        }
    }
    Some(format!("/{}", out.join("/")))
}

pub(crate) fn under(path: &str, root: &str) -> bool {
    path == root || (path.starts_with(root) && path.as_bytes().get(root.len()) == Some(&b'/'))
}

/// Path policy of the file commands (review security F1 / feasibility F31). The lexical check here is the
/// first gate; the handler then opens the path with `labproto::sys::openat2_beneath(root, rel,
/// RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` from the matching `RO_ROOTS` fd for ro (so symlinks cannot leave the
/// root and /proc magic links fail in the kernel), and re-checks `DENY_ALL` on the opened fd's
/// /proc/self/fd/N target for every role. Returns the normalised path.
pub fn path_policy(role: Role, op: PathOp, path: &str) -> Result<String, &'static str> {
    let p = normalize(path).ok_or("path must be absolute without '.', '..' or empty components")?;
    if DENY_ALL.iter().any(|r| under(&p, r)) {
        return Err("key material is never served as a file");
    }
    if op == PathOp::Write && DENY_WRITE.iter().any(|r| under(&p, r)) {
        return Err("daemon control files are not writable");
    }
    if role == Role::Ro {
        if op == PathOp::Write {
            return Err("admin key required");
        }
        if !RO_ROOTS.iter().any(|r| under(&p, r)) {
            return Err("path not allowed for the read-only key");
        }
        if under(&p, "/proc") && p.split('/').any(|c| PROC_DENY.contains(&c)) {
            return Err("path not allowed for the read-only key");
        }
        if SYS_DENY.iter().any(|r| under(&p, r)) {
            return Err("path not allowed for the read-only key");
        }
        // PCI BAR files (resource0..5, resource0_wc): read(2) on them is device I/O with possible side effects
        if under(&p, "/sys") && p.split('/').any(|c| c.strip_prefix("resource").is_some_and(|r| r.starts_with(|ch: char| ch.is_ascii_digit()))) {
            return Err("path not allowed for the read-only key");
        }
    }
    Ok(p)
}

/// Back-compat helper: may the ro key read `path`?
pub fn ro_path_allowed(path: &str) -> bool {
    path_policy(Role::Ro, PathOp::Read, path).is_ok()
}

impl Registry {
    /// Every catalogue entry; entries without a handler answer UNSUPPORTED.
    pub fn standard() -> Registry {
        let cmds = CATALOG
            .iter()
            .map(|spec| Command { spec, handler: crate::cmds::handler_for(spec.name).unwrap_or(unsupported) })
            .collect();
        Registry { cmds }
    }

    pub fn get(&self, name: &str) -> Option<&Command> {
        self.cmds.iter().find(|c| c.spec.name == name)
    }

    pub fn by_id(&self, id: u16) -> Option<&Command> {
        self.cmds.iter().find(|c| c.spec.id == id)
    }

    pub fn commands(&self) -> impl Iterator<Item = &Command> {
        self.cmds.iter()
    }

    /// The single entry point for all front ends.
    /// Order: planned => UNSUPPORTED, role, path policy (the path is
    /// the FIRST argv word, rewritten to its normal form, so handler and check can never disagree), limits,
    /// handler with panic catch, audit.
    pub fn dispatch(&self, ctx: &mut Ctx, cmd: &Command) -> Reply {
        if cmd.spec.planned() {
            return Reply::error(Status::Unsupported, &format!("{} is planned for {}", cmd.spec.name, cmd.spec.since));
        }
        if let (Access::Admin, Role::Ro) = (cmd.spec.access, ctx.role) {
            return Reply::error(Status::Eperm, "admin key required");
        }
        if let Some(op) = cmd.spec.path_op() {
            match ctx.args.first().filter(|a| !a.starts_with('-')) {
                None => return Reply::error(Status::BadArgs, "PATH must be the first argument"),
                Some(p) => match path_policy(ctx.role, op, p) {
                    Ok(n) => ctx.args[0] = n,
                    Err(why) => return Reply::error(Status::Eperm, why),
                },
            }
        }
        // per-host concurrency limits (PROTOCOL 8): the guard is held for the whole handler run
        let _gate = match ctx.daemon.limits.gate_for(cmd.spec.name) {
            Some(g) => match g.try_acquire() {
                Some(guard) => Some(guard),
                None => return Reply::error(Status::Busy, &format!("too many concurrent {} runs on this host", cmd.spec.name)),
            },
            None => None,
        };
        let handler = cmd.handler;
        let reply = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(ctx))) {
            Ok(r) => r,
            Err(_) => Reply::error(Status::Internal, "handler panicked"),
        };
        if cmd.spec.access != Access::Ro {
            let line = ctx.daemon.audit.record(&ctx.source, &ctx.actor, cmd.spec.name, &ctx.args, reply.status);
            ctx.daemon.events.publish(crate::events::Event::Audit(line));
        }
        reply
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn run(role: Role, name: &str, args: &[&str]) -> Reply {
        let d = Daemon::new(Config::default()).unwrap();
        let mut sink = CollectSink::default();
        let mut ctx = Ctx {
            daemon: &d,
            source: Source::Local,
            role,
            actor: "test".into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            sink: &mut sink,
            cancel: Arc::new(AtomicBool::new(false)),
        };
        let cmd = d.registry.get(name).unwrap();
        d.registry.dispatch(&mut ctx, cmd)
    }

    #[test]
    fn every_catalogue_entry_is_registered() {
        let r = Registry::standard();
        assert_eq!(r.commands().count(), CATALOG.len());
    }

    #[test]
    fn role_checks() {
        assert_eq!(run(Role::Ro, "reboot", &[]).status, Status::Eperm);
        assert_eq!(run(Role::Ro, "get", &["/etc/shadow"]).status, Status::Eperm);
        assert_eq!(run(Role::Ro, "get", &["/proc/../etc/shadow"]).status, Status::Eperm);
        assert_eq!(run(Role::Ro, "get", &["/proc/1/root/etc/i7lab/keys/admin.key"]).status, Status::Eperm);
        assert_eq!(run(Role::Ro, "get", &["--offset", "0", "/etc/shadow"]).status, Status::BadArgs);
        assert_eq!(run(Role::Ro, "ping", &[]).status, Status::Ok);
        assert_eq!(run(Role::Admin, "kexec", &[]).status, Status::Unsupported);
        assert!(ro_path_allowed("/proc/cpuinfo") && !ro_path_allowed("/procfoo"));
    }

    #[test]
    fn path_policy_table() {
        use PathOp::*;
        let ro = |p: &str| path_policy(Role::Ro, Read, p).is_ok();
        for bad in [
            "/proc/1/root/etc/i7lab/keys/admin.key",
            "/proc/self/root/etc/passwd",
            "/proc/self/cwd/x",
            "/proc/self/mem",
            "/proc/1/task/1/environ",
            "/proc/kcore",
            "/proc/self/fd/3",
            "/proc/../etc/i7lab/keys/admin.key",
            "/sys/firmware/efi/efivars/BootOrder-x",
            "/etc/i7lab/keys/ro.key",
            "relative/path",
            "/proc/./self",
            "/proc/kmsg",
            "/sys/bus/pci/devices/0000:00:02.0/resource0",
            "/sys/devices/pci0000:00/0000:00:1f.6/resource2_wc",
        ] {
            assert!(!ro(bad), "{}", bad);
        }
        for good in ["/proc/cpuinfo", "/proc/1/status", "/sys/class/net/eth0/address", "/var/log/x", "/etc/os-release", "/sys/bus/pci/devices/0000:00:02.0/resource"] {
            assert!(ro(good), "{}", good);
        }
        assert!(path_policy(Role::Admin, Read, "/etc/i7lab/keys/admin.key").is_err());
        assert!(path_policy(Role::Admin, Read, "/etc/shadow").is_ok());
        assert!(path_policy(Role::Admin, Write, "/run/i7lab/audit.log").is_err());
        assert!(path_policy(Role::Admin, Write, "/tmp/x").is_ok());
        assert!(path_policy(Role::Ro, Write, "/tmp/x").is_err());
        assert_eq!(path_policy(Role::Admin, Read, "//tmp//x/").unwrap(), "/tmp/x");
    }
}

/// Helpers for handler tests (a private run dir per daemon, admin or ro requests through the real dispatch).
#[cfg(test)]
pub mod tests_support {
    use super::*;
    use crate::config::Config;
    use std::sync::atomic::AtomicUsize;

    static N: AtomicUsize = AtomicUsize::new(0);

    pub fn test_config() -> Config {
        let d = std::env::temp_dir().join(format!("i7labd-t{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)));
        std::fs::create_dir_all(&d).unwrap();
        Config { audit_log: d.join("audit.log"), resolv_conf: d.join("resolv.conf"), run_dir: d, power_dry_run: true, dhcp: false, ..Config::default() }
    }

    pub fn test_daemon() -> Daemon {
        Daemon::new(test_config()).unwrap()
    }

    pub fn run_with(d: &Daemon, role: Role, name: &str, args: &[&str]) -> (Reply, CollectSink) {
        let mut sink = CollectSink::default();
        let reply = {
            let mut ctx = Ctx {
                daemon: d,
                source: Source::Local,
                role,
                actor: "test".into(),
                args: args.iter().map(|s| s.to_string()).collect(),
                sink: &mut sink,
                cancel: Arc::new(AtomicBool::new(false)),
            };
            let cmd = d.registry.get(name).unwrap();
            d.registry.dispatch(&mut ctx, cmd)
        };
        (reply, sink)
    }

    pub fn run_as_admin(name: &str, args: &[&str]) -> (Reply, CollectSink) {
        run_with(&test_daemon(), Role::Admin, name, args)
    }
}
