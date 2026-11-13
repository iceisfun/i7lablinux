//! Probe context and errors. Owner: P3.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// `root` is "/" on a live system or a fixture tree in tests (paths are joined without the leading '/').
#[derive(Clone, Debug)]
pub struct ProbeCtx {
    pub root: PathBuf,
    /// per-file read budget (sysfs on dying hardware can hang)
    pub budget: Duration,
    /// root privileges available (config space beyond 64 bytes, SG_IO, efivars)
    pub privileged: bool,
    /// boot media identity resolved ONCE at daemon start and cached (review security F18): the `i7lab.boot=`
    /// PARTUUID from the kernel cmdline and the devno of the whole disk that carried it at boot. The gate marks a
    /// disk boot media if its devno matches or any of its partitions has this PARTUUID (a clone of the stick is
    /// therefore also protected: fails safe). Filesystem labels are never used for this decision.
    pub boot_partuuid: Option<String>,
    pub boot_disk: Option<(u32, u32)>,
}

#[derive(Debug)]
pub enum ProbeError {
    Io(io::Error),
    Parse(String),
    Timeout,
    Unsupported,
    NotFound(String),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeError::Io(e) => write!(f, "io: {}", e),
            ProbeError::Parse(s) => write!(f, "parse: {}", s),
            ProbeError::Timeout => write!(f, "timeout"),
            ProbeError::Unsupported => write!(f, "unsupported"),
            ProbeError::NotFound(s) => write!(f, "not found: {}", s),
        }
    }
}

impl From<io::Error> for ProbeError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::NotFound {
            ProbeError::NotFound(e.to_string())
        } else {
            ProbeError::Io(e)
        }
    }
}

impl ProbeError {
    /// Stable short code for JSON (`{"error":"<code>","message":".."}`).
    pub fn code(&self) -> &'static str {
        match self {
            ProbeError::Io(_) => "io",
            ProbeError::Parse(_) => "parse",
            ProbeError::Timeout => "timeout",
            ProbeError::Unsupported => "unsupported",
            ProbeError::NotFound(_) => "not_found",
        }
    }
}

impl ProbeCtx {
    pub fn live() -> ProbeCtx {
        ProbeCtx { root: PathBuf::from("/"), budget: Duration::from_secs(2), privileged: true, boot_partuuid: None, boot_disk: None }
    }

    pub fn fixture(root: impl Into<PathBuf>) -> ProbeCtx {
        ProbeCtx { root: root.into(), budget: Duration::from_secs(2), privileged: false, boot_partuuid: None, boot_disk: None }
    }

    /// Absolute path inside `root` for an absolute system path such as "/sys/class/net".
    pub fn path(&self, sys_path: &str) -> PathBuf {
        self.root.join(sys_path.trim_start_matches('/'))
    }

    /// Read a small text file, trimmed. On the live root, /sys and /proc reads run on a helper thread and give up
    /// after `budget` (`ProbeError::Timeout`): sysfs files of dying hardware can block in the kernel for ever.
    /// (An abandoned helper stays blocked until the kernel returns; it holds no locks of ours.)
    pub fn read_trim(&self, sys_path: &str) -> Result<String, ProbeError> {
        let path = self.path(sys_path);
        let live = self.root == Path::new("/") && (sys_path.starts_with("/sys/") || sys_path.starts_with("/proc/"));
        let text = if live { read_budgeted(path, self.budget)? } else { std::fs::read_to_string(path)? };
        Ok(text.trim().to_string())
    }

    /// Raw bytes of a (binary) file, at most `max`.
    pub fn read_bytes(&self, sys_path: &str, max: usize) -> Result<Vec<u8>, ProbeError> {
        use std::io::Read;
        let mut v = Vec::new();
        std::fs::File::open(self.path(sys_path))?.take(max as u64).read_to_end(&mut v)?;
        Ok(v)
    }

    /// Last path component of a symlink's target (e.g. the driver name behind `.../driver`, the BDF behind a
    /// `device` link). Targets such as `../..` have no name of their own and are resolved to the real path.
    pub fn link_name(&self, sys_path: &str) -> Option<String> {
        let p = self.path(sys_path);
        let direct = std::fs::read_link(&p).ok().and_then(|t| t.file_name().map(|n| n.to_string_lossy().into_owned()));
        direct.or_else(|| std::fs::canonicalize(&p).ok().and_then(|t| t.file_name().map(|n| n.to_string_lossy().into_owned())))
    }

    pub fn exists(&self, sys_path: &str) -> bool {
        self.path(sys_path).exists()
    }

    pub fn read_opt(&self, sys_path: &str) -> Option<String> {
        self.read_trim(sys_path).ok().filter(|s| !s.is_empty())
    }

    pub fn list_dir(&self, sys_path: &str) -> Result<Vec<String>, ProbeError> {
        list_dir(&self.path(sys_path))
    }
}

type ReadReq = (PathBuf, std::sync::mpsc::Sender<io::Result<String>>);

thread_local! {
    /// One helper thread per calling thread, created on first use and replaced after a timeout (a helper stuck in
    /// the kernel is abandoned; it exits when its request channel closes). Saves a thread spawn per sysfs read.
    static WORKER: std::cell::RefCell<Option<std::sync::mpsc::Sender<ReadReq>>> = const { std::cell::RefCell::new(None) };
}

fn spawn_worker() -> std::sync::mpsc::Sender<ReadReq> {
    let (tx, rx) = std::sync::mpsc::channel::<ReadReq>();
    std::thread::Builder::new()
        .name("probe-read".into())
        .stack_size(128 * 1024)
        .spawn(move || {
            for (path, reply) in rx {
                let _ = reply.send(std::fs::read_to_string(&path));
            }
        })
        .expect("spawn probe reader");
    tx
}

fn read_budgeted(path: PathBuf, budget: Duration) -> Result<String, ProbeError> {
    WORKER.with(|w| {
        let mut slot = w.borrow_mut();
        let (rtx, rrx) = std::sync::mpsc::channel();
        // a worker whose receiver is gone (it died) rejects the send: replace it once
        let mut req = (path, rtx);
        loop {
            let tx = slot.get_or_insert_with(spawn_worker);
            match tx.send(req) {
                Ok(()) => break,
                Err(std::sync::mpsc::SendError(r)) => {
                    *slot = None;
                    req = r;
                }
            }
        }
        match rrx.recv_timeout(budget) {
            Ok(r) => Ok(r?),
            Err(_) => {
                *slot = None; // abandon the stuck helper
                Err(ProbeError::Timeout)
            }
        }
    })
}

pub fn list_dir(p: &Path) -> Result<Vec<String>, ProbeError> {
    let mut v: Vec<String> =
        std::fs::read_dir(p)?.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    v.sort();
    Ok(v)
}

/// Parse "0x1af4" / "1af4" / "0x00000002" (sysfs hex attributes).
pub fn parse_hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex() {
        assert_eq!(parse_hex("0x1af4\n"), Some(0x1af4));
        assert_eq!(parse_hex("8086"), Some(0x8086));
        assert_eq!(parse_hex("zz"), None);
    }

    #[test]
    fn fixture_reads_and_missing_is_not_found() {
        let c = ProbeCtx::fixture("/nonexistent-root");
        assert!(matches!(c.read_trim("/proc/uptime"), Err(ProbeError::NotFound(_))));
        assert_eq!(c.read_opt("/proc/uptime"), None);
    }

    #[test]
    fn live_read_with_budget_works_and_times_out_on_blocked_fifo() {
        let live = ProbeCtx::live();
        assert!(live.read_trim("/proc/uptime").is_ok());
        // a FIFO with no writer blocks open() for ever: the budget must turn that into Timeout
        let mut c = ProbeCtx::fixture("/");
        c.root = PathBuf::from("/");
        c.budget = Duration::from_millis(100);
        let p = std::env::temp_dir().join(format!("i7ll-fifo-{}", std::process::id()));
        let cs = std::ffi::CString::new(p.to_string_lossy().as_bytes()).unwrap();
        extern "C" {
            fn mkfifo(path: *const i8, mode: u32) -> i32;
        }
        // SAFETY: valid NUL-terminated path.
        assert_eq!(unsafe { mkfifo(cs.as_ptr() as *const i8, 0o600) }, 0);
        // the budgeted path only applies under /sys and /proc, so call the helper directly
        let r = read_budgeted(p.clone(), Duration::from_millis(100));
        assert!(matches!(r, Err(ProbeError::Timeout)));
        let _ = std::fs::remove_file(&p);
    }
}
