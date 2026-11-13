//! Audit log of every non-read-only command. Owner: P6a.
//! The file (`labprobe::block::AUDIT_LOG`, shared with i7labsh's block writes) is opened ONCE with O_APPEND
//! and kept as a daemon-internal fd; the path policy denies `put`/`fs.rm` under /run/i7lab for every role.
//! Each line is also published on the EventBus so `logs --audit -f` ships it off-box live. Honest limit
//! (review security F11): an admin-key holder can still stop future logging on the box itself (exec); the
//! off-box copy is the integrity control.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use labproto::Status;

use crate::registry::Source;

pub struct Audit {
    path: PathBuf,
    file: Mutex<Option<std::fs::File>>,
    recent: Mutex<Vec<String>>,
}

impl Audit {
    pub fn new(path: &Path) -> Audit {
        let file = std::fs::OpenOptions::new().create(true).append(true).open(path).ok();
        Audit { path: path.to_path_buf(), file: Mutex::new(file), recent: Mutex::new(Vec::new()) }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// One line: unix time, source, actor, command, argv (sanitised), status. Kept in RAM (last 256) and appended to the file.
    pub fn record(&self, source: &Source, actor: &str, cmd: &str, args: &[String], status: Status) -> String {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let argv: Vec<String> = args.iter().map(|a| labproto::text::sanitize(a).into_owned()).collect();
        let line = format!("{} {} actor={} cmd={} args={:?} status={}", t, source.describe(), actor, cmd, argv, status.name());
        if let Some(f) = self.file.lock().unwrap().as_mut() {
            let _ = writeln!(f, "{}", line);
        }
        let mut r = self.recent.lock().unwrap();
        if r.len() >= 256 {
            r.remove(0);
        }
        r.push(line.clone());
        line
    }

    pub fn recent(&self, n: usize) -> Vec<String> {
        let r = self.recent.lock().unwrap();
        r[r.len().saturating_sub(n)..].to_vec()
    }
}
