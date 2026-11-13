//! Detached jobs (`exec --detach`): children of i7labd in their own process group with stdout+stderr in
//! `<run_dir>/jobs/<id>`; they survive the session that started them (PROTOCOL.md section 5). Owner: P6a.

use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use crate::exec::{build_command, ExecSpec};
use crate::ffi;

#[derive(Clone, Debug)]
pub struct Job {
    pub id: u32,
    pub cmd: String,
    pub pid: Option<i32>,
    /// "running" | "exited" | "killed"
    pub state: String,
    pub exit_code: Option<i32>,
    pub started_unix: u64,
}

pub const MAX_JOBS: usize = 64;

#[derive(Default)]
pub struct Jobs {
    pub list: Arc<Mutex<Vec<Job>>>,
    next: AtomicU32,
}

pub fn jobs_dir(run_dir: &Path) -> PathBuf {
    run_dir.join("jobs")
}

pub fn output_path(run_dir: &Path, id: u32) -> PathBuf {
    jobs_dir(run_dir).join(id.to_string())
}

impl Jobs {
    /// Start `spec` detached. Errors: spawn failure, too many running jobs.
    pub fn start(&self, spec: &ExecSpec, run_dir: &Path) -> std::io::Result<u32> {
        {
            let l = self.list.lock().unwrap();
            if l.iter().filter(|j| j.state == "running").count() >= MAX_JOBS {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "too many running jobs"));
            }
        }
        std::fs::create_dir_all(jobs_dir(run_dir))?;
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let out = std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(output_path(run_dir, id))?;
        let mut cmd = build_command(spec);
        cmd.process_group(0).stdin(Stdio::null()).stdout(out.try_clone()?).stderr(out);
        let mut child = cmd.spawn()?;
        let pid = child.id() as i32;
        let started_unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        self.list.lock().unwrap().push(Job { id, cmd: spec.argv.join(" "), pid: Some(pid), state: "running".into(), exit_code: None, started_unix });
        let list = self.list.clone();
        std::thread::spawn(move || {
            let st = child.wait();
            let _ = ffi::killpg(pid, ffi::SIGKILL);
            let mut l = list.lock().unwrap();
            if let Some(j) = l.iter_mut().find(|j| j.id == id) {
                j.pid = None;
                match st {
                    Ok(s) => {
                        j.exit_code = s.code().or(s.signal().map(|x| 128 + x));
                        if j.state != "killed" {
                            j.state = "exited".into();
                        }
                    }
                    Err(_) => j.state = "exited".into(),
                }
            }
        });
        Ok(id)
    }

    pub fn snapshot(&self) -> Vec<Job> {
        self.list.lock().unwrap().clone()
    }

    /// SIGTERM the job's group (SIGKILL if `force`). `Err` = no such running job.
    pub fn kill(&self, id: u32, force: bool) -> Result<(), &'static str> {
        let mut l = self.list.lock().unwrap();
        let j = l.iter_mut().find(|j| j.id == id).ok_or("no such job")?;
        let pid = j.pid.ok_or("job is not running")?;
        j.state = "killed".into();
        ffi::killpg(pid, if force { ffi::SIGKILL } else { ffi::SIGTERM }).map_err(|_| "signal failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("i7labd-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn wait_state(j: &Jobs, id: u32, state: &str) -> Job {
        let t = Instant::now();
        loop {
            let s = j.snapshot().into_iter().find(|x| x.id == id).unwrap();
            if s.state == state || t.elapsed() > Duration::from_secs(5) {
                return s;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn job_runs_and_logs() {
        let d = tmpdir("job1");
        let j = Jobs::default();
        let spec = ExecSpec { argv: vec!["/bin/sh".into(), "-c".into(), "echo hi; echo e >&2; exit 4".into()], ..Default::default() };
        let id = j.start(&spec, &d).unwrap();
        let s = wait_state(&j, id, "exited");
        assert_eq!((s.state.as_str(), s.exit_code), ("exited", Some(4)));
        assert_eq!(std::fs::read_to_string(output_path(&d, id)).unwrap(), "hi\ne\n");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn job_kill() {
        let d = tmpdir("job2");
        let j = Jobs::default();
        let id = j.start(&ExecSpec { argv: vec!["/bin/sleep".into(), "30".into()], ..Default::default() }, &d).unwrap();
        j.kill(id, false).unwrap();
        let t = Instant::now();
        let s = loop {
            let s = j.snapshot().into_iter().find(|x| x.id == id).unwrap();
            if s.exit_code.is_some() || t.elapsed() > Duration::from_secs(5) {
                break s;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(s.state, "killed");
        assert_eq!(s.exit_code, Some(128 + 15));
        assert!(j.kill(id, false).is_err());
        assert!(j.kill(999, false).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
