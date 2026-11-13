//! Process spawning for the supervisor: the daemon (output into the log ring) and console shells.

use std::ffi::CString;
use std::io::{self, BufRead, Read};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

pub const DAEMON: &str = "/sbin/i7labd";
pub const SHELL: &str = "/bin/i7labsh";
pub const PATH_ENV: &str = "/sbin:/bin";

fn base(cmd: &mut Command) {
    cmd.env_clear().env("PATH", PATH_ENV).env("HOME", "/root").env("TERM", "linux");
}

/// Forward lines of a child's pipe into the ring (capped line length so a binary spew cannot grow memory).
fn pump<R: Read + Send + 'static>(name: &'static str, r: R) {
    std::thread::spawn(move || {
        let mut rd = io::BufReader::new(r);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match rd.by_ref().take(4096).read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let s = String::from_utf8_lossy(&buf);
                    crate::log::service_line(name, s.trim_end_matches(['\n', '\r']));
                }
            }
        }
    });
}

pub fn daemon(tui_off: bool) -> io::Result<i32> {
    let mut c = Command::new(DAEMON);
    base(&mut c);
    if tui_off {
        c.env("I7LAB_TUI", "off");
    }
    c.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn()?;
    let pid = child.id() as i32;
    if let Some(o) = child.stdout.take() {
        pump("i7labd", o);
    }
    if let Some(e) = child.stderr.take() {
        pump("i7labd", e);
    }
    // Dropping `child` neither waits nor kills; the reaper in main collects the exit status.
    Ok(pid)
}

/// Console shell on `/dev/<tty>` as session leader with that tty as controlling terminal.
pub fn shell(tty: &str) -> io::Result<i32> {
    let node = CString::new(format!("/dev/{}", tty)).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if tty == "tty1" {
        crate::ffi::activate_vt(1);
    }
    let mut c = Command::new(SHELL);
    base(&mut c);
    c.arg("-l").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    // SAFETY: the closure runs between fork and exec and only makes async-signal-safe syscalls on a prebuilt CString.
    unsafe {
        c.pre_exec(move || crate::ffi::become_tty_session_leader(&node));
    }
    Ok(c.spawn()?.id() as i32)
}
