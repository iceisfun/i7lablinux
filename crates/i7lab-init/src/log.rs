//! PID 1 log: a bounded in-memory ring (also mirrored to /run/i7lab/init.log), /dev/kmsg, and the console while no
//! TUI owns it. Service output lines go into the same ring. Never panics, never blocks on a full disk.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

pub const RING_BYTES: usize = 256 * 1024;
pub const LOG_FILE: &str = "/run/i7lab/init.log";

/// Byte-bounded line ring: the oldest lines go first.
pub struct Ring {
    cap: usize,
    lines: VecDeque<String>,
    bytes: usize,
    dirty: bool,
}

impl Ring {
    pub fn new(cap: usize) -> Ring {
        Ring { cap, lines: VecDeque::new(), bytes: 0, dirty: false }
    }
    pub fn push(&mut self, line: &str) {
        // a single oversized line is truncated at a char boundary so the cap holds
        let mut l = line.trim_end_matches('\n');
        if l.len() > self.cap / 4 {
            let mut e = self.cap / 4;
            while !l.is_char_boundary(e) {
                e -= 1;
            }
            l = &l[..e];
        }
        self.bytes += l.len() + 1;
        self.lines.push_back(l.to_string());
        while self.bytes > self.cap {
            match self.lines.pop_front() {
                Some(old) => self.bytes -= old.len() + 1,
                None => break,
            }
        }
        self.dirty = true;
    }
    pub fn text(&self) -> String {
        let mut s = String::with_capacity(self.bytes);
        for l in &self.lines {
            s.push_str(l);
            s.push('\n');
        }
        s
    }
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.lines.len()
    }
    pub fn take_dirty(&mut self) -> bool {
        std::mem::replace(&mut self.dirty, false)
    }
}

static RING: OnceLock<Mutex<Ring>> = OnceLock::new();
static KMSG: OnceLock<Mutex<Option<std::fs::File>>> = OnceLock::new();
static ECHO: AtomicBool = AtomicBool::new(true);

fn ring() -> &'static Mutex<Ring> {
    RING.get_or_init(|| Mutex::new(Ring::new(RING_BYTES)))
}

/// Echo to stderr (the console) while true. Cleared once the TUI owns tty1, or in debug mode where the kernel
/// already prints /dev/kmsg at loglevel 7.
pub fn set_echo(on: bool) {
    ECHO.store(on, Ordering::Relaxed);
}

pub fn uptime_s() -> f64 {
    std::fs::read_to_string("/proc/uptime").ok().and_then(|s| s.split_whitespace().next().and_then(|x| x.parse().ok())).unwrap_or(0.0)
}

pub fn format_line(up_s: f64, who: &str, msg: &str) -> String {
    format!("[{:9.3}] {}: {}", up_s, who, msg)
}

/// Log one line from init itself.
pub fn line(msg: &str) {
    let l = format_line(uptime_s(), "init", msg);
    push(&l);
    kmsg(msg);
    if ECHO.load(Ordering::Relaxed) {
        let _ = writeln!(std::io::stderr(), "i7lab-init: {}", msg);
    }
}

/// One output line of a supervised service (stdout/stderr pipe readers call this).
pub fn service_line(svc: &str, msg: &str) {
    push(&format_line(uptime_s(), svc, msg));
}

fn push(l: &str) {
    if let Ok(mut r) = ring().lock() {
        r.push(l);
    }
}

fn kmsg(msg: &str) {
    let k = KMSG.get_or_init(|| Mutex::new(std::fs::OpenOptions::new().write(true).open("/dev/kmsg").ok()));
    if let Ok(mut g) = k.lock() {
        if let Some(f) = g.as_mut() {
            // <6> = KERN_INFO; one write = one record
            let _ = f.write_all(format!("<6>i7lab-init: {}\n", msg.replace('\n', " ")).as_bytes());
        }
    }
}

/// Mirror the ring to LOG_FILE when it changed (tmpfs; rewritten whole, bounded by RING_BYTES).
pub fn flush() {
    let text = match ring().lock() {
        Ok(mut r) => {
            if !r.take_dirty() {
                return;
            }
            r.text()
        }
        Err(_) => return,
    };
    let tmp = format!("{}.tmp", LOG_FILE);
    if std::fs::write(&tmp, text).is_ok() {
        let _ = std::fs::rename(&tmp, LOG_FILE);
    }
}

#[macro_export]
macro_rules! logf {
    ($($a:tt)*) => { $crate::log::line(&format!($($a)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ring_is_byte_bounded_and_drops_oldest() {
        let mut r = Ring::new(100);
        for i in 0..50 {
            r.push(&format!("line {i:02}"));
        }
        assert!(r.text().len() <= 100);
        assert!(r.text().ends_with("line 49\n"));
        assert!(!r.text().contains("line 00"));
    }
    #[test]
    fn oversized_line_is_truncated_on_a_char_boundary() {
        let mut r = Ring::new(40);
        r.push(&"é".repeat(100));
        assert!(r.text().len() <= 41);
        assert!(r.len() == 1);
    }
    #[test]
    fn dirty_flag() {
        let mut r = Ring::new(100);
        assert!(!r.take_dirty());
        r.push("x");
        assert!(r.take_dirty());
        assert!(!r.take_dirty());
    }
    #[test]
    fn line_format() {
        assert_eq!(format_line(1.5, "i7labd", "up"), "[    1.500] i7labd: up");
    }
}
