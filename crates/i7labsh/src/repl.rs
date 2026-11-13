//! The read-eval loop: raw-mode line editing on a terminal, plain line reading otherwise.

use std::io::{BufRead, Read, Write};

use crate::edit::{Completer, Edit, Editor, KeyDecoder};
use crate::{builtins, ffi, Shell};

/// `i7lab-abc123:/path# ` with colour; the visible width never matters (redraw is relative to the line end).
pub fn prompt(sh: &Shell) -> String {
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname").map(|s| s.trim().to_string()).unwrap_or_else(|_| "i7lab".into());
    let cwd = sh.cwd.display().to_string();
    let cwd = match sh.get_var("HOME") {
        Some(h) if !h.is_empty() && h != "/" && (cwd == h || cwd.starts_with(&format!("{h}/"))) => format!("~{}", &cwd[h.len()..]),
        _ => cwd,
    };
    let (col, sym) = if sh.last_status == 0 { ("32", '#') } else { ("31", '#') };
    format!("\x1b[1;{col}m{host}\x1b[0m:{cwd}{sym} ")
}

pub fn banner() -> String {
    format!(
        "\x1b[1mi7lablinux {}\x1b[0m shell. Type help for the builtins; ^D or exit leaves the shell.\n",
        labproto::VERSION
    )
}

struct ShellCompleter {
    path: String,
}

impl Completer for ShellCompleter {
    fn commands(&self, prefix: &str) -> Vec<String> {
        let mut v: Vec<String> = builtins().iter().map(|b| b.name.to_string()).filter(|n| n.starts_with(prefix)).collect();
        for dir in self.path.split(':').filter(|d| !d.is_empty()) {
            if let Ok(rd) = std::fs::read_dir(dir) {
                v.extend(rd.flatten().filter_map(|e| e.file_name().into_string().ok()).filter(|n| n.starts_with(prefix)));
            }
        }
        v
    }
    fn entries(&self, dir: &str) -> Vec<String> {
        let d = if dir.is_empty() { "." } else { dir };
        let Ok(rd) = std::fs::read_dir(d) else { return Vec::new() };
        rd.flatten()
            .filter_map(|e| {
                let n = e.file_name().into_string().ok()?;
                let is_dir = e.path().is_dir();
                Some(if is_dir { format!("{n}/") } else { n })
            })
            .collect()
    }
}

/// Restores the terminal mode on drop (also when a builtin panics through `read_line`).
struct RawGuard {
    fd: i32,
    saved: ffi::Termios,
}

impl RawGuard {
    fn enter(fd: i32) -> Option<RawGuard> {
        let saved = ffi::get_termios(fd)?;
        ffi::set_termios(fd, &saved.raw()).ok()?;
        Some(RawGuard { fd, saved })
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        let _ = ffi::set_termios(self.fd, &self.saved);
    }
}

enum Read_ {
    Line(String),
    Interrupt,
    Eof,
}

fn out(s: &str) {
    let mut o = std::io::stdout();
    let _ = o.write_all(s.as_bytes());
    let _ = o.flush();
}

/// Read one line with editing. Falls back to a plain read when stdin cannot go raw.
fn read_line_tty(ed: &mut Editor, prompt: &str, comp: &dyn Completer) -> Read_ {
    let Some(_raw) = RawGuard::enter(0) else { return read_line_plain() };
    ed.reset();
    let mut dec = KeyDecoder::default();
    out(&ed.render(prompt));
    let mut stdin = std::io::stdin().lock();
    let mut b = [0u8; 1];
    loop {
        match stdin.read(&mut b) {
            Ok(0) => return Read_::Eof,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Read_::Eof,
        }
        let Some(key) = dec.feed(b[0]) else { continue };
        match ed.feed(key, comp) {
            Edit::None => {}
            Edit::Redraw => out(&ed.render(prompt)),
            Edit::Line(l) => {
                out("\r\n");
                return Read_::Line(l);
            }
            Edit::Interrupt => {
                out("^C\r\n");
                return Read_::Interrupt;
            }
            Edit::Eof => {
                out("\r\n");
                return Read_::Eof;
            }
            Edit::Clear => out(&format!("\x1b[H\x1b[2J{}", ed.render(prompt))),
            Edit::Candidates(c) => {
                out("\r\n");
                out(&c.join("  "));
                out("\r\n");
                out(&ed.render(prompt));
            }
        }
    }
}

fn read_line_plain() -> Read_ {
    let mut s = String::new();
    match std::io::stdin().lock().read_line(&mut s) {
        Ok(0) | Err(_) => Read_::Eof,
        Ok(_) => Read_::Line(s.trim_end_matches(['\n', '\r']).to_string()),
    }
}

impl Shell {
    /// Interactive loop on stdin (a terminal gets the line editor and prompt); returns the exit status.
    pub fn repl(&mut self) -> i32 {
        let tty = ffi::is_tty(0);
        if tty {
            ffi::install_sigint_flag();
        }
        let mut ed = Editor::new();
        loop {
            let line = if tty {
                let comp = ShellCompleter { path: self.get_var("PATH").unwrap_or(crate::DEFAULT_PATH).to_string() };
                read_line_tty(&mut ed, &prompt(self), &comp)
            } else {
                read_line_plain()
            };
            match line {
                Read_::Line(l) => {
                    ffi::take_interrupt();
                    self.run_line(&l);
                    ffi::take_interrupt();
                    if let Some(c) = self.exit_requested {
                        return c;
                    }
                }
                Read_::Interrupt => self.last_status = 130,
                Read_::Eof => return self.last_status,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prompt_shows_tilde_and_status_colour() {
        let mut sh = Shell::new(false);
        sh.set("HOME", "/root");
        sh.cwd = "/root/lab".into();
        sh.last_status = 0;
        assert!(prompt(&sh).contains(":~/lab# "));
        assert!(prompt(&sh).contains("1;32m"));
        sh.cwd = "/etc".into();
        sh.last_status = 1;
        let p = prompt(&sh);
        assert!(p.contains(":/etc# ") && p.contains("1;31m"));
        sh.set("HOME", "/");
        sh.cwd = "/etc".into();
        assert!(prompt(&sh).contains(":/etc# "), "HOME=/ must not turn every path into ~...");
    }
    #[test]
    fn banner_mentions_help() {
        assert!(banner().contains("help"));
    }
}
