//! i7labsh: the minimal shell of i7lablinux (PLAN.md section 4.6). No busybox: every applet is a builtin here.
//! Owner: P8 (implemented under task I6).
//!
//! * grammar: words, quotes, `$VAR`, `~`, globs, `|`, `<` `>` `>>` `N>` `2>&1`, `;`, `&&`, `||`, comments
//!   (`parse`, `expand`); no background jobs, subshells, command substitution or control flow (clear parse errors);
//! * execution (`exec`): builtins and external programs in pipelines without forking a shell; a builtin that is not
//!   the only stage of a pipeline runs in a thread over a clone of the shell state (like a subshell);
//! * the line editor (`edit`, `repl`): cursor keys, history, kill keys, tab completion;
//! * builtins (`builtins`): the v1 list of PLAN.md section 4.6.
//!
//! All variables are exported: assignments go into `Shell::env`, which is the environment of every child.

use std::path::PathBuf;

pub mod builtins;
pub mod edit;
pub mod exec;
pub mod expand;
mod ffi;
pub mod parse;
pub mod repl;

pub use parse::{parse, List, ParseError, Pipeline};

pub type RawFd = i32;

/// The three file descriptors a builtin works with. Builtins never touch fds 0-2 directly, so redirections and
/// pipes work for them exactly as for external programs.
#[derive(Clone, Copy, Debug)]
pub struct Io {
    pub stdin: RawFd,
    pub stdout: RawFd,
    pub stderr: RawFd,
}

fn borrowed(fd: RawFd) -> std::mem::ManuallyDrop<std::fs::File> {
    use std::os::unix::io::FromRawFd;
    // SAFETY: the Io owner keeps `fd` open for the duration of the builtin; ManuallyDrop means we never close it.
    std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) })
}

fn write_all_fd(fd: RawFd, mut b: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = borrowed(fd);
    while !b.is_empty() {
        match f.write(b) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero)),
            Ok(n) => b = &b[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                if ffi::interrupted() {
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

impl Io {
    pub fn std() -> Io {
        Io { stdin: 0, stdout: 1, stderr: 2 }
    }
    /// Write to stdout. A failure (closed pipe) is reported by `try_out`; builtins that can loop use that.
    pub fn out(&mut self, s: &str) {
        let _ = self.write_out(s.as_bytes());
    }
    pub fn err(&mut self, s: &str) {
        let _ = write_all_fd(self.stderr, s.as_bytes());
    }
    pub fn write_out(&mut self, b: &[u8]) -> std::io::Result<()> {
        write_all_fd(self.stdout, b)
    }
    /// `false` once stdout is gone (EPIPE): stop producing output.
    pub fn try_out(&mut self, s: &str) -> bool {
        self.write_out(s.as_bytes()).is_ok()
    }
    /// One read from stdin; `Interrupted` is returned only when ^C arrived.
    pub fn read_in(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::Read;
        let mut f = borrowed(self.stdin);
        loop {
            match f.read(buf) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted && !ffi::interrupted() => continue,
                r => return r,
            }
        }
    }
    pub fn read_all_in(&mut self) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = self.read_in(&mut buf)?;
            if n == 0 {
                return Ok(out);
            }
            out.extend_from_slice(&buf[..n]);
        }
    }
}

pub struct BuiltinSpec {
    pub name: &'static str,
    pub usage: &'static str,
    pub run: fn(&mut Shell, &[String], &mut Io) -> i32,
}

#[derive(Clone)]
pub struct Shell {
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
    pub last_status: i32,
    pub interactive: bool,
    pub exit_requested: Option<i32>,
    /// running as a pipeline stage over a clone: state changes (cd, exit, export) must not reach the process
    pub subshell: bool,
}

pub const DEFAULT_PATH: &str = "/sbin:/bin";

pub fn builtins() -> &'static [BuiltinSpec] {
    builtins::TABLE
}

pub fn find_builtin(name: &str) -> Option<&'static BuiltinSpec> {
    builtins().iter().find(|b| b.name == name)
}

impl Shell {
    pub fn new(interactive: bool) -> Shell {
        let mut env: Vec<(String, String)> = std::env::vars().collect();
        let mut sh = Shell {
            env: Vec::new(),
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
            last_status: 0,
            interactive,
            exit_requested: None,
            subshell: false,
        };
        std::mem::swap(&mut sh.env, &mut env);
        if sh.get_var("PATH").is_none() {
            sh.set("PATH", DEFAULT_PATH);
        }
        if sh.get_var("HOME").is_none() {
            sh.set("HOME", "/root");
        }
        if sh.get_var("TERM").is_none() {
            sh.set("TERM", "linux");
        }
        let cwd = sh.cwd.display().to_string();
        sh.set("PWD", &cwd);
        sh
    }

    /// Plain environment lookup.
    pub fn get_var(&self, name: &str) -> Option<&str> {
        self.env.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// Lookup as the expander sees it: `$?` and `$$` are special.
    pub fn lookup(&self, name: &str) -> Option<String> {
        match name {
            "?" => Some(self.last_status.to_string()),
            "$" => Some(ffi::pid().to_string()),
            _ => self.get_var(name).map(str::to_string),
        }
    }

    pub fn set(&mut self, name: &str, value: &str) {
        match self.env.iter_mut().find(|(k, _)| k == name) {
            Some(e) => e.1 = value.to_string(),
            None => self.env.push((name.to_string(), value.to_string())),
        }
    }

    pub fn unset(&mut self, name: &str) {
        self.env.retain(|(k, _)| k != name);
    }

    pub fn home(&self) -> String {
        self.get_var("HOME").unwrap_or("/root").to_string()
    }

    /// Parse and run one line (or a whole multi-line script) with the process's own stdio.
    pub fn run_line(&mut self, line: &str) -> i32 {
        self.run_line_io(line, &Io::std())
    }

    pub fn run_line_io(&mut self, line: &str, io: &Io) -> i32 {
        match parse(line) {
            Ok(list) => self.run_list(&list, io),
            Err(e) => {
                let mut io = *io;
                io.err(&format!("i7labsh: syntax error: {}\n", e.0));
                self.last_status = 2;
                2
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;
    use std::os::unix::io::AsRawFd;
    use std::sync::atomic::{AtomicU32, Ordering};

    static N: AtomicU32 = AtomicU32::new(0);

    /// A unique scratch directory under the system temp dir, removed on drop.
    pub struct Tmp(pub PathBuf);
    impl Tmp {
        pub fn new() -> Tmp {
            let p = std::env::temp_dir().join(format!("i7labsh-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
        pub fn path(&self, n: &str) -> String {
            self.0.join(n).display().to_string()
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Run `line` with stdout and stderr captured into files; returns (status, stdout, stderr). stdin is /dev/null.
    pub fn run(sh: &mut Shell, line: &str) -> (i32, String, String) {
        let t = Tmp::new();
        let out = std::fs::File::create(t.path("out")).unwrap();
        let err = std::fs::File::create(t.path("err")).unwrap();
        let inp = std::fs::File::open("/dev/null").unwrap();
        let io = Io { stdin: inp.as_raw_fd(), stdout: out.as_raw_fd(), stderr: err.as_raw_fd() };
        let st = sh.run_line_io(line, &io);
        (st, std::fs::read_to_string(t.path("out")).unwrap(), std::fs::read_to_string(t.path("err")).unwrap())
    }

    pub fn sh() -> Shell {
        let mut s = Shell::new(false);
        s.set("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        s
    }
}
