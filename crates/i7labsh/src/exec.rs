//! Execution: lists (`;` `&&` `||`), pipelines of builtins and external programs, redirections.
//!
//! A stage is prepared completely (words expanded, redirections opened) before anything runs, so a bad redirect
//! aborts the whole pipeline with status 1 and nothing started. fds are `OwnedFd`s that move into exactly one stage,
//! so when a stage ends its pipe ends close and the neighbours see EOF / EPIPE.

use std::fs::OpenOptions;
use std::os::unix::io::{AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::JoinHandle;

use crate::expand::{expand_one, expand_words, fs_list};
use crate::parse::{Command as Cmd, Conn, List, Pipeline, RedirOp};
use crate::{find_builtin, BuiltinSpec, Io, Shell, DEFAULT_PATH};

struct Stage {
    argv: Vec<String>,
    assigns: Vec<(String, String)>,
    fds: [OwnedFd; 3],
}

enum Running {
    Done(i32),
    Child(Child),
    Thread(JoinHandle<i32>),
}

fn dup_fd(fd: i32) -> std::io::Result<OwnedFd> {
    // SAFETY: the caller's Io keeps `fd` open while the pipeline is prepared.
    unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()
}

/// `PATH` search. A word with a slash is used as is.
pub fn find_in_path(name: &str, path: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    if name.contains('/') {
        return Some(PathBuf::from(name));
    }
    for dir in path.split(':') {
        let dir = if dir.is_empty() { "." } else { dir };
        let c = PathBuf::from(dir).join(name);
        if let Ok(m) = std::fs::metadata(&c) {
            if m.is_file() && m.permissions().mode() & 0o111 != 0 {
                return Some(c);
            }
        }
    }
    None
}

fn status_of(s: std::process::ExitStatus) -> i32 {
    s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0))
}

impl Shell {
    pub fn run_list(&mut self, list: &List, io: &Io) -> i32 {
        for (conn, p) in &list.items {
            if self.exit_requested.is_some() {
                break;
            }
            let run = match conn {
                Conn::Seq => true,
                Conn::And => self.last_status == 0,
                Conn::Or => self.last_status != 0,
            };
            if run {
                self.last_status = self.run_pipeline(p, io);
            }
        }
        self.last_status
    }

    fn prepare(&mut self, cmd: &Cmd, idx: usize, n: usize, pipes: &mut [(Option<OwnedFd>, Option<OwnedFd>)], io: &Io) -> Result<Stage, String> {
        let var = |name: &str| self.lookup(name);
        let home = self.home();
        let argv = expand_words(&cmd.words, &var, &home, &fs_list);
        let assigns: Vec<(String, String)> = cmd.assigns.iter().map(|(k, w)| (k.clone(), expand_one(w, &var, &home))).collect();

        let e = |e: std::io::Error| e.to_string();
        let stdin = if idx == 0 { dup_fd(io.stdin).map_err(e)? } else { pipes[idx - 1].0.take().ok_or("pipe")? };
        let stdout = if idx + 1 == n { dup_fd(io.stdout).map_err(e)? } else { pipes[idx].1.take().ok_or("pipe")? };
        let mut fds = [stdin, stdout, dup_fd(io.stderr).map_err(e)?];

        for r in &cmd.redirs {
            if !(0..=2).contains(&r.fd) {
                return Err(format!("redirection of fd {} is not supported (only 0, 1, 2)", r.fd));
            }
            let target = expand_one(&r.target, &var, &home);
            let slot = r.fd as usize;
            fds[slot] = match r.op {
                RedirOp::In => OwnedFd::from(std::fs::File::open(&target).map_err(|x| format!("{target}: {x}"))?),
                RedirOp::Out => OwnedFd::from(OpenOptions::new().write(true).create(true).truncate(true).open(&target).map_err(|x| format!("{target}: {x}"))?),
                RedirOp::Append => OwnedFd::from(OpenOptions::new().write(true).create(true).append(true).open(&target).map_err(|x| format!("{target}: {x}"))?),
                RedirOp::Dup => {
                    let m: usize = target.parse().ok().filter(|m| *m <= 2).ok_or_else(|| format!("bad file descriptor '{target}'"))?;
                    fds[m].try_clone().map_err(e)?
                }
            };
        }
        Ok(Stage { argv, assigns, fds })
    }

    pub fn run_pipeline(&mut self, p: &Pipeline, io: &Io) -> i32 {
        let n = p.cmds.len();
        let mut errio = *io;
        let mut pipes: Vec<(Option<OwnedFd>, Option<OwnedFd>)> = Vec::new();
        for _ in 1..n {
            match std::io::pipe() {
                Ok((r, w)) => pipes.push((Some(OwnedFd::from(r)), Some(OwnedFd::from(w)))),
                Err(e) => {
                    errio.err(&format!("i7labsh: pipe: {e}\n"));
                    return 1;
                }
            }
        }
        let mut stages = Vec::new();
        for (i, c) in p.cmds.iter().enumerate() {
            match self.prepare(c, i, n, &mut pipes, io) {
                Ok(s) => stages.push(s),
                Err(m) => {
                    errio.err(&format!("i7labsh: {m}\n"));
                    return 1;
                }
            }
        }

        let mut running = Vec::new();
        for st in stages {
            running.push(self.start(st, n == 1, &mut errio));
        }
        let mut status = 0;
        for r in running {
            status = match r {
                Running::Done(c) => c,
                Running::Child(mut c) => match c.wait() {
                    Ok(s) => status_of(s),
                    Err(_) => 1,
                },
                Running::Thread(h) => h.join().unwrap_or(101),
            };
        }
        if crate::ffi::take_interrupt() && status == 0 {
            status = 130;
        }
        status
    }

    fn start(&mut self, st: Stage, alone: bool, errio: &mut Io) -> Running {
        let Stage { argv, assigns, fds } = st;
        let [fin, fout, ferr] = fds;
        let Some(name) = argv.first() else {
            // assignments only (or only redirections, which already created/truncated their files)
            if alone && !self.subshell {
                for (k, v) in &assigns {
                    self.set(k, v);
                }
            }
            return Running::Done(0);
        };

        if let Some(spec) = find_builtin(name) {
            return if alone { self.run_builtin_inline(spec, argv, assigns, [fin, fout, ferr]) } else { self.run_builtin_thread(spec, argv, assigns, [fin, fout, ferr]) };
        }

        let path = self.get_var("PATH").unwrap_or(DEFAULT_PATH).to_string();
        let Some(exe) = find_in_path(name, &path) else {
            errio.err(&format!("i7labsh: {name}: not found\n"));
            return Running::Done(127);
        };
        let mut c = Command::new(&exe);
        c.args(&argv[1..]).env_clear().envs(self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        c.envs(assigns.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        c.current_dir(&self.cwd).stdin(Stdio::from(fin)).stdout(Stdio::from(fout)).stderr(Stdio::from(ferr));
        if let Some(a0) = argv.first() {
            c.arg0(a0);
        }
        match c.spawn() {
            Ok(child) => Running::Child(child),
            Err(e) => {
                let code = if e.kind() == std::io::ErrorKind::NotFound { 127 } else { 126 };
                errio.err(&format!("i7labsh: {name}: {e}\n"));
                Running::Done(code)
            }
        }
    }

    fn run_builtin_inline(&mut self, spec: &'static BuiltinSpec, argv: Vec<String>, assigns: Vec<(String, String)>, fds: [OwnedFd; 3]) -> Running {
        let saved: Vec<(String, Option<String>)> = assigns.iter().map(|(k, _)| (k.clone(), self.get_var(k).map(str::to_string))).collect();
        for (k, v) in &assigns {
            self.set(k, v);
        }
        let mut io = Io { stdin: fds[0].as_raw_fd(), stdout: fds[1].as_raw_fd(), stderr: fds[2].as_raw_fd() };
        let st = (spec.run)(self, &argv[1..], &mut io);
        for (k, old) in saved {
            match old {
                Some(v) => self.set(&k, &v),
                None => self.unset(&k),
            }
        }
        drop(fds);
        Running::Done(st)
    }

    fn run_builtin_thread(&mut self, spec: &'static BuiltinSpec, argv: Vec<String>, assigns: Vec<(String, String)>, fds: [OwnedFd; 3]) -> Running {
        let mut sub = self.clone();
        sub.subshell = true;
        sub.exit_requested = None;
        for (k, v) in &assigns {
            sub.set(k, v);
        }
        Running::Thread(std::thread::spawn(move || {
            let mut io = Io { stdin: fds[0].as_raw_fd(), stdout: fds[1].as_raw_fd(), stderr: fds[2].as_raw_fd() };
            let st = (spec.run)(&mut sub, &argv[1..], &mut io);
            drop(fds);
            st
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::testutil::*;

    #[test]
    fn lists_and_status() {
        let mut s = sh();
        assert_eq!(run(&mut s, "echo a; echo b").1, "a\nb\n");
        assert_eq!(run(&mut s, "true && echo yes").1, "yes\n");
        assert_eq!(run(&mut s, "false && echo yes").1, "");
        assert_eq!(run(&mut s, "false || echo no").1, "no\n");
        assert_eq!(run(&mut s, "false && echo x || echo y").1, "y\n");
        assert_eq!(run(&mut s, "true || echo x && echo y").1, "y\n");
        assert_eq!(run(&mut s, "false").0, 1);
        assert_eq!(run(&mut s, "false; echo $?").1, "1\n");
    }

    #[test]
    fn builtin_pipeline_without_a_shell() {
        let mut s = sh();
        let (st, out, _) = run(&mut s, "echo hello | cat");
        assert_eq!((st, out.as_str()), (0, "hello\n"));
        let (_, out, _) = run(&mut s, "echo a b c | wc -w | cat");
        assert_eq!(out.trim(), "3");
    }

    #[test]
    fn external_in_the_pipeline() {
        let mut s = sh();
        let (st, out, _) = run(&mut s, "echo b a | /bin/cat | cat");
        assert_eq!((st, out.as_str()), (0, "b a\n"));
        // exit status is the last stage's
        assert_eq!(run(&mut s, "echo x | false").0, 1);
        assert_eq!(run(&mut s, "false | true").0, 0);
    }

    #[test]
    fn redirections() {
        let mut s = sh();
        let t = Tmp::new();
        let f = t.path("f");
        run(&mut s, &format!("echo one > {f}"));
        run(&mut s, &format!("echo two >> {f}"));
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "one\ntwo\n");
        assert_eq!(run(&mut s, &format!("cat < {f}")).1, "one\ntwo\n");
        // stderr to stdout, then both into a pipe
        let (_, out, err) = run(&mut s, "cat /nonexistent/x 2>&1 | cat");
        assert!(out.contains("/nonexistent/x") && err.is_empty(), "{out:?} {err:?}");
        // order matters: `2>&1 >file` leaves stderr on the original stdout
        let g = t.path("g");
        let (_, out, _) = run(&mut s, &format!("cat /nonexistent/y 2>&1 > {g}"));
        assert!(out.contains("/nonexistent/y"));
        assert_eq!(std::fs::read_to_string(&g).unwrap(), "");
    }

    #[test]
    fn bad_redirect_aborts_the_whole_pipeline() {
        let mut s = sh();
        let (st, out, err) = run(&mut s, "echo hi | cat > /nonexistent-dir/x");
        assert_eq!(st, 1);
        assert_eq!(out, "");
        assert!(err.contains("/nonexistent-dir/x"));
        let (st, _, err) = run(&mut s, "echo hi 3>x");
        assert_eq!(st, 1);
        assert!(err.contains("not supported"));
    }

    #[test]
    fn variables_assignments_and_scoping() {
        let mut s = sh();
        assert_eq!(run(&mut s, "A=hello; echo $A").1, "hello\n");
        assert_eq!(run(&mut s, "B=1 echo $B").1, "\n"); // expanded before the prefix assignment applies, like sh
        // a prefix assignment is visible to the external program and does not stay
        assert_eq!(run(&mut s, "ZED=7 /usr/bin/env | /bin/grep -c ^ZED=7").1.trim(), "1");
        assert_eq!(s.get_var("ZED"), None);
        // $? and quoting
        assert_eq!(run(&mut s, "false; echo \"[$?]\" '$?'").1, "[1] $?\n");
    }

    #[test]
    fn exit_stops_the_list_but_not_inside_a_pipeline() {
        let mut s = sh();
        let (st, out, _) = run(&mut s, "echo a; exit 3; echo b");
        assert_eq!((st, out.as_str(), s.exit_requested), (3, "a\n", Some(3)));
        let mut s = sh();
        run(&mut s, "exit 5 | cat");
        assert_eq!(s.exit_requested, None, "a pipeline stage is a subshell");
    }

    #[test]
    fn cd_in_a_pipeline_does_not_move_the_shell() {
        let mut s = sh();
        let before = s.cwd.clone();
        run(&mut s, "cd / | cat");
        assert_eq!(s.cwd, before);
    }

    #[test]
    fn not_found_and_syntax_errors() {
        let mut s = sh();
        let (st, _, err) = run(&mut s, "nonesuch-cmd");
        assert_eq!(st, 127);
        assert!(err.contains("nonesuch-cmd: not found"));
        let (st, _, err) = run(&mut s, "echo 'x");
        assert_eq!(st, 2);
        assert!(err.contains("syntax error"));
        let (st, _, _) = run(&mut s, "/etc/passwd"); // exists, not executable
        assert_eq!(st, 126);
    }

    #[test]
    fn path_search() {
        assert!(super::find_in_path("sh", "/nonexistent:/bin:/usr/bin").is_some());
        assert_eq!(super::find_in_path("nonesuch-cmd", "/bin"), None);
        assert_eq!(super::find_in_path("./x", "/bin"), Some("./x".into()));
    }

    #[test]
    fn globbing_in_a_command() {
        let mut s = sh();
        let t = Tmp::new();
        for f in ["a.txt", "b.txt", "c.log"] {
            std::fs::write(t.path(f), f).unwrap();
        }
        let (_, out, _) = run(&mut s, &format!("echo {}/*.txt", t.0.display()));
        assert_eq!(out, format!("{0}/a.txt {0}/b.txt\n", t.0.display()));
    }
}
