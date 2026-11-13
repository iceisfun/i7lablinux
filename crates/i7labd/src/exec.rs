//! Process execution for `exec`, `shell` and detached jobs: argv is executed directly (no shell), in its own
//! process group (or its own session on a pty); output is streamed to a `Sink` with backpressure (bounded
//! channel -> full pipe -> blocked child), capped when the transport cannot stream; timeout and cancel send
//! SIGTERM to the group and SIGKILL after 3 s. Owner: P6a.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::time::{Duration, Instant};

use labproto::frame::Chan;
use labproto::json::JsonWriter;

use crate::ffi;
use crate::registry::Sink;

/// Absolute path of the in-image shell used by `shell` and as the console fallback.
pub const SHELL: &str = "/bin/i7labsh";
pub const DEFAULT_TIMEOUT_S: u64 = 300;
pub const MAX_OUTPUT: u64 = 64 << 20;
pub const KILL_GRACE: Duration = Duration::from_secs(3);
/// Output kept per ExecResult when the sink cannot stream (HTTP non-stream, console).
const CHUNK: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq)]
pub struct ExecSpec {
    pub argv: Vec<String>,
    /// None = no timeout
    pub timeout: Option<Duration>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<String>,
    /// (cols, rows): run on a pty
    pub tty: Option<(u16, u16)>,
    pub detach: bool,
    pub stdin: bool,
    pub max_output: u64,
}

impl Default for ExecSpec {
    fn default() -> Self {
        ExecSpec {
            argv: vec![],
            timeout: Some(Duration::from_secs(DEFAULT_TIMEOUT_S)),
            env: vec![],
            cwd: None,
            tty: None,
            detach: false,
            stdin: false,
            max_output: MAX_OUTPUT,
        }
    }
}

fn parse_dims(s: &str) -> Option<(u16, u16)> {
    let (c, r) = s.split_once(['x', 'X'])?;
    let (c, r): (u16, u16) = (c.parse().ok()?, r.parse().ok()?);
    (c > 0 && r > 0 && c <= 1000 && r <= 1000).then_some((c, r))
}

/// `[--timeout S] [--env K=V].. [--cwd D] [--tty CxR] [--detach] [--stdin] -- ARGV..`
pub fn parse_args(args: &[String]) -> Result<ExecSpec, String> {
    let split = args.iter().position(|a| a == "--").ok_or("usage: exec [options] -- ARGV..")?;
    let o = labproto::args::Opts::parse(&args[..split], &["detach", "stdin"], &["timeout", "env", "cwd", "tty"]).map_err(|e| e.to_string())?;
    if let Some(p) = o.positional().first() {
        return Err(format!("unexpected word {:?} before --", p));
    }
    let argv: Vec<String> = args[split + 1..].to_vec();
    if argv.is_empty() || argv[0].is_empty() {
        return Err("no command after --".into());
    }
    let mut spec = ExecSpec { argv, detach: o.flag("detach"), stdin: o.flag("stdin"), ..Default::default() };
    if let Some(t) = o.value("timeout") {
        let s: u64 = t.parse().map_err(|_| "bad --timeout".to_string())?;
        spec.timeout = if s == 0 { None } else { Some(Duration::from_secs(s)) };
    }
    for e in o.values("env") {
        let (k, v) = e.split_once('=').ok_or("--env needs K=V")?;
        if k.is_empty() || k.contains('\0') || v.contains('\0') {
            return Err("bad --env".into());
        }
        spec.env.push((k.to_string(), v.to_string()));
    }
    spec.cwd = o.value("cwd").map(str::to_string);
    if let Some(t) = o.value("tty") {
        spec.tty = Some(parse_dims(t).ok_or("--tty needs COLSxROWS")?);
    }
    if spec.argv.iter().any(|a| a.contains('\0')) {
        return Err("NUL in argument".into());
    }
    Ok(spec)
}

/// The in-image `shell` command: `[--cols N --rows N] [--term T]` becomes an exec of i7labsh on a pty.
pub fn parse_shell_args(args: &[String]) -> Result<(ExecSpec, String), String> {
    let o = labproto::args::Opts::parse(args, &[], &["cols", "rows", "term"]).map_err(|e| e.to_string())?;
    let cols: u16 = o.value("cols").map(|v| v.parse().map_err(|_| "bad --cols")).transpose()?.unwrap_or(80);
    let rows: u16 = o.value("rows").map(|v| v.parse().map_err(|_| "bad --rows")).transpose()?.unwrap_or(24);
    if cols == 0 || rows == 0 || cols > 1000 || rows > 1000 {
        return Err("bad terminal size".into());
    }
    let term = o.value("term").unwrap_or("xterm").to_string();
    if term.len() > 40 || !term.chars().all(|c| c.is_ascii_alphanumeric() || "-_.+".contains(c)) {
        return Err("bad --term".into());
    }
    let spec = ExecSpec {
        argv: vec![SHELL.to_string()],
        timeout: None,
        tty: Some((cols, rows)),
        stdin: true,
        env: vec![("TERM".into(), term.clone())],
        ..Default::default()
    };
    Ok((spec, term))
}

pub fn build_command(spec: &ExecSpec) -> Command {
    let mut c = Command::new(&spec.argv[0]);
    c.args(&spec.argv[1..]);
    c.env("PATH", "/sbin:/bin:/usr/sbin:/usr/bin");
    for (k, v) in &spec.env {
        c.env(k, v);
    }
    if let Some(d) = &spec.cwd {
        c.current_dir(d);
    }
    c
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub exit: i32,
    pub signal: Option<i32>,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub canceled: bool,
    pub truncated: bool,
}

/// RESP body of exec: `i32 BE exit` + JSON `{signal,duration_ms,timed_out,canceled,truncated}`.
pub fn outcome_body(o: &Outcome) -> Vec<u8> {
    let mut w = JsonWriter::new();
    w.begin_object();
    match o.signal {
        Some(s) => w.field_i64("signal", s as i64),
        None => {
            w.key("signal");
            w.null();
        }
    }
    w.field_u64("duration_ms", o.duration_ms);
    w.field_bool("timed_out", o.timed_out);
    w.field_bool("canceled", o.canceled);
    w.field_bool("truncated", o.truncated);
    w.end_object();
    let mut out = o.exit.to_be_bytes().to_vec();
    out.extend_from_slice(w.finish().as_bytes());
    out
}

fn pump<R: Read + Send + 'static>(mut r: R, chan: Chan, tx: SyncSender<(Chan, Vec<u8>)>) {
    std::thread::spawn(move || {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match r.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => {
                    if tx.send((chan, buf[..n].to_vec())).is_err() {
                        return;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return, // EIO on a pty master when the slave closes
            }
        }
    });
}

fn feed_stdin<W: Write + Send + 'static>(mut w: W, rx: Receiver<Vec<u8>>) {
    std::thread::spawn(move || {
        for chunk in rx {
            if w.write_all(&chunk).is_err() {
                return;
            }
            let _ = w.flush();
        }
        // dropping `w` closes the child's stdin (EOF)
    });
}

fn exit_code(st: &std::process::ExitStatus) -> (i32, Option<i32>) {
    match (st.code(), st.signal()) {
        (Some(c), _) => (c, None),
        (None, Some(s)) => (128 + s, Some(s)),
        _ => (-1, None),
    }
}

/// Run to completion, streaming to `sink`. `Err` only when the program could not be started.
pub fn run(spec: &ExecSpec, sink: &mut dyn Sink, cancel: &AtomicBool) -> std::io::Result<Outcome> {
    let mut cmd = build_command(spec);
    let (tx, rx) = sync_channel::<(Chan, Vec<u8>)>(8);
    let child;
    if let Some((cols, rows)) = spec.tty {
        let (master, slave) = ffi::open_pty()?;
        ffi::set_winsize(master.as_raw_fd(), cols, rows)?;
        cmd.stdin(Stdio::from(slave.try_clone()?)).stdout(Stdio::from(slave.try_clone()?)).stderr(Stdio::from(slave));
        // SAFETY: pre_exec runs between fork and exec: only async-signal-safe calls (setsid, ioctl).
        unsafe {
            cmd.pre_exec(|| {
                ffi::setsid()?;
                ffi::set_ctty(0)
            });
        }
        child = cmd.spawn()?;
        drop(cmd); // closes the parent's copies of the slave
        pump(master.try_clone()?, Chan::Stdout, tx);
        if spec.stdin {
            if let Some(input) = sink.input() {
                feed_stdin(master, input);
            }
        }
    } else {
        cmd.process_group(0).stdout(Stdio::piped()).stderr(Stdio::piped());
        cmd.stdin(if spec.stdin { Stdio::piped() } else { Stdio::null() });
        let mut c = cmd.spawn()?;
        pump(c.stdout.take().unwrap(), Chan::Stdout, tx.clone());
        pump(c.stderr.take().unwrap(), Chan::Stderr, tx);
        if let Some(stdin) = c.stdin.take() {
            if let Some(input) = sink.input() {
                feed_stdin(stdin, input);
            } // else: dropped, EOF at once
        }
        child = c;
    }
    Ok(supervise(child, rx, spec, sink, cancel))
}

fn supervise(mut child: Child, rx: Receiver<(Chan, Vec<u8>)>, spec: &ExecSpec, sink: &mut dyn Sink, cancel: &AtomicBool) -> Outcome {
    let start = Instant::now();
    let pgid = child.id() as i32;
    let cap = if sink.streaming() { None } else { Some(spec.max_output) };
    let mut out = Outcome::default();
    let mut total = 0u64;
    let mut term_at: Option<Instant> = None;
    let mut killed = false;
    let mut exited: Option<std::process::ExitStatus> = None;
    let mut exit_seen: Option<Instant> = None;
    let mut sink_gone = false;
    let mut readers_done = false;
    loop {
        match rx.recv_timeout(Duration::from_millis(25)) {
            Ok((chan, data)) => {
                total += data.len() as u64;
                if cap.is_some_and(|c| total > c) {
                    out.truncated = true;
                    if term_at.is_none() {
                        let _ = ffi::killpg(pgid, ffi::SIGTERM);
                        term_at = Some(Instant::now());
                    }
                } else if !sink_gone && sink.data(chan, &data).is_err() {
                    sink_gone = true;
                    cancel.store(true, Ordering::SeqCst);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => readers_done = true,
        }
        if exited.is_none() {
            if let Ok(Some(st)) = child.try_wait() {
                exited = Some(st);
                exit_seen = Some(Instant::now());
                // background grandchildren must not outlive the command
                let _ = ffi::killpg(pgid, ffi::SIGKILL);
            }
        }
        if let Some(st) = exited {
            if readers_done || exit_seen.is_some_and(|t| t.elapsed() > Duration::from_secs(1)) {
                let (c, s) = exit_code(&st);
                out.exit = c;
                out.signal = s;
                break;
            }
            continue;
        }
        if term_at.is_none() {
            if cancel.load(Ordering::SeqCst) {
                out.canceled = true;
                term_at = Some(Instant::now());
                let _ = ffi::killpg(pgid, ffi::SIGTERM);
            } else if spec.timeout.is_some_and(|t| start.elapsed() > t) {
                out.timed_out = true;
                term_at = Some(Instant::now());
                let _ = ffi::killpg(pgid, ffi::SIGTERM);
            }
        } else if !killed && term_at.is_some_and(|t| t.elapsed() > KILL_GRACE) {
            killed = true;
            let _ = ffi::killpg(pgid, ffi::SIGKILL);
        }
    }
    if out.timed_out {
        out.exit = 124;
    }
    out.duration_ms = start.elapsed().as_millis() as u64;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::CollectSink;

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_options_and_argv() {
        let s = parse_args(&argv(&["--timeout", "5", "--env", "A=b=c", "--cwd", "/tmp", "--tty", "100x30", "--detach", "--", "ls", "-l", "--", "x"])).unwrap();
        assert_eq!(s.argv, vec!["ls", "-l", "--", "x"]);
        assert_eq!(s.timeout, Some(Duration::from_secs(5)));
        assert_eq!(s.env, vec![("A".to_string(), "b=c".to_string())]);
        assert_eq!(s.tty, Some((100, 30)));
        assert!(s.detach && !s.stdin);
        assert_eq!(parse_args(&argv(&["--timeout", "0", "--", "x"])).unwrap().timeout, None);
        assert!(parse_args(&argv(&["ls"])).is_err(), "no --");
        assert!(parse_args(&argv(&["--"])).is_err(), "empty argv");
        assert!(parse_args(&argv(&["stray", "--", "x"])).is_err());
        assert!(parse_args(&argv(&["--tty", "0x0", "--", "x"])).is_err());
        assert!(parse_args(&argv(&["--env", "novalue", "--", "x"])).is_err());
        assert!(parse_args(&argv(&["--bogus", "--", "x"])).is_err());
    }

    #[test]
    fn shell_args() {
        let (s, term) = parse_shell_args(&argv(&["--cols", "132", "--rows", "50", "--term", "vt100"])).unwrap();
        assert_eq!((s.tty, term.as_str(), s.argv[0].as_str()), (Some((132, 50)), "vt100", SHELL));
        assert!(parse_shell_args(&argv(&["--term", "a b"])).is_err());
        assert!(parse_shell_args(&argv(&["--cols", "0"])).is_err());
    }

    #[test]
    fn outcome_body_layout() {
        let b = outcome_body(&Outcome { exit: -2, signal: Some(9), duration_ms: 7, ..Default::default() });
        assert_eq!(&b[..4], &(-2i32).to_be_bytes());
        let j = std::str::from_utf8(&b[4..]).unwrap();
        assert!(j.contains("\"signal\":9") && j.contains("\"duration_ms\":7"), "{}", j);
    }

    fn spec(a: &[&str]) -> ExecSpec {
        ExecSpec { argv: argv(a), timeout: Some(Duration::from_secs(10)), ..Default::default() }
    }

    #[test]
    fn runs_and_splits_streams() {
        let mut sink = CollectSink::default();
        let o = run(&spec(&["/bin/sh", "-c", "echo out; echo err >&2; exit 3"]), &mut sink, &AtomicBool::new(false)).unwrap();
        assert_eq!(o.exit, 3);
        assert_eq!(sink.stdout, b"out\n");
        assert_eq!(sink.stderr, b"err\n");
        assert!(!o.timed_out && !o.canceled);
    }

    #[test]
    fn missing_program_is_a_start_error() {
        let mut sink = CollectSink::default();
        assert!(run(&spec(&["/nonexistent/prog"]), &mut sink, &AtomicBool::new(false)).is_err());
    }

    #[test]
    fn timeout_kills_the_group() {
        let mut sink = CollectSink::default();
        let mut s = spec(&["/bin/sh", "-c", "sleep 30 & sleep 30"]);
        s.timeout = Some(Duration::from_millis(200));
        let t = Instant::now();
        let o = run(&s, &mut sink, &AtomicBool::new(false)).unwrap();
        assert!(o.timed_out && o.exit == 124 && t.elapsed() < Duration::from_secs(5), "{:?}", o);
    }

    #[test]
    fn cancel_terminates() {
        let mut sink = CollectSink::default();
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let c2 = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.store(true, Ordering::SeqCst);
        });
        let o = run(&spec(&["/bin/sleep", "30"]), &mut sink, &cancel).unwrap();
        assert!(o.canceled && o.signal == Some(15), "{:?}", o);
    }

    #[test]
    fn output_cap_applies_to_non_streaming_sinks() {
        let mut sink = CollectSink::default();
        let mut s = spec(&["/bin/sh", "-c", "yes"]);
        s.max_output = 100_000;
        let o = run(&s, &mut sink, &AtomicBool::new(false)).unwrap();
        assert!(o.truncated, "{:?}", o);
        assert!(sink.stdout.len() as u64 <= 100_000 + 2 * CHUNK as u64 * 8);
    }

    #[test]
    fn stdin_is_fed_and_closed() {
        struct In(Option<Receiver<Vec<u8>>>, CollectSink);
        impl Sink for In {
            fn data(&mut self, c: Chan, b: &[u8]) -> std::io::Result<()> {
                self.1.data(c, b)
            }
            fn event(&mut self, j: &str) -> std::io::Result<()> {
                self.1.event(j)
            }
            fn input(&mut self) -> Option<Receiver<Vec<u8>>> {
                self.0.take()
            }
        }
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(b"hello ".to_vec()).unwrap();
        tx.send(b"world".to_vec()).unwrap();
        drop(tx);
        let mut sink = In(Some(rx), CollectSink::default());
        let mut s = spec(&["/bin/cat"]);
        s.stdin = true;
        let o = run(&s, &mut sink, &AtomicBool::new(false)).unwrap();
        assert_eq!(o.exit, 0);
        assert_eq!(sink.1.stdout, b"hello world");
    }

    #[test]
    fn pty_gets_a_terminal_when_available() {
        if !std::path::Path::new("/dev/pts").exists() {
            return;
        }
        let mut sink = CollectSink::default();
        let mut s = spec(&["/bin/sh", "-c", "test -t 0 && echo tty"]);
        s.tty = Some((80, 24));
        match run(&s, &mut sink, &AtomicBool::new(false)) {
            Ok(o) => {
                assert_eq!(o.exit, 0, "{:?}", o);
                assert!(String::from_utf8_lossy(&sink.stdout).contains("tty"));
            }
            Err(_) => {} // no usable ptmx in this sandbox
        }
    }
}
