//! Streaming and file commands: exec, sh, shell, put, get, logs, blk read/write/verify, plus the generic stream
//! runner used by `--follow` style commands and the raw form. Owner: P9.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use labproto::catalog::{self, CmdSpec};
use labproto::crypto::{hex, Sha256};
use labproto::frame::Chan;
use labproto::keys::Role;
use labproto::Status;

use crate::cmds::{Done, Prepared, Run, Spec};
use crate::output::{self, data_event, result_event, ErrInfo, HostInfo, Paint};
use crate::{render, ClientError, ClientIo, Input};

/// Builtins of i7labsh: not programs, so `exec -- ls` cannot find them (review F-F21).
pub const SH_BUILTINS: &[&str] = &[
    "cd", "pwd", "echo", "export", "unset", "env", "exit", "help", "true", "false", "sleep", "ls", "cat", "cp", "mv", "rm", "mkdir", "rmdir", "ln", "touch", "head", "tail", "wc", "grep", "hexdump", "sha256sum", "mount", "umount", "ip", "dmesg", "ps", "kill", "free", "df", "uptime", "uname", "date", "sync",
    "reboot", "poweroff", "halt", "lsmod", "insmod", "lspci", "lsblk", "lsusb", "sensors", "probe", "blk", "lab",
];

// ---------------------------------------------------------------- input sources

pub trait InputSource {
    fn next(&mut self) -> Input;
}

/// A file as `Chan::File` (put) or `Chan::Stdin` (exec --stdin FILE), starting at `offset`.
pub struct FileInput {
    f: File,
    chan: Chan,
    done: bool,
    pub sent: u64,
}

impl FileInput {
    pub fn open(path: &Path, offset: u64, chan: Chan) -> std::io::Result<FileInput> {
        let mut f = File::open(path)?;
        if offset > 0 {
            f.seek(SeekFrom::Start(offset))?;
        }
        Ok(FileInput { f, chan, done: false, sent: 0 })
    }
}

impl InputSource for FileInput {
    fn next(&mut self) -> Input {
        if self.done {
            return Input::Pending;
        }
        let mut buf = vec![0u8; 16 * 1024];
        match self.f.read(&mut buf) {
            Ok(0) | Err(_) => {
                self.done = true;
                Input::End(self.chan)
            }
            Ok(n) => {
                buf.truncate(n);
                self.sent += n as u64;
                Input::Data(self.chan, buf)
            }
        }
    }
}

/// This process's stdin as `Chan::Stdin` (non-blocking poll).
pub struct StdinInput {
    done: bool,
}

impl StdinInput {
    pub fn new() -> StdinInput {
        StdinInput { done: false }
    }
}

impl Default for StdinInput {
    fn default() -> Self {
        Self::new()
    }
}

impl InputSource for StdinInput {
    fn next(&mut self) -> Input {
        if self.done {
            return Input::Pending;
        }
        let mut buf = vec![0u8; 8192];
        match crate::ffi::read_stdin_ready(&mut buf, 5) {
            Ok(None) => Input::Pending,
            Ok(Some(0)) | Err(_) => {
                self.done = true;
                Input::End(Chan::Stdin)
            }
            Ok(Some(n)) => {
                buf.truncate(n);
                Input::Data(Chan::Stdin, buf)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EscAction {
    Quit,
    Help,
    Reboot,
}

/// ssh-style local escapes: the escape character at the start of a line, then `.` quit, `?` help, `r` reboot,
/// or the escape character again for a literal one. Anything else passes through unchanged.
pub struct EscapeFilter {
    esc: Option<u8>,
    at_line_start: bool,
    tilde: bool,
}

impl EscapeFilter {
    pub fn new(esc: Option<u8>) -> EscapeFilter {
        EscapeFilter { esc, at_line_start: true, tilde: false }
    }

    pub fn feed(&mut self, input: &[u8]) -> (Vec<u8>, Vec<EscAction>) {
        let mut out = Vec::with_capacity(input.len());
        let mut acts = Vec::new();
        let Some(e) = self.esc else { return (input.to_vec(), acts) };
        for &b in input {
            if self.tilde {
                self.tilde = false;
                match b {
                    b'.' => acts.push(EscAction::Quit),
                    b'?' => acts.push(EscAction::Help),
                    b'r' => acts.push(EscAction::Reboot),
                    x if x == e => {
                        out.push(e);
                        self.at_line_start = false;
                    }
                    x => {
                        out.push(e);
                        out.push(x);
                        self.at_line_start = x == b'\r' || x == b'\n';
                    }
                }
                continue;
            }
            if self.at_line_start && b == e {
                self.tilde = true;
                self.at_line_start = false;
                continue;
            }
            out.push(b);
            self.at_line_start = b == b'\r' || b == b'\n';
        }
        (out, acts)
    }
}

/// Raw-mode terminal input with local escapes and window-size forwarding (shell, exec --tty).
pub struct TtyInput {
    _raw: Option<crate::ffi::RawMode>,
    esc: EscapeFilter,
    queue: VecDeque<Input>,
    size: Option<(u16, u16)>,
    armed_reboot: bool,
    done: bool,
}

impl TtyInput {
    pub fn new(esc: Option<u8>, raw: bool) -> TtyInput {
        let raw = if raw { crate::ffi::RawMode::enter().ok() } else { None };
        TtyInput { _raw: raw, esc: EscapeFilter::new(esc), queue: VecDeque::new(), size: crate::ffi::winsize(0), armed_reboot: false, done: false }
    }
}

fn say(s: &str) {
    // raw mode: CRLF
    let mut e = std::io::stderr();
    let _ = e.write_all(s.replace('\n', "\r\n").as_bytes());
}

impl InputSource for TtyInput {
    fn next(&mut self) -> Input {
        if let Some(i) = self.queue.pop_front() {
            return i;
        }
        if self.done {
            return Input::Pending;
        }
        if let Some(now) = crate::ffi::winsize(0) {
            if Some(now) != self.size {
                self.size = Some(now);
                return Input::Data(Chan::Ctl, ctl_resize(now.0, now.1));
            }
        }
        let mut buf = vec![0u8; 4096];
        match crate::ffi::read_stdin_ready(&mut buf, 5) {
            Ok(None) => Input::Pending,
            Ok(Some(0)) | Err(_) => {
                self.done = true;
                Input::End(Chan::Stdin)
            }
            Ok(Some(n)) => {
                let (fwd, acts) = self.esc.feed(&buf[..n]);
                for a in acts {
                    match a {
                        EscAction::Quit => {
                            say("\n[i7labctl: leaving the shell]\n");
                            self.done = true;
                            self.queue.push_back(Input::End(Chan::Stdin));
                        }
                        EscAction::Help => say("\nlocal escapes: ~. leave   ~r reboot the host (twice)   ~? this help   ~~ literal ~\n"),
                        EscAction::Reboot => {
                            if self.armed_reboot {
                                say("\n[i7labctl: rebooting the host]\n");
                                self.queue.push_back(Input::Data(Chan::Stdin, b"reboot\n".to_vec()));
                                self.armed_reboot = false;
                            } else {
                                say("\n[i7labctl: press ~r again to reboot the host]\n");
                                self.armed_reboot = true;
                            }
                        }
                    }
                }
                if !fwd.is_empty() {
                    self.armed_reboot = false;
                    self.queue.push_front(Input::Data(Chan::Stdin, fwd));
                }
                self.queue.pop_front().unwrap_or(Input::Pending)
            }
        }
    }
}

/// `chan 5` window size message: 'W' cols(2) rows(2), big endian (PROTOCOL 4/5).
pub fn ctl_resize(cols: u16, rows: u16) -> Vec<u8> {
    let mut v = vec![b'W'];
    v.extend_from_slice(&cols.to_be_bytes());
    v.extend_from_slice(&rows.to_be_bytes());
    v
}

// ---------------------------------------------------------------- sinks

/// Download target: `<local>.part`, hashing everything written.
pub struct FileSink {
    f: File,
    pub whole: Sha256,
    pub range: Sha256,
    pub total: u64,
    pub offset: u64,
    pub error: Option<std::io::Error>,
}

impl FileSink {
    /// Create or (with `resume`) continue `part`. Returns the sink; `offset` is the size already on disk.
    pub fn open(part: &Path, resume: bool) -> std::io::Result<FileSink> {
        let mut whole = Sha256::new();
        let mut offset = 0;
        let f = if resume && part.exists() {
            let mut old = File::open(part)?;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = old.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                whole.update(&buf[..n]);
                offset += n as u64;
            }
            std::fs::OpenOptions::new().append(true).open(part)?
        } else {
            File::create(part)?
        };
        Ok(FileSink { f, whole, range: Sha256::new(), total: offset, offset, error: None })
    }
    pub fn write(&mut self, b: &[u8]) {
        if self.error.is_some() {
            return;
        }
        if let Err(e) = self.f.write_all(b) {
            self.error = Some(e);
            return;
        }
        self.whole.update(b);
        self.range.update(b);
        self.total += b.len() as u64;
    }
}

// ---------------------------------------------------------------- the io the transports talk to

pub struct StreamIo<'a> {
    out: &'a mut dyn Write,
    err: &'a mut dyn Write,
    json: bool,
    /// show progress events as a status line on stderr
    progress: bool,
    input: Option<Box<dyn InputSource>>,
    sink: Option<&'a mut FileSink>,
    pub stdout_bytes: u64,
    last_progress: bool,
    input_done: bool,
}

impl<'a> StreamIo<'a> {
    pub fn new(out: &'a mut dyn Write, err: &'a mut dyn Write, json: bool, progress: bool, input: Option<Box<dyn InputSource>>, sink: Option<&'a mut FileSink>) -> StreamIo<'a> {
        StreamIo { out, err, json, progress, input, sink, stdout_bytes: 0, last_progress: false, input_done: false }
    }
    fn clear_progress(&mut self) {
        if self.last_progress {
            let _ = self.err.write_all(b"\r\x1b[K");
            self.last_progress = false;
        }
    }
}

impl ClientIo for StreamIo<'_> {
    fn stdout(&mut self, b: &[u8]) {
        if b.is_empty() {
            return;
        }
        self.stdout_bytes += b.len() as u64;
        if self.json {
            let _ = writeln!(self.out, "{}", data_event("stdout", b));
        } else {
            self.clear_progress();
            let _ = self.out.write_all(b);
            let _ = self.out.flush();
        }
    }
    fn stderr(&mut self, b: &[u8]) {
        if b.is_empty() {
            return;
        }
        if self.json {
            let _ = writeln!(self.out, "{}", data_event("stderr", b));
        } else {
            self.clear_progress();
            let _ = self.err.write_all(b);
        }
    }
    fn event(&mut self, j: &str) {
        if self.json {
            let _ = writeln!(self.out, "{}", j);
        } else if self.progress {
            if let Some(l) = render::progress_line(j) {
                let _ = write!(self.err, "\r{}\x1b[K", l);
                let _ = self.err.flush();
                self.last_progress = true;
            }
        }
    }
    fn file(&mut self, b: &[u8]) {
        if let Some(s) = self.sink.as_mut() {
            s.write(b);
        }
    }
    fn input(&mut self) -> Input {
        if self.input_done {
            return Input::None;
        }
        match self.input.as_mut() {
            None => Input::None,
            Some(src) => {
                let i = src.next();
                if matches!(i, Input::End(_)) {
                    // the transport asks again only for other channels; this source has one
                    self.input_done = true;
                }
                i
            }
        }
    }
}

impl Drop for StreamIo<'_> {
    fn drop(&mut self) {
        self.clear_progress();
    }
}

pub struct StreamOutcome {
    pub done: Done,
    pub info: HostInfo,
    pub stdout_bytes: u64,
}

/// Run one streaming call. Output goes live to the terminal (or as NDJSON with --json).
pub fn run_stream(run: &mut Run, mut prep: Prepared, spec: &'static CmdSpec, argv: &[String], input: Option<Box<dyn InputSource>>, sink: Option<&mut FileSink>, progress: bool) -> Result<StreamOutcome, ClientError> {
    let json = run.g.json;
    let show = progress && run.env.out_tty && !run.g.quiet;
    let (res, bytes) = {
        let mut io = StreamIo::new(&mut *run.env.out, &mut *run.env.err, json, show, input, sink);
        let r = prep.transport.call(spec, argv, &mut io);
        (r, io.stdout_bytes)
    };
    let res = res?;
    Ok(StreamOutcome { done: Done { transport: prep.transport.name(), role: prep.transport.role(), res }, info: prep.info, stdout_bytes: bytes })
}

/// End of a streaming command: the NDJSON result event, or the rendered result / error text. Returns the exit.
pub fn end_stream(run: &mut Run, wire: &str, o: &StreamOutcome, render_fn: Option<&dyn Fn(&str, Paint) -> String>, ok_exit: i32) -> i32 {
    let body = String::from_utf8_lossy(&o.done.res.body).into_owned();
    let st = o.done.res.status;
    if st == Status::Ok {
        if run.g.json {
            let line = result_event(ok_exit == 0, ok_exit, Some(&body));
            run.outln(&line);
        } else if let Some(f) = render_fn {
            if !body.trim().is_empty() {
                let t = f(&body, run.paint);
                run.out(&t);
                if !t.ends_with('\n') {
                    run.out("\n");
                }
            }
        }
        return ok_exit;
    }
    let (mut text, reasons) = output::remote_error_text(st.name(), &body);
    if st == Status::Eperm && o.done.role == Some(Role::Ro) {
        text.push_str(" (your key is read-only; this needs the admin key: --role admin)");
    }
    let exit = st.cli_exit();
    if run.g.json {
        let line = output::result_error_event(&ErrInfo { code: st.name(), status: Some(st as u16), exit, message: &text, reasons: &reasons });
        run.outln(&line);
    } else {
        run.err(&format!("i7labctl: {}: {}", wire, text));
        for r in &reasons {
            run.err(&format!("  reason: {}", labproto::text::sanitize(r)));
        }
    }
    exit
}

/// Generic streaming wire command (thermal --follow, jobs out -f, ...).
pub fn stream_wire(run: &mut Run, host: Option<&str>, wire: &str, argv: Vec<String>, render_fn: &dyn Fn(&str, Paint) -> String) -> Result<i32, ClientError> {
    let spec = catalog::by_name(wire).ok_or_else(|| ClientError::Usage(format!("unknown wire command {}", wire)))?;
    let timeout = run.g.timeout.unwrap_or(0.0);
    let prep = run.prepare(host, timeout)?;
    let o = run_stream(run, prep, spec, &argv, None, None, false)?;
    Ok(end_stream(run, wire, &o, Some(render_fn), 0))
}

// ---------------------------------------------------------------- dispatch

pub fn dispatch(run: &mut Run, name: &str, args: &[String]) -> Result<i32, ClientError> {
    match name {
        "exec" => exec(run, args, false),
        "sh" => exec(run, args, true),
        "shell" => shell(run, args),
        "put" => put(run, args),
        "get" => get(run, args),
        "logs" => logs(run, args),
        _ => Err(ClientError::Usage(format!("no handler for '{}'", name))),
    }
}

/// `exec --detach` result text: the job id.
fn detach_text(body: &str, _p: Paint) -> String {
    match crate::jv::parse(body).and_then(|v| crate::jv::u(&v, "job")) {
        Some(id) => format!("job {}\n", id),
        None => format!("started (unexpected reply: {})\n", labproto::text::sanitize(body.trim())),
    }
}

fn exec_exit(run: &mut Run, o: &StreamOutcome, argv0: Option<&str>) -> i32 {
    let st = o.done.res.status;
    let builtin = argv0.filter(|a| SH_BUILTINS.contains(a));
    let hint = |run: &mut Run, a: &str| {
        if !run.g.json {
            run.err(&format!("hint: '{}' is a builtin of the host shell, not a program; use: i7labctl sh <host> '{} ...'", a, a));
        }
    };
    if st != Status::Ok {
        // the command could not start (or was refused): i7labctl's own error, 255 (2 for bad arguments)
        let _ = end_stream(run, "exec", o, None, 0);
        if let Some(a) = builtin {
            hint(run, a);
        }
        return if st == Status::BadArgs { 2 } else { 255 };
    }
    let exit = o.done.res.exit_code.unwrap_or(0).clamp(0, 254);
    if exit == 127 {
        if let Some(a) = builtin {
            hint(run, a);
        }
    }
    let _ = end_stream(run, "exec", o, None, exit);
    exit
}

fn exec(run: &mut Run, args: &[String], via_sh: bool) -> Result<i32, ClientError> {
    let spec = if via_sh {
        Spec::new("sh <host> '<command line>'").valued(&["env", "cwd"]).pos(1, 1)
    } else {
        Spec::new("exec <host> [--timeout S] [--env K=V].. [--cwd D] [--stdin F|-] [--tty] [--detach] -- CMD..").flags(&["tty", "detach"]).valued(&["env", "cwd", "stdin"]).pos(1, usize::MAX)
    };
    let p = run.parse(args, &spec)?;
    let mut wire: Vec<String> = Vec::new();
    if let Some(t) = run.g.timeout {
        wire.extend(["--timeout".to_string(), format!("{}", t as u64)]);
    }
    for e in p.opts.values("env") {
        if !e.contains('=') {
            return Err(ClientError::Usage(format!("--env needs K=V, got '{}'", e)));
        }
        wire.extend(["--env".to_string(), e.to_string()]);
    }
    if let Some(c) = p.opts.value("cwd") {
        wire.extend(["--cwd".to_string(), c.to_string()]);
    }
    let words: Vec<String> = if via_sh {
        vec!["i7labsh".into(), "-c".into(), p.pos[0].clone()]
    } else {
        if !args.iter().any(|a| a == "--") {
            return Err(ClientError::Usage("put the command after `--`: i7labctl exec <host> -- CMD [args..] (shell syntax: use `sh`)".into()));
        }
        p.pos.clone()
    };
    if run.g.transport == crate::opts::TransportPref::Ssh || run.g.ssh.is_some() {
        // ssh transport: the system ssh runs the words (a command line for `sh`, argv words for `exec`)
        if words.first().is_some_and(|w| w.starts_with('-')) {
            return Err(ClientError::Usage("with the ssh transport the command must not start with '-'".into()));
        }
        let ssh_words: Vec<String> = if via_sh { vec![p.pos[0].clone()] } else { words.clone() };
        return crate::local::ssh_exec(run, p.host.as_deref(), &ssh_words, false);
    }
    let tty = !via_sh && p.opts.flag("tty");
    let detach = !via_sh && p.opts.flag("detach");
    let stdin_arg = if via_sh { None } else { p.opts.value("stdin").map(String::from) };
    if tty {
        let (c, r) = crate::ffi::winsize(0).unwrap_or((80, 24));
        wire.extend(["--tty".to_string(), format!("{}x{}", c, r)]);
    }
    if detach {
        wire.push("--detach".into());
    }
    let mut input: Option<Box<dyn InputSource>> = None;
    if let Some(s) = &stdin_arg {
        wire.push("--stdin".into());
        input = Some(if s == "-" {
            Box::new(StdinInput::new())
        } else {
            Box::new(FileInput::open(Path::new(s), 0, Chan::Stdin).map_err(|e| ClientError::Usage(format!("--stdin {}: {}", s, e)))?)
        });
    } else if tty && run.env.in_tty {
        input = Some(Box::new(TtyInput::new(None, true)));
    }
    wire.push("--".into());
    wire.extend(words.iter().cloned());
    let spec = catalog::by_name("exec").unwrap();
    let prep = run.prepare(p.host.as_deref(), 0.0)?;
    let o = run_stream(run, prep, spec, &wire, input, None, false)?;
    if detach && o.done.res.status == Status::Ok {
        // the host answers {"v":1,"job":N}: say which job, exit 0 (jobs ls / jobs out N / jobs kill N follow up)
        return Ok(end_stream(run, "exec", &o, Some(&detach_text), 0));
    }
    let argv0 = words.first().map(String::as_str);
    Ok(exec_exit(run, &o, argv0))
}

fn shell(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let p = run.parse(args, &Spec::new("shell <host> [--term T] [--escape C] [--via ether|ssh]").valued(&["term", "escape", "via"]))?;
    if let Some(v) = p.opts.value("via") {
        match v {
            "ether" => {}
            "ssh" => return crate::local::ssh_exec(run, p.host.as_deref(), &[], true),
            other => return Err(ClientError::Usage(format!("--via must be ether or ssh, got '{}'", other))),
        }
    }
    if run.g.transport == crate::opts::TransportPref::Ssh || run.g.ssh.is_some() {
        return crate::local::ssh_exec(run, p.host.as_deref(), &[], true);
    }
    let esc = match p.opts.value("escape") {
        None => Some(b'~'),
        Some("") => None,
        Some(s) => Some(s.as_bytes()[0]),
    };
    let mut wire = Vec::new();
    let (c, r) = crate::ffi::winsize(0).unwrap_or((80, 24));
    wire.extend(["--cols".to_string(), c.to_string(), "--rows".to_string(), r.to_string()]);
    let term = p.opts.value("term").map(String::from).or_else(|| std::env::var("TERM").ok()).unwrap_or_else(|| "xterm".into());
    wire.extend(["--term".to_string(), term]);
    let spec = catalog::by_name("shell").unwrap();
    let prep = run.prepare(p.host.as_deref(), 0.0)?;
    let tty = run.env.in_tty;
    let input: Box<dyn InputSource> = if tty { Box::new(TtyInput::new(esc, true)) } else { Box::new(StdinInput::new()) };
    let o = run_stream(run, prep, spec, &wire, Some(input), None, false)?;
    let st = o.done.res.status;
    if st != Status::Ok {
        let _ = end_stream(run, "shell", &o, None, 0);
        return Ok(255);
    }
    let exit = o.done.res.exit_code.unwrap_or(0).clamp(0, 254);
    let _ = end_stream(run, "shell", &o, None, exit);
    Ok(exit)
}

fn logs(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let p = run.parse(args, &Spec::new("logs <host> [--dmesg|--init|--daemon|--http|--audit] [-n N] [-f]").flags(&["dmesg", "init", "daemon", "http", "audit", "f"]).valued(&["n"]))?;
    let which: Vec<&str> = ["dmesg", "init", "daemon", "http", "audit"].into_iter().filter(|w| p.opts.flag(w)).collect();
    if which.len() > 1 {
        return Err(ClientError::Usage(format!("pick one log, not {}", which.join(" and "))));
    }
    let mut wire = vec![format!("--{}", which.first().copied().unwrap_or("dmesg"))];
    wire.extend(["-n".to_string(), p.uint("n")?.unwrap_or(200).to_string()]);
    let follow = p.opts.flag("f");
    if follow {
        wire.push("-f".into());
    }
    let spec = catalog::by_name("logs").unwrap();
    let timeout = run.g.timeout.unwrap_or(0.0);
    let prep = run.prepare(p.host.as_deref(), timeout)?;
    let o = run_stream(run, prep, spec, &wire, None, None, false)?;
    Ok(end_stream(run, "logs", &o, None, 0))
}

// ---------------------------------------------------------------- put / get

fn sha_of_file(path: &Path, from: u64) -> std::io::Result<(u64, [u8; 32])> {
    let mut f = File::open(path)?;
    let total = f.metadata()?.len();
    f.seek(SeekFrom::Start(from.min(total)))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok((total, h.finish()))
}

fn put(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let p = run.parse(args, &Spec::new("put <host> <local> <remote> [--mode 0644] [--resume] [--mkdirs]").flags(&["resume", "mkdirs"]).valued(&["mode"]).pos(2, 2))?;
    let (local, remote) = (PathBuf::from(&p.pos[0]), p.pos[1].clone());
    if let Some(m) = p.opts.value("mode") {
        if u32::from_str_radix(m.trim_start_matches("0o"), 8).is_err() {
            return Err(ClientError::Usage(format!("--mode needs an octal mode like 0644, got '{}'", m)));
        }
    }
    let (size, _) = sha_of_file(&local, 0).map_err(|e| ClientError::Usage(format!("cannot read {}: {}", local.display(), e)))?;
    let timeout = run.g.timeout.unwrap_or(0.0);
    let mut offset = 0u64;
    if p.opts.flag("resume") {
        // ask the host how much of <remote>.part it has
        let part = format!("{}.part", remote);
        if let Ok((d, _)) = run.simple_call(p.host.as_deref(), "fs.stat", &[part]) {
            if d.res.status == Status::Ok {
                let have = crate::jv::parse(&String::from_utf8_lossy(&d.res.body)).and_then(|v| crate::jv::u(&v, "size")).unwrap_or(0);
                if have > 0 && have < size {
                    offset = have;
                }
            }
        }
    }
    let (_, digest) = sha_of_file(&local, offset).map_err(|e| ClientError::Usage(format!("cannot read {}: {}", local.display(), e)))?;
    let mut wire = vec![remote.clone(), "--size".to_string(), size.to_string(), "--sha256".to_string(), hex(&digest)];
    if let Some(m) = p.opts.value("mode") {
        wire.extend(["--mode".to_string(), m.to_string()]);
    }
    if offset > 0 {
        wire.extend(["--offset".to_string(), offset.to_string()]);
    }
    if p.opts.flag("mkdirs") {
        wire.push("--mkdirs".into());
    }
    let input = FileInput::open(&local, offset, Chan::File)?;
    let spec = catalog::by_name("put").unwrap();
    let prep = run.prepare(p.host.as_deref(), timeout)?;
    let t0 = std::time::Instant::now();
    let o = run_stream(run, prep, spec, &wire, Some(Box::new(input)), None, true)?;
    let body = String::from_utf8_lossy(&o.done.res.body).into_owned();
    let sent = size - offset;
    if o.done.res.status == Status::Ok {
        let server_sha = crate::jv::parse(&body).and_then(|v| crate::jv::s(&v, "sha256").map(String::from));
        if let Some(s) = &server_sha {
            if !s.eq_ignore_ascii_case(&hex(&digest)) {
                return Err(ClientError::Failed(format!("the host reports sha256 {} but {} was sent: the file arrived damaged", s, hex(&digest))));
            }
        }
        let mibs = sent as f64 / 1048576.0 / t0.elapsed().as_secs_f64().max(0.001);
        let data = format!("{{\"bytes\":{},\"sha256\":\"{}\",\"path\":{},\"resumed_from\":{}}}", sent, hex(&digest), crate::jv::quote(&remote), offset);
        if run.g.json {
            let e = output::ok_envelope(o.done.transport, Some(&o.info), "put", Some(o.done.res.rtt_ms), &data);
            run.outln(&e);
        } else {
            run.outln(&format!("uploaded {} bytes to {} ({:.1} MiB/s{}), sha256 {}", sent, labproto::text::sanitize(&remote), mibs, if offset > 0 { format!(", resumed at {}", offset) } else { String::new() }, hex(&digest)));
            if server_sha.is_none() {
                run.note("note: the host did not report a sha256; integrity relied on the transport");
            }
        }
        return Ok(0);
    }
    Ok(end_stream(run, "put", &o, None, 0))
}

fn get(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let p = run.parse(args, &Spec::new("get <host> <remote> <local> [--resume]").flags(&["resume"]).pos(2, 2))?;
    let (remote, local) = (p.pos[0].clone(), PathBuf::from(&p.pos[1]));
    let part = PathBuf::from(format!("{}.part", local.display()));
    let mut sink = FileSink::open(&part, p.opts.flag("resume")).map_err(|e| ClientError::Failed(format!("cannot write {}: {}", part.display(), e)))?;
    let offset = sink.offset;
    let mut wire = vec![remote.clone()];
    if offset > 0 {
        wire.extend(["--offset".to_string(), offset.to_string()]);
    }
    let spec = catalog::by_name("get").unwrap();
    let timeout = run.g.timeout.unwrap_or(0.0);
    let prep = run.prepare(p.host.as_deref(), timeout)?;
    let t0 = std::time::Instant::now();
    let o = run_stream(run, prep, spec, &wire, None, Some(&mut sink), true)?;
    if let Some(e) = &sink.error {
        return Err(ClientError::Failed(format!("writing {}: {}", part.display(), e)));
    }
    if o.done.res.status != Status::Ok {
        let _ = std::fs::remove_file(&part).ok().filter(|_| sink.total == 0);
        return Ok(end_stream(run, "get", &o, None, 0));
    }
    let body = String::from_utf8_lossy(&o.done.res.body).into_owned();
    let whole = hex(&std::mem::replace(&mut sink.whole, Sha256::new()).finish());
    let range = hex(&std::mem::replace(&mut sink.range, Sha256::new()).finish());
    let server_sha = crate::jv::parse(&body).and_then(|v| crate::jv::s(&v, "sha256").map(|s| s.to_ascii_lowercase()));
    let mut verified = false;
    if let Some(s) = &server_sha {
        if *s != whole && *s != range {
            let _ = std::fs::remove_file(&part);
            return Err(ClientError::Failed(format!("sha256 mismatch: the host says {}, the downloaded data is {}; the partial file was removed", s, whole)));
        }
        verified = true;
    }
    std::fs::rename(&part, &local).map_err(|e| ClientError::Failed(format!("cannot rename {} to {}: {}", part.display(), local.display(), e)))?;
    let got = sink.total - offset;
    let mibs = got as f64 / 1048576.0 / t0.elapsed().as_secs_f64().max(0.001);
    let data = format!("{{\"bytes\":{},\"size\":{},\"sha256\":\"{}\",\"path\":{},\"verified\":{}}}", got, sink.total, whole, crate::jv::quote(&local.display().to_string()), verified);
    if run.g.json {
        let e = output::ok_envelope(o.done.transport, Some(&o.info), "get", Some(o.done.res.rtt_ms), &data);
        run.outln(&e);
    } else {
        run.outln(&format!("downloaded {} bytes to {} ({:.1} MiB/s), sha256 {}{}", got, local.display(), mibs, whole, if verified { "" } else { " (UNVERIFIED: the host sent no sha256)" }));
    }
    Ok(0)
}

// ---------------------------------------------------------------- blk

pub fn blk(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let (verb, rest) = args.split_first().ok_or_else(|| ClientError::Usage("blk needs a verb\nusage: i7labctl blk ls|smart|read|write|verify|image <host> ...".into()))?;
    let rest = rest.to_vec();
    match verb.as_str() {
        "ls" => {
            let p = run.parse(&rest, &Spec::new("blk ls <host> [--all]").flags(&["all"]))?;
            let argv: Vec<String> = if p.opts.flag("all") { vec!["--all".into()] } else { vec![] };
            let (d, info) = run.simple_call(p.host.as_deref(), "blk.ls", &argv)?;
            Ok(run.finish("blk.ls", &d, &info, &render::blk_ls))
        }
        "smart" => {
            let p = run.parse(&rest, &Spec::new("blk smart <host> DEV [--attrs] [--selftest short|long]").flags(&["attrs"]).valued(&["selftest"]).pos(1, 1))?;
            let mut argv = vec![p.pos[0].clone()];
            if p.opts.flag("attrs") {
                argv.push("--attrs".into());
            }
            if let Some(s) = p.opts.value("selftest") {
                if s != "short" && s != "long" {
                    return Err(ClientError::Usage(format!("--selftest must be short or long, got '{}'", s)));
                }
                argv.extend(["--selftest".to_string(), s.to_string()]);
            }
            let attrs = p.opts.flag("attrs");
            let (d, info) = run.simple_call(p.host.as_deref(), "blk.smart", &argv)?;
            let failed = d.res.status == Status::Ok && render::smart_failed(&String::from_utf8_lossy(&d.res.body));
            Ok(run.finish_with("blk.smart", &d, &info, &move |b, pt| render::blk_smart(b, attrs, pt), if failed { 3 } else { 0 }))
        }
        "read" | "write" | "verify" => blk_test(run, verb, &rest),
        "image" => crate::blkimage::run_cli(run, &rest),
        other => Err(ClientError::Usage(format!("blk: unknown verb '{}'\nusage: i7labctl blk ls|smart|read|write|verify|image <host> ...", other))),
    }
}

fn blk_test(run: &mut Run, verb: &str, args: &[String]) -> Result<i32, ClientError> {
    let usage = match verb {
        "read" => "blk read <host> DEV [--mb N] [--regions start,mid,end | --offset B --len B] [--bs 1m] [--direct]",
        "write" => "blk write <host> DEV --destructive --serial SERIAL [--allow-boot-media] [--mb N] [--regions ..] [--offset B --len B] [--seed N]",
        _ => "blk verify <host> DEV --seed N [--mb N] [--regions ..]",
    };
    let mut spec = Spec::new(usage).pos(1, 1);
    spec = match verb {
        "read" => spec.flags(&["direct"]).valued(&["mb", "regions", "offset", "len", "bs"]),
        "write" => spec.flags(&["destructive", "allow-boot-media", "direct"]).valued(&["mb", "regions", "offset", "len", "bs", "serial", "seed"]),
        _ => spec.valued(&["mb", "regions", "offset", "len", "bs", "seed"]),
    };
    let p = run.parse(args, &spec)?;
    if p.opts.value("regions").is_some() && (p.opts.value("offset").is_some() || p.opts.value("len").is_some()) {
        return Err(ClientError::Usage(format!("--regions and --offset/--len exclude each other\nusage: i7labctl {}", usage)));
    }
    if p.opts.value("offset").is_some() != p.opts.value("len").is_some() {
        return Err(ClientError::Usage(format!("--offset and --len go together\nusage: i7labctl {}", usage)));
    }
    let dev = p.pos[0].clone();
    if dev.contains('/') || dev.starts_with('-') {
        return Err(ClientError::Usage(format!("DEV is a name from `blk ls` (like sda or nvme0n1), not a path: '{}'", dev)));
    }
    let mut seed: Option<u64> = p.uint("seed")?;
    if verb == "write" {
        let serial = p.opts.value("serial").filter(|s| !s.trim().is_empty());
        if !p.opts.flag("destructive") || serial.is_none() {
            return Err(ClientError::Safety(format!(
                "blk write destroys data and needs BOTH --destructive and --serial SERIAL (the real serial of {} from `i7labctl blk ls`). Nothing was sent.",
                dev
            )));
        }
        if !run.confirm(&format!("Write test DESTROYS the contents of {} (serial {}) on the host{}. Continue?", dev, serial.unwrap(), if p.opts.flag("allow-boot-media") { " (--allow-boot-media: it may be the disk the host booted from)" } else { "" })) {
            return Err(ClientError::Safety("not confirmed".into()));
        }
        if seed.is_none() {
            let mut b = [0u8; 8];
            labproto::crypto::random_bytes(&mut b)?;
            seed = Some(u64::from_be_bytes(b) >> 12);
        }
    }
    if verb == "verify" && seed.is_none() {
        return Err(ClientError::Usage(format!("blk verify needs --seed N (the seed `blk write` printed)\nusage: i7labctl {}", usage)));
    }
    let mut wire = vec![dev.clone()];
    if verb == "write" {
        wire.push("--destructive".into());
        wire.extend(["--serial".to_string(), p.opts.value("serial").unwrap().to_string()]);
        if p.opts.flag("allow-boot-media") {
            wire.push("--allow-boot-media".into());
        }
    }
    for v in ["mb", "regions", "offset", "len", "bs"] {
        if let Some(x) = p.opts.value(v) {
            wire.extend([format!("--{}", v), x.to_string()]);
        }
    }
    if p.opts.flag("direct") {
        wire.push("--direct".into());
    }
    if let Some(s) = seed {
        wire.extend(["--seed".to_string(), s.to_string()]);
    }
    let name = format!("blk.{}", verb);
    let spec = catalog::by_name(&name).unwrap();
    let timeout = run.g.timeout.unwrap_or(0.0);
    let prep = run.prepare(p.host.as_deref(), timeout)?;
    let o = run_stream(run, prep, spec, &wire, None, None, true)?;
    if o.done.res.status != Status::Ok {
        return Ok(end_stream(run, &name, &o, None, 0));
    }
    let body = String::from_utf8_lossy(&o.done.res.body).into_owned();
    let (text, bad) = render::blk_test(&body, run.paint);
    let exit = if bad { 3 } else { 0 };
    if run.g.json {
        return Ok(end_stream(run, &name, &o, None, exit));
    }
    run.out(&text);
    if verb == "write" {
        if let Some(s) = seed {
            run.outln(&format!("seed {} (re-check later with: i7labctl blk verify <host> {} --seed {})", s, dev, s));
        }
    }
    Ok(exit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_filter_ssh_style() {
        let mut f = EscapeFilter::new(Some(b'~'));
        // at line start: ~. quits
        let (o, a) = f.feed(b"~.");
        assert!(o.is_empty());
        assert_eq!(a, vec![EscAction::Quit]);
        // not at line start: a tilde is literal
        let mut f = EscapeFilter::new(Some(b'~'));
        let (o, a) = f.feed(b"a~.");
        assert_eq!(o, b"a~.");
        assert!(a.is_empty());
        // after a newline it is an escape again; ~~ is a literal tilde
        let (o, a) = f.feed(b"\r~~x\r~?");
        assert_eq!(o, b"\r~x\r");
        assert_eq!(a, vec![EscAction::Help]);
        // unknown escape passes both bytes through
        let mut f = EscapeFilter::new(Some(b'~'));
        let (o, _) = f.feed(b"~q");
        assert_eq!(o, b"~q");
        // split across feeds
        let mut f = EscapeFilter::new(Some(b'~'));
        assert!(f.feed(b"~").0.is_empty());
        assert_eq!(f.feed(b"r").1, vec![EscAction::Reboot]);
        // disabled
        let mut f = EscapeFilter::new(None);
        assert_eq!(f.feed(b"~.").0, b"~.");
    }

    #[test]
    fn resize_message() {
        assert_eq!(ctl_resize(80, 24), vec![b'W', 0, 80, 0, 24]);
        assert_eq!(ctl_resize(300, 1), vec![b'W', 1, 44, 0, 1]);
    }

    #[test]
    fn file_input_and_sink_roundtrip() {
        let d = std::env::temp_dir().join(format!("i7ctl-stream-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let src = d.join("src.bin");
        let data: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src, &data).unwrap();
        let mut fi = FileInput::open(&src, 1000, Chan::File).unwrap();
        let mut got = Vec::new();
        loop {
            match fi.next() {
                Input::Data(Chan::File, b) => got.extend(b),
                Input::End(Chan::File) => break,
                other => panic!("{:?}", other),
            }
        }
        assert_eq!(got, &data[1000..]);
        let (size, dig) = sha_of_file(&src, 1000).unwrap();
        assert_eq!(size, 40_000);
        assert_eq!(dig, labproto::crypto::sha256(&data[1000..]));

        // sink: write in two goes with a resume in between
        let part = d.join("out.part");
        let mut s = FileSink::open(&part, false).unwrap();
        s.write(&data[..5000]);
        drop(s);
        let mut s = FileSink::open(&part, true).unwrap();
        assert_eq!(s.offset, 5000);
        s.write(&data[5000..]);
        assert_eq!(s.whole.clone().finish(), labproto::crypto::sha256(&data));
        assert_eq!(s.range.clone().finish(), labproto::crypto::sha256(&data[5000..]));
        assert_eq!(std::fs::read(&part).unwrap(), data);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn builtin_list_matches_plan() {
        for b in ["ls", "mount", "dmesg", "blk", "lab", "ip"] {
            assert!(SH_BUILTINS.contains(&b));
        }
        assert!(!SH_BUILTINS.contains(&"cargo") && !SH_BUILTINS.contains(&"i7labsh"));
    }
}
