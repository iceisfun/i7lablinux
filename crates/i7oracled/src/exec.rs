//! Running programs with captured output and a timeout, probe-name rules, and the results store.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const OUT_CAP: usize = 4 << 20;

#[derive(Debug, Default)]
pub struct ExecResult {
    pub exit: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
    pub duration_ms: u64,
    pub spawn_error: Option<String>,
}

fn drain<R: Read + Send + 'static>(mut r: R, cap: usize) -> mpsc::Receiver<(Vec<u8>, bool)> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut trunc = false;
        let mut buf = [0u8; 8192];
        loop {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = cap.saturating_sub(out.len());
                    if n > room {
                        trunc = true;
                    }
                    out.extend_from_slice(&buf[..n.min(room)]);
                }
            }
        }
        let _ = tx.send((out, trunc));
    });
    rx
}

#[cfg(windows)]
fn no_window(c: &mut Command) {
    use std::os::windows::process::CommandExt;
    c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
}
#[cfg(not(windows))]
fn no_window(_: &mut Command) {}

/// Run `program args` and capture stdout and stderr (each capped at `cap`). Kills the process (and on Windows its
/// tree) when `timeout` elapses. stdin is closed.
pub fn exec_capture(program: &str, args: &[String], cwd: Option<&Path>, timeout: Duration, cap: usize) -> ExecResult {
    let t0 = Instant::now();
    let mut cmd = Command::new(program);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    no_window(&mut cmd);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return ExecResult { spawn_error: Some(e.to_string()), duration_ms: t0.elapsed().as_millis() as u64, ..Default::default() },
    };
    let so = drain(child.stdout.take().unwrap(), cap);
    let se = drain(child.stderr.take().unwrap(), cap);
    let mut res = ExecResult::default();
    loop {
        match child.try_wait() {
            Ok(Some(st)) => {
                res.exit = st.code();
                break;
            }
            Ok(None) => {
                if t0.elapsed() >= timeout {
                    res.timed_out = true;
                    kill_tree(&mut child);
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(e) => {
                res.spawn_error = Some(e.to_string());
                break;
            }
        }
    }
    // a surviving grandchild may hold the pipes open: do not wait for them forever
    let grace = Duration::from_secs(if res.timed_out { 2 } else { 5 });
    if let Ok((b, t)) = so.recv_timeout(grace) {
        res.stdout = b;
        res.truncated |= t;
    }
    if let Ok((b, t)) = se.recv_timeout(grace) {
        res.stderr = b;
        res.truncated |= t;
    }
    res.duration_ms = t0.elapsed().as_millis() as u64;
    res
}

fn kill_tree(child: &mut std::process::Child) {
    #[cfg(windows)]
    {
        let mut c = Command::new("taskkill");
        c.args(["/F", "/T", "/PID", &child.id().to_string()]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        no_window(&mut c);
        let _ = c.status();
    }
    let _ = child.kill();
}

// ------------------------------------------------------------------------------------------------ probes

/// A probe is a plain file name in the probes directory: no separators, no drive letters, no dots-only names,
/// and an extension we know how to launch.
pub fn valid_probe_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 || name.starts_with('.') || name.contains("..") {
        return false;
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ' ')) {
        return false;
    }
    matches!(ext(name).as_str(), "exe" | "bat" | "cmd" | "ps1")
}

fn ext(name: &str) -> String {
    name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default()
}

/// Program and argv for launching probe `path` with `args` (scripts go through their interpreter).
pub fn command_for(path: &Path, args: &[String]) -> (String, Vec<String>) {
    let p = path.to_string_lossy().into_owned();
    match ext(&p).as_str() {
        "bat" | "cmd" => {
            let mut a = vec!["/c".to_string(), p];
            a.extend(args.iter().cloned());
            ("cmd.exe".into(), a)
        }
        "ps1" => {
            let mut a = vec!["-NoProfile".into(), "-NonInteractive".into(), "-ExecutionPolicy".into(), "Bypass".into(), "-File".into(), p];
            a.extend(args.iter().cloned());
            ("powershell.exe".into(), a)
        }
        _ => (p, args.to_vec()),
    }
}

/// Sorted names of the launchable files in `dir` that are `.exe` (sweep) or any probe type (`all`).
pub fn list_probes(dir: &Path, only_exe: bool) -> Vec<String> {
    let mut v: Vec<String> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).filter(|e| e.path().is_file()).filter_map(|e| e.file_name().into_string().ok()).filter(|n| valid_probe_name(n) && (!only_exe || ext(n) == "exe")).collect(),
        Err(_) => Vec::new(),
    };
    v.sort_by_key(|n| n.to_ascii_lowercase());
    v
}

// ------------------------------------------------------------------------------------------------ results

pub fn valid_result_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 200 && !n.starts_with('.') && !n.contains("..") && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn sanitize(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' }).collect()
}

/// Write `<utc>-<name>.txt` (never overwriting) and return the file name.
pub fn save_result(dir: &Path, utc_compact: &str, name: &str, header: &str, stdout: &[u8], stderr: &[u8]) -> io::Result<String> {
    std::fs::create_dir_all(dir)?;
    let base = format!("{}-{}", utc_compact, sanitize(name));
    for n in 0..1000 {
        let fname = if n == 0 { format!("{}.txt", base) } else { format!("{}-{}.txt", base, n) };
        match std::fs::OpenOptions::new().write(true).create_new(true).open(dir.join(&fname)) {
            Ok(mut f) => {
                f.write_all(header.as_bytes())?;
                f.write_all(b"--- stdout ---\n")?;
                f.write_all(stdout)?;
                f.write_all(b"\n--- stderr ---\n")?;
                f.write_all(stderr)?;
                f.write_all(b"\n")?;
                f.sync_all()?;
                return Ok(fname);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "too many results with the same name"))
}

/// (name, size) newest first (names start with a UTC stamp).
pub fn list_results(dir: &Path) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).filter_map(|e| Some((e.file_name().into_string().ok()?, e.metadata().ok()?.len()))).filter(|(n, _)| valid_result_name(n)).collect(),
        Err(_) => Vec::new(),
    };
    v.sort_by(|a, b| b.0.cmp(&a.0));
    v
}

pub fn read_result(dir: &Path, name: &str) -> io::Result<Vec<u8>> {
    if !valid_result_name(name) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad file name"));
    }
    let p: PathBuf = dir.join(name);
    let md = std::fs::metadata(&p)?;
    if !md.is_file() || md.len() > 16 << 20 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a readable result"));
    }
    std::fs::read(p)
}

pub fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

// ------------------------------------------------------------------------------------------------ collector

/// POST `body` to `http://<host_port><path>` with a short timeout. Unauthenticated by design (the collector is optional
/// and the body is a summary line only). Returns the status code.
pub fn http_post(host_port: &str, path: &str, body: &str, timeout: Duration) -> io::Result<u16> {
    use std::net::ToSocketAddrs;
    let addr = host_port.to_socket_addrs()?.next().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))?;
    let mut s = std::net::TcpStream::connect_timeout(&addr, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    let req = format!("POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", path, host_port, body.len(), body);
    s.write_all(req.as_bytes())?;
    let mut resp = Vec::new();
    let _ = s.take(4096).read_to_end(&mut resp);
    let line = String::from_utf8_lossy(&resp);
    line.split(' ').nth(1).and_then(|c| c.parse().ok()).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no status line"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(n: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("i7oracled-exec-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn probe_names() {
        for ok in ["win10_foo_probe.exe", "a.EXE", "x y.cmd", "s.ps1"] {
            assert!(valid_probe_name(ok), "{}", ok);
        }
        for bad in ["", "..\\x.exe", "../x.exe", "a/b.exe", "C:x.exe", ".hidden.exe", "a..b.exe", "noext", "a.dll", "a;b.exe", "a\"b.exe"] {
            assert!(!valid_probe_name(bad), "{}", bad);
        }
    }

    #[test]
    fn launch_lines() {
        let (p, a) = command_for(Path::new("C:\\oracle\\probes\\a.exe"), &["1".into()]);
        assert_eq!((p.as_str(), a), ("C:\\oracle\\probes\\a.exe", vec!["1".to_string()]));
        let (p, a) = command_for(Path::new("x.cmd"), &["q".into()]);
        assert_eq!((p.as_str(), a), ("cmd.exe", vec!["/c".into(), "x.cmd".into(), "q".into()]));
        assert_eq!(command_for(Path::new("x.ps1"), &[]).0, "powershell.exe");
    }

    #[test]
    fn results_store() {
        let d = tmpdir("results");
        let n = save_result(&d, "20261112T000000Z", "a b.exe", "# h\n", b"out", b"err").unwrap();
        assert_eq!(n, "20261112T000000Z-a_b.exe.txt");
        let n2 = save_result(&d, "20261112T000000Z", "a b.exe", "# h\n", b"2", b"").unwrap();
        assert_eq!(n2, "20261112T000000Z-a_b.exe-1.txt");
        let list = list_results(&d);
        assert_eq!(list.len(), 2);
        assert!(String::from_utf8(read_result(&d, &n).unwrap()).unwrap().contains("--- stdout ---\nout\n--- stderr ---\nerr"));
        assert!(read_result(&d, "../x").is_err());
        assert!(read_result(&d, "missing.txt").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn exec_captures_and_times_out() {
        let r = exec_capture("sh", &["-c".into(), "echo hi; echo err >&2; exit 3".into()], None, Duration::from_secs(10), 1000);
        assert_eq!((r.exit, r.timed_out), (Some(3), false));
        assert_eq!(r.stdout, b"hi\n");
        assert_eq!(r.stderr, b"err\n");
        let r = exec_capture("sh", &["-c".into(), "sleep 30".into()], None, Duration::from_millis(200), 1000);
        assert!(r.timed_out && r.exit != Some(0));
        assert!(r.duration_ms < 5000);
        let r = exec_capture("sh", &["-c".into(), "head -c 100000 /dev/zero".into()], None, Duration::from_secs(10), 1000);
        assert!(r.truncated && r.stdout.len() == 1000);
        let r = exec_capture("/nonexistent/prog", &[], None, Duration::from_secs(1), 10);
        assert!(r.spawn_error.is_some());
    }

    #[test]
    fn post_to_local_collector() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = [0u8; 2048];
            let n = s.read(&mut buf).unwrap();
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        let code = http_post(&format!("127.0.0.1:{}", port), "/oracle-hello", "{\"a\":1}", Duration::from_secs(3)).unwrap();
        assert_eq!(code, 200);
        let got = t.join().unwrap();
        assert!(got.starts_with("POST /oracle-hello HTTP/1.1") && got.ends_with("{\"a\":1}"));
    }

    #[test]
    fn probes_listing_sorted() {
        let d = tmpdir("probes");
        for n in ["b.exe", "A.exe", "c.cmd", "d.txt"] {
            std::fs::write(d.join(n), b"").unwrap();
        }
        assert_eq!(list_probes(&d, true), vec!["A.exe", "b.exe"]);
        assert_eq!(list_probes(&d, false), vec!["A.exe", "b.exe", "c.cmd"]);
    }
}
