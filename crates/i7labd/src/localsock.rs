//! Local control socket `<run_dir>/ctl.sock` for `i7labsh lab <cmd> ...` (root only, role admin, same dispatch).
//! Codec: `labproto::local` (shared with the i7labsh `lab` builtin). SO_PEERCRED uid 0 only; mode 0600; one
//! request per connection; output of streaming commands is collected into the reply body. Owner: P6a.

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use labproto::frame::Chan;
use labproto::keys::Role;
use labproto::local;
use labproto::Status;

use crate::daemon::Daemon;
use crate::registry::{Content, Ctx, Sink, Source};

pub const PATH: &str = labproto::local::PATH;
pub const MAX_CONNECTIONS: usize = 8;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Collects every data byte in arrival order (stdout, stderr, file), capped at the reply limit.
struct LocalSink {
    out: Vec<u8>,
}

impl Sink for LocalSink {
    fn data(&mut self, _c: Chan, b: &[u8]) -> io::Result<()> {
        if self.out.len() + b.len() > local::MAX_REPLY {
            return Err(io::Error::new(io::ErrorKind::Other, "reply too large"));
        }
        self.out.extend_from_slice(b);
        Ok(())
    }
    fn event(&mut self, _j: &str) -> io::Result<()> {
        Ok(())
    }
    fn streaming(&self) -> bool {
        false
    }
}

pub fn socket_path(d: &Daemon) -> std::path::PathBuf {
    d.config.run_dir.join("ctl.sock")
}

/// Answer one framed request.
pub fn handle_request(d: &Daemon, msg: &[u8]) -> Vec<u8> {
    let (cmd_id, argv) = match local::decode_request(msg) {
        Ok(x) => x,
        Err(e) => return local::encode_reply(Status::BadArgs, 0, crate::registry::Reply::error(Status::BadArgs, &e.to_string()).body.as_slice()),
    };
    let Some(cmd) = d.registry.by_id(cmd_id) else {
        return local::encode_reply(Status::Unsupported, 0, crate::registry::Reply::error(Status::Unsupported, "unknown command id").body.as_slice());
    };
    let mut sink = LocalSink { out: Vec::new() };
    let reply = {
        let mut ctx = Ctx {
            daemon: d,
            source: Source::Local,
            role: Role::Admin,
            actor: "local".into(),
            args: argv,
            sink: &mut sink,
            cancel: Arc::new(AtomicBool::new(false)),
        };
        d.registry.dispatch(&mut ctx, cmd)
    };
    let exit = match (reply.content, reply.status) {
        (Content::ExecResult, _) if reply.body.len() >= 4 => i32::from_be_bytes(reply.body[..4].try_into().unwrap()),
        (_, Status::Ok) => 0,
        (_, s) => s as i32,
    };
    let body = if !sink.out.is_empty() {
        sink.out
    } else if reply.content == Content::ExecResult && reply.body.len() >= 4 {
        reply.body[4..].to_vec()
    } else {
        reply.body
    };
    local::encode_reply(reply.status, exit, &body)
}

fn serve_conn(d: &Daemon, mut s: UnixStream) -> io::Result<()> {
    s.set_read_timeout(Some(IO_TIMEOUT))?;
    s.set_write_timeout(Some(IO_TIMEOUT))?;
    if crate::ffi::peer_uid(s.as_raw_fd())? != 0 && !cfg!(test) {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > local::MAX_REQ + 2 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut msg = vec![0u8; n];
    s.read_exact(&mut msg)?;
    // a long-running command may take longer than the read timeout allows for the reply write
    s.set_write_timeout(Some(Duration::from_secs(60)))?;
    s.write_all(&handle_request(d, &msg))
}

/// Serve on an already bound listener until it fails.
pub fn serve_listener(d: Arc<Daemon>, l: UnixListener) -> io::Result<()> {
    let active = Arc::new(AtomicUsize::new(0));
    for conn in l.incoming() {
        let Ok(c) = conn else { continue };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            continue; // dropped: the client sees EOF
        }
        let (d, a) = (d.clone(), active.clone());
        std::thread::spawn(move || {
            let _ = serve_conn(&d, c);
            a.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

pub fn serve(d: Arc<Daemon>) -> io::Result<()> {
    let path = socket_path(&d);
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(std::path::Path::new("/")));
    let _ = std::fs::remove_file(&path);
    let l = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    serve_listener(d, l)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests_support::test_daemon;

    fn call(path: &std::path::Path, cmd: u16, argv: &[&str]) -> (Status, i32, Vec<u8>) {
        let mut c = UnixStream::connect(path).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        c.write_all(&local::encode_request(cmd, &argv)).unwrap();
        let mut len = [0u8; 4];
        c.read_exact(&mut len).unwrap();
        let mut msg = vec![0u8; u32::from_be_bytes(len) as usize];
        c.read_exact(&mut msg).unwrap();
        let (st, exit, body) = local::decode_reply(&msg).unwrap();
        (st, exit, body.to_vec())
    }

    #[test]
    fn loopback_ping_exec_and_errors() {
        let d = Arc::new(test_daemon());
        let path = socket_path(&d);
        let l = UnixListener::bind(&path).unwrap();
        let d2 = d.clone();
        std::thread::spawn(move || serve_listener(d2, l));
        let (st, exit, body) = call(&path, 0x0001, &["x"]);
        assert_eq!((st, exit), (Status::Ok, 0));
        assert!(String::from_utf8_lossy(&body).contains("\"echo\":\"x\""));
        // exec: output collected, exit code surfaced
        let (st, exit, body) = call(&path, 0x0020, &["--", "/bin/sh", "-c", "echo hello; exit 7"]);
        assert_eq!((st, exit, body.as_slice()), (Status::Ok, 7, &b"hello\n"[..]));
        // unknown command, planned command
        assert_eq!(call(&path, 0x7777, &[]).0, Status::Unsupported);
        assert_eq!(call(&path, 0x0042, &["--kernel", "/x"]).0, Status::Unsupported);
        // refused by the registry: a path under the key directory
        assert_eq!(call(&path, 0x0031, &["/etc/i7lab/keys/admin.key"]).0, Status::Eperm);
        // oversized request is dropped without a reply
        let mut c = UnixStream::connect(&path).unwrap();
        c.write_all(&(10_000_000u32).to_be_bytes()).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut b = [0u8; 1];
        assert!(matches!(c.read(&mut b), Ok(0) | Err(_)));
    }
}
