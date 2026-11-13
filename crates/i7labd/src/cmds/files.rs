//! get, put, fs.ls, fs.stat, fs.rm (PROTOCOL.md section 7, PLAN.md C22).
//!
//! `registry::dispatch` has already applied `path_policy` and rewritten `args[0]` to the normal form. Here the
//! open itself is hardened: the read-only key opens with `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` from
//! the allow-listed root (`labproto::sys::openat2_beneath`; until P2 implements it the call fails closed and the
//! ro key gets UNSUPPORTED); every role is re-checked against `DENY_ALL` on the opened fd's real target.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Duration;

use labproto::crypto::{hex, unhex, Sha256};
use labproto::frame::Chan;
use labproto::json::JsonWriter;
use labproto::keys::Role;
use labproto::sys::resolve::{RESOLVE_BENEATH, RESOLVE_NO_MAGICLINKS};
use labproto::Status;

use crate::registry::{under, Ctx, Handler, Reply, DENY_ALL, RO_ROOTS};

pub const TABLE: &[(&str, Handler)] =
    &[("get", get), ("put", put), ("fs.ls", fs_ls), ("fs.stat", fs_stat), ("fs.rm", fs_rm)];

const CHUNK: usize = 32 * 1024;
const LS_MAX: usize = 5000;
const PUT_IDLE: Duration = Duration::from_secs(60);

fn io_reply(e: &std::io::Error) -> Reply {
    let st = match e.kind() {
        std::io::ErrorKind::NotFound => Status::NotFound,
        std::io::ErrorKind::PermissionDenied => Status::Eperm,
        std::io::ErrorKind::AlreadyExists => Status::Exists,
        std::io::ErrorKind::Unsupported => Status::Unsupported,
        _ => Status::Io,
    };
    Reply::error(st, &e.to_string())
}

/// Allow-list entry containing `path` -> (directory to open beneath, relative path).
pub fn ro_root_rel(path: &str) -> Option<(String, String)> {
    for r in RO_ROOTS {
        if under(path, r) {
            let is_file = Path::new(r).is_file();
            return Some(if is_file {
                let p = Path::new(r);
                (p.parent()?.to_string_lossy().into_owned(), p.file_name()?.to_string_lossy().into_owned())
            } else {
                let rel = path[r.len()..].trim_start_matches('/');
                ((*r).to_string(), if rel.is_empty() { ".".to_string() } else { rel.to_string() })
            });
        }
    }
    None
}

/// Open `path` read-only as the request's role may.
fn open_for(role: Role, path: &str) -> Result<File, Reply> {
    let f = if role == Role::Ro {
        let (root, rel) = ro_root_rel(path).ok_or_else(|| Reply::error(Status::Eperm, "path not allowed for the read-only key"))?;
        labproto::sys::openat2_beneath(Path::new(&root), Path::new(&rel), RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS).map_err(|e| {
            if e.kind() == std::io::ErrorKind::Unsupported {
                Reply::error(Status::Unsupported, "read-only file access is unavailable (openat2 not implemented): failing closed")
            } else {
                io_reply(&e)
            }
        })?
    } else {
        File::open(path).map_err(|e| io_reply(&e))?
    };
    // symlinks may have led anywhere: the opened object must not be key material
    if let Ok(t) = std::fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd())) {
        let t = t.to_string_lossy();
        if DENY_ALL.iter().any(|d| under(&t, d)) {
            return Err(Reply::error(Status::Eperm, "key material is never served as a file"));
        }
    }
    Ok(f)
}

fn type_name(m: &Metadata) -> &'static str {
    let t = m.file_type();
    if t.is_dir() {
        "dir"
    } else if t.is_file() {
        "file"
    } else if t.is_symlink() {
        "symlink"
    } else {
        "other"
    }
}

fn write_stat(w: &mut JsonWriter, m: &Metadata) {
    w.field_str("type", type_name(m));
    w.field_u64("size", m.len());
    w.field_u64("mode", (m.mode() & 0o7777) as u64);
    w.field_u64("uid", m.uid() as u64);
    w.field_u64("gid", m.gid() as u64);
    w.field_i64("mtime", m.mtime());
}

fn fs_stat(ctx: &mut Ctx) -> Reply {
    let f = match open_for(ctx.role, &ctx.args[0]) {
        Ok(f) => f,
        Err(r) => return r,
    };
    match f.metadata() {
        Ok(m) => {
            let mut w = JsonWriter::new();
            w.begin_object();
            w.field_u64("v", 1);
            w.field_str("path", &ctx.args[0]);
            write_stat(&mut w, &m);
            w.end_object();
            Reply::json(w.finish())
        }
        Err(e) => io_reply(&e),
    }
}

fn fs_ls(ctx: &mut Ctx) -> Reply {
    let o = match labproto::args::Opts::parse(&ctx.args[1..], &["long"], &[]) {
        Ok(o) => o,
        Err(e) => return Reply::error(Status::BadArgs, &e.to_string()),
    };
    let f = match open_for(ctx.role, &ctx.args[0]) {
        Ok(f) => f,
        Err(r) => return r,
    };
    match f.metadata() {
        Ok(m) if !m.is_dir() => return Reply::error(Status::BadArgs, "not a directory"),
        Err(e) => return io_reply(&e),
        _ => {}
    }
    // list through the fd so the checked open is the one that is read
    let fdpath = format!("/proc/self/fd/{}", f.as_raw_fd());
    let mut names: Vec<(String, std::fs::FileType)> = match std::fs::read_dir(&fdpath) {
        Ok(rd) => rd.flatten().filter_map(|e| Some((e.file_name().to_string_lossy().into_owned(), e.file_type().ok()?))).collect(),
        Err(e) => return io_reply(&e),
    };
    names.sort_by(|a, b| a.0.cmp(&b.0));
    let truncated = names.len() > LS_MAX;
    names.truncate(LS_MAX);
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_u64("v", 1);
    w.field_str("path", &ctx.args[0]);
    w.field_bool("truncated", truncated);
    w.key("entries");
    w.begin_array();
    for (name, ft) in names {
        w.begin_object();
        w.field_str("name", &name);
        if o.flag("long") {
            match std::fs::symlink_metadata(format!("{}/{}", fdpath, name)) {
                Ok(m) => write_stat(&mut w, &m),
                Err(_) => w.field_str("type", "unknown"),
            }
        } else {
            w.field_str("type", if ft.is_dir() { "dir" } else if ft.is_file() { "file" } else if ft.is_symlink() { "symlink" } else { "other" });
        }
        w.end_object();
    }
    w.end_array();
    w.end_object();
    Reply::json(w.finish())
}

fn fs_rm(ctx: &mut Ctx) -> Reply {
    let o = match labproto::args::Opts::parse(&ctx.args[1..], &["recursive"], &[]) {
        Ok(o) => o,
        Err(e) => return Reply::error(Status::BadArgs, &e.to_string()),
    };
    let p = &ctx.args[0];
    if p == "/" {
        return Reply::error(Status::Refused, "refusing to remove /");
    }
    let m = match std::fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) => return io_reply(&e),
    };
    let r = if m.is_dir() {
        if o.flag("recursive") {
            std::fs::remove_dir_all(p)
        } else {
            std::fs::remove_dir(p)
        }
    } else {
        std::fs::remove_file(p)
    };
    match r {
        Ok(()) => Reply::ok_empty(),
        Err(e) => io_reply(&e),
    }
}

fn parse_u64(o: &labproto::args::Opts, k: &str) -> Result<Option<u64>, Reply> {
    match o.value(k) {
        None => Ok(None),
        Some(v) => v.parse().map(Some).map_err(|_| Reply::error(Status::BadArgs, &format!("bad --{}", k))),
    }
}

/// `get PATH [--offset N] [--len N]`: chan 4 data, RESP `{size,mode,mtime,offset,sent,sha256}` (sha256 of the bytes sent).
fn get(ctx: &mut Ctx) -> Reply {
    let o = match labproto::args::Opts::parse(&ctx.args[1..], &[], &["offset", "len"]) {
        Ok(o) => o,
        Err(e) => return Reply::error(Status::BadArgs, &e.to_string()),
    };
    let (offset, len) = match (parse_u64(&o, "offset"), parse_u64(&o, "len")) {
        (Ok(a), Ok(b)) => (a.unwrap_or(0), b),
        (Err(r), _) | (_, Err(r)) => return r,
    };
    let mut f = match open_for(ctx.role, &ctx.args[0]) {
        Ok(f) => f,
        Err(r) => return r,
    };
    let meta = match f.metadata() {
        Ok(m) => m,
        Err(e) => return io_reply(&e),
    };
    if meta.is_dir() {
        return Reply::error(Status::BadArgs, "is a directory (use fs.ls)");
    }
    if offset > 0 && f.seek(SeekFrom::Start(offset)).is_err() {
        return Reply::error(Status::BadArgs, "cannot seek");
    }
    let mut left = len.unwrap_or(u64::MAX);
    let (mut sent, mut h) = (0u64, Sha256::new());
    let mut buf = vec![0u8; CHUNK];
    while left > 0 {
        if ctx.cancel.load(Ordering::SeqCst) {
            return Reply::error(Status::Canceled, "canceled");
        }
        let want = (left.min(CHUNK as u64)) as usize;
        let n = match f.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return io_reply(&e),
        };
        h.update(&buf[..n]);
        if ctx.sink.data(Chan::File, &buf[..n]).is_err() {
            return Reply::error(Status::Canceled, "transport closed");
        }
        sent += n as u64;
        left -= n as u64;
    }
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_u64("v", 1);
    w.field_u64("size", meta.len());
    w.field_u64("mode", (meta.mode() & 0o7777) as u64);
    w.field_i64("mtime", meta.mtime());
    w.field_u64("offset", offset);
    w.field_u64("sent", sent);
    w.field_str("sha256", &hex(&h.finish()));
    w.end_object();
    Reply::json(w.finish())
}

/// `put PATH --size N --sha256 HEX [--mode 0644] [--offset N] [--mkdirs]`: bytes arrive through `Sink::input`;
/// they go to `PATH.part`, which is renamed after size and sha256 (of this request's bytes) check out.
fn put(ctx: &mut Ctx) -> Reply {
    let o = match labproto::args::Opts::parse(&ctx.args[1..], &["mkdirs"], &["size", "sha256", "mode", "offset"]) {
        Ok(o) => o,
        Err(e) => return Reply::error(Status::BadArgs, &e.to_string()),
    };
    let size = match parse_u64(&o, "size") {
        Ok(Some(s)) => s,
        Ok(None) => return Reply::error(Status::BadArgs, "--size is required"),
        Err(r) => return r,
    };
    let offset = match parse_u64(&o, "offset") {
        Ok(v) => v.unwrap_or(0),
        Err(r) => return r,
    };
    if offset > size {
        return Reply::error(Status::BadArgs, "--offset beyond --size");
    }
    let want_sha: [u8; 32] = match o.value("sha256").and_then(unhex).and_then(|v| v.try_into().ok()) {
        Some(h) => h,
        None => return Reply::error(Status::BadArgs, "--sha256 (64 hex digits) is required"),
    };
    let mode = match o.value("mode") {
        None => 0o644,
        Some(m) => match u32::from_str_radix(m, 8) {
            Ok(v) if v <= 0o777 => v,
            _ => return Reply::error(Status::BadArgs, "bad --mode (octal, at most 0777)"),
        },
    };
    let path = ctx.args[0].clone();
    let part = format!("{}.part", path);
    let Some(input) = ctx.sink.input() else {
        return Reply::error(Status::Unsupported, "this transport has no upload channel");
    };
    if let Some(parent) = Path::new(&path).parent() {
        if o.flag("mkdirs") {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return io_reply(&e);
            }
        }
    }
    if std::fs::symlink_metadata(&path).map(|m| m.is_dir()).unwrap_or(false) {
        return Reply::error(Status::BadArgs, "target is a directory");
    }
    let mut f = {
        let mut oo = OpenOptions::new();
        oo.write(true).create(true).custom_flags(0o400000 /* O_NOFOLLOW */).mode(0o600);
        if offset == 0 {
            oo.truncate(true);
        }
        match oo.open(&part) {
            Ok(f) => f,
            Err(e) => return io_reply(&e),
        }
    };
    if offset > 0 {
        match f.metadata() {
            Ok(m) if m.len() >= offset => {}
            Ok(_) => return Reply::error(Status::BadArgs, ".part file is shorter than --offset"),
            Err(e) => return io_reply(&e),
        }
        if f.set_len(offset).is_err() || f.seek(SeekFrom::Start(offset)).is_err() {
            return Reply::error(Status::Io, "cannot position .part file");
        }
    }
    let expect = size - offset;
    let (mut got, mut h) = (0u64, Sha256::new());
    let mut last_data = std::time::Instant::now();
    while got < expect {
        if ctx.cancel.load(Ordering::SeqCst) {
            return Reply::error(Status::Canceled, "canceled (the .part file is kept for --offset resume)");
        }
        match input.recv_timeout(PUT_IDLE.min(Duration::from_millis(500))) {
            Ok(chunk) => {
                last_data = std::time::Instant::now();
                if got + chunk.len() as u64 > expect {
                    let _ = std::fs::remove_file(&part);
                    return Reply::error(Status::TooBig, "more data than --size");
                }
                h.update(&chunk);
                if let Err(e) = f.write_all(&chunk) {
                    return io_reply(&e);
                }
                got += chunk.len() as u64;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if last_data.elapsed() > PUT_IDLE {
                    return Reply::error(Status::Timeout, "upload stalled (the .part file is kept for --offset resume)");
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    if let Ok(extra) = input.try_recv() {
        if !extra.is_empty() {
            let _ = std::fs::remove_file(&part);
            return Reply::error(Status::TooBig, "more data than --size");
        }
    }
    if got != expect {
        return Reply::error(Status::Io, &format!("upload ended after {} of {} bytes (the .part file is kept for --offset resume)", got, expect));
    }
    let digest = h.finish();
    if digest != want_sha {
        let _ = std::fs::remove_file(&part);
        return Reply::error(Status::Io, "sha256 mismatch: .part removed");
    }
    if f.sync_all().is_err() || f.set_permissions(std::fs::Permissions::from_mode(mode)).is_err() {
        return Reply::error(Status::Io, "cannot finalise file");
    }
    if let Err(e) = std::fs::rename(&part, &path) {
        return io_reply(&e);
    }
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_u64("v", 1);
    w.field_u64("bytes", got);
    w.field_str("sha256", &hex(&digest));
    w.end_object();
    Reply::json(w.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests_support::*;
    use crate::registry::{CollectSink, Ctx, Sink, Source};
    use labproto::crypto::sha256;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc::Receiver;
    use std::sync::Arc;

    struct Upload(Option<Receiver<Vec<u8>>>, CollectSink);
    impl Sink for Upload {
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

    fn do_put(d: &crate::Daemon, args: &[String], chunks: &[&[u8]]) -> Reply {
        let (tx, rx) = std::sync::mpsc::channel();
        for c in chunks {
            tx.send(c.to_vec()).unwrap();
        }
        drop(tx);
        let mut sink = Upload(Some(rx), CollectSink::default());
        let mut ctx = Ctx { daemon: d, source: Source::Local, role: Role::Admin, actor: "t".into(), args: args.to_vec(), sink: &mut sink, cancel: Arc::new(AtomicBool::new(false)) };
        let cmd = d.registry.get("put").unwrap();
        d.registry.dispatch(&mut ctx, cmd)
    }

    #[test]
    fn put_then_get_roundtrip_with_hash_check() {
        let d = test_daemon();
        let dir = d.config.run_dir.join("files");
        let path = dir.join("a.bin");
        let data = b"hello world, some bytes";
        let args = |extra: &[&str]| -> Vec<String> {
            let mut v = vec![path.to_string_lossy().into_owned(), "--size".into(), data.len().to_string(), "--sha256".into(), hex(&sha256(data)), "--mkdirs".into()];
            v.extend(extra.iter().map(|s| s.to_string()));
            v
        };
        let r = do_put(&d, &args(&["--mode", "0600"]), &[&data[..5], &data[5..]]);
        assert_eq!(r.status, Status::Ok, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(std::fs::read(&path).unwrap(), data);
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(!dir.join("a.bin.part").exists());
        // get it back
        let (r, sink) = run_with(&d, Role::Admin, "get", &[path.to_str().unwrap(), "--offset", "6", "--len", "5"]);
        assert_eq!(r.status, Status::Ok);
        assert_eq!(sink.file, b"world");
        assert!(String::from_utf8_lossy(&r.body).contains(&hex(&sha256(b"world"))));
        // wrong hash: .part removed, target untouched
        let mut bad = args(&[]);
        bad[4] = hex(&sha256(b"other"));
        let r = do_put(&d, &bad, &[data]);
        assert_eq!(r.status, Status::Io);
        assert!(!dir.join("a.bin.part").exists());
        // short upload keeps .part for resume, too much data is TOO_BIG
        let r = do_put(&d, &args(&[]), &[&data[..4]]);
        assert_eq!(r.status, Status::Io);
        assert!(dir.join("a.bin.part").exists());
        let r = do_put(&d, &args(&["--offset", "4"]), &[&data[4..]]);
        assert_eq!(r.status, Status::Io, "sub-range sha256 covers only this request's bytes");
        let r = do_put(&d, &args(&[]), &[data, b"x"]);
        assert_eq!(r.status, Status::TooBig);
        let _ = std::fs::remove_dir_all(&d.config.run_dir);
    }

    #[test]
    fn resume_uses_a_sub_range_hash() {
        let d = test_daemon();
        let path = d.config.run_dir.join("r.bin");
        let data = b"0123456789";
        let mk = |size: usize, sha: [u8; 32], off: &str| vec![path.to_string_lossy().into_owned(), "--size".into(), size.to_string(), "--sha256".into(), hex(&sha), "--offset".into(), off.into()];
        assert_eq!(do_put(&d, &mk(10, sha256(data), "0"), &[&data[..4]]).status, Status::Io);
        let r = do_put(&d, &mk(10, sha256(&data[4..]), "4"), &[&data[4..]]);
        assert_eq!(r.status, Status::Ok, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(std::fs::read(&path).unwrap(), data);
        let _ = std::fs::remove_dir_all(&d.config.run_dir);
    }

    #[test]
    fn ls_stat_rm() {
        let d = test_daemon();
        let base = d.config.run_dir.join("lsdir");
        std::fs::create_dir_all(base.join("sub")).unwrap();
        std::fs::write(base.join("f"), b"abc").unwrap();
        let b = base.to_str().unwrap();
        let (r, _) = run_with(&d, Role::Admin, "fs.ls", &[b, "--long"]);
        let j = String::from_utf8(r.body).unwrap();
        assert!(j.contains("\"name\":\"f\"") && j.contains("\"name\":\"sub\"") && j.contains("\"size\":3"), "{}", j);
        let (r, _) = run_with(&d, Role::Admin, "fs.stat", &[base.join("f").to_str().unwrap()]);
        assert!(String::from_utf8(r.body).unwrap().contains("\"type\":\"file\""));
        assert_eq!(run_with(&d, Role::Admin, "fs.rm", &[b]).0.status, Status::Io, "non-empty dir without --recursive");
        assert_eq!(run_with(&d, Role::Admin, "fs.rm", &[b, "--recursive"]).0.status, Status::Ok);
        assert_eq!(run_with(&d, Role::Admin, "fs.stat", &[b]).0.status, Status::NotFound);
        assert_eq!(run_with(&d, Role::Admin, "fs.rm", &["/"]).0.status, Status::Refused);
        let _ = std::fs::remove_dir_all(&d.config.run_dir);
    }

    #[test]
    fn denied_paths_and_ro_fail_closed() {
        let d = test_daemon();
        assert_eq!(run_with(&d, Role::Admin, "get", &["/etc/i7lab/keys/admin.key"]).0.status, Status::Eperm);
        assert_eq!(run_with(&d, Role::Admin, "put", &["/run/i7lab/audit.log", "--size", "0", "--sha256", &"0".repeat(64)]).0.status, Status::Eperm);
        assert_eq!(run_with(&d, Role::Ro, "get", &["/etc/shadow"]).0.status, Status::Eperm);
        assert_eq!(run_with(&d, Role::Ro, "get", &["/proc/self/mem"]).0.status, Status::Eperm);
        // an allowed ro path either works (openat2 landed) or fails closed: never a plain open
        let st = run_with(&d, Role::Ro, "get", &["/proc/cpuinfo"]).0.status;
        assert!(matches!(st, Status::Ok | Status::Unsupported), "{:?}", st);
    }

    #[test]
    fn ro_root_mapping() {
        assert_eq!(ro_root_rel("/proc/1/status"), Some(("/proc".into(), "1/status".into())));
        assert_eq!(ro_root_rel("/var/log"), Some(("/var/log".into(), ".".into())));
        assert_eq!(ro_root_rel("/etc/shadow"), None);
        if Path::new("/etc/os-release").is_file() {
            assert_eq!(ro_root_rel("/etc/os-release"), Some(("/etc".into(), "os-release".into())));
        }
    }
}
