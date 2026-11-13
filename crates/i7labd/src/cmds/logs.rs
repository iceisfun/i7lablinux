//! logs [--dmesg|--init|--daemon|--http|--audit] [-n LINES] [-f]: text lines on the stdout channel.
//! Sources: kernel ring (/dev/kmsg), init log file, daemon and HTTP rings, audit lines (live from the EventBus).

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::Ordering;
use std::time::Duration;

use labproto::frame::Chan;
use labproto::json::JsonWriter;
use labproto::Status;

use crate::events::Event;
use crate::logring::LogRing;
use crate::opts_or_bad;
use crate::registry::{Ctx, Handler, Reply};

pub const TABLE: &[(&str, Handler)] = &[("logs", logs)];

pub const DEFAULT_LINES: usize = 200;
pub const MAX_LINES: usize = 5000;
const POLL: Duration = Duration::from_millis(200);

fn emit(ctx: &mut Ctx, lines: &[String]) -> bool {
    for l in lines {
        let s = format!("{}\n", labproto::text::sanitize(l));
        if ctx.sink.data(Chan::Stdout, s.as_bytes()).is_err() {
            return false;
        }
    }
    true
}

fn done(n: usize) -> Reply {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_u64("v", 1);
    w.field_u64("lines", n as u64);
    w.end_object();
    Reply::json(w.finish())
}

fn follow_ring(ctx: &mut Ctx, ring: &LogRing, n: usize, follow: bool) -> Reply {
    let (tail, mut next) = ring.tail(n);
    let mut total = tail.len();
    if !emit(ctx, &tail) {
        return Reply::error(Status::Canceled, "transport closed");
    }
    while follow && !ctx.cancel.load(Ordering::SeqCst) {
        std::thread::sleep(POLL);
        let (lines, nx) = ring.since(next);
        next = nx;
        total += lines.len();
        if !emit(ctx, &lines) {
            break;
        }
    }
    done(total)
}

/// "pri,seq,ts;text" records of /dev/kmsg -> "[  12.345678] text" (non-blocking drain).
fn drain_kmsg(f: &mut File, out: &mut Vec<String>) {
    let mut buf = vec![0u8; 8192];
    loop {
        match f.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                let rec = String::from_utf8_lossy(&buf[..n]);
                if let Some(l) = labprobe::kmsg::parse_record(&rec) {
                    out.push(format!("[{:>5}.{:06}] {}", l.ts_us / 1_000_000, l.ts_us % 1_000_000, l.text));
                }
            }
            // EPIPE = the record we were at was overwritten; the next read continues at the oldest one
            Err(e) if e.raw_os_error() == Some(32) => {}
            Err(_) => return, // EAGAIN: drained
        }
    }
}

fn dmesg(ctx: &mut Ctx, n: usize, follow: bool) -> Reply {
    let mut f = match std::fs::OpenOptions::new().read(true).custom_flags(0o4000 /* O_NONBLOCK */).open("/dev/kmsg") {
        Ok(f) => f,
        Err(e) => return Reply::error(Status::Io, &format!("/dev/kmsg: {}", e)),
    };
    let mut lines = Vec::new();
    drain_kmsg(&mut f, &mut lines);
    let skip = lines.len().saturating_sub(n);
    let mut total = lines.len() - skip;
    if !emit(ctx, &lines[skip..]) {
        return Reply::error(Status::Canceled, "transport closed");
    }
    while follow && !ctx.cancel.load(Ordering::SeqCst) {
        std::thread::sleep(POLL);
        let mut more = Vec::new();
        drain_kmsg(&mut f, &mut more);
        total += more.len();
        if !emit(ctx, &more) {
            break;
        }
    }
    done(total)
}

fn tail_file(ctx: &mut Ctx, path: &std::path::Path, n: usize, follow: bool) -> Reply {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) => return Reply::error(if e.kind() == std::io::ErrorKind::NotFound { Status::NotFound } else { Status::Io }, &format!("{}: {}", path.display(), e)),
    };
    let mut text = String::new();
    let _ = f.read_to_string(&mut text);
    let mut pos = text.len() as u64;
    let all: Vec<String> = text.lines().map(str::to_string).collect();
    let tail = &all[all.len().saturating_sub(n)..];
    let mut total = tail.len();
    if !emit(ctx, tail) {
        return Reply::error(Status::Canceled, "transport closed");
    }
    while follow && !ctx.cancel.load(Ordering::SeqCst) {
        std::thread::sleep(POLL);
        let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(pos);
        if len > pos {
            use std::io::{Seek, SeekFrom};
            let mut chunk = String::new();
            if f.seek(SeekFrom::Start(pos)).is_ok() && f.read_to_string(&mut chunk).is_ok() {
                pos += chunk.len() as u64;
                let lines: Vec<String> = chunk.lines().map(str::to_string).collect();
                total += lines.len();
                if !emit(ctx, &lines) {
                    break;
                }
            }
        }
    }
    done(total)
}

fn audit(ctx: &mut Ctx, n: usize, follow: bool) -> Reply {
    let rx = ctx.daemon.events.subscribe();
    let recent = ctx.daemon.audit.recent(n);
    let mut total = recent.len();
    if !emit(ctx, &recent) {
        return Reply::error(Status::Canceled, "transport closed");
    }
    while follow && !ctx.cancel.load(Ordering::SeqCst) {
        match rx.recv_timeout(POLL) {
            Ok(Event::Audit(l)) => {
                total += 1;
                if !emit(ctx, &[l]) {
                    break;
                }
            }
            Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => break,
        }
    }
    done(total)
}

fn logs(ctx: &mut Ctx) -> Reply {
    let o = opts_or_bad!(ctx, &["dmesg", "init", "daemon", "http", "audit", "f"], &["n"]);
    let n = match o.value("n").map(|v| v.parse::<usize>()) {
        Some(Ok(n)) if n > 0 => n.min(MAX_LINES),
        Some(_) => return Reply::error(Status::BadArgs, "bad -n"),
        None => DEFAULT_LINES,
    };
    let chosen: Vec<&str> = ["dmesg", "init", "daemon", "http", "audit"].into_iter().filter(|s| o.flag(s)).collect();
    if chosen.len() > 1 {
        return Reply::error(Status::BadArgs, "choose one of --dmesg --init --daemon --http --audit");
    }
    // following needs a transport that streams; a buffering sink would never see the end
    let follow = o.flag("f") && ctx.sink.streaming();
    let d = ctx.daemon;
    match chosen.first().copied().unwrap_or("dmesg") {
        "daemon" => follow_ring(ctx, &d.logs, n, follow),
        "http" => follow_ring(ctx, &d.http_log, n, follow),
        "audit" => audit(ctx, n, follow),
        "init" => {
            let p = d.config.run_dir.join("init.log");
            tail_file(ctx, &p, n, follow)
        }
        _ => dmesg(ctx, n, follow),
    }
}

#[cfg(test)]
mod tests {
    use crate::registry::tests_support::*;
    use labproto::keys::Role;
    use labproto::Status;

    #[test]
    fn daemon_and_init_and_audit_sources() {
        let d = test_daemon();
        for i in 0..5 {
            d.log(&format!("line {}", i));
        }
        let (r, s) = run_with(&d, Role::Ro, "logs", &["--daemon", "-n", "2"]);
        assert_eq!(r.status, Status::Ok);
        let out = String::from_utf8(s.stdout).unwrap();
        assert_eq!(out.lines().count(), 2, "{}", out);
        assert!(out.contains("line 4") && !out.contains("line 2"));
        // init log file
        std::fs::write(d.config.run_dir.join("init.log"), "a\nb\nc\n").unwrap();
        let (_, s) = run_with(&d, Role::Ro, "logs", &["--init", "-n", "2"]);
        assert_eq!(String::from_utf8(s.stdout).unwrap(), "b\nc\n");
        assert_eq!(run_with(&d, Role::Ro, "logs", &["--http"]).0.status, Status::Ok);
        // audit: an admin command shows up
        run_with(&d, Role::Admin, "time.set", &["1800000000"]);
        let (_, s) = run_with(&d, Role::Ro, "logs", &["--audit"]);
        assert!(String::from_utf8(s.stdout).unwrap().contains("cmd=time.set"));
        assert_eq!(run_with(&d, Role::Ro, "logs", &["--daemon", "--http"]).0.status, Status::BadArgs);
        assert_eq!(run_with(&d, Role::Ro, "logs", &["-n", "0"]).0.status, Status::BadArgs);
        assert_eq!(run_with(&d, Role::Ro, "logs", &["--init", "-n", "1"]).0.status, Status::Ok);
    }

    #[test]
    fn ring_follow_stops_on_cancel() {
        use crate::registry::{CollectSink, Ctx, Source};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        // a streaming sink is needed for -f: reuse the exec test pattern with a tiny wrapper
        struct S(CollectSink);
        impl crate::registry::Sink for S {
            fn data(&mut self, c: labproto::frame::Chan, b: &[u8]) -> std::io::Result<()> {
                self.0.data(c, b)
            }
            fn event(&mut self, j: &str) -> std::io::Result<()> {
                self.0.event(j)
            }
        }
        let d = Arc::new(test_daemon());
        d.log("first");
        let cancel = Arc::new(AtomicBool::new(false));
        let (d2, c2) = (d.clone(), cancel.clone());
        let h = std::thread::spawn(move || {
            let mut sink = S(CollectSink::default());
            let reply = {
                let mut ctx = Ctx { daemon: &d2, source: Source::Local, role: Role::Ro, actor: "t".into(), args: vec!["--daemon".into(), "-f".into()], sink: &mut sink, cancel: c2 };
                let cmd = d2.registry.get("logs").unwrap();
                d2.registry.dispatch(&mut ctx, cmd)
            };
            (reply.status, String::from_utf8(sink.0.stdout).unwrap())
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        d.log("second");
        std::thread::sleep(std::time::Duration::from_millis(500));
        cancel.store(true, Ordering::SeqCst);
        let (st, out) = h.join().unwrap();
        assert_eq!(st, Status::Ok);
        assert!(out.contains("first") && out.contains("second"), "{}", out);
    }
}
