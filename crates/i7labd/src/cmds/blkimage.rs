//! blk.image: stream a disk image (20-60 GiB, possibly sparse) from the operator onto a WHOLE disk without staging
//! it in RAM. Wire format: `labproto::blkwire` (DATA/ZERO/END records on the request's upload channel);
//! protocol notes: docs/PROTOCOL.md section 7.1.
//!
//! Safety: the disk is opened ONLY through `labprobe::block::WriteGuard::acquire` (admin key, `--destructive`,
//! the real serial, no mount/holder/swap/boot media, O_EXCL + cross-process flock); nothing in this file opens a
//! block device. A session keeps its guard between requests (HTTP sends the stream in batches; an ether stream that
//! is cut can be continued with `--resume`) and drops it after `IDLE_TTL` without activity.
//!
//! Memory: one record at a time (`blkwire::MAX_BODY`) plus the upload queue of the transport, which the sender
//! bounds by its window (it never has more than ~3 MiB un-acknowledged; the ether input queue holds 4096 frames).
//! Records must arrive in order at the session's `next` offset; every DATA record is checked against its own
//! SHA-256 before it is written, END carries the SHA-256 of the whole image, compared with the running hash the
//! host kept while writing (and, with `--verify`, with a streaming re-read of the disk range).
//!
//! Verification (`--verify-ranges`): after END the session stays in a verify phase and the sender asks for the
//! SHA-256 of bounded disk ranges (`--hash-range OFF:LEN`, each request short, read with a 1 MiB buffer) and
//! compares them with the image itself; every such request refreshes the session TTL. `--finish` then relocates
//! the GPT backup and ends the session. `--hash-disk OFF:LEN` hashes a range of a disk WITHOUT a session and
//! without the write gate (read only: admin key + serial + no write session on the disk), for `--verify-only`.
//!
//! Zero ranges are executed with BLKZEROOUT (guaranteed zeros), falling back to writing zero pages; never
//! BLKDISCARD, whose read-back is unspecified.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use labprobe::block::image::{relocate_backup_gpt, ImageWriter};
use labprobe::block::{self, Reason, WriteGuard, WriteRequest};
use labproto::blkwire::{Record, RecordReader, MAX_PAYLOAD};
use labproto::crypto::{hex, sha256, Sha256};
use labproto::json::{to_json, JsonWriter};
use labproto::Status;

use super::probe::probe_status;
use crate::opts_or_bad;
use crate::registry::{Ctx, Handler, Reply};

pub const TABLE: &[(&str, Handler)] = &[("blk.image", image)];

/// A paused session (no request attached) is dropped, and its disk lock released, after this many seconds.
pub static IDLE_TTL_SECS: AtomicU64 = AtomicU64::new(300);
/// An attached request that receives nothing for this long is detached (the session stays resumable).
const INPUT_IDLE: Duration = Duration::from_secs(60);
/// fdatasync + state file every this many bytes written.
pub const CHECKPOINT: u64 = 64 << 20;

fn ttl() -> Duration {
    Duration::from_secs(IDLE_TTL_SECS.load(Ordering::Relaxed))
}

struct State {
    id: String,
    dev: String,
    size: u64,
    base: u64,
    block: u64,
    dev_size: u64,
    next: u64,
    durable: u64,
    since_ckpt: u64,
    /// running SHA-256 of the image bytes written so far; `None` after a resume (the disk is re-read at the end)
    whole: Option<Sha256>,
    data_bytes: u64,
    zero_bytes: u64,
    serial: Option<String>,
    state_path: PathBuf,
    started: Instant,
    /// set when END was accepted and the session waits in the verify phase: (total, image SHA-256)
    end: Option<(u64, [u8; 32])>,
    /// bytes of disk range hashes served in the verify phase (reported as `verified` when they cover the image)
    hashed: u64,
}

struct Session {
    guard: WriteGuard,
    st: State,
}

struct Slot {
    dev: String,
    id: String,
    size: u64,
    next: u64,
    last: Instant,
    in_use: bool,
    sess: Option<Session>,
}

static SLOTS: Mutex<Vec<Slot>> = Mutex::new(Vec::new());
static REAPER: AtomicBool = AtomicBool::new(false);

fn reap(slots: &mut Vec<Slot>, now: Instant) {
    // dropping a Slot drops its Session and with it the WriteGuard (O_EXCL fd + flock)
    slots.retain(|s| s.in_use || now.duration_since(s.last) < ttl());
}

fn start_reaper() {
    if REAPER.swap(true, Ordering::SeqCst) {
        return;
    }
    let _ = std::thread::Builder::new().name("blkimage-reap".into()).spawn(|| loop {
        std::thread::sleep(Duration::from_secs(2));
        let mut g = SLOTS.lock().unwrap();
        reap(&mut g, Instant::now());
        if g.is_empty() {
            REAPER.store(false, Ordering::SeqCst);
            return;
        }
    });
}

struct Fail {
    status: Status,
    code: &'static str,
    msg: String,
    /// the session survives (the sender can fix the stream and continue)
    keep: bool,
}

fn fail(status: Status, code: &'static str, msg: impl Into<String>, keep: bool) -> Fail {
    Fail { status, code, msg: msg.into(), keep }
}

fn fail_reply(f: &Fail, next: u64) -> Reply {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.key("error");
    w.begin_object();
    w.field_str("code", f.code);
    w.field_str("message", &f.msg);
    w.end_object();
    w.field_u64("next", next);
    w.field_bool("resumable", f.keep);
    w.end_object();
    Reply { status: f.status, body: w.finish().into_bytes(), content: crate::registry::Content::Json }
}

fn io_fail(what: &str, e: &std::io::Error) -> Fail {
    fail(Status::Io, "io", format!("{}: {}", what, e), false)
}

struct Params {
    dev: String,
    size: u64,
    id: String,
    base: u64,
    serial: Option<String>,
    destructive: bool,
    allow_boot_media: bool,
    resume: bool,
    verify: bool,
    grow_last: bool,
    relocate: bool,
    verify_ranges: bool,
    finish: bool,
    hash_range: Option<(u64, u64)>,
}

/// Longest range one hash request may cover: it must finish well inside the transports' timeouts.
pub const MAX_HASH_RANGE: u64 = 1 << 30;

fn parse_range(s: &str) -> Option<(u64, u64)> {
    let (a, b) = s.split_once(':')?;
    let (off, len) = (super::blk::parse_u64(a)?, super::blk::parse_u64(b)?);
    (len > 0).then_some((off, len))
}

fn parse_hex_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

fn num(o: &labproto::args::Opts, k: &str) -> Result<Option<u64>, Reply> {
    o.value(k).map(|v| super::blk::parse_u64(v).ok_or_else(|| Reply::error(Status::BadArgs, &format!("bad --{}", k)))).transpose()
}

fn state_file(ctx: &Ctx, dev: &str) -> PathBuf {
    ctx.daemon.config.run_dir.join("blkimage").join(format!("{}.state", dev))
}

fn read_state(p: &PathBuf) -> Option<(String, u64, u64)> {
    let t = std::fs::read_to_string(p).ok()?;
    let mut it = t.split_whitespace();
    Some((it.next()?.to_string(), it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

fn write_state(st: &State) {
    if let Some(d) = st.state_path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(&st.state_path, format!("{} {} {}\n", st.id, st.size, st.durable));
}

fn image(ctx: &mut Ctx) -> Reply {
    let o = opts_or_bad!(ctx, &["status", "abort", "destructive", "allow-boot-media", "resume", "verify", "grow-last", "no-relocate", "verify-ranges", "finish"], &["serial", "size", "image-id", "dest-offset", "hash-range", "hash-disk"]);
    let dev = match o.positional() {
        [d] if block::valid_dev_name(d) => d.clone(),
        [_] => return Reply::error(Status::BadArgs, "bad device name"),
        _ => return Reply::error(Status::BadArgs, "usage: blk.image DEV (see help)"),
    };
    let id = o.value("image-id").map(str::to_ascii_lowercase);
    if let Some(i) = &id {
        if !parse_hex_id(i) {
            return Reply::error(Status::BadArgs, "bad --image-id (1..64 hex digits)");
        }
    }
    if o.flag("status") {
        return status(ctx, &dev, id.as_deref());
    }
    if o.flag("abort") {
        return abort(ctx, &dev);
    }
    let hash_range = match o.value("hash-range").map(parse_range) {
        Some(None) => return Reply::error(Status::BadArgs, "bad --hash-range (OFF:LEN, LEN > 0)"),
        Some(Some(r)) => Some(r),
        None => None,
    };
    if let Some(spec) = o.value("hash-disk") {
        let Some((off, len)) = parse_range(spec) else { return Reply::error(Status::BadArgs, "bad --hash-disk (OFF:LEN, LEN > 0)") };
        return match (num(&o, "size"), num(&o, "dest-offset")) {
            (Ok(Some(size)), Ok(base)) if size > 0 => hash_disk(ctx, &dev, off, len, size, base.unwrap_or(0), o.value("serial")),
            (Ok(_), Ok(_)) => Reply::error(Status::BadArgs, "--size N (image bytes, > 0) is required"),
            (Err(r), _) | (_, Err(r)) => r,
        };
    }
    let (size, base) = match (num(&o, "size"), num(&o, "dest-offset")) {
        (Ok(Some(s)), Ok(b)) if s > 0 => (s, b.unwrap_or(0)),
        (Ok(_), Ok(_)) => return Reply::error(Status::BadArgs, "--size N (image bytes, > 0) is required"),
        (Err(r), _) | (_, Err(r)) => return r,
    };
    let Some(id) = id else { return Reply::error(Status::BadArgs, "--image-id is required") };
    let p = Params {
        dev,
        size,
        id,
        base,
        serial: o.value("serial").map(str::to_string),
        destructive: o.flag("destructive"),
        allow_boot_media: o.flag("allow-boot-media"),
        resume: o.flag("resume"),
        verify: o.flag("verify"),
        grow_last: o.flag("grow-last"),
        relocate: !o.flag("no-relocate") && base == 0,
        verify_ranges: o.flag("verify-ranges"),
        finish: o.flag("finish"),
        hash_range,
    };
    if p.finish || p.hash_range.is_some() {
        // verify phase requests: they continue a session that exists, never create one
        if !p.resume || !p.destructive || p.serial.is_none() {
            return Reply::error(Status::BadArgs, "--hash-range and --finish need --resume --destructive --serial (the session's own flags)");
        }
        let have = SLOTS.lock().unwrap().iter().any(|s| s.dev == p.dev && s.id == p.id);
        if !have {
            return fail_reply(&fail(Status::NotFound, "no_session", "the host has no session for this transfer (expired, aborted or the host restarted)", false), 0);
        }
        let mut sess = match acquire(ctx, &p) {
            Ok(s) => s,
            Err(r) => return r,
        };
        let (reply, keep) = verify_phase(ctx, &mut sess, &p);
        release(&p.dev, if keep { Some(sess) } else { None });
        return reply;
    }
    let Some(input) = ctx.sink.input() else {
        return Reply::error(Status::Unsupported, "this transport has no upload channel");
    };
    let mut sess = match acquire(ctx, &p) {
        Ok(s) => s,
        Err(r) => return r,
    };
    start_reaper();
    let (reply, keep) = run(ctx, &mut sess, &p, &input);
    release(&p.dev, if keep { Some(sess) } else { None });
    reply
}

/// Take the session of `p.dev` (same image id) out of the table, or create one behind the write gate.
fn acquire(ctx: &Ctx, p: &Params) -> Result<Session, Reply> {
    {
        let mut g = SLOTS.lock().unwrap();
        reap(&mut g, Instant::now());
        if let Some(i) = g.iter().position(|s| s.dev == p.dev) {
            if g[i].in_use {
                return Err(Reply::error(Status::Busy, "a blk.image transfer to this disk is running"));
            }
            if g[i].id != p.id {
                return Err(Reply::error(Status::Busy, &format!("an unfinished transfer of another image (id {}) holds this disk: finish it or run blk.image --abort", g[i].id)));
            }
            if p.resume {
                let s = g[i].sess.take().expect("idle slot has a session");
                if s.st.serial != p.serial || !p.destructive || (s.guard.device().boot_media && !p.allow_boot_media) {
                    g[i].sess = Some(s);
                    return Err(Reply::error(Status::Refused, "resuming needs the same --destructive and --serial (and --allow-boot-media) as the transfer it continues"));
                }
                g[i].in_use = true;
                return Ok(s);
            }
            // a fresh start discards the old session (its guard drops here, before the new one is taken)
            g.remove(i);
        }
        g.push(Slot { dev: p.dev.clone(), id: p.id.clone(), size: p.size, next: 0, last: Instant::now(), in_use: true, sess: None });
    }
    match create(ctx, p) {
        Ok(s) => Ok(s),
        Err(r) => {
            SLOTS.lock().unwrap().retain(|s| s.dev != p.dev);
            Err(r)
        }
    }
}

fn create(ctx: &Ctx, p: &Params) -> Result<Session, Reply> {
    let req = WriteRequest { dev: p.dev.clone(), destructive: p.destructive, serial: p.serial.clone(), allow_boot_media: p.allow_boot_media, actor: format!("{} {}", ctx.actor, ctx.source.describe()) };
    // `under_test` alone can be a lock still held by a forked child that has not exec'd yet (the flock belongs to
    // the open file description, which a fork shares until exec closes the CLOEXEC copy): retry briefly. A lock
    // that is really held stays held and is refused after ~1 s.
    let mut tries = 0;
    let guard = loop {
        match WriteGuard::acquire(&ctx.daemon.probe, &req) {
            Ok(g) => break g,
            Err(r) if tries < 40 && r.reasons == [Reason::UnderTest] => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(refusal) => return Err(Reply::refused(&to_json(&refusal.reasons), "write refused by the safety gate")),
        }
    };
    let d = guard.device();
    let (dev_size, block) = (d.size_bytes, d.logical_block.max(512) as u64);
    if p.base % block != 0 {
        return Err(Reply::error(Status::BadArgs, &format!("--dest-offset must be a multiple of the logical block size {}", block)));
    }
    if p.base.checked_add(p.size).map_or(true, |e| e > dev_size) {
        return Err(Reply::error(Status::TooBig, &format!("image ({} bytes at offset {}) is larger than the disk ({} bytes)", p.size, p.base, dev_size)));
    }
    let state_path = state_file(ctx, &p.dev);
    let (next, whole) = if p.resume {
        match read_state(&state_path) {
            Some((id, size, durable)) if id == p.id && size == p.size && durable <= p.size => (durable, if durable == 0 { Some(Sha256::new()) } else { None }),
            _ => return Err(Reply::error(Status::BadArgs, "nothing to resume for this image (no session, no state file): start without --resume")),
        }
    } else {
        let _ = std::fs::remove_file(&state_path);
        (0, Some(Sha256::new()))
    };
    let st = State {
        id: p.id.clone(),
        dev: p.dev.clone(),
        size: p.size,
        base: p.base,
        block,
        dev_size,
        next,
        durable: next,
        since_ckpt: 0,
        whole,
        data_bytes: 0,
        zero_bytes: 0,
        serial: p.serial.clone(),
        state_path,
        started: Instant::now(),
        end: None,
        hashed: 0,
    };
    Ok(Session { guard, st })
}

fn release(dev: &str, sess: Option<Session>) {
    let mut g = SLOTS.lock().unwrap();
    match sess {
        Some(s) => {
            if let Some(slot) = g.iter_mut().find(|x| x.dev == dev) {
                slot.next = s.st.next;
                slot.size = s.st.size;
                slot.last = Instant::now();
                slot.in_use = false;
                slot.sess = Some(s);
            }
        }
        None => g.retain(|x| x.dev != dev),
    }
}

fn ack(ctx: &mut Ctx, next: u64) -> bool {
    ctx.sink.event(&format!("{{\"event\":\"ack\",\"next\":{}}}", next)).is_ok()
}

fn hash_zeros(h: &mut Sha256, mut n: u64) {
    static Z: [u8; 65536] = [0; 65536];
    while n > 0 {
        let k = n.min(Z.len() as u64) as usize;
        h.update(&Z[..k]);
        n -= k as u64;
    }
}

/// Process the request's records. Returns the reply and whether the session survives.
fn run(ctx: &mut Ctx, sess: &mut Session, p: &Params, input: &Receiver<Vec<u8>>) -> (Reply, bool) {
    let Session { guard, st } = sess;
    let mut w = match ImageWriter::new(guard.file(), st.block, st.dev_size, st.base, st.size) {
        Ok(w) => w,
        Err(e) => return (fail_reply(&fail(Status::BadArgs, "bad_range", e.to_string(), false), st.next), false),
    };
    let mut rd = RecordReader::new();
    let mut idle = Instant::now();
    loop {
        loop {
            match rd.next() {
                Ok(None) => break,
                Ok(Some(rec)) => match apply(&mut w, st, rec) {
                    Ok(None) => {
                        if !ack(ctx, st.next) {
                            return (fail_reply(&fail(Status::Canceled, "canceled", "transport closed", true), st.next), true);
                        }
                    }
                    Ok(Some((total, sha))) => return finish(ctx, guard, &mut w, st, p, total, sha),
                    Err(f) => return (fail_reply(&f, st.next), f.keep),
                },
                Err(e) => return (fail_reply(&fail(Status::BadArgs, "bad_record", e, true), st.next), true),
            }
        }
        if ctx.cancel.load(Ordering::SeqCst) {
            return (fail_reply(&fail(Status::Canceled, "canceled", "canceled (the transfer can be resumed with --resume)", true), st.next), true);
        }
        match input.recv_timeout(Duration::from_millis(500)) {
            Ok(chunk) => {
                idle = Instant::now();
                rd.push(&chunk);
            }
            Err(RecvTimeoutError::Timeout) => {
                if idle.elapsed() > INPUT_IDLE {
                    return (fail_reply(&fail(Status::Timeout, "stalled", "upload stalled (the transfer can be resumed with --resume)", true), st.next), true);
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                // end of this request's input without END: a batch (HTTP) or a cut stream. The session stays.
                if rd.pending() > 0 {
                    return (fail_reply(&fail(Status::BadArgs, "truncated", "the upload ended inside a record", true), st.next), true);
                }
                let mut j = JsonWriter::new();
                j.begin_object();
                j.field_u64("v", 1);
                j.field_u64("next", st.next);
                j.field_u64("size", st.size);
                j.field_bool("done", false);
                j.end_object();
                return (Reply::json(j.finish()), true);
            }
        }
    }
}

/// Apply one record. `Ok(Some(..))` = END (total, sha).
fn apply(w: &mut ImageWriter, st: &mut State, rec: Record) -> Result<Option<(u64, [u8; 32])>, Fail> {
    match rec {
        Record::Data { off, sha, payload } => {
            if off != st.next {
                return Err(fail(Status::BadArgs, "gap", format!("record at offset {} but the next expected offset is {}", off, st.next), true));
            }
            if payload.len() > MAX_PAYLOAD {
                return Err(fail(Status::TooBig, "too_big", "payload larger than the host accepts", true));
            }
            if sha256(&payload) != sha {
                return Err(fail(Status::Io, "chunk_sha", format!("chunk at offset {} is damaged (SHA-256 mismatch); not written", off), true));
            }
            let end = off + payload.len() as u64;
            if end > st.size {
                return Err(fail(Status::BadArgs, "range", format!("chunk {}..{} is past the declared image size {}", off, end, st.size), true));
            }
            w.write_data(off, &payload).map_err(|e| io_fail(&format!("write at {}", off), &e))?;
            if let Some(h) = st.whole.as_mut() {
                h.update(&payload);
            }
            st.next = end;
            st.data_bytes += payload.len() as u64;
            checkpoint(w, st, payload.len() as u64)?;
            Ok(None)
        }
        Record::Zero { off, len } => {
            if off != st.next {
                return Err(fail(Status::BadArgs, "gap", format!("record at offset {} but the next expected offset is {}", off, st.next), true));
            }
            if len == 0 || off.checked_add(len).map_or(true, |e| e > st.size) {
                return Err(fail(Status::BadArgs, "range", format!("zero range {}+{} is outside the image ({} bytes)", off, len, st.size), true));
            }
            w.write_zeros(off, len).map_err(|e| io_fail(&format!("zero at {}", off), &e))?;
            if let Some(h) = st.whole.as_mut() {
                hash_zeros(h, len);
            }
            st.next = off + len;
            st.zero_bytes += len;
            checkpoint(w, st, len)?;
            Ok(None)
        }
        Record::End { total, sha } => {
            if total != st.size || st.next != st.size {
                return Err(fail(Status::BadArgs, "incomplete", format!("END at {} of {} bytes (declared total {})", st.next, st.size, total), true));
            }
            Ok(Some((total, sha)))
        }
    }
}

fn checkpoint(w: &mut ImageWriter, st: &mut State, n: u64) -> Result<(), Fail> {
    st.since_ckpt += n;
    if st.since_ckpt >= CHECKPOINT {
        w.durable_sync().map_err(|e| io_fail("fdatasync", &e))?;
        st.since_ckpt = 0;
        st.durable = st.next;
        write_state(st);
    }
    Ok(())
}

fn finish(ctx: &mut Ctx, guard: &WriteGuard, w: &mut ImageWriter, st: &mut State, p: &Params, total: u64, client_sha: [u8; 32]) -> (Reply, bool) {
    let next = st.next;
    let f = |status, code, msg: String| (fail_reply(&fail(status, code, msg, false), next), false);
    if let Err(e) = w.sync() {
        return f(Status::Io, "io", format!("fsync: {}", e));
    }
    // the hash the host kept while writing, or (after a resume) a streaming re-read of the whole range; with
    // --verify-ranges that re-read is left to the sender's bounded hash requests (one long request would outlive
    // the transports' timeouts)
    let reread = |w: &mut ImageWriter| -> Result<[u8; 32], String> {
        let mut h = Sha256::new();
        w.hash_range(0, total, &mut h).map_err(|e| format!("read-back: {}", e))?;
        Ok(h.finish())
    };
    let (host_sha, mut verified, mode) = match st.whole.take() {
        Some(h) => (h.finish(), false, "stream"),
        None if p.verify_ranges => (client_sha, false, "ranges"),
        None => match reread(w) {
            Ok(h) => (h, true, "reread"),
            Err(e) => return f(Status::Io, "io", e),
        },
    };
    if host_sha != client_sha {
        return f(Status::Io, "image_sha", format!("whole-image SHA-256 mismatch: sender {} host {}", hex(&client_sha), hex(&host_sha)));
    }
    if p.verify_ranges {
        st.end = Some((total, host_sha));
        let mut j = JsonWriter::new();
        j.begin_object();
        j.field_u64("v", 1);
        j.field_u64("next", total);
        j.field_u64("size", st.size);
        j.field_bool("done", false);
        j.field_str("phase", "verify");
        j.field_str("sha256", &hex(&host_sha));
        j.end_object();
        return (Reply::json(j.finish()), true);
    }
    if p.verify && mode == "stream" {
        match reread(w) {
            Ok(h) if h == client_sha => verified = true,
            Ok(h) => return f(Status::Io, "readback_mismatch", format!("READ-BACK MISMATCH: image {} disk {}", hex(&client_sha), hex(&h))),
            Err(e) => return f(Status::Io, "io", e),
        }
    }
    complete(ctx, guard, st, p, total, host_sha, verified, mode)
}

/// One request of the verify phase: `--hash-range OFF:LEN` (a bounded read-back hash) or `--finish`.
fn verify_phase(ctx: &mut Ctx, sess: &mut Session, p: &Params) -> (Reply, bool) {
    let Session { guard, st } = sess;
    let Some((total, sha)) = st.end else {
        return (fail_reply(&fail(Status::BadArgs, "not_ended", "the image has not been completely written yet", true), st.next), true);
    };
    if let Some((off, len)) = p.hash_range {
        if len > MAX_HASH_RANGE {
            return (fail_reply(&fail(Status::TooBig, "too_big", format!("a hash range is at most {} bytes", MAX_HASH_RANGE), true), st.next), true);
        }
        let mut w = match ImageWriter::new(guard.file(), st.block, st.dev_size, st.base, st.size) {
            Ok(w) => w,
            Err(e) => return (fail_reply(&fail(Status::BadArgs, "bad_range", e.to_string(), true), st.next), true),
        };
        let t0 = Instant::now();
        let mut h = Sha256::new();
        if let Err(e) = w.hash_range(off, len, &mut h) {
            return (fail_reply(&fail(Status::Io, "io", format!("read-back at {}: {}", off, e), true), st.next), true);
        }
        st.hashed += len;
        return (hash_reply(off, len, &h.finish(), t0.elapsed()), true);
    }
    // --finish
    let verified = st.hashed >= total;
    complete(ctx, guard, st, p, total, sha, verified, if verified { "ranges" } else { "none" })
}

fn hash_reply(off: u64, len: u64, sha: &[u8; 32], el: Duration) -> Reply {
    let mut j = JsonWriter::new();
    j.begin_object();
    j.field_u64("v", 1);
    j.field_u64("off", off);
    j.field_u64("len", len);
    j.field_str("sha256", &hex(sha));
    j.field_u64("ms", el.as_millis() as u64);
    j.end_object();
    Reply::json(j.finish())
}

/// `--hash-disk OFF:LEN`: SHA-256 of image bytes OFF..OFF+LEN as they lie on the disk (image at `base`). Read only:
/// no write gate, but still the admin key and the real serial, and never while a write session holds the disk.
fn hash_disk(ctx: &mut Ctx, dev: &str, off: u64, len: u64, size: u64, base: u64, serial: Option<&str>) -> Reply {
    if len > MAX_HASH_RANGE {
        return Reply::error(Status::TooBig, &format!("a hash range is at most {} bytes", MAX_HASH_RANGE));
    }
    if off.checked_add(len).map_or(true, |e| e > size) {
        return Reply::error(Status::BadArgs, "range is outside the image");
    }
    let report = match block::probe(&ctx.daemon.probe, true) {
        Ok(r) => r,
        Err(e) => return Reply::error(probe_status(&e), &e.to_string()),
    };
    let Some(d) = report.devices.iter().find(|d| d.name == dev) else {
        return Reply::error(Status::NotFound, &format!("no block device {}", dev));
    };
    match (d.serial.as_deref().or(d.wwid.as_deref()), serial) {
        (None, _) => return Reply::error(Status::Refused, "the disk reports no serial: refusing to name it"),
        (Some(_), None) => return Reply::error(Status::Refused, "--serial is required (the real serial of the disk)"),
        (Some(e), Some(g)) if e.trim() != g.trim() => return Reply::error(Status::Refused, "serial mismatch"),
        _ => {}
    }
    if SLOTS.lock().unwrap().iter().any(|s| s.dev == dev) {
        return Reply::error(Status::Busy, "a blk.image transfer holds this disk: it cannot be verified until that ends");
    }
    let path = ctx.daemon.probe.path(&format!("/dev/{}", dev));
    if ctx.daemon.probe.root == std::path::Path::new("/") && !labprobe::block::ioctl::is_block_device(&path) {
        return Reply::error(Status::Refused, "not a block device");
    }
    let file = match labprobe::block::ioctl::open(&path, false, false, true) {
        Ok(f) => f,
        Err(e) => return Reply::error(Status::Io, &format!("open {}: {}", dev, e)),
    };
    let dev_size = labprobe::block::ioctl::size_bytes(&file).unwrap_or(d.size_bytes);
    let block = d.logical_block.max(512) as u64;
    let mut w = match ImageWriter::new(&file, block, dev_size, base, size) {
        Ok(w) => w,
        Err(e) => return Reply::error(Status::BadArgs, &e.to_string()),
    };
    let t0 = Instant::now();
    let mut h = Sha256::new();
    if let Err(e) = w.hash_range(off, len, &mut h) {
        return Reply::error(Status::Io, &format!("read at {}: {}", off, e));
    }
    hash_reply(off, len, &h.finish(), t0.elapsed())
}

/// The disk now holds the (verified) image: fix the GPT backup, ask the kernel to re-read the table, end the session.
#[allow(clippy::too_many_arguments)]
fn complete(ctx: &mut Ctx, guard: &WriteGuard, st: &mut State, p: &Params, total: u64, host_sha: [u8; 32], verified: bool, mode: &str) -> (Reply, bool) {
    // the disk now holds the image: fix the GPT backup, ask the kernel to re-read the table
    let mut j = JsonWriter::new();
    j.begin_object();
    j.field_u64("v", 1);
    j.field_bool("done", true);
    j.field_u64("bytes", total);
    j.field_str("sha256", &hex(&host_sha));
    j.field_bool("verified", verified);
    j.field_str("verify_mode", if verified { mode } else { "none" });
    j.field_u64("data_bytes", st.data_bytes);
    j.field_u64("zero_bytes", st.zero_bytes);
    j.field_u64("elapsed_ms", st.started.elapsed().as_millis() as u64);
    j.key("gpt");
    j.begin_object();
    if !p.relocate {
        j.field_str("action", "skipped");
        j.field_str("reason", if st.base != 0 { "image is not at the start of the disk" } else { "--no-relocate" });
    } else {
        match relocate_backup_gpt(guard.file(), st.dev_size, st.block, p.grow_last) {
            Ok(m) => {
                j.field_str("action", m.action);
                j.field_u64("backup_lba", m.backup_lba);
                j.field_u64("last_usable", m.last_usable);
                if let Some((i, old, new)) = m.grown {
                    j.key("grown");
                    j.begin_object();
                    j.field_u64("partition", i as u64);
                    j.field_u64("old_last_lba", old);
                    j.field_u64("new_last_lba", new);
                    j.end_object();
                }
            }
            Err(e) => {
                j.field_str("action", "error");
                j.field_str("message", &e);
            }
        }
    }
    j.end_object();
    match guard.reread_partitions() {
        Ok(()) => j.field_str("rrpart", "ok"),
        Err(e) if e.raw_os_error() == Some(25) => j.field_str("rrpart", "n/a (not a block device)"),
        Err(e) => j.field_str("rrpart", &format!("failed: {}", e)),
    }
    j.end_object();
    let _ = std::fs::remove_file(&st.state_path);
    let _ = block::audit_write(&format!("blk.image dev={} done bytes={} sha256={} actor={}", st.dev, total, hex(&host_sha), ctx.actor));
    (Reply::json(j.finish()), false)
}

fn status(ctx: &mut Ctx, dev: &str, id: Option<&str>) -> Reply {
    let report = match block::probe(&ctx.daemon.probe, true) {
        Ok(r) => r,
        Err(e) => return Reply::error(probe_status(&e), &e.to_string()),
    };
    let Some(d) = report.devices.iter().find(|d| d.name == dev) else {
        return Reply::error(Status::NotFound, &format!("no block device {}", dev));
    };
    let mut resume_at: Option<u64> = None;
    let mut sess_json = None;
    {
        let mut g = SLOTS.lock().unwrap();
        reap(&mut g, Instant::now());
        if let Some(s) = g.iter().find(|s| s.dev == dev) {
            sess_json = Some((s.id.clone(), s.size, s.next, s.in_use, s.last.elapsed().as_secs()));
            if Some(s.id.as_str()) == id && !s.in_use {
                resume_at = Some(s.next);
            }
        }
    }
    if resume_at.is_none() && sess_json.is_none() {
        if let (Some(id), Some((sid, _, durable))) = (id, read_state(&state_file(ctx, dev))) {
            if sid == id {
                resume_at = Some(durable);
            }
        }
    }
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_u64("v", 1);
    w.field_u64("max_payload", MAX_PAYLOAD as u64);
    w.key("device");
    w.value(d);
    w.key("session");
    match sess_json {
        Some((sid, size, next, in_use, idle)) => {
            w.begin_object();
            w.field_str("id", &sid);
            w.field_u64("size", size);
            w.field_u64("next", next);
            w.field_bool("in_use", in_use);
            w.field_u64("idle_s", idle);
            w.end_object();
        }
        None => w.null(),
    }
    w.field_opt_u64("resume_at", resume_at);
    w.end_object();
    Reply::json(w.finish())
}

fn abort(ctx: &mut Ctx, dev: &str) -> Reply {
    let mut g = SLOTS.lock().unwrap();
    if g.iter().any(|s| s.dev == dev && s.in_use) {
        return Reply::error(Status::Busy, "a transfer is running on this disk (stop the sender first)");
    }
    let before = g.len();
    g.retain(|s| s.dev != dev);
    let had = g.len() != before;
    drop(g);
    let sf = state_file(ctx, dev);
    let had_state = std::fs::remove_file(sf).is_ok();
    let _ = block::audit_write(&format!("blk.image dev={} abort actor={}", dev, ctx.actor));
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_u64("v", 1);
    w.field_bool("aborted", had || had_state);
    w.end_object();
    Reply::json(w.finish())
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests_support::test_daemon;
    use crate::registry::{Sink, Source};
    use labprobe::block::parttable::{build_gpt, check_backup, parse_gpt_header};
    use labproto::blkwire::{encode_data, encode_end, encode_zero};
    use labproto::frame::Chan;
    use labproto::keys::Role;
    use std::os::unix::fs::FileExt;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    const MIB: u64 = 1 << 20;
    const SER: &str = "SER-IMG";

    struct Fx {
        root: PathBuf,
    }

    impl Drop for Fx {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    impl Fx {
        fn new(label: &str) -> Fx {
            let root = std::env::temp_dir().join(format!("i7bi-{}-{}", label, std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("sys/block")).unwrap();
            std::fs::create_dir_all(root.join("dev")).unwrap();
            std::fs::create_dir_all(root.join("proc/self")).unwrap();
            std::fs::write(root.join("proc/self/mountinfo"), "").unwrap();
            std::fs::write(root.join("proc/swaps"), "Filename Type Size Used Priority\n").unwrap();
            Fx { root }
        }
        /// A virtio-style disk with 4096-byte logical blocks (so O_DIRECT on the backing file is always aligned).
        fn disk(&self, name: &str, size: u64, minor: u32, serial: &str) {
            let real = self.root.join("sys/devices/pci0000:00/0000:00:03.0/virtio0/block").join(name);
            std::fs::create_dir_all(real.join("queue")).unwrap();
            std::fs::create_dir_all(real.join("holders")).unwrap();
            let w = |f: &str, c: String| std::fs::write(real.join(f), c).unwrap();
            w("dev", format!("252:{}\n", minor));
            w("size", format!("{}\n", size / 512));
            w("ro", "0\n".into());
            w("removable", "0\n".into());
            w("queue/logical_block_size", "4096\n".into());
            w("queue/physical_block_size", "4096\n".into());
            w("queue/rotational", "0\n".into());
            w("serial", serial.into());
            std::os::unix::fs::symlink(std::path::Path::new("../devices/pci0000:00/0000:00:03.0/virtio0/block").join(name), self.root.join("sys/block").join(name)).unwrap();
            std::fs::File::create(self.root.join("dev").join(name)).unwrap().set_len(size).unwrap();
        }
        fn put(&self, name: &str, off: u64, d: &[u8]) {
            let f = std::fs::OpenOptions::new().write(true).open(self.root.join("dev").join(name)).unwrap();
            f.write_all_at(d, off).unwrap();
        }
        fn get(&self, name: &str, off: u64, n: usize) -> Vec<u8> {
            let f = std::fs::File::open(self.root.join("dev").join(name)).unwrap();
            let mut b = vec![0u8; n];
            f.read_exact_at(&mut b, off).unwrap();
            b
        }
        fn daemon(&self) -> crate::Daemon {
            let mut d = test_daemon();
            d.probe = labprobe::ProbeCtx::fixture(&self.root);
            d
        }
    }

    struct Up {
        rx: Option<Receiver<Vec<u8>>>,
        events: Vec<String>,
    }
    impl Sink for Up {
        fn data(&mut self, _c: Chan, _b: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
        fn event(&mut self, j: &str) -> std::io::Result<()> {
            self.events.push(j.to_string());
            Ok(())
        }
        fn input(&mut self) -> Option<Receiver<Vec<u8>>> {
            self.rx.take()
        }
    }

    fn call(d: &crate::Daemon, role: Role, args: &[&str], chunks: &[&[u8]]) -> (Reply, Vec<String>) {
        let (tx, rx) = std::sync::mpsc::channel();
        for c in chunks {
            tx.send(c.to_vec()).unwrap();
        }
        drop(tx);
        let mut sink = Up { rx: Some(rx), events: vec![] };
        let mut ctx = Ctx { daemon: d, source: Source::Local, role, actor: "t".into(), args: args.iter().map(|s| s.to_string()).collect(), sink: &mut sink, cancel: Arc::new(AtomicBool::new(false)) };
        let cmd = d.registry.get("blk.image").unwrap();
        let r = d.registry.dispatch(&mut ctx, cmd);
        (r, sink.events)
    }

    fn body(r: &Reply) -> String {
        String::from_utf8_lossy(&r.body).into_owned()
    }

    fn image(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| ((i as u32).wrapping_mul(2654435761).rotate_left(5) as u8) ^ seed).collect()
    }

    /// The record stream a sender produces: all-zero MiB blocks become ZERO records, others DATA of `chunk` bytes.
    fn records(img: &[u8], chunk: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut off = 0usize;
        while off < img.len() {
            let n = (img.len() - off).min(MIB as usize);
            let blk = &img[off..off + n];
            if blk.iter().all(|b| *b == 0) {
                out.push(encode_zero(off as u64, n as u64));
            } else {
                for (k, c) in blk.chunks(chunk).enumerate() {
                    out.push(encode_data((off + k * chunk) as u64, c));
                }
            }
            off += n;
        }
        out
    }

    fn end(img: &[u8]) -> Vec<u8> {
        encode_end(img.len() as u64, &sha256(img))
    }

    fn args<'a>(dev: &'a str, size: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
        let mut v = vec![dev, "--size", size, "--image-id", "ab12", "--serial", SER, "--destructive"];
        v.extend_from_slice(extra);
        v
    }

    fn refs(v: &[Vec<u8>]) -> Vec<&[u8]> {
        v.iter().map(|x| x.as_slice()).collect()
    }

    #[test]
    fn streams_a_sparse_image_and_verifies() {
        let fx = Fx::new("happy");
        fx.disk("vdi1", 8 * MIB, 1, SER);
        fx.put("vdi1", 0, &vec![0xEE; 8 << 20]);
        let d = fx.daemon();
        let mut img = image(3 * MIB as usize, 1);
        img[MIB as usize..2 * MIB as usize].fill(0); // a hole
        let mut recs = records(&img, 256 << 10);
        assert!(recs.iter().any(|r| r[0] == 2), "the hole travels as a ZERO record");
        recs.push(end(&img));
        let size = img.len().to_string();
        let (r, ev) = call(&d, Role::Admin, &args("vdi1", &size, &["--verify"]), &refs(&recs));
        assert_eq!(r.status, Status::Ok, "{}", body(&r));
        let j = body(&r);
        assert!(j.contains("\"verified\":true") && j.contains("\"done\":true") && j.contains(&hex(&sha256(&img))), "{}", j);
        assert!(j.contains("\"zero_bytes\":1048576"), "{}", j);
        assert_eq!(fx.get("vdi1", 0, img.len()), img);
        assert_eq!(fx.get("vdi1", 3 * MIB, 8), vec![0xEE; 8], "nothing past the image is touched");
        assert_eq!(ev.last().unwrap(), &format!("{{\"event\":\"ack\",\"next\":{}}}", img.len()));
        // the session is gone: the disk can be claimed again
        let (r, _) = call(&d, Role::Admin, &["vdi1", "--abort"], &[]);
        assert!(body(&r).contains("\"aborted\":false"));
    }

    #[test]
    fn dropped_chunk_is_a_gap_and_resume_continues() {
        let fx = Fx::new("gap");
        fx.disk("vdi2", 8 * MIB, 2, SER);
        let d = fx.daemon();
        let img = image(2 * MIB as usize, 2);
        let recs = records(&img, 256 << 10);
        let size = img.len().to_string();
        // record 1 is dropped on the way
        let sent: Vec<&[u8]> = vec![&recs[0], &recs[2], &recs[3]];
        let (r, _) = call(&d, Role::Admin, &args("vdi2", &size, &[]), &sent);
        assert_eq!(r.status, Status::BadArgs, "{}", body(&r));
        let j = body(&r);
        assert!(j.contains("\"code\":\"gap\"") && j.contains(&format!("\"next\":{}", 256 << 10)) && j.contains("\"resumable\":true"), "{}", j);
        // status tells where to continue
        let (s, _) = call(&d, Role::Admin, &["vdi2", "--status", "--image-id", "ab12"], &[]);
        assert!(body(&s).contains(&format!("\"resume_at\":{}", 256 << 10)), "{}", body(&s));
        assert!(body(&s).contains(&format!("\"serial\":\"{}\"", SER)));
        // continue from `next`
        let mut rest: Vec<Vec<u8>> = recs[1..].to_vec();
        rest.push(end(&img));
        let (r, _) = call(&d, Role::Admin, &args("vdi2", &size, &["--resume"]), &refs(&rest));
        assert_eq!(r.status, Status::Ok, "{}", body(&r));
        assert_eq!(fx.get("vdi2", 0, img.len()), img);
        // resuming with the wrong serial is refused, a finished session cannot be resumed
        let (r, _) = call(&d, Role::Admin, &args("vdi2", &size, &["--resume"]), &[]);
        assert_eq!(r.status, Status::BadArgs);
    }

    #[test]
    fn cut_stream_pauses_and_resumes_from_the_session() {
        let fx = Fx::new("pause");
        fx.disk("vdi3", 8 * MIB, 3, SER);
        let d = fx.daemon();
        let img = image(2 * MIB as usize, 3);
        let mut recs = records(&img, 512 << 10);
        recs.push(end(&img));
        let size = img.len().to_string();
        // the first batch ends in the middle of a record
        let cut = recs[0].len() + recs[1].len() + 100;
        let all: Vec<u8> = recs.concat();
        let (r, _) = call(&d, Role::Admin, &args("vdi3", &size, &[]), &[&all[..cut]]);
        assert_eq!(r.status, Status::BadArgs);
        assert!(body(&r).contains("\"code\":\"truncated\""), "{}", body(&r));
        let (s, _) = call(&d, Role::Admin, &["vdi3", "--status", "--image-id", "ab12"], &[]);
        assert!(body(&s).contains(&format!("\"resume_at\":{}", MIB)), "{}", body(&s));
        // a clean batch end is a plain "not done"
        let (r, _) = call(&d, Role::Admin, &args("vdi3", &size, &["--resume"]), &[&recs[2]]);
        assert_eq!(r.status, Status::Ok, "{}", body(&r));
        assert!(body(&r).contains("\"done\":false") && body(&r).contains(&format!("\"next\":{}", MIB + (512 << 10))), "{}", body(&r));
        let rest: Vec<&[u8]> = recs[3..].iter().map(|x| x.as_slice()).collect();
        let (r, _) = call(&d, Role::Admin, &args("vdi3", &size, &["--resume"]), &rest);
        assert_eq!(r.status, Status::Ok, "{}", body(&r));
        assert_eq!(fx.get("vdi3", 0, img.len()), img);
    }

    #[test]
    fn damaged_chunk_is_rejected_before_it_is_written() {
        let fx = Fx::new("sha");
        fx.disk("vdi4", 8 * MIB, 4, SER);
        let d = fx.daemon();
        let img = image(MIB as usize, 4);
        let mut recs = records(&img, 256 << 10);
        let last = recs[1].len() - 1;
        recs[1][last] ^= 0x40; // flip a payload bit after the sender hashed it
        let size = img.len().to_string();
        let (r, _) = call(&d, Role::Admin, &args("vdi4", &size, &[]), &refs(&recs));
        assert_eq!(r.status, Status::Io);
        let j = body(&r);
        assert!(j.contains("\"code\":\"chunk_sha\"") && j.contains(&format!("\"next\":{}", 256 << 10)), "{}", j);
        assert_eq!(fx.get("vdi4", 256 << 10, 16), vec![0; 16], "the bad chunk was not written");
        assert_eq!(fx.get("vdi4", 0, 256 << 10), img[..256 << 10]);
    }

    #[test]
    fn end_with_a_wrong_image_hash_and_a_tampered_disk_are_errors() {
        let fx = Fx::new("endsha");
        fx.disk("vdi5", 8 * MIB, 5, SER);
        let d = fx.daemon();
        let img = image(MIB as usize, 5);
        let recs = records(&img, 256 << 10);
        let size = img.len().to_string();
        let mut r1 = recs.clone();
        r1.push(encode_end(img.len() as u64, &[0u8; 32]));
        let (r, _) = call(&d, Role::Admin, &args("vdi5", &size, &[]), &refs(&r1));
        assert_eq!(r.status, Status::Io);
        assert!(body(&r).contains("\"code\":\"image_sha\""), "{}", body(&r));
        // data in one request, tamper with the disk, END --verify in the next
        let (r, _) = call(&d, Role::Admin, &args("vdi5", &size, &[]), &refs(&recs));
        assert_eq!(r.status, Status::Ok, "{}", body(&r));
        fx.put("vdi5", 300 << 10, &[0x55; 4096]);
        let e = end(&img);
        let (r, _) = call(&d, Role::Admin, &args("vdi5", &size, &["--resume", "--verify"]), &[&e]);
        assert_eq!(r.status, Status::Io, "{}", body(&r));
        assert!(body(&r).contains("READ-BACK MISMATCH"), "{}", body(&r));
    }

    #[test]
    fn the_gate_refuses_before_anything_is_written() {
        let fx = Fx::new("gate");
        let img = image(MIB as usize, 6);
        let mut recs = records(&img, 256 << 10);
        recs.push(end(&img));
        let size = img.len().to_string();
        let reasons = |r: &Reply| body(r);
        // no --destructive / no serial / wrong serial
        fx.disk("vdg1", 8 * MIB, 11, SER);
        let d = fx.daemon();
        let (r, _) = call(&d, Role::Admin, &["vdg1", "--size", &size, "--image-id", "ab12"], &refs(&recs));
        assert_eq!(r.status, Status::Refused);
        assert!(reasons(&r).contains("not_destructive") && reasons(&r).contains("serial_missing"), "{}", body(&r));
        let (r, _) = call(&d, Role::Admin, &["vdg1", "--size", &size, "--image-id", "ab12", "--destructive", "--serial", "WRONG"], &refs(&recs));
        assert_eq!(r.status, Status::Refused);
        assert!(reasons(&r).contains("serial_mismatch"));
        assert_eq!(fx.get("vdg1", 0, 8), vec![0; 8]);
        // mounted partition
        fx.disk("vdg2", 8 * MIB, 20, SER);
        std::fs::create_dir_all(fx.root.join("sys/block/vdg2/vdg2p1")).unwrap();
        std::fs::write(fx.root.join("sys/block/vdg2/vdg2p1/dev"), "252:21\n").unwrap();
        std::fs::write(fx.root.join("sys/block/vdg2/vdg2p1/partition"), "1\n").unwrap();
        std::fs::write(fx.root.join("proc/self/mountinfo"), "30 1 252:21 / /mnt rw - ext4 /dev/vdg2p1 rw\n").unwrap();
        let (r, _) = call(&d, Role::Admin, &args("vdg2", &size, &[]), &refs(&recs));
        assert_eq!(r.status, Status::Refused);
        assert!(reasons(&r).contains("\"mounted\""), "{}", body(&r));
        std::fs::write(fx.root.join("proc/self/mountinfo"), "").unwrap();
        // boot media
        fx.disk("vdg3", 8 * MIB, 30, SER);
        let mut d2 = fx.daemon();
        d2.probe.boot_disk = Some((252, 30));
        let (r, _) = call(&d2, Role::Admin, &args("vdg3", &size, &[]), &refs(&recs));
        assert_eq!(r.status, Status::Refused);
        assert!(reasons(&r).contains("boot_media"), "{}", body(&r));
        assert_eq!(fx.get("vdg3", 0, 8), vec![0; 8]);
        // boot media of a RAM-resident host: still refused without --allow-boot-media (reason is overridable)
        let proc = fx.root.join("proc/self");
        std::fs::write(proc.join("mountinfo"), "1 1 0:2 / / rw - rootfs rootfs rw\n").unwrap();
        let _ = std::fs::remove_file(proc.join("exe"));
        std::os::unix::fs::symlink("/usr/sbin/i7labd", proc.join("exe")).unwrap();
        let (r, _) = call(&d2, Role::Admin, &args("vdg3", &size, &[]), &refs(&recs));
        assert_eq!(r.status, Status::Refused);
        assert!(reasons(&r).contains("ram-resident") && reasons(&r).contains("\"overridable\":true"), "{}", body(&r));
        assert_eq!(fx.get("vdg3", 0, 8), vec![0; 8], "nothing written without the flag");
        // the flag alone (no --destructive) does not do it either
        let (r, _) = call(&d2, Role::Admin, &["vdg3", "--size", &size, "--image-id", "ab12", "--serial", SER, "--allow-boot-media"], &refs(&recs));
        assert_eq!(r.status, Status::Refused);
        assert!(reasons(&r).contains("not_destructive"), "{}", body(&r));
        // wrong serial with the flag
        let (r, _) = call(&d2, Role::Admin, &["vdg3", "--size", &size, "--image-id", "ab12", "--destructive", "--serial", "WRONG", "--allow-boot-media"], &refs(&recs));
        assert!(reasons(&r).contains("serial_mismatch"), "{}", body(&r));
        // root on the boot disk itself: absolute even with the flag
        std::fs::write(proc.join("mountinfo"), "1 1 8:1 / / rw - ext4 /dev/vdg3 rw\n").unwrap();
        let (r, _) = call(&d2, Role::Admin, &args("vdg3", &size, &["--allow-boot-media"]), &refs(&recs));
        assert_eq!(r.status, Status::Refused);
        assert!(reasons(&r).contains("boot_media") && !reasons(&r).contains("ram-resident"), "{}", body(&r));
        assert_eq!(fx.get("vdg3", 0, 8), vec![0; 8]);
        // RAM-resident + all three flags: written, and the audit log says the override was used
        std::fs::write(proc.join("mountinfo"), "1 1 0:2 / / rw - rootfs rootfs rw\n").unwrap();
        let (r, _) = call(&d2, Role::Admin, &args("vdg3", &size, &["--allow-boot-media"]), &refs(&recs));
        assert_eq!(r.status, Status::Ok, "{}", body(&r));
        assert_eq!(fx.get("vdg3", 0, img.len()), img);
        let log = std::fs::read_to_string(fx.root.join("run/i7lab/audit.log")).unwrap_or_default();
        assert!(log.contains("allow_boot_media=true") && log.contains("BOOT-MEDIA-OVERRIDE"), "{}", log);
        // a disk with a partition table needs the same two flags: refused without, written with
        fx.disk("vdg4", 8 * MIB, 40, SER);
        fx.put("vdg4", 0, &build_gpt(4096, 8 * MIB / 4096, &[(34, 100, "old")]));
        let (r, _) = call(&d, Role::Admin, &["vdg4", "--size", &size, "--image-id", "ab12", "--serial", SER], &refs(&recs));
        assert_eq!(r.status, Status::Refused);
        assert!(reasons(&r).contains("partition_table"), "{}", body(&r));
        let (r, _) = call(&d, Role::Admin, &args("vdg4", &size, &[]), &refs(&recs));
        assert_eq!(r.status, Status::Ok, "{}", body(&r));
        assert_eq!(fx.get("vdg4", 0, img.len()), img);
        // the read-only key cannot even start
        let (r, _) = call(&d, Role::Ro, &args("vdg1", &size, &[]), &refs(&recs));
        assert_eq!(r.status, Status::Eperm);
        // bad requests
        assert_eq!(call(&d, Role::Admin, &["vdg1"], &[]).0.status, Status::BadArgs);
        assert_eq!(call(&d, Role::Admin, &["../x", "--status"], &[]).0.status, Status::BadArgs);
        assert_eq!(call(&d, Role::Admin, &["vdg1", "--size", "0", "--image-id", "ab"], &[]).0.status, Status::BadArgs);
        assert_eq!(call(&d, Role::Admin, &["nosuchdisk", "--size", "10", "--image-id", "ab", "--destructive", "--serial", "x"], &[]).0.status, Status::Refused);
    }

    #[test]
    fn an_image_larger_than_the_disk_is_refused() {
        let fx = Fx::new("big");
        fx.disk("vdi6", 4 * MIB, 6, SER);
        let d = fx.daemon();
        let size = (4 * MIB + 1).to_string();
        let (r, _) = call(&d, Role::Admin, &args("vdi6", &size, &[]), &[]);
        assert_eq!(r.status, Status::TooBig, "{}", body(&r));
        // with a destination offset it is the sum that counts
        let size = (3 * MIB).to_string();
        let (r, _) = call(&d, Role::Admin, &args("vdi6", &size, &["--dest-offset", "1048577"]), &[]);
        assert_eq!(r.status, Status::BadArgs, "unaligned offset");
        let (r, _) = call(&d, Role::Admin, &args("vdi6", &size, &["--dest-offset", &(2 * MIB).to_string()]), &[]);
        assert_eq!(r.status, Status::TooBig);
        // the failed request left no session behind
        let (r, _) = call(&d, Role::Admin, &["vdi6", "--status", "--image-id", "ab12"], &[]);
        assert!(body(&r).contains("\"session\":null"), "{}", body(&r));
    }

    #[test]
    fn backup_gpt_moves_to_the_end_of_a_larger_disk() {
        let fx = Fx::new("gpt");
        fx.disk("vdi7", 8 * MIB, 7, SER);
        let d = fx.daemon();
        // a 4 MiB image (1024 sectors of 4096) whose GPT backup would sit at its own last LBA
        let mut img = vec![0u8; 4 * MIB as usize];
        let g = build_gpt(4096, 1024, &[(34, 200, "root"), (201, 900, "data")]);
        img[..g.len()].copy_from_slice(&g);
        img[300 * 4096..300 * 4096 + 64].copy_from_slice(&[7; 64]);
        let mut recs = records(&img, 512 << 10);
        recs.push(end(&img));
        let size = img.len().to_string();
        let (r, _) = call(&d, Role::Admin, &args("vdi7", &size, &["--verify"]), &refs(&recs));
        assert_eq!(r.status, Status::Ok, "{}", body(&r));
        let j = body(&r);
        assert!(j.contains("\"action\":\"moved\"") && j.contains("\"backup_lba\":2047") && j.contains("\"rrpart\":\"n/a"), "{}", j);
        let p = fx.get("vdi7", 4096, 4096);
        let hd = parse_gpt_header(&p).unwrap();
        assert!(hd.crc_ok);
        assert_eq!(hd.alt_lba, 2047);
        assert!(check_backup(&fx.get("vdi7", 2047 * 4096, 4096), 2047));
        // the image's own data and the primary entries are intact
        assert_eq!(fx.get("vdi7", 300 * 4096, 64), vec![7; 64]);
        assert_eq!(fx.get("vdi7", 2 * 4096, 128 * 128), g[2 * 4096..2 * 4096 + 128 * 128]);
        // --no-relocate leaves the disk exactly as streamed
        fx.disk("vdi8", 8 * MIB, 8, SER);
        let (r, _) = call(&d, Role::Admin, &args("vdi8", &size, &["--no-relocate"]), &refs(&recs));
        assert_eq!(r.status, Status::Ok);
        assert!(body(&r).contains("\"action\":\"skipped\""));
        assert_eq!(fx.get("vdi8", 4096, 4096)[32..40], 1023u64.to_le_bytes());
    }

    #[test]
    fn abort_releases_the_disk_and_another_image_is_busy_meanwhile() {
        let fx = Fx::new("abort");
        fx.disk("vdi9", 8 * MIB, 9, SER);
        let d = fx.daemon();
        let img = image(MIB as usize, 9);
        let recs = records(&img, 256 << 10);
        let size = img.len().to_string();
        let (r, _) = call(&d, Role::Admin, &args("vdi9", &size, &[]), &[&recs[0]]);
        assert!(body(&r).contains("\"done\":false"), "{}", body(&r));
        // another image id cannot take the disk
        let mut other = args("vdi9", &size, &[]);
        other[4] = "ffff";
        assert_eq!(call(&d, Role::Admin, &other, &[]).0.status, Status::Busy);
        // status shows the session
        let (s, _) = call(&d, Role::Admin, &["vdi9", "--status"], &[]);
        assert!(body(&s).contains("\"id\":\"ab12\"") && body(&s).contains("\"in_use\":false"), "{}", body(&s));
        let (r, _) = call(&d, Role::Admin, &["vdi9", "--abort"], &[]);
        assert!(body(&r).contains("\"aborted\":true"));
        let mut e = recs.clone();
        e.push(end(&img));
        let (r, _) = call(&d, Role::Admin, &other, &refs(&e));
        assert_eq!(r.status, Status::Ok, "{}", body(&r));
    }

    #[test]
    fn idle_sessions_are_reaped() {
        let now = Instant::now();
        let Some(old) = now.checked_sub(Duration::from_secs(400)) else { return };
        let mk = |dev: &str, last, in_use| Slot { dev: dev.into(), id: "x".into(), size: 1, next: 0, last, in_use, sess: None };
        let mut v = vec![mk("a", old, false), mk("b", old, true), mk("c", now, false)];
        reap(&mut v, now);
        assert_eq!(v.iter().map(|s| s.dev.as_str()).collect::<Vec<_>>(), ["b", "c"]);
    }
}
