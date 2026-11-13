//! `blk image`: stream a raw disk image onto a whole disk of a lab host (docs/I7LABCTL.md, docs/PROTOCOL.md 7.1).
//!
//! The sender reads the file once, sequentially, never holding more than one 1 MiB block plus the records it has
//! not yet handed to the transport. All-zero 1 MiB blocks (runs of them are merged, up to 256 MiB) travel as one
//! ZERO record; everything else as DATA records of `Tuning::chunk` bytes, each with its offset and SHA-256. The
//! host acknowledges every record with an `ack` event; the sender never has more than `Tuning::window` bytes
//! un-acknowledged (a ZERO record counts 4 KiB), so the host's upload queue stays bounded whatever the link does.
//! A damaged or dropped record, a cut connection or a stalled link end the call; the sender asks the host how far
//! it got (`--status`) and continues from there, up to `MAX_RETRIES` times.
//!
//! The core (`flash`) talks to any `Transport`, so it is exercised in tests with in-process hosts.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use labproto::blkwire::{encode_data, encode_end, encode_zero};
use labproto::catalog;
use labproto::crypto::{hex, Sha256};
use labproto::frame::Chan;
use labproto::json::Value;
use labproto::Status;

use crate::output::fmt_bytes;
use crate::{jv, CallResult, ClientError, ClientIo, Input, NullIo, Transport};

pub const ZERO_BLOCK: usize = 1 << 20;
pub const MAX_ZERO_RUN: u64 = 256 << 20;
pub const MAX_RETRIES: u32 = 8;
const ZERO_WEIGHT: u64 = 4096;
const MAX_INFLIGHT_RECORDS: usize = 128;

#[derive(Clone, Copy, Debug)]
pub struct Tuning {
    pub chunk: usize,
    pub window: u64,
}

impl Tuning {
    /// Ether: the host queues at most 4096 frames of ~1.3 KB per request; 3 MiB in flight stays well below.
    /// HTTP: every batch is one signed request, so the window is also the batch size.
    pub fn for_transport(name: &str) -> Tuning {
        if name == "http" {
            Tuning { chunk: 512 << 10, window: 2 << 20 }
        } else {
            Tuning { chunk: 256 << 10, window: 3 << 20 }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Progress {
    pub total: u64,
    pub start: u64,
    /// bytes the host has acknowledged (image offset)
    pub acked: u64,
    pub data_sent: u64,
    pub zero_sent: u64,
    pub elapsed: Duration,
    /// MiB/s over the whole transfer so far (zero ranges count: this is image progress)
    pub rate_mib: f64,
}

/// Identity of an image for resuming: size, destination offset and the first and last MiB. A different image that
/// shares all of those is still caught: the whole-image SHA-256 at the end (and the host's re-read on a resume).
pub fn image_id(path: &Path, size: u64, dest: u64) -> std::io::Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    h.update(b"i7blk1");
    h.update(&size.to_be_bytes());
    h.update(&dest.to_be_bytes());
    let mut buf = vec![0u8; ZERO_BLOCK];
    let n = f.read(&mut buf)?;
    h.update(&buf[..n]);
    let tail = size.saturating_sub(ZERO_BLOCK as u64);
    f.seek(SeekFrom::Start(tail))?;
    let mut t = Vec::new();
    f.take(ZERO_BLOCK as u64).read_to_end(&mut t)?;
    h.update(&t);
    Ok(hex(&h.finish())[..32].to_string())
}

fn is_zero(b: &[u8]) -> bool {
    b.iter().all(|x| *x == 0)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Data,
    Zero,
    End,
}

struct Item {
    end: u64,
    /// what it counts against the window
    w: u64,
    kind: Kind,
    rec: Vec<u8>,
}

/// The `ClientIo` of one transfer attempt: produces records (the upload side) and reads acks (the event side).
pub struct Sender<'a> {
    file: File,
    size: u64,
    tuning: Tuning,
    start: u64,
    /// offset of the next byte to read from the file
    read_pos: u64,
    carry: Option<(u64, Vec<u8>)>,
    queue: VecDeque<Item>,
    inflight: VecDeque<(u64, u64)>,
    weight: u64,
    acked: u64,
    /// image offset after the last record handed out
    sent_to: u64,
    whole: Sha256,
    end_queued: bool,
    fin_sent: bool,
    pub error: Option<std::io::Error>,
    pub data_sent: u64,
    pub zero_sent: u64,
    t0: Instant,
    last_report: Instant,
    ui: Option<&'a mut dyn Ui>,
    /// the host asked to stop (an error event) or a record failed locally: no more records
    pub stopped: bool,
}

impl<'a> Sender<'a> {
    /// `start`: image offset to continue from (the SHA-256 of the bytes before it is recomputed here).
    pub fn new(path: &Path, size: u64, start: u64, tuning: Tuning, ui: Option<&'a mut dyn Ui>) -> std::io::Result<Sender<'a>> {
        let mut file = File::open(path)?;
        let mut whole = Sha256::new();
        let mut left = start;
        let mut buf = vec![0u8; 4 << 20];
        while left > 0 {
            let n = (left.min(buf.len() as u64)) as usize;
            file.read_exact(&mut buf[..n])?;
            whole.update(&buf[..n]);
            left -= n as u64;
        }
        let now = Instant::now();
        Ok(Sender {
            file,
            size,
            tuning,
            start,
            read_pos: start,
            carry: None,
            queue: VecDeque::new(),
            inflight: VecDeque::new(),
            weight: 0,
            acked: start,
            sent_to: start,
            whole,
            end_queued: false,
            fin_sent: false,
            error: None,
            data_sent: 0,
            zero_sent: 0,
            t0: now,
            last_report: now - Duration::from_secs(1),
            ui,
            stopped: false,
        })
    }

    pub fn acked(&self) -> u64 {
        self.acked
    }

    fn read_block(&mut self) -> std::io::Result<Option<(u64, Vec<u8>)>> {
        if let Some(c) = self.carry.take() {
            return Ok(Some(c));
        }
        if self.read_pos >= self.size {
            return Ok(None);
        }
        let n = (self.size - self.read_pos).min(ZERO_BLOCK as u64) as usize;
        let mut b = vec![0u8; n];
        self.file.read_exact(&mut b)?;
        self.whole.update(&b);
        let off = self.read_pos;
        self.read_pos += n as u64;
        Ok(Some((off, b)))
    }

    /// Turn the next unit of the file into records on the queue.
    fn refill(&mut self) -> std::io::Result<()> {
        let Some((off, blk)) = self.read_block()? else {
            if !self.end_queued {
                self.queue.push_back(Item { end: self.size, w: 0, kind: Kind::End, rec: encode_end(self.size, &self.whole.clone().finish()) });
                self.end_queued = true;
            }
            return Ok(());
        };
        if is_zero(&blk) {
            let mut len = blk.len() as u64;
            while len < MAX_ZERO_RUN {
                match self.read_block()? {
                    None => break,
                    Some((o, b)) if is_zero(&b) => {
                        debug_assert_eq!(o, off + len);
                        len += b.len() as u64;
                    }
                    Some(c) => {
                        self.carry = Some(c);
                        break;
                    }
                }
            }
            self.queue.push_back(Item { end: off + len, w: ZERO_WEIGHT, kind: Kind::Zero, rec: encode_zero(off, len) });
        } else {
            for (k, c) in blk.chunks(self.tuning.chunk).enumerate() {
                let o = off + (k * self.tuning.chunk) as u64;
                self.queue.push_back(Item { end: o + c.len() as u64, w: c.len() as u64, kind: Kind::Data, rec: encode_data(o, c) });
            }
        }
        Ok(())
    }

    fn report(&mut self) {
        if self.ui.is_none() || self.last_report.elapsed() < Duration::from_millis(250) {
            return;
        }
        self.last_report = Instant::now();
        let el = self.t0.elapsed();
        let p = Progress {
            total: self.size,
            start: self.start,
            acked: self.acked,
            data_sent: self.data_sent,
            zero_sent: self.zero_sent,
            elapsed: el,
            rate_mib: (self.acked - self.start) as f64 / 1048576.0 / el.as_secs_f64().max(0.001),
        };
        if let Some(u) = self.ui.as_mut() {
            u.progress(&p);
        }
    }

    fn on_ack(&mut self, next: u64) {
        if next > self.acked {
            self.acked = next;
        }
        while let Some(&(end, w)) = self.inflight.front() {
            if end <= self.acked {
                self.weight -= w;
                self.inflight.pop_front();
            } else {
                break;
            }
        }
    }
}

impl ClientIo for Sender<'_> {
    fn stdout(&mut self, _b: &[u8]) {}
    fn stderr(&mut self, _b: &[u8]) {}
    fn event(&mut self, j: &str) {
        if j.contains("\"ack\"") {
            if let Some(n) = jv::parse(j).and_then(|v| jv::u(&v, "next")) {
                self.on_ack(n);
            }
        }
    }
    fn input(&mut self) -> Input {
        self.report();
        if self.stopped || self.error.is_some() {
            return Input::End(Chan::File);
        }
        if self.fin_sent {
            return Input::Pending;
        }
        if self.queue.is_empty() {
            if self.end_queued {
                self.fin_sent = true;
                return Input::End(Chan::File);
            }
            if let Err(e) = self.refill() {
                self.error = Some(e);
                return Input::End(Chan::File);
            }
        }
        let Some(front) = self.queue.front() else { return Input::Pending };
        let w = front.w;
        if front.kind != Kind::End && self.weight > 0 && (self.weight + w > self.tuning.window || self.inflight.len() >= MAX_INFLIGHT_RECORDS) {
            return Input::Pending;
        }
        let it = self.queue.pop_front().unwrap();
        match it.kind {
            Kind::End => return Input::Data(Chan::File, it.rec),
            Kind::Zero => self.zero_sent += it.end - self.sent_to,
            Kind::Data => self.data_sent += it.end - self.sent_to,
        }
        self.sent_to = it.end;
        self.weight += w;
        self.inflight.push_back((it.end, w));
        Input::Data(Chan::File, it.rec)
    }
}

// ------------------------------------------------------------------------------------------------ flash

#[derive(Clone, Debug)]
pub struct Params {
    pub file: PathBuf,
    pub serial: String,
    pub verify: bool,
    pub dest_offset: u64,
    pub resume: bool,
    pub grow_last: bool,
    pub no_relocate: bool,
    /// override of the transport's tuning (tests)
    pub tuning: Option<Tuning>,
}

pub trait Ui {
    fn say(&mut self, s: &str);
    /// The summary of what is about to happen; true = go on.
    fn confirm(&mut self, summary: &str) -> bool;
    fn progress(&mut self, p: &Progress);
}

#[derive(Debug)]
pub struct Outcome {
    pub bytes: u64,
    pub sha256: String,
    pub host: String,
    pub attempts: u32,
    pub resumed_from: u64,
    pub elapsed: Duration,
    pub data_sent: u64,
    pub zero_sent: u64,
    pub verified: bool,
    pub gpt_action: String,
    pub rrpart: String,
}

#[derive(Debug)]
pub enum FlashError {
    Client(ClientError),
    /// the disk does not hold the image (hash mismatch): exit 3
    Mismatch(String),
}

impl From<ClientError> for FlashError {
    fn from(e: ClientError) -> Self {
        FlashError::Client(e)
    }
}

impl From<std::io::Error> for FlashError {
    fn from(e: std::io::Error) -> Self {
        FlashError::Client(ClientError::Failed(e.to_string()))
    }
}

fn call_json(t: &mut dyn Transport, args: &[String]) -> Result<(Status, String), ClientError> {
    let spec = catalog::by_name("blk.image").ok_or_else(|| ClientError::Unsupported("blk.image is not in this build's catalogue".into()))?;
    let r: CallResult = t.call(spec, args, &mut NullIo)?;
    Ok((r.status, String::from_utf8_lossy(&r.body).into_owned()))
}

pub struct HostStatus {
    pub v: Value,
    pub dev_size: u64,
    pub resume_at: Option<u64>,
}

pub fn host_status(t: &mut dyn Transport, dev: &str, id: &str) -> Result<HostStatus, ClientError> {
    let (st, body) = call_json(t, &[dev.to_string(), "--status".into(), "--image-id".into(), id.to_string()])?;
    if st != Status::Ok {
        let (text, _) = crate::output::remote_error_text(st.name(), &body);
        return Err(match st {
            Status::Unsupported => ClientError::Unsupported(format!("the host does not serve blk.image ({}): its image is older than this i7labctl", text)),
            Status::Refused => ClientError::Safety(text),
            Status::Eperm => ClientError::Auth(text),
            _ => ClientError::Failed(format!("blk.image --status: {}", text)),
        });
    }
    let v = jv::parse(&body).ok_or_else(|| ClientError::Failed("unreadable blk.image status from the host".into()))?;
    let dev_size = jv::u(&v, "device.size_bytes").unwrap_or(0);
    let resume_at = jv::u(&v, "resume_at");
    Ok(HostStatus { v, dev_size, resume_at })
}

/// Human text of the target disk as the host describes it.
pub fn describe_device(v: &Value, image: &Path, size: u64, dest: u64) -> String {
    let d = |p: &str| jv::s(v, &format!("device.{}", p)).unwrap_or("-").to_string();
    let mut out = String::new();
    out.push_str(&format!("target   {}  {} {}  serial {}  {}  {}\n", d("name"), d("vendor").trim(), d("model").trim(), d("serial"), fmt_bytes(jv::u(v, "device.size_bytes").unwrap_or(0)), d("kind")));
    out.push_str(&format!("image    {}  {} ({} bytes){}\n", image.display(), fmt_bytes(size), size, if dest > 0 { format!(", at disk offset {}", dest) } else { String::new() }));
    let kind = jv::s(v, "device.partition_table.kind").unwrap_or("none");
    let parts = jv::arr(v, "device.partitions");
    out.push_str(&format!("current  partition table: {}, {} partition(s)\n", kind, parts.len()));
    for p in parts.iter().take(12) {
        out.push_str(&format!(
            "           {:>2}: LBA {}..{}  {}  {}\n",
            jv::u(p, "index").unwrap_or(0),
            jv::u(p, "first_lba").unwrap_or(0),
            jv::u(p, "last_lba").unwrap_or(0),
            jv::s(p, "name").unwrap_or("-"),
            jv::s(p, "type_guid").or(jv::s(p, "mbr_type")).unwrap_or("")
        ));
    }
    let sigs: Vec<String> = jv::arr(v, "device.signatures").iter().map(|s| format!("{}@{}", jv::s(s, "kind").unwrap_or("?"), jv::u(s, "offset").unwrap_or(0))).collect();
    if !sigs.is_empty() {
        out.push_str(&format!("           signatures: {}\n", sigs.join(", ")));
    }
    let mounts: Vec<&str> = jv::arr(v, "device.mounts").iter().filter_map(Value::as_str).collect();
    if !mounts.is_empty() {
        out.push_str(&format!("           MOUNTED: {}\n", mounts.join(", ")));
    }
    out.push_str(&format!("verdict  {}\n", jv::s(v, "device.write_safety.verdict").unwrap_or("?")));
    out
}

/// `error.reasons` of a refusal: strings, or the gate's objects `{"code":..,"detail":..}`.
fn reason_texts(body: &str) -> Vec<String> {
    let Some(v) = jv::parse(body) else { return Vec::new() };
    jv::arr(&v, "error.reasons")
        .iter()
        .map(|r| match r.as_str() {
            Some(s) => s.to_string(),
            None => match jv::s(r, "detail") {
                Some(d) => format!("{} ({})", jv::s(r, "code").unwrap_or("?"), d),
                None => jv::s(r, "code").unwrap_or("?").to_string(),
            },
        })
        .collect()
}

fn error_next(body: &str) -> (String, Option<u64>) {
    let code = jv::error_parts(body).map(|(c, _, _)| c).unwrap_or_default();
    let next = jv::parse(body).and_then(|v| jv::u(&v, "next"));
    (code, next)
}

/// The whole job. `t` is a connected transport; the safety checks of the host are authoritative, the checks here
/// (serial, size) only fail early and cheaply.
pub fn flash(t: &mut dyn Transport, dev: &str, p: &Params, ui: &mut dyn Ui) -> Result<Outcome, FlashError> {
    let size = std::fs::metadata(&p.file).map_err(|e| ClientError::Usage(format!("cannot read {}: {}", p.file.display(), e)))?.len();
    if size == 0 {
        return Err(ClientError::Usage(format!("{} is empty", p.file.display())).into());
    }
    let id = image_id(&p.file, size, p.dest_offset)?;
    let st = host_status(t, dev, &id)?;
    if st.dev_size == 0 {
        return Err(ClientError::Failed("the host reported no size for the disk".into()).into());
    }
    if size.checked_add(p.dest_offset).map_or(true, |e| e > st.dev_size) {
        return Err(ClientError::Safety(format!("the image ({} bytes at offset {}) is larger than the disk ({} bytes). Nothing was sent.", size, p.dest_offset, st.dev_size)).into());
    }
    let have = jv::s(&st.v, "device.serial").or(jv::s(&st.v, "device.wwid")).unwrap_or("");
    if have.trim() != p.serial.trim() {
        return Err(ClientError::Safety(format!("serial mismatch: {} has serial '{}', you gave '{}'. Nothing was sent.", dev, have, p.serial)).into());
    }
    // a killed sender can leave its request attached on the host (over ether nothing tells the host) until the host's
    // input idle timeout (60 s); `--resume` then has to wait for it instead of finding nothing to resume
    let mut st = st;
    if p.resume && jv::b(&st.v, "session.in_use") == Some(true) {
        ui.say("the host still has the previous request of this transfer attached; waiting for it to detach (up to 90 s)");
        for _ in 0..45 {
            std::thread::sleep(Duration::from_secs(2));
            match host_status(t, dev, &id) {
                Ok(s) => {
                    let busy = jv::b(&s.v, "session.in_use") == Some(true);
                    st = s;
                    if !busy {
                        break;
                    }
                }
                Err(ClientError::Transport(_)) | Err(ClientError::Timeout) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    let mut summary = describe_device(&st.v, &p.file, size, p.dest_offset);
    let mut resume_at = if p.resume { st.resume_at } else { None };
    if p.resume {
        match resume_at {
            Some(n) => summary.push_str(&format!("resume   continuing at byte {} ({:.1}%)\n", n, n as f64 * 100.0 / size as f64)),
            None => summary.push_str("resume   nothing to resume on the host: starting at byte 0\n"),
        }
    }
    summary.push_str(&format!("THIS OVERWRITES {} of {} (everything on it is lost). Continue?", fmt_bytes(size), dev));
    if !ui.confirm(&summary) {
        return Err(ClientError::Safety("not confirmed".into()).into());
    }
    let tuning = p.tuning.unwrap_or_else(|| Tuning::for_transport(t.name()));
    let spec = catalog::by_name("blk.image").ok_or_else(|| ClientError::Unsupported("blk.image is not in this build's catalogue".into()))?;
    let t0 = Instant::now();
    let first_start = resume_at.unwrap_or(0);
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        let start = resume_at.unwrap_or(0);
        let mut args = vec![dev.to_string(), "--size".into(), size.to_string(), "--image-id".into(), id.clone(), "--serial".into(), p.serial.clone(), "--destructive".into()];
        if resume_at.is_some() {
            args.push("--resume".into());
        }
        if p.verify {
            args.push("--verify".into());
        }
        if p.grow_last {
            args.push("--grow-last".into());
        }
        if p.no_relocate {
            args.push("--no-relocate".into());
        }
        if p.dest_offset > 0 {
            args.extend(["--dest-offset".to_string(), p.dest_offset.to_string()]);
        }
        if start > 0 {
            ui.say(&format!("hashing the first {} of the image (resume)...", fmt_bytes(start)));
        }
        let mut sender = Sender::new(&p.file, size, start, tuning, Some(&mut *ui))?;
        let r = t.call(spec, &args, &mut sender);
        let (data_sent, zero_sent) = (sender.data_sent, sender.zero_sent);
        if let Some(e) = sender.error.take() {
            return Err(FlashError::Client(ClientError::Failed(format!("reading {}: {}", p.file.display(), e))));
        }
        let retry_reason = match r {
            Ok(res) if res.status == Status::Ok => {
                let body = String::from_utf8_lossy(&res.body).into_owned();
                let v = jv::parse(&body);
                if v.as_ref().and_then(|v| jv::b(v, "done")) == Some(false) {
                    format!("the host acknowledged {} bytes but the image is not complete", v.as_ref().and_then(|v| jv::u(v, "next")).unwrap_or(0))
                } else {
                    let v = v.ok_or_else(|| ClientError::Failed(format!("unreadable result from the host: {}", labproto::text::sanitize(&body))))?;
                    let host_sha = jv::s(&v, "sha256").unwrap_or("").to_string();
                    return Ok(Outcome {
                        bytes: size,
                        sha256: host_sha,
                        host: body.clone(),
                        attempts,
                        resumed_from: first_start,
                        elapsed: t0.elapsed(),
                        data_sent,
                        zero_sent,
                        verified: jv::b(&v, "verified").unwrap_or(false),
                        gpt_action: jv::s(&v, "gpt.action").unwrap_or("").to_string(),
                        rrpart: jv::s(&v, "rrpart").unwrap_or("").to_string(),
                    });
                }
            }
            Ok(res) => {
                let body = String::from_utf8_lossy(&res.body).into_owned();
                let (code, _) = error_next(&body);
                let (text, _) = crate::output::remote_error_text(res.status.name(), &body);
                let reasons = reason_texts(&body);
                match code.as_str() {
                    "gap" | "chunk_sha" | "truncated" | "canceled" | "stalled" => text,
                    "image_sha" | "readback_mismatch" => return Err(FlashError::Mismatch(text)),
                    _ => {
                        let mut full = text;
                        for r in reasons {
                            full.push_str(&format!("\n  reason: {}", labproto::text::sanitize(&r)));
                        }
                        return Err(FlashError::Client(match res.status {
                            Status::Refused => ClientError::Safety(full),
                            Status::Eperm => ClientError::Auth(full),
                            Status::Unsupported => ClientError::Unsupported(full),
                            _ => ClientError::Failed(full),
                        }));
                    }
                }
            }
            Err(ClientError::Transport(m)) => format!("transport: {}", m),
            Err(ClientError::Timeout) => "no response (timeout)".to_string(),
            Err(e) => return Err(e.into()),
        };
        if attempts > MAX_RETRIES {
            return Err(FlashError::Client(ClientError::Failed(format!("giving up after {} attempts: {}", attempts, retry_reason))));
        }
        ui.say(&format!("attempt {} failed ({}); asking the host how far it got", attempts, retry_reason));
        // the host may need a moment (a reboot is not survivable: the session is gone and so is the state file)
        let mut st2 = None;
        // (a cut request can stay attached on the host while it drains the records it already holds: the status
        // then has `session.in_use` and no `resume_at`; wait for it to detach rather than start over into BUSY)
        for k in 0..40u64 {
            std::thread::sleep(Duration::from_millis((500 * (k + 1)).min(2000)));
            match host_status(t, dev, &id) {
                Ok(s) if jv::b(&s.v, "session.in_use") == Some(true) && k < 39 => continue,
                Ok(s) => {
                    st2 = Some(s);
                    break;
                }
                Err(ClientError::Transport(_)) | Err(ClientError::Timeout) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        let Some(s2) = st2 else {
            return Err(FlashError::Client(ClientError::Transport(format!("the host stopped answering after: {}", retry_reason))));
        };
        resume_at = s2.resume_at;
        match resume_at {
            Some(n) => ui.say(&format!("continuing at byte {} ({:.1}%)", n, n as f64 * 100.0 / size as f64)),
            None => ui.say("the host lost the transfer state: starting over from byte 0"),
        }
    }
}

pub fn progress_line(p: &Progress) -> String {
    let pct = p.acked as f64 * 100.0 / p.total.max(1) as f64;
    let moved = (p.acked - p.start).max(1) as f64;
    let remain = p.total.saturating_sub(p.acked) as f64;
    let eta = if p.rate_mib > 0.1 { remain / 1048576.0 / p.rate_mib } else { 0.0 };
    format!(
        "{} / {}  {:5.1}%  {:6.1} MiB/s  elapsed {}  eta {}  (sent {} data, {} zero ranges)",
        fmt_bytes(p.acked),
        fmt_bytes(p.total),
        pct,
        p.rate_mib,
        fmt_dur(p.elapsed.as_secs()),
        if moved < 1.0 || eta <= 0.0 { "-".to_string() } else { fmt_dur(eta as u64) },
        fmt_bytes(p.data_sent),
        fmt_bytes(p.zero_sent)
    )
}

pub fn fmt_dur(s: u64) -> String {
    if s >= 3600 {
        format!("{}h{:02}m{:02}s", s / 3600, s / 60 % 60, s % 60)
    } else {
        format!("{}m{:02}s", s / 60, s % 60)
    }
}

// ------------------------------------------------------------------------------------------------ CLI

use std::io::Write;

use crate::cmds::{Run, Spec};
use crate::output;

struct CliUi<'r, 'e> {
    run: &'r mut Run<'e>,
    live: bool,
    drew: bool,
}

impl CliUi<'_, '_> {
    fn clear(&mut self) {
        if self.drew {
            let _ = self.run.env.err.write_all(b"\r\x1b[K");
            self.drew = false;
        }
    }
}

impl Ui for CliUi<'_, '_> {
    fn say(&mut self, s: &str) {
        self.clear();
        self.run.note(s);
    }

    fn confirm(&mut self, summary: &str) -> bool {
        let (body, question) = summary.rsplit_once('\n').unwrap_or(("", summary));
        if !self.run.g.json {
            self.run.err(body);
        }
        if self.run.g.yes {
            return true;
        }
        if let Some(a) = self.run.env.fake_answer {
            return a;
        }
        if !self.run.env.in_tty {
            self.run.err("i7labctl: blk image destroys a whole disk: stdin is not a terminal, pass --yes to confirm in scripts");
            return false;
        }
        let _ = write!(self.run.env.err, "{} [y/N] ", question);
        let _ = self.run.env.err.flush();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).is_ok() && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    }

    fn progress(&mut self, p: &Progress) {
        if self.live {
            let _ = write!(self.run.env.err, "\r{}\x1b[K", progress_line(p));
            let _ = self.run.env.err.flush();
            self.drew = true;
        }
    }
}

pub fn run_cli(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let spec = Spec::new("blk image <host> DISK --file IMG --serial SERIAL --destructive [--yes] [--verify] [--offset N] [--resume] [--grow-last] [--no-relocate]")
        .flags(&["destructive", "verify", "resume", "grow-last", "no-relocate"])
        .valued(&["file", "serial", "offset"])
        .pos(1, 1);
    let p = run.parse(args, &spec)?;
    let dev = p.pos[0].clone();
    if dev.contains('/') || dev.starts_with('-') {
        return Err(ClientError::Usage(format!("DISK is a whole-disk name from `blk ls` (like nvme0n1), not a path: '{}'", dev)));
    }
    let file = p.opts.value("file").ok_or_else(|| ClientError::Usage("blk image needs --file IMG (a raw disk image)".into()))?;
    let serial = p.opts.value("serial").filter(|s| !s.trim().is_empty());
    if !p.opts.flag("destructive") || serial.is_none() {
        return Err(ClientError::Safety(format!(
            "blk image overwrites the whole disk and needs BOTH --destructive and --serial SERIAL (the real serial of {} from `i7labctl blk ls`). Nothing was sent.",
            dev
        )));
    }
    let dest = p.uint("offset")?.unwrap_or(0);
    if dest % 4096 != 0 {
        return Err(ClientError::Usage(format!("--offset is the byte offset on the disk and must be a multiple of 4096, got {}", dest)));
    }
    let params = Params {
        file: PathBuf::from(file),
        serial: serial.unwrap().to_string(),
        verify: p.opts.flag("verify"),
        dest_offset: dest,
        resume: p.opts.flag("resume"),
        grow_last: p.opts.flag("grow-last"),
        no_relocate: p.opts.flag("no-relocate"),
        tuning: None,
    };
    let mut prep = run.prepare(p.host.as_deref(), 0.0)?;
    let live = run.env.out_tty && !run.g.json && !run.g.quiet;
    let json = run.g.json;
    let res = {
        let mut ui = CliUi { run: &mut *run, live, drew: false };
        let r = flash(&mut *prep.transport, &dev, &params, &mut ui);
        ui.clear();
        r
    };
    let tname = prep.transport.name();
    match res {
        Ok(o) => {
            let secs = o.elapsed.as_secs_f64().max(0.001);
            let warn_gpt = o.gpt_action == "error";
            let warn_rr = o.rrpart.starts_with("failed");
            if json {
                let e = output::ok_envelope(tname, Some(&prep.info), "blk.image", None, &o.host);
                run.outln(&e);
            } else {
                run.outln(&format!(
                    "wrote {} to {} in {} ({:.1} MiB/s image rate; {} sent, {} zero ranges skipped{}{})",
                    fmt_bytes(o.bytes),
                    dev,
                    fmt_dur(secs as u64),
                    (o.bytes - o.resumed_from) as f64 / 1048576.0 / secs,
                    fmt_bytes(o.data_sent),
                    fmt_bytes(o.zero_sent),
                    if o.resumed_from > 0 { format!(", resumed at {}", o.resumed_from) } else { String::new() },
                    if o.attempts > 1 { format!(", {} attempts", o.attempts) } else { String::new() }
                ));
                run.outln(&format!("sha256 {} ({})", o.sha256, if o.verified { "verified by reading the disk back" } else { "host stream hash matched; read back not requested (--verify)" }));
                run.outln(&format!("gpt backup: {}; partition table re-read: {}", if o.gpt_action.is_empty() { "-" } else { &o.gpt_action }, if o.rrpart.is_empty() { "-" } else { &o.rrpart }));
                if warn_gpt {
                    run.err("warning: the image is written and verified, but the GPT backup could not be moved to the end of the disk (see the host's gpt.message with --json)");
                }
                if warn_rr {
                    run.err("warning: the kernel did not re-read the partition table; reboot the host or run blkdev --rereadpt there");
                }
            }
            Ok(if warn_gpt || warn_rr { 3 } else { 0 })
        }
        Err(FlashError::Mismatch(m)) => {
            let e = ClientError::Failed(m);
            Ok(crate::cli::emit_error(run.env, &run.g, "blk.image", &e, 3))
        }
        Err(FlashError::Client(e)) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use labproto::blkwire::{Record, RecordReader};
    use std::sync::{Arc, Mutex};

    fn tmpfile(label: &str, data: &[u8]) -> PathBuf {
        let p = std::env::temp_dir().join(format!("i7ctl-img-{}-{}", label, std::process::id()));
        std::fs::write(&p, data).unwrap();
        p
    }

    fn pump(s: &mut Sender, acks: bool) -> Vec<Record> {
        // drain the sender like a transport would; acknowledge everything when `acks`
        let mut rd = RecordReader::new();
        let mut out = Vec::new();
        for _ in 0..100_000 {
            match s.input() {
                Input::Data(_, d) => {
                    rd.push(&d);
                    while let Some(r) = rd.next().unwrap() {
                        if acks {
                            let end = match &r {
                                Record::Data { off, payload, .. } => off + payload.len() as u64,
                                Record::Zero { off, len } => off + len,
                                Record::End { .. } => 0,
                            };
                            s.event(&format!("{{\"event\":\"ack\",\"next\":{}}}", end));
                        }
                        out.push(r);
                    }
                }
                Input::End(_) => break,
                Input::Pending => {
                    if !acks {
                        break;
                    }
                }
                Input::None => break,
            }
        }
        out
    }

    #[test]
    fn zero_blocks_merge_and_everything_else_is_chunked() {
        let mut img = vec![0u8; 5 * ZERO_BLOCK + 1000];
        img[ZERO_BLOCK * 3 + 7] = 1; // block 3 has data, blocks 0-2 and 4-5 (+tail) are zero
        let p = tmpfile("zero", &img);
        let t = Tuning { chunk: 256 << 10, window: 3 << 20 };
        let mut s = Sender::new(&p, img.len() as u64, 0, t, None).unwrap();
        let recs = pump(&mut s, true);
        let kinds: Vec<String> = recs
            .iter()
            .map(|r| match r {
                Record::Zero { off, len } => format!("Z{}+{}", off, len),
                Record::Data { off, payload, .. } => format!("D{}+{}", off, payload.len()),
                Record::End { total, .. } => format!("E{}", total),
            })
            .collect();
        let m = ZERO_BLOCK as u64;
        assert_eq!(kinds[0], format!("Z0+{}", 3 * m));
        assert_eq!(kinds.iter().filter(|k| k.starts_with('D')).count(), 4);
        assert_eq!(kinds[1], format!("D{}+{}", 3 * m, 256 << 10));
        assert_eq!(kinds[5], format!("Z{}+{}", 4 * m, m + 1000), "the zero tail merges with the zero block before it");
        assert_eq!(kinds[6], format!("E{}", img.len()));
        // END carries the SHA-256 of the whole image
        let Record::End { sha, .. } = recs.last().unwrap() else { panic!() };
        assert_eq!(*sha, labproto::crypto::sha256(&img));
        assert_eq!(s.zero_sent, 4 * m + 1000);
        assert_eq!(s.data_sent, m);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn window_bounds_the_unacknowledged_bytes() {
        let img: Vec<u8> = (0..8 * ZERO_BLOCK).map(|i| (i % 253) as u8 | 1).collect();
        let p = tmpfile("win", &img);
        let t = Tuning { chunk: 256 << 10, window: 1 << 20 };
        let mut s = Sender::new(&p, img.len() as u64, 0, t, None).unwrap();
        // without acks the sender stops after one window
        let mut sent = 0u64;
        let mut rd = RecordReader::new();
        loop {
            match s.input() {
                Input::Data(_, d) => {
                    rd.push(&d);
                    while let Some(Record::Data { payload, .. }) = rd.next().unwrap() {
                        sent += payload.len() as u64;
                    }
                }
                Input::Pending => break,
                other => panic!("{:?}", other),
            }
        }
        assert_eq!(sent, 1 << 20, "exactly one window of data without any ack");
        s.event("{\"event\":\"ack\",\"next\":262144}");
        assert!(matches!(s.input(), Input::Data(..)), "an ack opens the window again");
        assert!(matches!(s.input(), Input::Pending));
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn resume_hashes_the_prefix_and_continues_at_the_offset() {
        let img: Vec<u8> = (0..3 * ZERO_BLOCK + 5).map(|i| (i % 251) as u8 | 2).collect();
        let p = tmpfile("res", &img);
        let start = ZERO_BLOCK as u64 + 4096;
        let mut s = Sender::new(&p, img.len() as u64, start, Tuning { chunk: 128 << 10, window: 1 << 20 }, None).unwrap();
        let recs = pump(&mut s, true);
        let Record::Data { off, .. } = &recs[0] else { panic!() };
        assert_eq!(*off, start);
        let Record::End { sha, total } = recs.last().unwrap() else { panic!() };
        assert_eq!((*total, *sha), (img.len() as u64, labproto::crypto::sha256(&img)), "whole-image hash covers the skipped prefix");
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn image_id_depends_on_size_dest_and_both_ends() {
        let a = vec![5u8; 3 << 20];
        let mut b = a.clone();
        let (pa, pb) = (tmpfile("ida", &a), tmpfile("idb", &b));
        assert_eq!(image_id(&pa, a.len() as u64, 0).unwrap(), image_id(&pa, a.len() as u64, 0).unwrap());
        assert_ne!(image_id(&pa, a.len() as u64, 0).unwrap(), image_id(&pa, a.len() as u64, 4096).unwrap());
        assert_eq!(image_id(&pa, a.len() as u64, 0).unwrap(), image_id(&pb, a.len() as u64, 0).unwrap());
        b[10] = 6;
        std::fs::write(&pb, &b).unwrap();
        assert_ne!(image_id(&pa, a.len() as u64, 0).unwrap(), image_id(&pb, a.len() as u64, 0).unwrap());
        let _ = (std::fs::remove_file(pa), std::fs::remove_file(pb));
    }

    // ---- flash() against a scripted transport

    struct Script {
        calls: Arc<Mutex<Vec<Vec<String>>>>,
        transfers: Vec<Result<(Status, String), ClientError>>,
        status_resume: Vec<Option<u64>>,
        dev_size: u64,
        serial: &'static str,
    }

    impl Transport for Script {
        fn call(&mut self, _c: &catalog::CmdSpec, args: &[String], io: &mut dyn ClientIo) -> Result<CallResult, ClientError> {
            self.calls.lock().unwrap().push(args.to_vec());
            if args.iter().any(|a| a == "--status") {
                let r = if self.status_resume.is_empty() { None } else { self.status_resume.remove(0) };
                let body = format!("{{\"v\":1,\"device\":{{\"name\":\"vdz\",\"serial\":\"{}\",\"size_bytes\":{},\"kind\":\"virtio\",\"partition_table\":null,\"partitions\":[],\"signatures\":[],\"mounts\":[],\"write_safety\":{{\"verdict\":\"safe\"}}}},\"session\":null,\"resume_at\":{}}}", self.serial, self.dev_size, r.map(|x| x.to_string()).unwrap_or("null".into()));
                return Ok(CallResult { status: Status::Ok, body: body.into_bytes(), exit_code: None, rtt_ms: 0.0 });
            }
            // consume the upload so the sender runs (acks as the host would)
            for _ in 0..100_000 {
                match io.input() {
                    Input::End(_) | Input::None => break,
                    Input::Pending => io.event("{\"event\":\"ack\",\"next\":4194304}"),
                    Input::Data(..) => {}
                }
            }
            match self.transfers.remove(0) {
                Ok((status, body)) => Ok(CallResult { status, body: body.into_bytes(), exit_code: None, rtt_ms: 0.0 }),
                Err(e) => Err(e),
            }
        }
        fn name(&self) -> &'static str {
            "ether"
        }
    }

    #[derive(Default)]
    struct TUi {
        yes: bool,
        said: Vec<String>,
        asked: Vec<String>,
    }
    impl Ui for TUi {
        fn say(&mut self, s: &str) {
            self.said.push(s.into());
        }
        fn confirm(&mut self, s: &str) -> bool {
            self.asked.push(s.into());
            self.yes
        }
        fn progress(&mut self, _p: &Progress) {}
    }

    fn params(p: &PathBuf) -> Params {
        Params { file: p.clone(), serial: "SER1".into(), verify: true, dest_offset: 0, resume: false, grow_last: false, no_relocate: false, tuning: Some(Tuning { chunk: 256 << 10, window: 1 << 20 }) }
    }

    const OK_BODY: &str = "{\"v\":1,\"done\":true,\"sha256\":\"ab\",\"verified\":true,\"gpt\":{\"action\":\"moved\"},\"rrpart\":\"ok\"}";

    fn script(transfers: Vec<Result<(Status, String), ClientError>>, resume: Vec<Option<u64>>, dev_size: u64, serial: &'static str) -> (Script, Arc<Mutex<Vec<Vec<String>>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (Script { calls: calls.clone(), transfers, status_resume: resume, dev_size, serial }, calls)
    }

    #[test]
    fn local_checks_fail_before_anything_is_sent() {
        let img = vec![3u8; 4 << 20];
        let p = tmpfile("chk", &img);
        let mut ui = TUi { yes: true, ..Default::default() };
        // image larger than the disk
        let (mut t, calls) = script(vec![], vec![None], 3 << 20, "SER1");
        let e = flash(&mut t, "vdz", &params(&p), &mut ui).unwrap_err();
        assert!(matches!(&e, FlashError::Client(ClientError::Safety(m)) if m.contains("larger than the disk")), "{:?}", e);
        assert_eq!(calls.lock().unwrap().len(), 1, "only the status query went out");
        // wrong serial
        let (mut t, _) = script(vec![], vec![None], 8 << 20, "OTHER");
        let e = flash(&mut t, "vdz", &params(&p), &mut ui).unwrap_err();
        assert!(matches!(&e, FlashError::Client(ClientError::Safety(m)) if m.contains("serial mismatch")), "{:?}", e);
        // declined
        let (mut t, calls) = script(vec![], vec![None], 8 << 20, "SER1");
        let mut no = TUi::default();
        let e = flash(&mut t, "vdz", &params(&p), &mut no).unwrap_err();
        assert!(matches!(&e, FlashError::Client(ClientError::Safety(m)) if m.contains("not confirmed")), "{:?}", e);
        assert!(no.asked[0].contains("THIS OVERWRITES") && no.asked[0].contains("vdz"));
        assert_eq!(calls.lock().unwrap().len(), 1);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn a_dropped_chunk_is_resumed_from_the_host_offset() {
        let img: Vec<u8> = (0..4 << 20).map(|i| (i % 249) as u8 | 1).collect();
        let p = tmpfile("retry", &img);
        let gap = "{\"error\":{\"code\":\"gap\",\"message\":\"record at 524288 but next is 262144\"},\"next\":262144,\"resumable\":true}".to_string();
        let (mut t, calls) = script(vec![Ok((Status::BadArgs, gap)), Err(ClientError::Transport("cut".into())), Ok((Status::Ok, OK_BODY.into()))], vec![None, Some(262144), Some(1048576)], 8 << 20, "SER1");
        let mut ui = TUi { yes: true, ..Default::default() };
        let o = flash(&mut t, "vdz", &params(&p), &mut ui).unwrap();
        assert_eq!(o.attempts, 3);
        assert!(o.verified && o.gpt_action == "moved" && o.rrpart == "ok");
        let c = calls.lock().unwrap();
        let transfers: Vec<&Vec<String>> = c.iter().filter(|a| !a.iter().any(|x| x == "--status")).collect();
        assert_eq!(transfers.len(), 3);
        assert!(!transfers[0].iter().any(|a| a == "--resume"));
        assert!(transfers[1].iter().any(|a| a == "--resume") && transfers[2].iter().any(|a| a == "--resume"));
        for a in &transfers {
            assert!(a.iter().any(|x| x == "--destructive") && a.iter().any(|x| x == "--verify"));
            assert_eq!(a.iter().position(|x| x == "--serial").map(|i| a[i + 1].as_str()), Some("SER1"));
        }
        assert!(ui.said.iter().any(|s| s.contains("continuing at byte 262144")), "{:?}", ui.said);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn refusal_and_mismatch_are_not_retried() {
        let img = vec![9u8; 2 << 20];
        let p = tmpfile("fatal", &img);
        let refused = "{\"error\":{\"code\":\"REFUSED\",\"message\":\"write refused by the safety gate\",\"reasons\":[\"mounted\"]}}".to_string();
        let (mut t, calls) = script(vec![Ok((Status::Refused, refused))], vec![None], 8 << 20, "SER1");
        let mut ui = TUi { yes: true, ..Default::default() };
        let e = flash(&mut t, "vdz", &params(&p), &mut ui).unwrap_err();
        assert!(matches!(&e, FlashError::Client(ClientError::Safety(m)) if m.contains("reason: mounted")), "{:?}", e);
        assert_eq!(calls.lock().unwrap().len(), 2);
        let bad = "{\"error\":{\"code\":\"readback_mismatch\",\"message\":\"READ-BACK MISMATCH\"},\"next\":2097152}".to_string();
        let (mut t, _) = script(vec![Ok((Status::Io, bad))], vec![None], 8 << 20, "SER1");
        assert!(matches!(flash(&mut t, "vdz", &params(&p), &mut ui), Err(FlashError::Mismatch(m)) if m.contains("MISMATCH")));
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn progress_line_is_readable() {
        let p = Progress { total: 20 << 30, start: 0, acked: 5 << 30, data_sent: 4 << 30, zero_sent: 1 << 30, elapsed: Duration::from_secs(50), rate_mib: 102.4 };
        let l = progress_line(&p);
        assert!(l.contains("5.0 GiB / 20.0 GiB") && l.contains("25.0%") && l.contains("102.4 MiB/s") && l.contains("eta"), "{}", l);
    }
}
