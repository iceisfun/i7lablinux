//! Fragmentation, reassembly, ACK/SACK and retransmission timing (PROTOCOL.md section 6).
//! Transport independent; time is passed in so tests are deterministic. Owner: P1.
//!
//! Three pieces, all sans-IO:
//! * `Reassembler`: one fixed-length message, eager buffer (kept for the contract and simple users).
//! * `StreamRx`: the receiver the session engine uses. In-order delivery with a bounded out-of-order store
//!   (never more than `window * frag` bytes, fragments further ahead are dropped, not buffered).
//! * `SendWindow` / `TxStream`: sender in-flight table, Jacobson/Karels RTO, SACK driven fast retransmit.
//!
//! Clarification of PROTOCOL.md 6.1: fragments of a fixed-length message (`Aligned`) are exactly `frag` bytes
//! except the last. Fragments of an unbounded stream (stdout, stdin, file chunks) may be shorter than `frag`
//! (output appears as it is produced, one keystroke is one frame); the receiver then identifies them by byte
//! offset only and SACK bit i means "a fragment starts at next + (i+1)*frag".

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use crate::frame::FrameError;

/// Reassembles one (req_id, chan) message of known length.
pub struct Reassembler {
    msg_len: u32,
    frag: u16,
    buf: Vec<u8>,
    have: Vec<bool>,
}

impl Reassembler {
    pub fn new(msg_len: u32, frag: u16, limit: u32) -> Result<Reassembler, FrameError> {
        if msg_len > limit {
            return Err(FrameError::TooBig);
        }
        if frag == 0 {
            return Err(FrameError::BadLength);
        }
        let n = (msg_len as usize).div_ceil(frag as usize).max(1);
        Ok(Reassembler { msg_len, frag, buf: vec![0; msg_len as usize], have: vec![false; n] })
    }

    pub fn insert(&mut self, off: u32, data: &[u8], fin: bool) -> Result<(), FrameError> {
        let end = off as u64 + data.len() as u64;
        if end > self.msg_len as u64 {
            return Err(FrameError::TooBig);
        }
        if off % self.frag as u32 != 0 {
            return Err(FrameError::Misaligned);
        }
        if !fin && data.len() != self.frag as usize {
            return Err(FrameError::BadLength);
        }
        let idx = (off / self.frag as u32) as usize;
        if idx < self.have.len() && !self.have[idx] {
            self.buf[off as usize..end as usize].copy_from_slice(data);
            self.have[idx] = true;
        }
        Ok(())
    }

    pub fn next_expected(&self) -> u32 {
        let first_missing = self.have.iter().position(|h| !h).unwrap_or(self.have.len());
        ((first_missing as u64 * self.frag as u64).min(self.msg_len as u64)) as u32
    }

    /// bit i set = fragment at next_expected + (i+1)*frag received
    pub fn sack_bitmap(&self) -> u64 {
        let base = (self.next_expected() / self.frag as u32) as usize;
        let mut m = 0u64;
        for i in 0..64 {
            if self.have.get(base + 1 + i).copied().unwrap_or(false) {
                m |= 1 << i;
            }
        }
        m
    }

    pub fn complete(&self) -> bool {
        self.have.iter().all(|h| *h)
    }

    pub fn take(self) -> Vec<u8> {
        self.buf
    }
}

/// Retransmissions of one fragment before the stream is declared dead (PROTOCOL 6.3).
pub const MAX_RETRIES: u8 = 8;
/// Hard ceiling of the frame window (PROTOCOL 6.3).
pub const MAX_WINDOW: u16 = 64;
/// Frames sent per `TxStream::poll` call (pacing burst, PROTOCOL 6.3).
pub const BURST: usize = 16;
const RTO_INIT: Duration = Duration::from_millis(250);
const RTO_MIN: Duration = Duration::from_millis(100);
const RTO_MAX: Duration = Duration::from_secs(2);
/// A retransmission timer doubles per retry up to this.
const BACKOFF_CAP: Duration = Duration::from_secs(4);

struct Seg {
    len: u16,
    fin: bool,
    sent_at: Instant,
    retries: u8,
    sacked: bool,
    fast: bool,
}

/// In-flight table of one outgoing stream: which fragments are unacknowledged, when to resend them.
pub struct SendWindow {
    frag: u16,
    win: u16,
    srtt: Option<Duration>,
    rttvar: Duration,
    segs: BTreeMap<u32, Seg>,
    acked: u32,
    last_fast: Option<Instant>,
    dead: bool,
}

impl SendWindow {
    pub fn new(frag: u16, win: u16) -> SendWindow {
        SendWindow { frag, win: win.clamp(1, MAX_WINDOW), srtt: None, rttvar: Duration::ZERO, segs: BTreeMap::new(), acked: 0, last_fast: None, dead: false }
    }

    /// Base RTO: 250 ms until the first sample, then clamp(srtt + 4 * rttvar, 100 ms, 2 s).
    pub fn rto(&self) -> Duration {
        match self.srtt {
            None => RTO_INIT,
            Some(s) => (s + self.rttvar * 4).clamp(RTO_MIN, RTO_MAX),
        }
    }

    fn timeout(&self, retries: u8) -> Duration {
        (self.rto() * (1u32 << retries.min(6))).min(BACKOFF_CAP)
    }

    pub fn frag(&self) -> u16 {
        self.frag
    }
    pub fn window(&self) -> u16 {
        self.win
    }
    pub fn in_flight(&self) -> usize {
        self.segs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.segs.is_empty()
    }
    pub fn can_send(&self) -> bool {
        !self.dead && self.segs.len() < self.win as usize
    }
    /// Highest cumulative acknowledgement seen.
    pub fn acked(&self) -> u32 {
        self.acked
    }
    /// A fragment used up its retries: the stream and session are dead (PROTOCOL 6.3).
    pub fn dead(&self) -> bool {
        self.dead
    }
    pub fn seg(&self, off: u32) -> Option<(u16, bool)> {
        self.segs.get(&off).map(|s| (s.len, s.fin))
    }

    /// Record a first transmission of fragment `off`.
    pub fn on_sent(&mut self, off: u32, len: u16, fin: bool, now: Instant) {
        self.segs.insert(off, Seg { len, fin, sent_at: now, retries: 0, sacked: false, fast: false });
    }

    /// Cumulative ACK (`next` = next expected byte), SACK bitmap and the peer's window. `fin_done` is the FIN
    /// flag of the ACK frame: the receiver has the whole stream including its end, so a zero-length FIN
    /// fragment (which `next` alone cannot acknowledge) is acknowledged too.
    pub fn on_ack_full(&mut self, next: u32, sack: u64, win: u16, fin_done: bool, now: Instant) {
        self.win = win.clamp(1, MAX_WINDOW);
        if fin_done {
            self.sample_rtt_from(self.segs.values().filter(|s| s.retries == 0).map(|s| s.sent_at).max(), now);
            self.segs.clear();
            return;
        }
        let mut sample: Option<Instant> = None;
        let acked: Vec<u32> = self.segs.iter().filter(|(o, s)| **o as u64 + s.len as u64 <= next as u64 && (s.len > 0)).map(|(o, _)| *o).collect();
        for o in acked {
            if let Some(s) = self.segs.remove(&o) {
                if s.retries == 0 {
                    sample = Some(sample.map_or(s.sent_at, |x| x.max(s.sent_at)));
                }
            }
        }
        if next > self.acked {
            self.acked = next;
        }
        self.sample_rtt_from(sample, now);
        // SACK: bit i = a fragment starting at next + (i+1)*frag arrived
        let mut highest_sacked: Option<u32> = None;
        for i in 0..64u32 {
            if sack & (1u64 << i) != 0 {
                let off = next as u64 + (i as u64 + 1) * self.frag as u64;
                if off <= u32::MAX as u64 {
                    if let Some(s) = self.segs.get_mut(&(off as u32)) {
                        s.sacked = true;
                        highest_sacked = Some(highest_sacked.map_or(off as u32, |h| h.max(off as u32)));
                    }
                }
            }
        }
        // fast retransmit: an unsacked fragment below a sacked one is a hole; once per RTT
        if let Some(h) = highest_sacked {
            let rtt = self.srtt.unwrap_or(RTO_MIN).max(RTO_MIN);
            if self.last_fast.map_or(true, |t| now.saturating_duration_since(t) >= rtt) {
                let mut any = false;
                for (o, s) in self.segs.iter_mut() {
                    if *o < h && !s.sacked && now.saturating_duration_since(s.sent_at) >= rtt {
                        s.fast = true;
                        any = true;
                    }
                }
                if any {
                    self.last_fast = Some(now);
                }
            }
        }
    }

    pub fn on_ack(&mut self, next: u32, sack: u64, win: u16, now: Instant) {
        self.on_ack_full(next, sack, win, false, now)
    }

    fn sample_rtt_from(&mut self, sent: Option<Instant>, now: Instant) {
        let Some(sent) = sent else { return };
        let r = now.saturating_duration_since(sent);
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(s) => {
                let diff = if s > r { s - r } else { r - s };
                self.rttvar = (self.rttvar * 3 + diff) / 4;
                self.srtt = Some((s * 7 + r) / 8);
            }
        }
    }

    /// Offsets that must be (re)sent now. The retry bookkeeping is done here: the caller just sends them.
    /// A fragment out of retries marks the window `dead()`.
    pub fn due(&mut self, now: Instant) -> Vec<u32> {
        let mut out = Vec::new();
        let rto = self.rto();
        let mut dead = false;
        for (o, s) in self.segs.iter_mut() {
            if s.sacked {
                continue;
            }
            let t = (rto * (1u32 << s.retries.min(6))).min(BACKOFF_CAP);
            let expired = now.saturating_duration_since(s.sent_at) >= t;
            if expired || s.fast {
                if s.retries >= MAX_RETRIES {
                    dead = true;
                    continue;
                }
                s.retries += 1;
                s.sent_at = now;
                s.fast = false;
                out.push(*o);
            }
        }
        if dead {
            self.dead = true;
        }
        out
    }

    /// When `due` next has something to do.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.segs.values().filter(|s| !s.sacked).map(|s| s.sent_at + self.timeout(s.retries)).min()
    }
}

/// One fragment to put on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutSeg {
    pub off: u32,
    pub data: Vec<u8>,
    pub fin: bool,
    pub retransmit: bool,
}

/// Sender of one stream: buffered bytes, in-flight fragments, FIN.
pub struct TxStream {
    win: SendWindow,
    pending: VecDeque<u8>,
    next_off: u32,
    data: BTreeMap<u32, Vec<u8>>,
    fin_queued: bool,
    fin_segmented: bool,
}

impl TxStream {
    pub fn new(frag: u16, win: u16) -> TxStream {
        TxStream { win: SendWindow::new(frag, win), pending: VecDeque::new(), next_off: 0, data: BTreeMap::new(), fin_queued: false, fin_segmented: false }
    }

    /// Queue bytes. Ignored after `finish`.
    pub fn push(&mut self, data: &[u8]) {
        if !self.fin_queued {
            self.pending.extend(data.iter().copied());
        }
    }

    /// Queue the end of the stream (FIN rides on the last fragment, or alone when nothing is left).
    pub fn finish(&mut self) {
        self.fin_queued = true;
    }

    pub fn is_finished_queued(&self) -> bool {
        self.fin_queued
    }

    /// Bytes buffered and not yet acknowledged (the backpressure measure).
    pub fn buffered(&self) -> usize {
        self.pending.len() + self.data.values().map(|d| d.len()).sum::<usize>()
    }

    pub fn has_unsent(&self) -> bool {
        !self.pending.is_empty() || (self.fin_queued && !self.fin_segmented)
    }

    /// Fragments to send now: due retransmissions first, then new fragments up to the window and the burst.
    pub fn poll(&mut self, now: Instant) -> Vec<OutSeg> {
        let mut out = Vec::new();
        for off in self.win.due(now) {
            if let (Some((_, fin)), Some(d)) = (self.win.seg(off), self.data.get(&off)) {
                out.push(OutSeg { off, data: d.clone(), fin, retransmit: true });
            }
        }
        let frag = self.win.frag() as usize;
        let mut new = 0;
        while new < BURST && self.win.can_send() && self.has_unsent() {
            let take = self.pending.len().min(frag);
            let chunk: Vec<u8> = self.pending.drain(..take).collect();
            let fin = self.fin_queued && self.pending.is_empty();
            let off = self.next_off;
            self.next_off = off.wrapping_add(take as u32);
            self.win.on_sent(off, take as u16, fin, now);
            if fin {
                self.fin_segmented = true;
            }
            self.data.insert(off, chunk.clone());
            out.push(OutSeg { off, data: chunk, fin, retransmit: false });
            new += 1;
        }
        out
    }

    pub fn on_ack(&mut self, next: u32, sack: u64, win: u16, fin_done: bool, now: Instant) {
        self.win.on_ack_full(next, sack, win, fin_done, now);
        let keep: Vec<u32> = self.win.segs.keys().copied().collect();
        self.data.retain(|o, _| keep.binary_search(o).is_ok());
    }

    /// FIN sent and everything acknowledged.
    pub fn done(&self) -> bool {
        self.fin_segmented && self.win.is_empty()
    }

    pub fn dead(&self) -> bool {
        self.win.dead()
    }

    pub fn window(&self) -> &SendWindow {
        &self.win
    }

    /// Earliest time `poll` has work: now when unsent data and window room exist, else the RTO deadline.
    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        let t = self.win.next_deadline();
        if self.has_unsent() && self.win.can_send() {
            Some(now)
        } else {
            t
        }
    }
}

/// What `StreamRx::insert` did with one fragment.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RxResult {
    /// newly contiguous bytes, in stream order
    pub data: Vec<u8>,
    /// the fragment arrived ahead of `next_expected` (a hole exists): ACK immediately
    pub out_of_order: bool,
    /// nothing new (already delivered, already stored, or dropped beyond the window)
    pub duplicate: bool,
    /// dropped because it lies beyond `next + window * frag` (not buffered)
    pub beyond_window: bool,
}

/// Receiver of one stream: delivers bytes in order, holds at most `window * frag` out-of-order bytes.
pub struct StreamRx {
    frag: u16,
    window: u16,
    aligned: bool,
    msg_len: Option<u32>,
    limit: u32,
    next: u32,
    ooo: BTreeMap<u32, Vec<u8>>,
    ooo_bytes: usize,
    fin_end: Option<u32>,
}

impl StreamRx {
    /// `msg_len`: declared length of a message (REQ/RESP body), `None` for an open stream. `limit`: hard cap of
    /// the total length (64 KiB REQ, 16 MiB RESP, 4 GiB-1 streams). A declared `msg_len` above `limit` fails.
    pub fn new(frag: u16, window: u16, limit: u32, msg_len: Option<u32>, aligned: bool) -> Result<StreamRx, FrameError> {
        if frag == 0 {
            return Err(FrameError::BadLength);
        }
        if msg_len.is_some_and(|m| m > limit) {
            return Err(FrameError::TooBig);
        }
        Ok(StreamRx { frag, window: window.clamp(1, MAX_WINDOW), aligned, msg_len, limit, next: 0, ooo: BTreeMap::new(), ooo_bytes: 0, fin_end: None })
    }

    pub fn next_expected(&self) -> u32 {
        self.next
    }
    /// The declared message length, if this stream is a fixed-length message.
    pub fn declared_len(&self) -> Option<u32> {
        self.msg_len
    }
    /// bytes held out of order (never more than `window * frag`)
    pub fn held_bytes(&self) -> usize {
        self.ooo_bytes
    }
    pub fn max_held(&self) -> usize {
        self.window as usize * self.frag as usize
    }
    pub fn complete(&self) -> bool {
        self.fin_end == Some(self.next)
    }
    /// Remaining window in frames to advertise in an ACK (at least 1).
    pub fn advertised_window(&self) -> u16 {
        self.window.saturating_sub(self.ooo.len().min(u16::MAX as usize) as u16).max(1)
    }

    pub fn sack_bitmap(&self) -> u64 {
        let mut m = 0u64;
        for k in self.ooo.keys() {
            let d = (*k - self.next) as u64;
            let f = self.frag as u64;
            if d % f == 0 && (1..=64).contains(&(d / f)) {
                m |= 1u64 << (d / f - 1);
            }
        }
        m
    }

    pub fn insert(&mut self, off: u32, data: &[u8], fin: bool) -> Result<RxResult, FrameError> {
        let end = off as u64 + data.len() as u64;
        if data.len() > self.frag as usize {
            return Err(FrameError::BadLength);
        }
        if end > self.limit as u64 {
            return Err(FrameError::TooBig);
        }
        if let Some(m) = self.msg_len {
            if end > m as u64 {
                return Err(FrameError::TooBig);
            }
            if fin && end != m as u64 {
                return Err(FrameError::BadLength);
            }
        }
        if self.aligned {
            if off % self.frag as u32 != 0 {
                return Err(FrameError::Misaligned);
            }
            if !fin && data.len() != self.frag as usize {
                return Err(FrameError::BadLength);
            }
        }
        if fin {
            match self.fin_end {
                Some(e) if e as u64 != end => return Err(FrameError::BadLength),
                _ => self.fin_end = Some(end as u32),
            }
        }
        if let Some(e) = self.fin_end {
            if end > e as u64 {
                return Err(FrameError::BadLength);
            }
        }
        let mut res = RxResult::default();
        if end <= self.next as u64 && !(data.is_empty() && fin && off == self.next) {
            res.duplicate = true;
            return Ok(res);
        }
        if off > self.next {
            res.out_of_order = true;
            if off as u64 >= self.next as u64 + self.max_held() as u64 || self.ooo_bytes + data.len() > self.max_held() {
                res.beyond_window = true;
                res.duplicate = true;
                return Ok(res);
            }
            if data.is_empty() || self.ooo.contains_key(&off) {
                res.duplicate = true;
                return Ok(res);
            }
            self.ooo_bytes += data.len();
            self.ooo.insert(off, data.to_vec());
            return Ok(res);
        }
        // off <= next < end (or an empty FIN at next)
        let skip = (self.next - off) as usize;
        res.data.extend_from_slice(&data[skip.min(data.len())..]);
        self.next = end.max(self.next as u64) as u32;
        while let Some((&k, _)) = self.ooo.iter().next() {
            if k > self.next {
                break;
            }
            let d = self.ooo.remove(&k).unwrap();
            self.ooo_bytes -= d.len();
            let e = k as u64 + d.len() as u64;
            if e > self.next as u64 {
                res.data.extend_from_slice(&d[(self.next - k) as usize..]);
                self.next = e as u32;
            }
        }
        res.out_of_order = !self.ooo.is_empty();
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reassemble_out_of_order() {
        let mut r = Reassembler::new(10, 4, 1 << 20).unwrap();
        r.insert(8, b"ij", true).unwrap();
        assert_eq!(r.next_expected(), 0);
        assert_eq!(r.sack_bitmap(), 0b10);
        r.insert(0, b"abcd", false).unwrap();
        r.insert(4, b"efgh", false).unwrap();
        assert!(r.complete());
        assert_eq!(r.take(), b"abcdefghij");
        assert!(Reassembler::new(10, 4, 5).is_err());
    }

    /// xorshift64*, seeded: deterministic fuzz-ish tests.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545F4914F6CDD1D)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    #[test]
    fn reassembler_rejects_bad_fragments() {
        let mut r = Reassembler::new(10, 4, 1 << 20).unwrap();
        assert_eq!(r.insert(2, b"ab", false), Err(FrameError::Misaligned));
        assert_eq!(r.insert(8, b"ijk", true), Err(FrameError::TooBig));
        assert_eq!(r.insert(0, b"ab", false), Err(FrameError::BadLength));
        assert!(Reassembler::new(10, 0, 100).is_err());
        // duplicates: first wins
        r.insert(0, b"abcd", false).unwrap();
        r.insert(0, b"WXYZ", false).unwrap();
        r.insert(4, b"efgh", false).unwrap();
        r.insert(8, b"ij", true).unwrap();
        assert_eq!(r.take(), b"abcdefghij");
    }

    #[test]
    fn stream_rx_in_order_and_holes() {
        let mut rx = StreamRx::new(4, 4, 1000, None, false).unwrap();
        let r = rx.insert(4, b"efgh", false).unwrap();
        assert!(r.out_of_order && r.data.is_empty());
        assert_eq!(rx.sack_bitmap(), 1);
        let r = rx.insert(0, b"abcd", false).unwrap();
        assert_eq!(r.data, b"abcdefgh");
        assert_eq!(rx.next_expected(), 8);
        assert!(rx.insert(0, b"abcd", false).unwrap().duplicate);
        assert!(!rx.complete());
        let r = rx.insert(8, b"ij", true).unwrap();
        assert_eq!(r.data, b"ij");
        assert!(rx.complete());
        // empty FIN
        let mut rx = StreamRx::new(4, 4, 1000, None, false).unwrap();
        rx.insert(0, b"ab", false).unwrap();
        let r = rx.insert(2, b"", true).unwrap();
        assert!(r.data.is_empty() && rx.complete());
    }

    #[test]
    fn stream_rx_memory_cap_under_flood() {
        // one hole at 0, then a flood of fragments far ahead and inside the window
        let mut rx = StreamRx::new(100, 8, u32::MAX, None, true).unwrap();
        let mut rng = Rng(7);
        for _ in 0..10_000 {
            let off = (rng.below(5000) as u32 + 1) * 100;
            let _ = rx.insert(off, &[0xAA; 100], false);
            assert!(rx.held_bytes() <= 8 * 100, "held {}", rx.held_bytes());
        }
        assert_eq!(rx.next_expected(), 0);
        // inside window: stored; beyond: dropped
        let mut rx = StreamRx::new(100, 8, u32::MAX, None, true).unwrap();
        assert!(!rx.insert(700, &[1; 100], false).unwrap().beyond_window);
        assert!(rx.insert(800, &[1; 100], false).unwrap().beyond_window);
    }

    #[test]
    fn stream_rx_limits_and_alignment() {
        assert!(StreamRx::new(100, 4, 50, Some(51), true).is_err());
        let mut m = StreamRx::new(100, 4, 1000, Some(250), true).unwrap();
        assert_eq!(m.insert(50, &[0; 100], false).err(), Some(FrameError::Misaligned));
        assert_eq!(m.insert(0, &[0; 50], false).err(), Some(FrameError::BadLength));
        assert_eq!(m.insert(200, &[0; 100], true).err(), Some(FrameError::TooBig));
        assert_eq!(m.insert(0, &[0; 101], false).err(), Some(FrameError::BadLength));
        assert_eq!(m.insert(100, &[0; 100], true).err(), Some(FrameError::BadLength)); // FIN must end at msg_len
        m.insert(0, &[1; 100], false).unwrap();
        m.insert(100, &[2; 100], false).unwrap();
        m.insert(200, &[3; 50], true).unwrap();
        assert!(m.complete());
        // two different FIN positions
        let mut s = StreamRx::new(100, 4, 1000, None, false).unwrap();
        s.insert(0, b"abc", true).unwrap();
        assert!(s.insert(0, b"abcd", true).is_err());
        assert!(s.insert(3, b"x", false).is_err());
    }

    #[test]
    fn send_window_rto_and_retry_limit() {
        let t0 = Instant::now();
        let mut w = SendWindow::new(100, 4);
        assert_eq!(w.rto(), Duration::from_millis(250));
        w.on_sent(0, 100, false, t0);
        assert!(w.due(t0 + Duration::from_millis(249)).is_empty());
        assert_eq!(w.due(t0 + Duration::from_millis(250)), vec![0]);
        // second timeout doubled: 500 ms after the resend
        let t1 = t0 + Duration::from_millis(250);
        assert!(w.due(t1 + Duration::from_millis(499)).is_empty());
        assert_eq!(w.due(t1 + Duration::from_millis(500)), vec![0]);
        // run out of retries
        let mut t = t1 + Duration::from_millis(500);
        for _ in 0..20 {
            t += Duration::from_secs(5);
            let _ = w.due(t);
        }
        assert!(w.dead());
        assert!(!w.can_send());
    }

    #[test]
    fn send_window_rtt_sampling_and_karn() {
        let t0 = Instant::now();
        let mut w = SendWindow::new(100, 4);
        w.on_sent(0, 100, false, t0);
        w.on_ack(100, 0, 16, t0 + Duration::from_millis(40));
        // srtt 40, rttvar 20 => rto = 120 ms
        assert_eq!(w.rto(), Duration::from_millis(120));
        assert!(w.is_empty());
        // retransmitted fragment gives no sample (Karn)
        w.on_sent(100, 100, false, t0 + Duration::from_millis(50));
        let _ = w.due(t0 + Duration::from_millis(400));
        let before = w.rto();
        w.on_ack(200, 0, 16, t0 + Duration::from_millis(900));
        assert_eq!(w.rto(), before);
        // clamp
        let mut c = SendWindow::new(100, 4);
        c.on_sent(0, 1, false, t0);
        c.on_ack(1, 0, 4, t0 + Duration::from_micros(10));
        assert_eq!(c.rto(), Duration::from_millis(100));
    }

    #[test]
    fn send_window_sack_fast_retransmit_once_per_rtt() {
        let t0 = Instant::now();
        let mut w = SendWindow::new(100, 16);
        for i in 0..5u32 {
            w.on_sent(i * 100, 100, false, t0);
        }
        // fragment 0 lost; 1, 2, 3 arrived (sack bits 0,1,2 = offsets next+100,+200,+300), 4 in flight
        let t = t0 + Duration::from_millis(150);
        w.on_ack(0, 0b111, 16, t);
        assert_eq!(w.due(t), vec![0]);
        assert!(w.due(t).is_empty(), "retransmitted fragment must wait for its timer");
        // sacked fragments are never resent by timer
        let late = t + Duration::from_secs(1);
        let d = w.due(late);
        assert!(!d.contains(&100) && !d.contains(&200) && !d.contains(&300));
    }

    /// TxStream -> lossy, reordering channel -> StreamRx; every byte arrives exactly once in order.
    fn run_transfer(seed: u64, loss_pct: u64, total: usize, frag: u16, window: u16) {
        let mut rng = Rng(seed);
        let payload: Vec<u8> = (0..total).map(|_| rng.next() as u8).collect();
        let t0 = Instant::now();
        let mut now = t0;
        let mut tx = TxStream::new(frag, window);
        tx.push(&payload);
        tx.finish();
        let mut rx = StreamRx::new(frag, window, u32::MAX, None, false).unwrap();
        let mut got = Vec::new();
        let mut net: Vec<(Instant, OutSeg)> = Vec::new();
        let mut acks: Vec<(Instant, (u32, u64, u16, bool))> = Vec::new();
        for _ in 0..200_000 {
            now += Duration::from_millis(5);
            for s in tx.poll(now) {
                if rng.below(100) >= loss_pct {
                    let delay = Duration::from_millis(5 + rng.below(40));
                    net.push((now + delay, s));
                }
            }
            let mut i = 0;
            while i < net.len() {
                if net[i].0 <= now {
                    let (_, s) = net.swap_remove(i);
                    let r = rx.insert(s.off, &s.data, s.fin).unwrap();
                    got.extend_from_slice(&r.data);
                    assert!(rx.held_bytes() <= rx.max_held());
                    if rng.below(100) >= loss_pct {
                        acks.push((now + Duration::from_millis(5 + rng.below(20)), (rx.next_expected(), rx.sack_bitmap(), rx.advertised_window(), rx.complete())));
                    }
                } else {
                    i += 1;
                }
            }
            let mut i = 0;
            while i < acks.len() {
                if acks[i].0 <= now {
                    let (_, a) = acks.swap_remove(i);
                    tx.on_ack(a.0, a.1, a.2, a.3, now);
                } else {
                    i += 1;
                }
            }
            if tx.done() && rx.complete() {
                break;
            }
            assert!(!tx.dead(), "seed {} dead", seed);
        }
        assert!(rx.complete(), "seed {} loss {}", seed, loss_pct);
        assert_eq!(got.len(), payload.len());
        assert!(got == payload, "seed {} corrupt", seed);
    }

    #[test]
    fn tx_rx_property_loss_and_reorder() {
        for seed in 1..=12u64 {
            let loss = [0, 5, 10, 20][(seed % 4) as usize];
            let total = [0usize, 1, 1399, 1400, 1401, 50_000, 300_000][(seed % 7) as usize];
            run_transfer(seed * 0x9E37, loss, total, 1400, 16);
        }
    }
}
