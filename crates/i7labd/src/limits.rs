//! Per-host concurrency limits (PROTOCOL.md section 8: 4 exec, 1 block write test, 2 block read tests) and the
//! protocol/HTTP counters shown by `stats`. Owner: P6a.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// Counting gate; `try_acquire` returns a guard that releases on drop.
pub struct Gate {
    cur: Arc<AtomicUsize>,
    max: usize,
}

pub struct GateGuard(Arc<AtomicUsize>);

impl Drop for GateGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Gate {
    pub fn new(max: usize) -> Gate {
        Gate { cur: Arc::new(AtomicUsize::new(0)), max }
    }
    pub fn try_acquire(&self) -> Option<GateGuard> {
        let mut c = self.cur.load(Ordering::SeqCst);
        loop {
            if c >= self.max {
                return None;
            }
            match self.cur.compare_exchange(c, c + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Some(GateGuard(self.cur.clone())),
                Err(x) => c = x,
            }
        }
    }
    pub fn current(&self) -> usize {
        self.cur.load(Ordering::SeqCst)
    }
}

pub struct Limits {
    pub exec: Gate,
    pub blk_write: Gate,
    pub blk_read: Gate,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { exec: Gate::new(4), blk_write: Gate::new(1), blk_read: Gate::new(2) }
    }
}

impl Limits {
    /// The gate a command runs under, if it has one.
    pub fn gate_for(&self, cmd: &str) -> Option<&Gate> {
        match cmd {
            "exec" | "shell" => Some(&self.exec),
            "blk.write" => Some(&self.blk_write),
            "blk.read" | "blk.verify" => Some(&self.blk_read),
            _ => None,
        }
    }
    /// A destructive test is running: the beacon says `state=busy`.
    pub fn busy(&self) -> bool {
        self.blk_write.current() > 0
    }
}

/// Counters (relaxed atomics; they are statistics, not synchronisation).
#[derive(Default)]
pub struct Stats {
    pub frames_rx: AtomicU64,
    pub frames_tx: AtomicU64,
    pub ether_requests: AtomicU64,
    pub ether_dropped_busy: AtomicU64,
    pub http_requests: AtomicU64,
    pub http_auth_fail: AtomicU64,
    pub http_rejected: AtomicU64,
    pub beacons_tx: AtomicU64,
    pub probes_rx: AtomicU64,
    pub hints_applied: AtomicU64,
    pub hints_rejected: AtomicU64,
}

impl Stats {
    pub fn bump(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }
    pub fn add(c: &AtomicU64, n: u64) {
        c.fetch_add(n, Ordering::Relaxed);
    }
    pub fn to_json(&self, sessions: usize) -> String {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        let mut w = labproto::json::JsonWriter::new();
        w.begin_object();
        w.field_u64("v", 1);
        w.field_u64("frames_rx", g(&self.frames_rx));
        w.field_u64("frames_tx", g(&self.frames_tx));
        w.field_u64("ether_requests", g(&self.ether_requests));
        w.field_u64("ether_dropped_busy", g(&self.ether_dropped_busy));
        w.field_u64("http_requests", g(&self.http_requests));
        w.field_u64("http_auth_fail", g(&self.http_auth_fail));
        w.field_u64("http_rejected", g(&self.http_rejected));
        w.field_u64("beacons_tx", g(&self.beacons_tx));
        w.field_u64("probes_rx", g(&self.probes_rx));
        w.field_u64("hints_applied", g(&self.hints_applied));
        w.field_u64("hints_rejected", g(&self.hints_rejected));
        w.field_u64("sessions", sessions as u64);
        w.end_object();
        w.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gate_limits_and_releases() {
        let g = Gate::new(2);
        let a = g.try_acquire().unwrap();
        let _b = g.try_acquire().unwrap();
        assert!(g.try_acquire().is_none());
        drop(a);
        assert_eq!(g.current(), 1);
        assert!(g.try_acquire().is_some());
    }
    #[test]
    fn gates_by_command() {
        let l = Limits::default();
        assert!(l.gate_for("exec").is_some() && l.gate_for("ping").is_none());
        let _w = l.blk_write.try_acquire().unwrap();
        assert!(l.busy() && l.blk_write.try_acquire().is_none());
    }
}
