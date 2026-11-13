//! Small in-RAM line rings for `logs --daemon` / `--http` (and the daemon's own messages). Owner: P6a.

use std::collections::VecDeque;
use std::sync::Mutex;

pub struct LogRing {
    cap: usize,
    inner: Mutex<(u64, VecDeque<String>)>,
}

impl LogRing {
    pub fn new(cap: usize) -> LogRing {
        LogRing { cap, inner: Mutex::new((0, VecDeque::new())) }
    }

    pub fn push(&self, line: String) {
        let mut g = self.inner.lock().unwrap();
        if g.1.len() >= self.cap {
            g.1.pop_front();
        }
        g.1.push_back(line);
        g.0 += 1;
    }

    /// Sequence number the NEXT pushed line gets.
    pub fn next_seq(&self) -> u64 {
        self.inner.lock().unwrap().0
    }

    /// Last `n` lines and the next sequence number.
    pub fn tail(&self, n: usize) -> (Vec<String>, u64) {
        let g = self.inner.lock().unwrap();
        let skip = g.1.len().saturating_sub(n);
        (g.1.iter().skip(skip).cloned().collect(), g.0)
    }

    /// Lines pushed at or after `seq` (those already evicted are lost) and the next sequence number.
    pub fn since(&self, seq: u64) -> (Vec<String>, u64) {
        let g = self.inner.lock().unwrap();
        let first = g.0 - g.1.len() as u64;
        let skip = seq.saturating_sub(first) as usize;
        (g.1.iter().skip(skip).cloned().collect(), g.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ring_tail_since_and_eviction() {
        let r = LogRing::new(3);
        for i in 0..5 {
            r.push(format!("l{}", i));
        }
        let (t, next) = r.tail(2);
        assert_eq!(t, vec!["l3", "l4"]);
        assert_eq!(next, 5);
        assert_eq!(r.since(4).0, vec!["l4"]);
        assert_eq!(r.since(0).0, vec!["l2", "l3", "l4"], "evicted lines are lost, not an error");
        assert!(r.since(5).0.is_empty());
    }
}
