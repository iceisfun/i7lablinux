//! Per-session, per-direction counter window (PROTOCOL.md 4.3). Owner: P1.

#[derive(Clone, Debug, Default)]
pub struct ReplayWindow {
    max: u64,
    bits: u64,
}

impl ReplayWindow {
    pub fn new() -> Self {
        ReplayWindow { max: 0, bits: 0 }
    }

    /// Cheap pre-check before the HMAC: is `ctr` new or inside the 64-frame window and unseen?
    pub fn check(&self, ctr: u64) -> bool {
        if ctr == 0 {
            return false;
        }
        if ctr > self.max {
            return true;
        }
        let back = self.max - ctr;
        back < 64 && self.bits & (1u64 << back) == 0
    }

    /// Record `ctr` as seen; call only after the tag verified.
    pub fn commit(&mut self, ctr: u64) {
        if ctr > self.max {
            let shift = ctr - self.max;
            self.bits = if shift >= 64 { 0 } else { self.bits << shift };
            self.bits |= 1;
            self.max = ctr;
        } else {
            let back = self.max - ctr;
            if back < 64 {
                self.bits |= 1u64 << back;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn window() {
        let mut w = ReplayWindow::new();
        assert!(!w.check(0));
        for c in [1, 3, 2] {
            assert!(w.check(c));
            w.commit(c);
            assert!(!w.check(c));
        }
        w.commit(100);
        assert!(!w.check(36));
        assert!(w.check(37));
    }

    #[test]
    fn window_table() {
        let mut w = ReplayWindow::new();
        // (ctr, expect check(), commit?)
        let steps: &[(u64, bool, bool)] = &[
            (0, false, false), (1, true, true), (1, false, false), (5, true, true), (3, true, true), (3, false, false),
            (2, true, true), (2, false, false), (64, true, true), (1, false, false), (4, true, false), (65, true, true),
            (2, false, false), (3, false, false), (4, true, false), (200, true, true), (136, false, false),
            (137, true, true), (137, false, false), (u64::MAX, true, true), (u64::MAX, false, false),
            (u64::MAX - 63, true, false), (u64::MAX - 64, false, false),
        ];
        for (i, (ctr, ok, commit)) in steps.iter().enumerate() {
            assert_eq!(w.check(*ctr), *ok, "step {} ctr {}", i, ctr);
            if *commit {
                w.commit(*ctr);
            }
        }
    }

    #[test]
    fn window_matches_reference_model() {
        // a reference implementation with a HashSet: accepts ctr iff new and not older than max-63
        let mut rng = 0x1234_5678_9abc_def1u64;
        let mut w = ReplayWindow::new();
        let mut seen = std::collections::HashSet::new();
        let mut max = 0u64;
        for _ in 0..50_000 {
            rng ^= rng >> 12;
            rng ^= rng << 25;
            rng ^= rng >> 27;
            let r = rng.wrapping_mul(0x2545F4914F6CDD1D);
            let ctr = if r % 5 == 0 { max + 1 + (r >> 8) % 100 } else { max.saturating_sub((r >> 8) % 90) };
            let model = ctr != 0 && !seen.contains(&ctr) && (ctr > max || max - ctr < 64);
            assert_eq!(w.check(ctr), model, "ctr {} max {}", ctr, max);
            if model {
                w.commit(ctr);
                seen.insert(ctr);
                max = max.max(ctr);
            }
        }
    }
}
