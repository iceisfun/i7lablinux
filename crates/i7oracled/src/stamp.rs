//! High-resolution timestamps and UTC formatting. Pure formatting, platform clock behind `Stamp::now`.

/// Everything the recorder needs to see a clock jump across a suspend: three clocks that disagree while asleep.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Stamp {
    /// QueryPerformanceCounter ticks.
    pub qpc: u64,
    pub qpc_hz: u64,
    /// GetSystemTimePreciseAsFileTime: 100 ns units since 1601-01-01 UTC (wall clock, steps on resume).
    pub wall_100ns: u64,
    /// GetTickCount64 in ms.
    pub tick_ms: u64,
    /// QueryUnbiasedInterruptTime: 100 ns, does NOT count time asleep or hibernated.
    pub unbiased_100ns: u64,
    /// QueryInterruptTime: 100 ns, DOES count time asleep (0 when unavailable).
    pub interrupt_100ns: u64,
}

pub const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

impl Stamp {
    #[cfg(windows)]
    pub fn now() -> Stamp {
        crate::win::stamp_now()
    }

    #[cfg(not(windows))]
    pub fn now() -> Stamp {
        use std::sync::OnceLock;
        use std::time::{Instant, SystemTime, UNIX_EPOCH};
        static T0: OnceLock<Instant> = OnceLock::new();
        let t0 = *T0.get_or_init(Instant::now);
        let el = t0.elapsed();
        let unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        Stamp {
            qpc: el.as_nanos() as u64,
            qpc_hz: 1_000_000_000,
            wall_100ns: FILETIME_UNIX_EPOCH + (unix.as_nanos() / 100) as u64,
            tick_ms: el.as_millis() as u64,
            unbiased_100ns: (el.as_nanos() / 100) as u64,
            interrupt_100ns: (el.as_nanos() / 100) as u64,
        }
    }

    /// Fields (no braces) shared by every log record.
    pub fn json_fields(&self) -> String {
        format!(
            "\"utc\":\"{}\",\"wall_100ns\":{},\"qpc\":{},\"qpc_hz\":{},\"tick_ms\":{},\"unb_100ns\":{},\"int_100ns\":{}",
            filetime_to_utc(self.wall_100ns),
            self.wall_100ns,
            self.qpc,
            self.qpc_hz,
            self.tick_ms,
            self.unbiased_100ns,
            self.interrupt_100ns
        )
    }

    pub fn qpc_ms(&self) -> f64 {
        if self.qpc_hz == 0 {
            0.0
        } else {
            self.qpc as f64 * 1000.0 / self.qpc_hz as f64
        }
    }
}

/// Clock deltas between two stamps, in ms. `wall_ms` can be negative (clock stepped back).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Jump {
    pub wall_ms: f64,
    pub qpc_ms: f64,
    pub tick_ms: f64,
    pub unbiased_ms: f64,
    pub interrupt_ms: f64,
}

pub fn jump(prev: &Stamp, now: &Stamp) -> Jump {
    Jump {
        wall_ms: (now.wall_100ns as f64 - prev.wall_100ns as f64) / 10_000.0,
        qpc_ms: now.qpc_ms() - prev.qpc_ms(),
        tick_ms: now.tick_ms as f64 - prev.tick_ms as f64,
        unbiased_ms: (now.unbiased_100ns as f64 - prev.unbiased_100ns as f64) / 10_000.0,
        interrupt_ms: (now.interrupt_100ns as f64 - prev.interrupt_100ns as f64) / 10_000.0,
    }
}

impl Jump {
    /// True when the clocks disagree with each other or with the 1 s sampling period by more than `tol_ms`:
    /// the signature of a suspend (wall and interrupt time advance, unbiased/QPC may not) or a clock step.
    pub fn is_gap(&self, expected_ms: f64, tol_ms: f64) -> bool {
        (self.wall_ms - self.qpc_ms).abs() > tol_ms
            || (self.wall_ms - self.unbiased_ms).abs() > tol_ms
            || (self.wall_ms - expected_ms).abs() > tol_ms + expected_ms
            || self.wall_ms < 0.0
    }

    pub fn json(&self) -> String {
        format!(
            "{{\"wall_ms\":{:.3},\"qpc_ms\":{:.3},\"tick_ms\":{:.0},\"unbiased_ms\":{:.3},\"interrupt_ms\":{:.3}}}",
            self.wall_ms, self.qpc_ms, self.tick_ms, self.unbiased_ms, self.interrupt_ms
        )
    }
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

struct Civil {
    y: i64,
    mo: u32,
    d: u32,
    h: u32,
    mi: u32,
    s: u32,
    frac_100ns: u32,
}

fn civil(ft: u64) -> Civil {
    let secs = ft / 10_000_000;
    let frac = (ft % 10_000_000) as u32;
    let days = (secs / 86_400) as i64 - 134_774; // 1601-01-01 .. 1970-01-01
    let rem = (secs % 86_400) as u32;
    let (y, mo, d) = civil_from_days(days);
    Civil { y, mo, d, h: rem / 3600, mi: rem % 3600 / 60, s: rem % 60, frac_100ns: frac }
}

/// `2026-11-12T10:20:30.1234567Z`
pub fn filetime_to_utc(ft: u64) -> String {
    let c = civil(ft);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:07}Z", c.y, c.mo, c.d, c.h, c.mi, c.s, c.frac_100ns)
}

/// `20261112T102030Z`, safe in a Windows file name.
pub fn filetime_compact(ft: u64) -> String {
    let c = civil(ft);
    format!("{:04}{:02}{:02}T{:02}{:02}{:02}Z", c.y, c.mo, c.d, c.h, c.mi, c.s)
}

/// `2026-11-12T10:20:30` (no zone), for scheduled-task XML in local time given a filetime already shifted by the bias.
pub fn filetime_to_iso_local(ft: u64) -> String {
    let c = civil(ft);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}", c.y, c.mo, c.d, c.h, c.mi, c.s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_formats() {
        assert_eq!(filetime_to_utc(FILETIME_UNIX_EPOCH), "1970-01-01T00:00:00.0000000Z");
        // 2026-11-12T10:20:30.5Z
        let ft = FILETIME_UNIX_EPOCH + 1_794_478_830 * 10_000_000 + 5_000_000;
        assert_eq!(filetime_to_utc(ft), "2026-11-12T10:20:30.5000000Z");
        assert_eq!(filetime_compact(ft), "20261112T102030Z");
        // leap day
        let ft = FILETIME_UNIX_EPOCH + 1_709_164_800 * 10_000_000; // 2024-02-29
        assert_eq!(filetime_compact(ft), "20240229T000000Z");
    }

    #[test]
    fn suspend_gap_detected() {
        let a = Stamp { qpc: 0, qpc_hz: 10_000_000, wall_100ns: 1_000_000_000, tick_ms: 0, unbiased_100ns: 0, interrupt_100ns: 0 };
        let steady = Stamp { qpc: 10_000_000, wall_100ns: 1_000_000_000 + 10_000_000, tick_ms: 1000, unbiased_100ns: 10_000_000, interrupt_100ns: 10_000_000, ..a };
        assert!(!jump(&a, &steady).is_gap(1000.0, 500.0));
        // 60 s asleep: wall advances 61 s, QPC/unbiased only 1 s
        let slept = Stamp { qpc: 10_000_000, wall_100ns: 1_000_000_000 + 610_000_000, tick_ms: 1000, unbiased_100ns: 10_000_000, interrupt_100ns: 610_000_000, ..a };
        let j = jump(&a, &slept);
        assert!(j.is_gap(1000.0, 500.0));
        assert!((j.wall_ms - 61_000.0).abs() < 1e-6);
        assert!(j.json().contains("\"wall_ms\":61000.000"));
    }

    #[test]
    fn fields_are_json() {
        let s = Stamp::now();
        let j = format!("{{{}}}", s.json_fields());
        assert!(crate::json::parse(&j, &crate::json::Limits::default()).is_ok());
    }
}
