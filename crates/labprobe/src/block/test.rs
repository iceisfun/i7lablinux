//! Block test engine: read (sequential / random) / write+verify / verify, with a seeded position-dependent
//! pattern (a function of seed, absolute device offset and generation), direct I/O, throughput and latency,
//! resumable regions and a progress callback. Owner: P4.
//!
//! The write path exists only behind a `WriteGuard`: `Write` mode without a guard for the same device returns
//! `Unsupported` before the device is touched, and the engine writes through `guard.file()` (the O_EXCL fd that
//! backed the gate decision), never through a second open.

use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use labproto::json::{JsonWriter, ToJson};

use crate::ctx::{ProbeCtx, ProbeError};

use super::guard::WriteGuard;
use super::ioctl::{self, AlignedBuf};

/// Per region, stop after this many I/O errors (a dying device would otherwise take hours to fail).
pub const MAX_IO_ERRORS: u64 = 64;
const MAX_BS: u32 = 64 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestMode {
    Read,
    Write,
    Verify,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pattern {
    /// w = splitmix64(seed ^ (offset / 8)) for each 8-byte word at absolute device offset (generation 0)
    Seeded(u64),
    /// as `Seeded`, with a generation number mixed in: w = splitmix64(seed ^ splitmix64(gen) ^ (offset / 8)).
    /// `Generation(s, 0)` equals `Seeded(s)`. A re-run with a new generation cannot be satisfied by stale data.
    Generation(u64, u64),
    Zeros,
    Ones,
    Aa55,
}

pub fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl Pattern {
    /// Fill `buf` with the pattern for absolute device offset `off` (8-byte aligned).
    pub fn fill(&self, off: u64, buf: &mut [u8]) {
        for (i, chunk) in buf.chunks_mut(8).enumerate() {
            let o = off + (i as u64) * 8;
            let w = match self {
                Pattern::Seeded(s) => splitmix64(s ^ (o / 8)),
                Pattern::Generation(s, g) => splitmix64(s ^ if *g == 0 { 0 } else { splitmix64(*g) } ^ (o / 8)),
                Pattern::Zeros => 0,
                Pattern::Ones => u64::MAX,
                Pattern::Aa55 => if (o / 512) % 2 == 0 { 0xAAAA_AAAA_AAAA_AAAA } else { 0x5555_5555_5555_5555 },
            };
            let b = w.to_le_bytes();
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Region {
    pub name: String,
    pub offset: u64,
    pub len: u64,
}

#[derive(Clone, Debug)]
pub struct TestSpec {
    pub dev: String,
    pub mode: TestMode,
    /// empty = `default_regions(size, 256)`
    pub regions: Vec<Region>,
    /// I/O size in bytes: a multiple of the logical block size, at most 64 MiB
    pub bs: u32,
    pub direct: bool,
    pub pattern: Pattern,
    /// Read / Verify: sample `len / bs` random block-aligned positions instead of a sequential sweep
    /// (writes are always sequential)
    pub random: bool,
    /// bytes already done per region (from a previous `RegionResult::done_bytes`); sequential access only
    pub resume_from: Vec<u64>,
    /// minimum milliseconds between progress callbacks (0 = after every I/O)
    pub progress_ms: u64,
}

impl TestSpec {
    pub fn new(dev: &str, mode: TestMode, pattern: Pattern) -> TestSpec {
        TestSpec { dev: dev.into(), mode, regions: vec![], bs: 1 << 20, direct: true, pattern, random: false, resume_from: vec![], progress_ms: 200 }
    }

    /// `mb` MiB split into start / mid / end regions, each aligned to 1 MiB and inside the device.
    pub fn default_regions(size_bytes: u64, mb: u64) -> Vec<Region> {
        const MIB: u64 = 1 << 20;
        let per = (mb * MIB / 3).max(MIB) / MIB * MIB;
        if size_bytes < per * 3 {
            return vec![Region { name: "all".into(), offset: 0, len: size_bytes / MIB * MIB }];
        }
        let mid = (size_bytes / 2 - per / 2) / MIB * MIB;
        let end = (size_bytes - per) / MIB * MIB;
        vec![
            Region { name: "start".into(), offset: 0, len: per },
            Region { name: "mid".into(), offset: mid, len: per },
            Region { name: "end".into(), offset: end, len: per },
        ]
    }
}

#[derive(Clone, Debug, Default)]
pub struct Progress {
    pub region: String,
    /// "read" | "write" | "verify"
    pub phase: String,
    pub done_bytes: u64,
    pub total_bytes: u64,
    pub mib_s: f64,
}

#[derive(Clone, Debug, Default)]
pub struct RegionResult {
    pub name: String,
    pub offset: u64,
    pub len: u64,
    /// bytes finished in the main phase (write for Write, read for Read/Verify); pass back as `resume_from`
    pub done_bytes: u64,
    /// throughput of the main phase (write for Write mode)
    pub mib_s: f64,
    /// Write mode: throughput of the read-back pass
    pub verify_mib_s: Option<f64>,
    pub lat_max_us: u64,
    pub lat_avg_us: u64,
    pub io_errors: u64,
    /// mismatching 8-byte words
    pub mismatches: u64,
    /// absolute device offset of the first differing byte
    pub first_mismatch: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct TestReport {
    pub dev: String,
    pub serial: Option<String>,
    pub mode: TestMode,
    pub seed: Option<u64>,
    pub generation: Option<u64>,
    pub bs: u32,
    pub random: bool,
    pub regions: Vec<RegionResult>,
    /// false when cancelled or a region gave up after `MAX_IO_ERRORS`
    pub complete: bool,
    pub ok: bool,
}

impl Pattern {
    pub fn seed(&self) -> Option<u64> {
        match self {
            Pattern::Seeded(s) | Pattern::Generation(s, _) => Some(*s),
            _ => None,
        }
    }
    pub fn generation(&self) -> Option<u64> {
        match self {
            Pattern::Seeded(_) => Some(0),
            Pattern::Generation(_, g) => Some(*g),
            _ => None,
        }
    }
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// Mutable state of one pass over one region.
struct Pass<'a> {
    file: &'a File,
    block: u64,
    bs: u64,
    direct_pattern: Pattern,
    progress: &'a mut dyn FnMut(&Progress),
    cancel: &'a AtomicBool,
    progress_ms: u64,
    region: &'a Region,
    phase: &'static str,
    res: RegionResult,
    lat_sum_us: u128,
    ios: u64,
    cancelled: bool,
    gave_up: bool,
    last_report: Instant,
    started: Instant,
}

impl<'a> Pass<'a> {
    fn report(&mut self, done: u64, force: bool) {
        if force || self.last_report.elapsed().as_millis() >= self.progress_ms as u128 {
            self.last_report = Instant::now();
            let secs = self.started.elapsed().as_secs_f64().max(1e-9);
            (self.progress)(&Progress {
                region: self.region.name.clone(),
                phase: self.phase.to_string(),
                done_bytes: done,
                total_bytes: self.region.len,
                mib_s: done as f64 / (1 << 20) as f64 / secs,
            });
        }
    }

    fn note_io(&mut self, t: Instant) {
        let us = t.elapsed().as_micros();
        self.lat_sum_us += us;
        self.ios += 1;
        self.res.lat_max_us = self.res.lat_max_us.max(us.min(u64::MAX as u128) as u64);
    }

    fn io_error(&mut self) {
        self.res.io_errors += 1;
        if self.res.io_errors >= MAX_IO_ERRORS {
            self.gave_up = true;
        }
    }

    fn stop(&mut self) -> bool {
        if self.cancel.load(Ordering::Relaxed) {
            self.cancelled = true;
        }
        self.cancelled || self.gave_up
    }

    fn compare(&mut self, off: u64, got: &[u8], want: &[u8]) {
        if got == want {
            return;
        }
        for (i, (g, w)) in got.chunks(8).zip(want.chunks(8)).enumerate() {
            if g != w {
                self.res.mismatches += 1;
                if self.res.first_mismatch.is_none() {
                    let b = g.iter().zip(w).position(|(a, b)| a != b).unwrap_or(0) as u64;
                    self.res.first_mismatch = Some(off + i as u64 * 8 + b);
                }
            }
        }
    }

    /// Sequential or sampled pass reading `[start, region end)`; compares with the pattern when `verify`.
    /// Returns bytes completed (sequential) or sampled bytes.
    fn read_pass(&mut self, start_done: u64, verify: bool, random: bool, buf: &mut AlignedBuf, exp: &mut AlignedBuf) -> u64 {
        let (base, len) = (self.region.offset, self.region.len);
        let mut done = if random { 0 } else { start_done.min(len) };
        let mut rng = Rng(self.direct_pattern.seed().unwrap_or(0x5EED_1234) ^ base ^ 0x9E37_79B9_7F4A_7C15 | 1);
        while done < len && !self.stop() {
            let n = self.bs.min(len - done);
            let off = if random {
                let slots = (len - n) / self.block + 1;
                base + (rng.next() % slots) * self.block
            } else {
                base + done
            };
            let t = Instant::now();
            let r = ioctl::read_full_at(self.file, &mut buf.as_mut_slice()[..n as usize], off);
            self.note_io(t);
            match r {
                Ok(m) if m as u64 == n => {
                    if verify {
                        self.direct_pattern.fill(off, &mut exp.as_mut_slice()[..n as usize]);
                        self.compare(off, &buf.as_slice()[..n as usize], &exp.as_slice()[..n as usize]);
                    }
                }
                _ => self.io_error(),
            }
            done += n;
            self.report(done, false);
        }
        self.report(done, true);
        done
    }

    /// Sequential write pass; returns bytes written (resumable).
    fn write_pass(&mut self, start_done: u64, buf: &mut AlignedBuf) -> u64 {
        let (base, len) = (self.region.offset, self.region.len);
        let mut done = start_done.min(len);
        while done < len && !self.stop() {
            let n = self.bs.min(len - done);
            let off = base + done;
            self.direct_pattern.fill(off, &mut buf.as_mut_slice()[..n as usize]);
            let t = Instant::now();
            let r = ioctl::write_all_at(self.file, &buf.as_slice()[..n as usize], off);
            self.note_io(t);
            if r.is_err() {
                self.io_error();
            }
            done += n;
            self.report(done, false);
        }
        done
    }
}

fn logical_block_of(ctx: &ProbeCtx, name: &str, file: &File) -> u64 {
    ioctl::logical_block(file)
        .or_else(|| ctx.read_opt(&format!("/sys/block/{}/queue/logical_block_size", name)).and_then(|s| s.parse().ok()))
        .unwrap_or(512) as u64
}

/// Run a test. `Write` requires `guard` (obtained from `WriteGuard::acquire` for the same device); without it the
/// call fails before touching the device. `Read` and `Verify` open the device O_RDONLY (+O_DIRECT).
///
/// Write mode, per region: write the pattern sequentially, fsync + BLKFLSBUF, then read it back with O_DIRECT and
/// compare. A cancelled or aborted run returns `Ok` with `complete == false` and per-region `done_bytes` so the
/// caller can resume with `TestSpec::resume_from`.
pub fn run_test(
    ctx: &ProbeCtx,
    spec: &TestSpec,
    guard: Option<&WriteGuard>,
    progress: &mut dyn FnMut(&Progress),
    cancel: &AtomicBool,
) -> Result<TestReport, ProbeError> {
    if !super::valid_dev_name(&spec.dev) {
        return Err(ProbeError::NotFound(spec.dev.clone()));
    }
    if spec.mode == TestMode::Write && guard.map(|g| g.device().name != spec.dev).unwrap_or(true) {
        return Err(ProbeError::Unsupported);
    }
    let owned;
    let file: &File = match (spec.mode, guard) {
        (TestMode::Write, Some(g)) => g.file(),
        _ => {
            owned = ioctl::open(&ctx.path(&format!("/dev/{}", spec.dev)), false, false, spec.direct)?;
            &owned
        }
    };
    let size = ioctl::size_bytes(file)?;
    let block = logical_block_of(ctx, &spec.dev, file);
    let bs = spec.bs as u64;
    if spec.bs == 0 || spec.bs > MAX_BS || bs % block != 0 {
        return Err(ProbeError::Parse(format!("bs must be a multiple of the logical block size {} and at most 64 MiB", block)));
    }
    let regions = if spec.regions.is_empty() { TestSpec::default_regions(size, 256) } else { spec.regions.clone() };
    for r in &regions {
        if r.len == 0 || r.offset % block != 0 || r.len % block != 0 || r.offset.checked_add(r.len).map(|e| e > size).unwrap_or(true) {
            return Err(ProbeError::Parse(format!("region {} must be block aligned, non-empty and inside the device ({} bytes)", r.name, size)));
        }
    }
    let serial = match guard {
        Some(g) => g.device().serial.clone().or_else(|| g.device().wwid.clone()),
        None => super::enumerate::describe_basic(ctx, &spec.dev).ok().and_then(|d| d.serial),
    };
    let mut buf = AlignedBuf::new(spec.bs as usize);
    let mut exp = AlignedBuf::new(spec.bs as usize);
    let mut results = Vec::new();
    let mut complete = true;

    for (i, region) in regions.iter().enumerate() {
        let resume = if spec.random { 0 } else { spec.resume_from.get(i).copied().unwrap_or(0) };
        let now = Instant::now();
        let mut pass = Pass {
            file,
            block,
            bs,
            direct_pattern: spec.pattern,
            progress: &mut *progress,
            cancel,
            progress_ms: spec.progress_ms,
            region,
            phase: match spec.mode {
                TestMode::Read => "read",
                TestMode::Write => "write",
                TestMode::Verify => "verify",
            },
            res: RegionResult { name: region.name.clone(), offset: region.offset, len: region.len, ..Default::default() },
            lat_sum_us: 0,
            ios: 0,
            cancelled: false,
            gave_up: false,
            last_report: now,
            started: now,
        };
        match spec.mode {
            TestMode::Read | TestMode::Verify => {
                let done = pass.read_pass(resume, spec.mode == TestMode::Verify, spec.random, &mut buf, &mut exp);
                pass.res.done_bytes = done;
                pass.res.mib_s = done as f64 / (1 << 20) as f64 / pass.started.elapsed().as_secs_f64().max(1e-9);
            }
            TestMode::Write => {
                let done = pass.write_pass(resume, &mut buf);
                let flushed = ioctl::flush(file);
                if flushed.is_err() {
                    pass.io_error();
                }
                pass.res.done_bytes = done;
                pass.res.mib_s = (done - resume.min(done)) as f64 / (1 << 20) as f64 / pass.started.elapsed().as_secs_f64().max(1e-9);
                if done >= region.len && !pass.cancelled && !pass.gave_up {
                    pass.phase = "verify";
                    pass.started = Instant::now();
                    pass.read_pass(0, true, false, &mut buf, &mut exp);
                    pass.res.verify_mib_s = Some(region.len as f64 / (1 << 20) as f64 / pass.started.elapsed().as_secs_f64().max(1e-9));
                }
            }
        }
        if pass.ios > 0 {
            pass.res.lat_avg_us = (pass.lat_sum_us / pass.ios as u128) as u64;
        }
        let stopped = pass.cancelled || pass.gave_up;
        results.push(pass.res.clone());
        if stopped {
            complete = false;
            break;
        }
    }
    let ok = complete && results.iter().all(|r| r.io_errors == 0 && r.mismatches == 0);
    Ok(TestReport {
        dev: spec.dev.clone(),
        serial,
        mode: spec.mode,
        seed: spec.pattern.seed(),
        generation: spec.pattern.generation(),
        bs: spec.bs,
        random: spec.random,
        regions: results,
        complete,
        ok,
    })
}

impl TestMode {
    pub fn name(self) -> &'static str {
        match self {
            TestMode::Read => "read",
            TestMode::Write => "write",
            TestMode::Verify => "verify",
        }
    }
}

impl ToJson for TestReport {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_u64("v", crate::SCHEMA_V);
        w.field_str("dev", &self.dev);
        w.field_opt_str("serial", self.serial.as_deref());
        w.field_str("mode", self.mode.name());
        w.field_opt_u64("seed", self.seed);
        w.field_opt_u64("generation", self.generation);
        w.field_u64("bs", self.bs as u64);
        w.field_bool("random", self.random);
        w.key("regions");
        w.begin_array();
        for r in &self.regions {
            w.begin_object();
            w.field_str("name", &r.name);
            w.field_u64("offset", r.offset);
            w.field_u64("len", r.len);
            w.field_u64("done_bytes", r.done_bytes);
            w.field_f64("mib_s", r.mib_s);
            w.field_opt_f64("verify_mib_s", r.verify_mib_s);
            w.field_u64("lat_max_us", r.lat_max_us);
            w.field_u64("lat_avg_us", r.lat_avg_us);
            w.field_u64("io_errors", r.io_errors);
            w.field_u64("mismatches", r.mismatches);
            w.field_opt_u64("first_mismatch", r.first_mismatch);
            w.end_object();
        }
        w.end_array();
        w.field_bool("complete", self.complete);
        w.field_bool("ok", self.ok);
        w.end_object();
    }
}

impl ToJson for Progress {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_str("event", "progress");
        w.field_str("region", &self.region);
        w.field_str("phase", &self.phase);
        w.field_u64("done_bytes", self.done_bytes);
        w.field_u64("total_bytes", self.total_bytes);
        w.field_f64("mib_s", self.mib_s);
        w.end_object();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pattern_is_position_dependent() {
        let p = Pattern::Seeded(42);
        let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
        p.fill(0, &mut a);
        p.fill(8, &mut b);
        assert_eq!(a[8..], b[..8]);
        assert_ne!(a[..8], b[..8]);
    }
    #[test]
    fn regions() {
        let r = TestSpec::default_regions(1 << 30, 256);
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|x| x.offset + x.len <= 1 << 30));
        assert_eq!(TestSpec::default_regions(4 << 20, 256).len(), 1);
    }
}
