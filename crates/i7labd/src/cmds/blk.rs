//! blk.ls, blk.smart, blk.read, blk.write, blk.verify. The write path goes only through labprobe's WriteGuard:
//! no handler here opens a block device for writing.

use labprobe::block::{self, Pattern, Region, TestMode, TestSpec, WriteGuard, WriteRequest};
use labproto::json::to_json;
use labproto::Status;

use super::probe::{probe_reply, probe_status};
use crate::opts_or_bad;
use crate::registry::{Ctx, Handler, Reply};

pub const TABLE: &[(&str, Handler)] =
    &[("blk.ls", ls), ("blk.smart", smart), ("blk.read", read), ("blk.write", write), ("blk.verify", verify)];

pub const DEFAULT_MB: u64 = 256;
pub const MAX_MB: u64 = 1 << 20;

fn ls(ctx: &mut Ctx) -> Reply {
    let o = opts_or_bad!(ctx, &["all"], &[]);
    probe_reply(block::probe(&ctx.daemon.probe, o.flag("all")))
}

fn smart(ctx: &mut Ctx) -> Reply {
    let o = opts_or_bad!(ctx, &["attrs"], &[]);
    let Some(dev) = o.positional().first() else { return Reply::error(Status::BadArgs, "usage: blk.smart DEV [--attrs]") };
    if !block::valid_dev_name(dev) {
        return Reply::error(Status::BadArgs, "bad device name");
    }
    probe_reply(block::smart::probe(&ctx.daemon.probe, dev))
}

/// "4096", "512k", "1m" (powers of two between 512 B and 64 MiB).
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.to_ascii_lowercase();
    let (num, mult) = match s.strip_suffix('k') {
        Some(n) => (n, 1u64 << 10),
        None => match s.strip_suffix('m') {
            Some(n) => (n, 1 << 20),
            None => (s.as_str(), 1),
        },
    };
    num.parse::<u64>().ok()?.checked_mul(mult)
}

/// Decimal or 0x hex.
pub fn parse_u64(s: &str) -> Option<u64> {
    match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Regions from `--regions start,mid,end` (names of `default_regions`) or `--offset B --len B`, bounded by the
/// device size. Offsets and lengths must be multiples of the logical block size.
pub fn select_regions(size: u64, logical_block: u32, mb: u64, names: Option<&str>, offset: Option<u64>, len: Option<u64>) -> Result<Vec<Region>, String> {
    let lb = logical_block.max(512) as u64;
    match (names, offset, len) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => Err("--regions excludes --offset/--len".into()),
        (None, None, None) => Ok(TestSpec::default_regions(size, mb)),
        (Some(list), None, None) => {
            let all = TestSpec::default_regions(size, mb);
            let mut out = Vec::new();
            for n in list.split(',') {
                let r = all.iter().find(|r| r.name == n).or(if n == "all" { all.first() } else { None }).ok_or_else(|| format!("no region {:?} on this device (have: {})", n, all.iter().map(|r| r.name.as_str()).collect::<Vec<_>>().join(",")))?;
                out.push(r.clone());
            }
            Ok(out)
        }
        (None, off, l) => {
            let off = off.unwrap_or(0);
            let l = l.unwrap_or_else(|| (mb << 20).min(size.saturating_sub(off)));
            if l == 0 || off % lb != 0 || l % lb != 0 {
                return Err(format!("--offset and --len must be non-empty multiples of {} bytes", lb));
            }
            if off.checked_add(l).map(|e| e > size).unwrap_or(true) {
                return Err("region extends past the end of the device".into());
            }
            Ok(vec![Region { name: "custom".into(), offset: off, len: l }])
        }
    }
}

struct Parsed {
    dev: String,
    mb: u64,
    spec: TestSpec,
}

/// Shared argument parsing of the three test commands.
fn parse_test(ctx: &mut Ctx, mode: TestMode) -> Result<Parsed, Reply> {
    let bad = |m: &str| Reply::error(Status::BadArgs, m);
    let o = match labproto::args::Opts::parse(&ctx.args, &["direct", "random", "destructive"], &["mb", "regions", "offset", "len", "bs", "seed", "generation", "serial"]) {
        Ok(o) => o,
        Err(e) => return Err(bad(&e.to_string())),
    };
    let dev = match o.positional() {
        [d] if block::valid_dev_name(d) => d.clone(),
        [_] => return Err(bad("bad device name")),
        _ => return Err(bad("usage: DEV [options] (see help)")),
    };
    let num = |k: &str| -> Result<Option<u64>, Reply> {
        o.value(k).map(|v| parse_u64(v).ok_or_else(|| bad(&format!("bad --{}", k)))).transpose()
    };
    let mb = num("mb")?.unwrap_or(DEFAULT_MB);
    if mb == 0 || mb > MAX_MB {
        return Err(bad("bad --mb"));
    }
    let bs = match o.value("bs") {
        None => 1 << 20,
        Some(v) => match parse_size(v) {
            Some(b) if b.is_power_of_two() && (512..=(64 << 20)).contains(&b) => b as u32,
            _ => return Err(bad("bad --bs (power of two, 512 B .. 64 MiB, e.g. 4k, 1m)")),
        },
    };
    let seed = num("seed")?;
    let generation = num("generation")?;
    let pattern = match (mode, seed) {
        (TestMode::Read, _) => Pattern::Zeros,
        (TestMode::Verify, None) => return Err(bad("--seed is required (the seed blk.write reported)")),
        (_, s) => {
            let s = match s {
                Some(s) => s,
                None => {
                    let mut b = [0u8; 8];
                    labproto::crypto::random_bytes(&mut b).map_err(|e| Reply::error(Status::Io, &e.to_string()))?;
                    u64::from_le_bytes(b)
                }
            };
            match generation {
                Some(g) if g != 0 => Pattern::Generation(s, g),
                _ => Pattern::Seeded(s),
            }
        }
    };
    // device facts for the region maths
    let report = block::probe(&ctx.daemon.probe, true).map_err(|e| Reply::error(probe_status(&e), &e.to_string()))?;
    let Some(d) = report.devices.iter().find(|d| d.name == dev) else {
        return Err(Reply::error(Status::NotFound, &format!("no block device {}", dev)));
    };
    let regions = select_regions(d.size_bytes, d.logical_block, mb, o.value("regions"), num("offset")?, num("len")?).map_err(|m| bad(&m))?;
    if regions.is_empty() || regions.iter().any(|r| r.len == 0) {
        return Err(bad("empty region (device too small?)"));
    }
    if bs as u64 % d.logical_block.max(512) as u64 != 0 {
        return Err(bad("--bs must be a multiple of the logical block size"));
    }
    let mut spec = TestSpec::new(&dev, mode, pattern);
    spec.regions = regions;
    spec.bs = bs;
    spec.direct = mode == TestMode::Write || o.flag("direct");
    spec.random = o.flag("random") && mode != TestMode::Write;
    Ok(Parsed { dev, mb, spec })
}

fn finish(ctx: &Ctx, r: Result<block::TestReport, labprobe::ProbeError>) -> Reply {
    match r {
        Ok(rep) => {
            let body = to_json(&rep).into_bytes();
            let status = if rep.ok {
                Status::Ok
            } else if ctx.cancel.load(std::sync::atomic::Ordering::SeqCst) && !rep.complete {
                Status::Canceled
            } else {
                Status::Io
            };
            Reply { status, body, content: crate::registry::Content::Json }
        }
        Err(e) => Reply::error(probe_status(&e), &e.to_string()),
    }
}

fn run(ctx: &mut Ctx, p: &Parsed, guard: Option<&WriteGuard>) -> Reply {
    let _ = p.mb;
    let sink = &mut *ctx.sink;
    let mut progress = |pr: &block::Progress| {
        let _ = sink.event(&to_json(pr));
    };
    let r = block::run_test(&ctx.daemon.probe, &p.spec, guard, &mut progress, &ctx.cancel);
    finish(ctx, r)
}

/// `DEV [--mb N] [--regions ..|--offset B --len B] [--bs 1m] [--direct] [--random]`: never writes.
fn read(ctx: &mut Ctx) -> Reply {
    match parse_test(ctx, TestMode::Read) {
        Ok(p) => run(ctx, &p, None),
        Err(r) => r,
    }
}

/// `DEV --seed N [--generation G] [--mb N] [--regions ..]`: compare with the pattern a blk.write left behind.
fn verify(ctx: &mut Ctx) -> Reply {
    match parse_test(ctx, TestMode::Verify) {
        Ok(p) => run(ctx, &p, None),
        Err(r) => r,
    }
}

/// `DEV --destructive --serial S [...]`: the gate decides; every refusal comes back with its reason list.
fn write(ctx: &mut Ctx) -> Reply {
    let o = opts_or_bad!(ctx, &["destructive", "direct", "random"], &["serial", "mb", "regions", "offset", "len", "bs", "seed", "generation"]);
    let parsed = match parse_test(ctx, TestMode::Write) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let req = WriteRequest {
        dev: parsed.dev.clone(),
        destructive: o.flag("destructive"),
        serial: o.value("serial").map(str::to_string),
        actor: format!("{} {}", ctx.actor, ctx.source.describe()),
    };
    let guard = match WriteGuard::acquire(&ctx.daemon.probe, &req) {
        Ok(g) => g,
        Err(refusal) => return Reply::refused(&to_json(&refusal.reasons), "write refused by the safety gate"),
    };
    let reply = run(ctx, &parsed, Some(&guard));
    // the partition table may be gone: make /sys and blk.ls match the disk
    let _ = guard.reread_partitions();
    reply
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests_support::*;
    use labproto::keys::Role;

    #[test]
    fn size_and_number_parsing() {
        assert_eq!(parse_size("4k"), Some(4096));
        assert_eq!(parse_size("1M"), Some(1 << 20));
        assert_eq!(parse_size("512"), Some(512));
        assert_eq!(parse_size("x"), None);
        assert_eq!(parse_u64("0x10"), Some(16));
        assert_eq!(parse_u64("17"), Some(17));
        assert_eq!(parse_u64("-1"), None);
    }

    #[test]
    fn region_selection() {
        let gib = 1u64 << 30;
        let d = select_regions(gib, 512, 256, None, None, None).unwrap();
        assert_eq!(d.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["start", "mid", "end"]);
        let m = select_regions(gib, 512, 256, Some("end,start"), None, None).unwrap();
        assert_eq!((m[0].name.as_str(), m[1].name.as_str()), ("end", "start"));
        assert!(select_regions(gib, 512, 256, Some("nope"), None, None).is_err());
        assert!(select_regions(gib, 512, 256, Some("start"), Some(0), None).is_err(), "exclusive");
        let c = select_regions(gib, 4096, 256, None, Some(4096), Some(1 << 20)).unwrap();
        assert_eq!((c[0].offset, c[0].len), (4096, 1 << 20));
        assert!(select_regions(gib, 4096, 256, None, Some(512), Some(4096)).is_err(), "misaligned");
        assert!(select_regions(gib, 512, 256, None, Some(gib - 512), Some(4096)).is_err(), "past the end");
        assert!(select_regions(gib, 512, 256, None, Some(u64::MAX - 10), Some(4096)).is_err(), "overflow");
    }

    #[test]
    fn argument_validation_and_gate_refusal() {
        let d = test_daemon();
        for (name, args) in [
            ("blk.read", vec![]),
            ("blk.read", vec!["../etc"]),
            ("blk.read", vec!["sda", "sdb"]),
            ("blk.read", vec!["sda", "--bs", "3000"]),
            ("blk.read", vec!["sda", "--mb", "0"]),
            ("blk.verify", vec!["sda"]), // --seed required
            ("blk.read", vec!["sda", "--bogus"]),
        ] {
            assert_eq!(run_with(&d, Role::Ro, name, &args).0.status, Status::BadArgs, "{} {:?}", name, args);
        }
        assert_eq!(run_with(&d, Role::Ro, "blk.write", &["sda"]).0.status, Status::Eperm, "ro key");
        assert_eq!(run_with(&d, Role::Ro, "blk.read", &["nosuchdisk0"]).0.status, Status::NotFound);
        // a write request without --destructive/--serial on a device that does not exist is NotFound (before the
        // gate) or REFUSED with reasons (device exists): never a started write
        let (r, _) = run_with(&d, Role::Admin, "blk.write", &["nosuchdisk0"]);
        assert_eq!(r.status, Status::NotFound);
    }

    #[test]
    fn write_without_confirmation_is_refused_with_reasons_on_a_real_disk() {
        // On machines that have a block device, a bare blk.write must come back REFUSED and name the reasons.
        let d = test_daemon();
        let Ok(rep) = block::probe(&d.probe, true) else { return };
        let Some(dev) = rep.devices.iter().find(|x| x.size_bytes > 64 << 20) else { return };
        let (r, _) = run_with(&d, Role::Admin, "blk.write", &[&dev.name, "--mb", "1"]);
        assert_eq!(r.status, Status::Refused, "{}", String::from_utf8_lossy(&r.body));
        let j = String::from_utf8(r.body).unwrap();
        // the gate may name busy / not_destructive / serial_missing / ...: what matters is that reasons are listed
        assert!(j.contains("\"reasons\":[{"), "{}", j);
    }
}
