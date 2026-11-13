//! Block test engine against regular files standing in for devices (O_DIRECT falls back on tmpfs).

mod block_util;

use std::sync::atomic::{AtomicBool, Ordering};

use block_util::{DiskSpec, Fx};
use labprobe::block::{self, Pattern, Region, TestMode, TestSpec, WriteGuard, WriteRequest};
use labproto::json::to_json;

const MIB: u64 = 1 << 20;

fn setup(size: u64) -> Fx {
    let fx = Fx::new("eng");
    fx.disk(&DiskSpec::virtio("vda", size, 0, "SER-A"));
    fx
}

fn guard(fx: &Fx) -> WriteGuard {
    WriteGuard::acquire(&fx.ctx(), &WriteRequest { dev: "vda".into(), destructive: true, serial: Some("SER-A".into()), allow_boot_media: false, actor: "t".into() }).unwrap()
}

fn spec(mode: TestMode, pat: Pattern, regions: Vec<Region>) -> TestSpec {
    let mut s = TestSpec::new("vda", mode, pat);
    s.bs = 4096;
    s.regions = regions;
    s.progress_ms = 0;
    s
}

fn region(name: &str, off: u64, len: u64) -> Region {
    Region { name: name.into(), offset: off, len }
}

fn run(fx: &Fx, s: &TestSpec, g: Option<&WriteGuard>) -> block::TestReport {
    let cancel = AtomicBool::new(false);
    block::run_test(&fx.ctx(), s, g, &mut |_| {}, &cancel).unwrap()
}

#[test]
fn write_then_verify_roundtrip_and_pattern_on_disk() {
    let fx = setup(4 * MIB);
    let g = guard(&fx);
    let regs = vec![region("start", 0, 64 << 10), region("end", 4 * MIB - (64 << 10), 64 << 10)];
    let rep = run(&fx, &spec(TestMode::Write, Pattern::Seeded(42), regs.clone()), Some(&g));
    assert!(rep.ok && rep.complete, "{}", to_json(&rep));
    assert_eq!(rep.seed, Some(42));
    assert_eq!(rep.serial.as_deref(), Some("SER-A"));
    assert!(rep.regions.iter().all(|r| r.done_bytes == r.len && r.verify_mib_s.is_some()));
    // bytes on disk equal the documented pattern: splitmix64(seed ^ (offset/8))
    let got = fx.get("vda", 8, 8);
    assert_eq!(got, block::test::splitmix64(42 ^ 1).to_le_bytes());
    // outside the regions nothing was written
    assert!(fx.get("vda", 64 << 10, 4096).iter().all(|b| *b == 0));
    drop(g);
    // standalone verify (read-only open) agrees
    let v = run(&fx, &spec(TestMode::Verify, Pattern::Seeded(42), regs), None);
    assert!(v.ok, "{}", to_json(&v));
}

#[test]
fn verify_finds_corruption_with_exact_first_offset() {
    let fx = setup(2 * MIB);
    let g = guard(&fx);
    let regs = vec![region("all", 0, MIB)];
    assert!(run(&fx, &spec(TestMode::Write, Pattern::Seeded(7), regs.clone()), Some(&g)).ok);
    drop(g);
    fx.put("vda", 123_456, &[0xFF]);
    fx.put("vda", 600_000, &[0x00, 0x01, 0x02]);
    let v = run(&fx, &spec(TestMode::Verify, Pattern::Seeded(7), regs), None);
    assert!(!v.ok && v.complete);
    assert_eq!(v.regions[0].first_mismatch, Some(123_456));
    assert_eq!(v.regions[0].mismatches, 2, "two corrupted 8-byte words");
}

#[test]
fn misdirected_write_is_detected() {
    // two 4 KiB blocks swapped: each still carries a valid pattern, but for the wrong offset
    let fx = setup(MIB);
    let g = guard(&fx);
    let regs = vec![region("all", 0, 64 << 10)];
    assert!(run(&fx, &spec(TestMode::Write, Pattern::Seeded(9), regs.clone()), Some(&g)).ok);
    drop(g);
    let (a, b) = (fx.get("vda", 0, 4096), fx.get("vda", 4096, 4096));
    fx.put("vda", 0, &b);
    fx.put("vda", 4096, &a);
    let v = run(&fx, &spec(TestMode::Verify, Pattern::Seeded(9), regs), None);
    assert!(!v.ok);
    assert_eq!(v.regions[0].first_mismatch, Some(0));
    assert!(v.regions[0].mismatches >= 1000);
}

#[test]
fn generation_changes_the_pattern_but_zero_equals_seeded() {
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    let mut c = [0u8; 64];
    Pattern::Seeded(5).fill(4096, &mut a);
    Pattern::Generation(5, 0).fill(4096, &mut b);
    Pattern::Generation(5, 1).fill(4096, &mut c);
    assert_eq!(a, b);
    assert_ne!(a, c);
    let fx = setup(MIB);
    let g = guard(&fx);
    let regs = vec![region("all", 0, 64 << 10)];
    assert!(run(&fx, &spec(TestMode::Write, Pattern::Generation(5, 1), regs.clone()), Some(&g)).ok);
    drop(g);
    assert!(run(&fx, &spec(TestMode::Verify, Pattern::Generation(5, 1), regs.clone()), None).ok);
    let stale = run(&fx, &spec(TestMode::Verify, Pattern::Generation(5, 2), regs), None);
    assert!(!stale.ok && stale.regions[0].first_mismatch == Some(0));
}

#[test]
fn write_without_a_guard_is_unsupported_and_touches_nothing() {
    let fx = setup(MIB);
    let cancel = AtomicBool::new(false);
    let s = spec(TestMode::Write, Pattern::Seeded(1), vec![region("all", 0, 8192)]);
    let r = block::run_test(&fx.ctx(), &s, None, &mut |_| {}, &cancel);
    assert!(matches!(r, Err(labprobe::ProbeError::Unsupported)));
    assert!(fx.get("vda", 0, 8192).iter().all(|b| *b == 0));
    // a guard for another disk does not unlock this one
    fx.disk(&DiskSpec::virtio("vdb", MIB, 16, "SER-B"));
    let gb = WriteGuard::acquire(&fx.ctx(), &WriteRequest { dev: "vdb".into(), destructive: true, serial: Some("SER-B".into()), allow_boot_media: false, actor: "t".into() }).unwrap();
    let r = block::run_test(&fx.ctx(), &s, Some(&gb), &mut |_| {}, &cancel);
    assert!(matches!(r, Err(labprobe::ProbeError::Unsupported)));
    assert!(fx.get("vda", 0, 8192).iter().all(|b| *b == 0));
}

#[test]
fn cancel_then_resume_completes_and_final_data_is_correct() {
    let fx = setup(MIB);
    let g = guard(&fx);
    let regs = vec![region("r", 0, 64 << 10)]; // 16 chunks of 4 KiB
    let mut s = spec(TestMode::Write, Pattern::Seeded(3), regs.clone());
    let cancel = AtomicBool::new(false);
    let mut seen = 0;
    let rep = block::run_test(&fx.ctx(), &s, Some(&g), &mut |p| {
        seen += 1;
        if p.phase == "write" && p.done_bytes >= 8 * 4096 {
            cancel.store(true, Ordering::SeqCst);
        }
    }, &cancel)
    .unwrap();
    assert!(seen >= 8);
    assert!(!rep.complete && !rep.ok);
    let done = rep.regions[0].done_bytes;
    assert_eq!(done, 8 * 4096, "stopped at the chunk boundary after the cancel");
    assert!(fx.get("vda", done, 4096).iter().all(|b| *b == 0), "nothing past the cursor was written");
    s.resume_from = vec![done];
    let rep2 = run(&fx, &s, Some(&g));
    assert!(rep2.ok && rep2.complete, "{}", to_json(&rep2));
    assert_eq!(rep2.regions[0].done_bytes, 64 << 10);
    drop(g);
    assert!(run(&fx, &spec(TestMode::Verify, Pattern::Seeded(3), regs), None).ok);
}

#[test]
fn read_modes_sequential_and_random_and_progress() {
    let fx = setup(4 * MIB);
    fx.put("vda", 0, &vec![0xAB; 4 * MIB as usize]);
    let mut s = spec(TestMode::Read, Pattern::Zeros, vec![region("all", 0, 4 * MIB)]);
    s.bs = 64 << 10;
    let cancel = AtomicBool::new(false);
    let mut last = 0;
    let mut calls = 0;
    let rep = block::run_test(&fx.ctx(), &s, None, &mut |p| {
        assert!(p.done_bytes >= last && p.total_bytes == 4 * MIB && p.phase == "read");
        last = p.done_bytes;
        calls += 1;
    }, &cancel)
    .unwrap();
    assert!(rep.ok && rep.regions[0].done_bytes == 4 * MIB && rep.regions[0].mib_s > 0.0);
    assert!(calls >= 64, "one callback per I/O at progress_ms=0, got {calls}");
    assert_eq!(last, 4 * MIB);
    s.random = true;
    s.bs = 4096;
    let r = run(&fx, &s, None);
    assert!(r.ok && r.random && r.regions[0].done_bytes == 4 * MIB);
    assert!(r.regions[0].lat_max_us >= r.regions[0].lat_avg_us);
}

#[test]
fn bad_parameters_are_rejected() {
    let fx = setup(MIB);
    let cancel = AtomicBool::new(false);
    let ctx = fx.ctx();
    let mut s = spec(TestMode::Read, Pattern::Zeros, vec![region("x", 0, MIB + 512)]);
    assert!(matches!(block::run_test(&ctx, &s, None, &mut |_| {}, &cancel), Err(labprobe::ProbeError::Parse(_))));
    s.regions = vec![region("x", 100, 512)]; // unaligned offset
    assert!(matches!(block::run_test(&ctx, &s, None, &mut |_| {}, &cancel), Err(labprobe::ProbeError::Parse(_))));
    s.regions = vec![region("x", 0, 0)];
    assert!(matches!(block::run_test(&ctx, &s, None, &mut |_| {}, &cancel), Err(labprobe::ProbeError::Parse(_))));
    s.regions = vec![region("x", 0, 512)];
    s.bs = 700;
    assert!(matches!(block::run_test(&ctx, &s, None, &mut |_| {}, &cancel), Err(labprobe::ProbeError::Parse(_))));
    s.bs = 4096;
    s.dev = "../etc".into();
    assert!(matches!(block::run_test(&ctx, &s, None, &mut |_| {}, &cancel), Err(labprobe::ProbeError::NotFound(_))));
}

#[test]
fn default_regions_used_when_none_given() {
    let fx = setup(8 * MIB);
    let mut s = TestSpec::new("vda", TestMode::Read, Pattern::Zeros);
    s.bs = 4096;
    let r = run(&fx, &s, None);
    assert_eq!(r.regions.len(), 1);
    assert_eq!(r.regions[0].len, 8 * MIB);
}
