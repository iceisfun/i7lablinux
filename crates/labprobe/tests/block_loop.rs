//! Live-root tests on a real loop block device: O_EXCL claim, BLKGETSIZE64, O_DIRECT reads, real GPT/ext4 detection,
//! mountinfo. #[ignore]d: they need passwordless sudo for losetup/mkfs/mount, so run them explicitly:
//!   cargo test -p labprobe --test block_loop -- --ignored --test-threads=1
//! A loop device has no serial, so a write is always refused with `no_serial` here (that is asserted); the
//! allowed-write path on a real device is covered by the QEMU e2e (virtio disks have serials).

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicBool;

use labprobe::block::{self, parttable::build_gpt, Pattern, Region, TestMode, TestSpec, WriteGuard, WriteRequest};
use labprobe::ProbeCtx;

fn sh(cmd: &str) -> String {
    let o = Command::new("sudo").args(["-n", "sh", "-c", cmd]).output().expect("run sudo");
    assert!(o.status.success(), "`{cmd}` failed: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

struct Loop {
    img: PathBuf,
    dev: String,
    mnt: PathBuf,
}

impl Drop for Loop {
    fn drop(&mut self) {
        let _ = Command::new("sudo").args(["-n", "umount", self.mnt.to_str().unwrap()]).output();
        let _ = Command::new("sudo").args(["-n", "losetup", "-d", &format!("/dev/{}", self.dev)]).output();
        let _ = std::fs::remove_file(&self.img);
        let _ = std::fs::remove_dir(&self.mnt);
    }
}

const MIB: u64 = 1 << 20;

fn setup() -> Loop {
    use std::os::unix::fs::FileExt;
    let img = std::env::temp_dir().join(format!("i7ll-loop-{}.img", std::process::id()));
    let f = std::fs::File::create(&img).unwrap();
    f.set_len(64 * MIB).unwrap();
    f.write_all_at(&build_gpt(512, 64 * MIB / 512, &[(2048, 60_000, "i7test")]), 0).unwrap();
    // a seeded pattern in the unpartitioned tail region 40..41 MiB
    let mut buf = vec![0u8; MIB as usize];
    Pattern::Seeded(77).fill(40 * MIB, &mut buf);
    f.write_all_at(&buf, 40 * MIB).unwrap();
    drop(f);
    let dev = sh(&format!("losetup -f --show -P {}", img.display()));
    let dev = dev.trim_start_matches("/dev/").to_string();
    sh(&format!("chmod a+rw /dev/{dev}; mkdir -p /run/i7lab/blk; chmod -R a+rwx /run/i7lab"));
    // partition nodes appear asynchronously
    for _ in 0..50 {
        if std::path::Path::new(&format!("/dev/{dev}p1")).exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    sh(&format!("mkfs.ext4 -q -L i7test /dev/{dev}p1; chmod a+rw /dev/{dev}p1"));
    let mnt = std::env::temp_dir().join(format!("i7ll-mnt-{}", std::process::id()));
    std::fs::create_dir_all(&mnt).unwrap();
    Loop { img, dev, mnt }
}

fn req(dev: &str) -> WriteRequest {
    WriteRequest { dev: dev.into(), destructive: true, serial: Some("irrelevant".into()), actor: "loop-test".into() }
}

#[test]
#[ignore = "needs sudo losetup/mkfs/mount"]
fn real_loop_device_end_to_end() {
    let l = setup();
    let ctx = ProbeCtx::live();
    let d = block::enumerate::describe(&ctx, &l.dev).unwrap();
    assert_eq!(d.size_bytes, 64 * MIB, "sysfs size");
    let t = d.partition_table.as_ref().expect("GPT read through a real O_DIRECT fd");
    assert_eq!((t.kind.as_str(), t.header_crc_ok, t.entries_crc_ok), ("gpt", true, true));
    assert_eq!(d.partitions.len(), 1);
    let ext = d.signatures.iter().find(|s| s.kind == "ext4").expect("ext4 signature inside the partition");
    assert_eq!(ext.offset, 2048 * 512 + 0x438);
    assert_eq!(ext.label.as_deref(), Some("i7test"));
    assert!(d.mounts.is_empty() && !d.boot_media);
    // no serial on a loop device: refused with no_serial (+ the listed data structures); neither not_a_disk, busy
    // nor unreadable appears, so the live open / rdev check / content read all ran
    let r = WriteGuard::acquire(&ctx, &req(&l.dev)).err().expect("refused");
    let codes: Vec<&str> = r.reasons.iter().map(|x| x.code()).collect();
    assert_eq!(codes, ["no_serial", "partition_table", "signature"], "{codes:?}");
    // a partition name is not a disk
    let r = WriteGuard::acquire(&ctx, &req(&format!("{}p1", l.dev))).err().unwrap();
    assert_eq!(r.reasons[0].code(), "not_a_disk", "partitions are not whole disks");

    // O_DIRECT verify of the seeded region through the real block device
    let mut s = TestSpec::new(&l.dev, TestMode::Verify, Pattern::Seeded(77));
    s.bs = 4096;
    s.regions = vec![Region { name: "tail".into(), offset: 40 * MIB, len: MIB }];
    let rep = block::run_test(&ctx, &s, None, &mut |_| {}, &AtomicBool::new(false)).unwrap();
    assert!(rep.ok && rep.regions[0].mismatches == 0, "{}", labproto::json::to_json(&rep));
    s.pattern = Pattern::Seeded(78);
    let bad = block::run_test(&ctx, &s, None, &mut |_| {}, &AtomicBool::new(false)).unwrap();
    assert!(!bad.ok && bad.regions[0].first_mismatch == Some(40 * MIB));
    // writes need a guard: none exists for a serial-less loop device
    s.mode = TestMode::Write;
    assert!(block::run_test(&ctx, &s, None, &mut |_| {}, &AtomicBool::new(false)).is_err());

    // mounted partition: mountinfo shows it, the kernel's O_EXCL claim on the whole disk fails with EBUSY
    sh(&format!("mount /dev/{}p1 {}", l.dev, l.mnt.display()));
    block::enumerate::invalidate(&l.dev);
    let d = block::enumerate::describe(&ctx, &l.dev).unwrap();
    assert_eq!(d.mounts, [l.mnt.to_str().unwrap().to_string()]);
    assert!(d.write_safety.absolute.iter().any(|r| r.code() == "mounted"));
    let r = WriteGuard::acquire(&ctx, &req(&l.dev)).err().unwrap();
    assert_eq!(r.reasons[0].code(), "busy", "{:?}", r.reasons);
}
