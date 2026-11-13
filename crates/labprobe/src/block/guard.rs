//! The block write gate (docs/PLAN.md section 6). Owner: P4.
//! Policy implemented here and nowhere else. `WriteGuard` is the only constructor of a writable block handle.

use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;

use labproto::json::{JsonWriter, ToJson};
use labproto::sys::{flock, flock_op};

use crate::ctx::ProbeCtx;

use super::enumerate;
use super::ioctl;
use super::BlockDevice;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    NotDestructive,
    SerialMissing,
    SerialMismatch,
    /// device has neither serial nor WWID: writes are impossible to confirm, always refused
    NoSerial,
    /// the boot media, host NOT proven RAM-resident: never writable
    BootMedia,
    /// the boot media of a host that proved it is fully RAM-resident (`ram::ram_resident`): writable with
    /// `--allow-boot-media` in addition to `--destructive` + the serial. Same code `boot_media`, detail `ram-resident`.
    BootMediaRam,
    BacksRunningSystem,
    Mounted(String),
    Held(String),
    Swap,
    /// O_EXCL open failed (claimed by the kernel or another opener)
    Busy,
    ReadOnly,
    UnderTest,
    PartitionTable(String),
    Signature(String),
    NotFound,
    NotADisk,
    /// the device could not be read from the locked fd (fail closed: its content is unknown)
    Unreadable,
}

impl Reason {
    /// true only for the "has data structures" class (allowed when `--destructive` and the matching serial are
    /// given) and the RAM-resident boot media (which also needs `--allow-boot-media`, see `decide`).
    pub fn overridable(&self) -> bool {
        matches!(self, Reason::PartitionTable(_) | Reason::Signature(_) | Reason::BootMediaRam)
    }

    pub fn code(&self) -> &'static str {
        match self {
            Reason::NotDestructive => "not_destructive",
            Reason::SerialMissing => "serial_missing",
            Reason::SerialMismatch => "serial_mismatch",
            Reason::NoSerial => "no_serial",
            Reason::BootMedia | Reason::BootMediaRam => "boot_media",
            Reason::BacksRunningSystem => "backs_running_system",
            Reason::Mounted(_) => "mounted",
            Reason::Held(_) => "held",
            Reason::Swap => "swap",
            Reason::Busy => "busy",
            Reason::ReadOnly => "read_only",
            Reason::UnderTest => "under_test",
            Reason::PartitionTable(_) => "partition_table",
            Reason::Signature(_) => "signature",
            Reason::NotFound => "not_found",
            Reason::NotADisk => "not_a_disk",
            Reason::Unreadable => "unreadable",
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            Reason::BootMediaRam => Some("ram-resident"),
            Reason::Mounted(s) | Reason::Held(s) | Reason::PartitionTable(s) | Reason::Signature(s) => Some(s),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Verdict {
    /// blank disk: writable with --destructive --serial
    Safe,
    /// partition table / signatures: writable with --destructive --serial (reasons shown)
    NeedsOverride,
    /// never writable in the current state
    #[default]
    Refused,
}

#[derive(Clone, Debug, Default)]
pub struct WriteSafety {
    pub verdict: Verdict,
    pub absolute: Vec<Reason>,
    pub overridable: Vec<Reason>,
}

/// Path of the cross-process lock file of a disk.
fn lock_path(ctx: &ProbeCtx, name: &str) -> std::path::PathBuf {
    ctx.path(&format!("{}/{}.lock", LOCK_DIR, name))
}

/// Is another opener (same or other process) holding the "under test" lock? Probes with a non-blocking shared
/// flock and releases it at once; never creates the lock file.
fn under_test(ctx: &ProbeCtx, name: &str) -> bool {
    let Ok(f) = File::open(lock_path(ctx, name)) else { return false };
    match flock(f.as_raw_fd(), flock_op::LOCK_SH | flock_op::LOCK_NB) {
        Ok(()) => {
            let _ = flock(f.as_raw_fd(), flock_op::LOCK_UN);
            false
        }
        Err(e) => e.kind() == io::ErrorKind::WouldBlock,
    }
}

/// Static assessment for `blk.ls` (no flags considered).
pub fn assess(ctx: &ProbeCtx, dev: &BlockDevice) -> WriteSafety {
    let mut s = assess_parts(dev);
    if under_test(ctx, &dev.name) {
        s.absolute.push(Reason::UnderTest);
        s.verdict = Verdict::Refused;
    }
    s
}

fn assess_parts(dev: &BlockDevice) -> WriteSafety {
    let mut absolute = Vec::new();
    let mut overridable = Vec::new();
    if dev.boot_media {
        if dev.ram_resident {
            overridable.push(Reason::BootMediaRam);
        } else {
            absolute.push(Reason::BootMedia);
        }
    }
    if dev.read_only {
        absolute.push(Reason::ReadOnly);
    }
    if dev.serial.is_none() && dev.wwid.is_none() {
        absolute.push(Reason::NoSerial);
    }
    for m in &dev.mounts {
        if enumerate::is_system_mount(m) {
            absolute.push(Reason::BacksRunningSystem);
        } else {
            absolute.push(Reason::Mounted(m.clone()));
        }
    }
    for h in &dev.holders {
        absolute.push(Reason::Held(h.clone()));
    }
    if dev.swap {
        absolute.push(Reason::Swap);
    }
    if let Some(t) = &dev.partition_table {
        overridable.push(Reason::PartitionTable(t.kind.clone()));
    }
    for s in &dev.signatures {
        overridable.push(Reason::Signature(s.kind.clone()));
    }
    let verdict = if !absolute.is_empty() {
        Verdict::Refused
    } else if !overridable.is_empty() {
        Verdict::NeedsOverride
    } else {
        Verdict::Safe
    };
    WriteSafety { verdict, absolute, overridable }
}

#[derive(Clone, Debug)]
pub struct WriteRequest {
    pub dev: String,
    pub destructive: bool,
    pub serial: Option<String>,
    /// `--allow-boot-media`: required in addition to `destructive` + `serial` to overwrite the boot media of a host
    /// that is proven RAM-resident; ignored (never enough) otherwise
    pub allow_boot_media: bool,
    /// key id + source (MAC/IP) or "console", for the audit log
    pub actor: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Refusal {
    pub reasons: Vec<Reason>,
}

/// Cross-process lock dir: `<LOCK_DIR>/<devname>.lock`, flock(LOCK_EX|LOCK_NB) held for the guard's life, so
/// i7labd and i7labsh (which works with i7labd dead) cannot test the same disk at once (review feasibility F14).
pub const LOCK_DIR: &str = "/run/i7lab/blk";
/// Shared audit log. i7labd and i7labsh both append with O_APPEND (one line per write attempt, allowed or not).
pub const AUDIT_LOG: &str = "/run/i7lab/audit.log";

/// Append one audit line (`<unix s> <line>`) to `AUDIT_LOG` with O_APPEND. Never fails the caller's decision:
/// returns the io error for the caller to report.
pub fn audit_write(line: &str) -> io::Result<()> {
    audit_write_in(&ProbeCtx::live(), line)
}

/// `audit_write` under `ctx.root` (host tests).
pub fn audit_write_in(ctx: &ProbeCtx, line: &str) -> io::Result<()> {
    use std::io::Write;
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let path = ctx.path(AUDIT_LOG);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    // one write(2) call so concurrent appenders do not interleave inside a line
    f.write_all(format!("{} {}\n", t, labproto::text::sanitize(line)).as_bytes())
}

/// Pure policy over a description built FROM THE LOCKED FD (see `WriteGuard::acquire`). Returns every reason
/// that blocks the request; empty => allowed. Overridable reasons (partition table, signatures) block only when
/// `--destructive` + the matching serial are absent; absolute reasons always block. Host-testable.
pub fn decide(dev: &BlockDevice, req: &WriteRequest) -> Result<(), Refusal> {
    let mut reasons = Vec::new();
    if !req.destructive {
        reasons.push(Reason::NotDestructive);
    }
    let expect = dev.serial.as_deref().or(dev.wwid.as_deref());
    match (expect, req.serial.as_deref()) {
        (None, _) => {} // NoSerial comes from assess_parts (absolute)
        (Some(_), None) => reasons.push(Reason::SerialMissing),
        (Some(e), Some(g)) if e.trim() != g.trim() => reasons.push(Reason::SerialMismatch),
        _ => {}
    }
    let safety = assess_parts(dev);
    reasons.extend(safety.absolute);
    let confirmed = !reasons.iter().any(|r| matches!(r, Reason::NotDestructive | Reason::SerialMissing | Reason::SerialMismatch | Reason::NoSerial));
    if !confirmed {
        reasons.extend(safety.overridable);
    } else if !req.allow_boot_media && safety.overridable.contains(&Reason::BootMediaRam) {
        reasons.push(Reason::BootMediaRam);
    }
    if reasons.is_empty() {
        Ok(())
    } else {
        Err(Refusal { reasons })
    }
}

/// Holds the O_RDWR|O_EXCL|O_DIRECT fd and the cross-process "under test" flock; Drop releases both.
pub struct WriteGuard {
    dev: BlockDevice,
    file: File,
    #[allow(dead_code)]
    lock: File,
}

fn refuse(r: Reason) -> Refusal {
    Refusal { reasons: vec![r] }
}

/// `st_rdev` -> (major, minor) as glibc/musl `gnu_dev_major/minor`.
fn rdev_split(rdev: u64) -> (u32, u32) {
    let major = ((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfff);
    let minor = (rdev & 0xff) | ((rdev >> 12) & !0xff);
    (major as u32, minor as u32)
}

impl WriteGuard {
    /// Lock FIRST, then decide from the locked fd (review security F4; no probe-then-open window):
    /// 1. `valid_dev_name`, whole disk only (`/sys/block/<name>` exists, not a partition) else NotADisk/NotFound;
    /// 2. flock(LOCK_EX|LOCK_NB) on `LOCK_DIR/<name>.lock` (EWOULDBLOCK => UnderTest);
    /// 3. open `/dev/<name>` O_RDWR|O_EXCL|O_DIRECT|O_NOFOLLOW|O_CLOEXEC: EBUSY => Busy (the kernel refuses O_EXCL
    ///    while any partition is mounted, held by md/dm or swapped on), EROFS/EACCES/EPERM => ReadOnly;
    ///    BLKROGET => ReadOnly; on the live root the node must be a block device whose rdev equals sysfs `dev`;
    /// 4. with the claim held, re-read partition table + signatures (head 1 MiB, tail 1 MiB, each partition's
    ///    head) FROM THIS FD, and mountinfo / holders / swaps / boot identity (ctx.boot_disk, ctx.boot_partuuid);
    ///    an unreadable device is refused (`Unreadable`), never assumed blank;
    /// 5. `decide(&dev, req)`; 6. `audit_write` the outcome (refusals too); then return the guard.
    /// The fd that backed the decision is the fd that is written.
    ///
    /// Under a fixture root (`ctx.root != "/"`) `/dev/<name>` may be a regular file so host tests run the real
    /// code path; the live root requires a block device.
    pub fn acquire(ctx: &ProbeCtx, req: &WriteRequest) -> Result<WriteGuard, Refusal> {
        let r = Self::acquire_inner(ctx, req);
        let outcome = match &r {
            Ok(g) => format!(
                "ALLOWED serial={}{}",
                g.dev.serial.as_deref().or(g.dev.wwid.as_deref()).unwrap_or("-"),
                if g.dev.boot_media { " BOOT-MEDIA-OVERRIDE ram-resident" } else { "" }
            ),
            Err(f) => format!("REFUSED reasons={}", f.reasons.iter().map(|x| x.code()).collect::<Vec<_>>().join(",")),
        };
        let _ = audit_write_in(
            ctx,
            &format!(
                "blk.write dev={} actor={} destructive={} serial_given={} allow_boot_media={} {}",
                req.dev,
                req.actor,
                req.destructive,
                req.serial.as_deref().unwrap_or("-"),
                req.allow_boot_media,
                outcome
            ),
        );
        r
    }

    fn acquire_inner(ctx: &ProbeCtx, req: &WriteRequest) -> Result<WriteGuard, Refusal> {
        let name = req.dev.as_str();
        if !super::valid_dev_name(name) {
            return Err(refuse(Reason::NotFound));
        }
        if !ctx.path(&format!("/sys/block/{}", name)).exists() {
            return Err(refuse(if ctx.path(&format!("/sys/class/block/{}/partition", name)).exists() { Reason::NotADisk } else { Reason::NotFound }));
        }
        let live = ctx.root == std::path::Path::new("/");

        // 2. lock
        let lp = lock_path(ctx, name);
        if let Some(dir) = lp.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let lock = std::fs::OpenOptions::new().create(true).read(true).write(true).open(&lp).map_err(|_| refuse(Reason::Busy))?;
        match flock(lock.as_raw_fd(), flock_op::LOCK_EX | flock_op::LOCK_NB) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Err(refuse(Reason::UnderTest)),
            Err(_) => return Err(refuse(Reason::Busy)),
        }

        // 3. exclusive open
        let devpath = ctx.path(&format!("/dev/{}", name));
        if live && !ioctl::is_block_device(&devpath) {
            return Err(refuse(Reason::NotADisk));
        }
        let file = ioctl::open(&devpath, true, true, true).map_err(|e| match e.raw_os_error() {
            Some(16) => refuse(Reason::Busy),
            Some(30) | Some(13) | Some(1) => refuse(Reason::ReadOnly),
            Some(2) | Some(20) => refuse(Reason::NotFound),
            _ => refuse(Reason::Unreadable),
        })?;

        // 4. describe from this fd
        let (dev, read_ok) = enumerate::describe_from(ctx, name, &file).map_err(|_| refuse(Reason::NotFound))?;
        if live {
            use std::os::unix::fs::MetadataExt;
            let rdev = file.metadata().map(|m| rdev_split(m.rdev())).map_err(|_| refuse(Reason::Unreadable))?;
            if rdev != dev.devno {
                return Err(refuse(Reason::NotADisk));
            }
        }
        if !read_ok || dev.size_bytes == 0 {
            return Err(refuse(Reason::Unreadable));
        }

        // 5. policy
        decide(&dev, req)?;
        Ok(WriteGuard { dev, file, lock })
    }

    pub fn device(&self) -> &BlockDevice {
        &self.dev
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    /// BLKRRPART after a write that destroyed the partition table, so `blk.ls` matches the disk (feasibility F21).
    /// Fails with ENOTTY on a regular file (fixtures) and EBUSY while a partition is in use.
    pub fn reread_partitions(&self) -> io::Result<()> {
        ioctl::reread_partitions(&self.file)
    }
}

impl Drop for WriteGuard {
    fn drop(&mut self) {
        enumerate::invalidate(&self.dev.name);
        // the O_EXCL fd and the flock are released when the fields are dropped
    }
}

impl ToJson for Reason {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_str("code", self.code());
        w.field_opt_str("detail", self.detail());
        w.field_bool("overridable", self.overridable());
        w.end_object();
    }
}

impl ToJson for WriteSafety {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_str(
            "verdict",
            match self.verdict {
                Verdict::Safe => "safe",
                Verdict::NeedsOverride => "needs_override",
                Verdict::Refused => "refused",
            },
        );
        w.key("absolute");
        w.value(&self.absolute);
        w.key("overridable");
        w.value(&self.overridable);
        w.end_object();
    }
}

impl ToJson for Refusal {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.key("reasons");
        w.value(&self.reasons);
        w.end_object();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_device_is_refused() {
        let ctx = ProbeCtx::fixture("/nonexistent");
        let r = WriteGuard::acquire(&ctx, &WriteRequest { dev: "sda".into(), destructive: true, serial: Some("X".into()), allow_boot_media: false, actor: "t".into() });
        assert!(r.is_err());
        assert!(Reason::Signature("ext4".into()).overridable());
        assert!(!Reason::BootMedia.overridable());
        assert!(!Reason::Mounted("/".into()).overridable());
    }

    fn dev(serial: Option<&str>) -> BlockDevice {
        BlockDevice {
            name: "vda".into(),
            devno: (252, 0),
            size_bytes: 1 << 30,
            logical_block: 512,
            physical_block: 512,
            kind: super::super::DiskKind::Virtio,
            model: None,
            vendor: None,
            serial: serial.map(str::to_string),
            serial_source: None,
            wwid: None,
            firmware_rev: None,
            rotational: false,
            removable: false,
            read_only: false,
            partition_table: None,
            partitions: vec![],
            signatures: vec![],
            mounts: vec![],
            holders: vec![],
            swap: false,
            boot_media: false,
            ram_resident: false,
            write_safety: Default::default(),
        }
    }

    fn req(destructive: bool, serial: Option<&str>) -> WriteRequest {
        WriteRequest { dev: "vda".into(), destructive, serial: serial.map(str::to_string), allow_boot_media: false, actor: "t".into() }
    }

    fn codes(r: Result<(), Refusal>) -> Vec<&'static str> {
        r.err().map(|f| f.reasons.iter().map(Reason::code).collect()).unwrap_or_default()
    }

    #[test]
    fn decide_table() {
        let blank = dev(Some("S1"));
        assert_eq!(decide(&blank, &req(true, Some("S1"))), Ok(()));
        assert_eq!(codes(decide(&blank, &req(false, Some("S1")))), vec!["not_destructive"]);
        assert_eq!(codes(decide(&blank, &req(true, None))), vec!["serial_missing"]);
        assert_eq!(codes(decide(&blank, &req(true, Some("S2")))), vec!["serial_mismatch"]);
        assert_eq!(codes(decide(&dev(None), &req(true, Some("S1")))), vec!["no_serial"]);

        let mut gpt = dev(Some("S1"));
        gpt.signatures.push(super::super::Signature { kind: "ext4".into(), offset: 1080, label: None, uuid: None });
        assert_eq!(decide(&gpt, &req(true, Some("S1"))), Ok(()), "overridable with both flags");
        assert_eq!(codes(decide(&gpt, &req(false, Some("S1")))), vec!["not_destructive", "signature"]);

        let mut boot = gpt.clone();
        boot.boot_media = true;
        assert_eq!(codes(decide(&boot, &req(true, Some("S1")))), vec!["boot_media"]);
        let mut with_flag = req(true, Some("S1"));
        with_flag.allow_boot_media = true;
        assert_eq!(codes(decide(&boot, &with_flag)), vec!["boot_media"], "not proven RAM-resident: absolute even with the flag");
        assert!(!assess_parts(&boot).absolute.is_empty());

        // RAM-resident boot media: overridable, but only with --allow-boot-media on top of --destructive + serial
        let mut ram = dev(Some("S1"));
        ram.boot_media = true;
        ram.ram_resident = true;
        let s = assess_parts(&ram);
        assert!(s.absolute.is_empty() && s.verdict == Verdict::NeedsOverride);
        assert_eq!((s.overridable[0].code(), s.overridable[0].detail(), s.overridable[0].overridable()), ("boot_media", Some("ram-resident"), true));
        assert_eq!(codes(decide(&ram, &req(true, Some("S1")))), vec!["boot_media"], "needs the flag");
        assert_eq!(decide(&ram, &with_flag), Ok(()));
        let mut no_destructive = with_flag.clone();
        no_destructive.destructive = false;
        assert_eq!(codes(decide(&ram, &no_destructive)), vec!["not_destructive", "boot_media"]);
        let mut no_serial = with_flag.clone();
        no_serial.serial = None;
        assert_eq!(codes(decide(&ram, &no_serial)), vec!["serial_missing", "boot_media"]);
        let mut wrong = with_flag.clone();
        wrong.serial = Some("S2".into());
        assert_eq!(codes(decide(&ram, &wrong)), vec!["serial_mismatch", "boot_media"]);
        // the flag never lifts the other absolute reasons
        ram.mounts.push("/mnt".into());
        assert_eq!(codes(decide(&ram, &with_flag)), vec!["mounted"]);
        let mut mounted = dev(Some("S1"));
        mounted.mounts.push("/mnt".into());
        assert_eq!(codes(decide(&mounted, &req(true, Some("S1")))), vec!["mounted"]);
    }
}
