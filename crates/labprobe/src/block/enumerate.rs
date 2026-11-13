//! /sys/block walk + identity (model, serial, wwid), partition table and signatures read from the device,
//! mounts (mountinfo), holders, swap, boot media. Owner: P4.
//!
//! Everything is read through `ctx` (`ctx.root` = "/" live, a fixture tree in tests; `/dev/<name>` may be a
//! regular file in a fixture). Content reads (partition table + signatures) are cached for 10 s on the live root
//! so a refreshing TUI does not re-read every disk; `WriteGuard` never uses the cache.

use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::ctx::{ProbeCtx, ProbeError};

use super::ioctl;
use super::parttable::{self, PartTable, Partition};
use super::signatures::{self, Signature};
use super::{BlockDevice, BlockReport, DiskKind, SerialSource};

const MIB: u64 = 1 << 20;
const MAX_PART_SCAN: usize = 32;

pub fn enumerate(ctx: &ProbeCtx, all: bool) -> Result<BlockReport, ProbeError> {
    let mut rep = BlockReport::default();
    for name in ctx.list_dir("/sys/block")? {
        if !all && ["loop", "ram", "zram", "dm-", "md", "nbd"].iter().any(|p| name.starts_with(p)) {
            continue;
        }
        if let Ok(d) = describe(ctx, &name) {
            rep.devices.push(d);
        }
    }
    Ok(rep)
}

/// What the device itself says: partition table, partitions, signatures. `read_ok` false = could not read.
#[derive(Clone, Debug, Default)]
pub struct Content {
    pub table: Option<PartTable>,
    pub partitions: Vec<Partition>,
    pub signatures: Vec<Signature>,
    pub read_ok: bool,
}

/// Read the partition table and signatures from an open device: head 1 MiB, tail 1 MiB, the GPT backup header
/// and the first MiB of each partition. Works on O_DIRECT fds (aligned buffer, block-multiple lengths).
pub fn read_content(file: &File, size: u64, block: u32) -> Content {
    let mut c = Content::default();
    let block = block.max(512) as u64;
    if size < block * 2 {
        return c;
    }
    let mut head = ioctl::AlignedBuf::new((MIB.min(size) / block * block) as usize);
    let hlen = head.len().min((size / block * block) as usize);
    let n = match ioctl::read_full_at(file, &mut head.as_mut_slice()[..hlen], 0) {
        Ok(n) => n,
        Err(_) => return c,
    };
    let head = &head.as_slice()[..n];
    c.read_ok = true;
    let mut sigs = signatures::detect(head);
    if let Some((mut t, parts)) = parttable::parse(head, block as u32) {
        let superfloppy = t.kind == "mbr" && sigs.iter().any(|s| s.offset < 512 && matches!(s.kind.as_str(), "vfat" | "exfat" | "ntfs" | "bitlocker"));
        if !superfloppy {
            if t.kind == "gpt" {
                let last = size / block - 1;
                let mut one = ioctl::AlignedBuf::new(block as usize);
                if let Ok(m) = ioctl::read_full_at(file, &mut one.as_mut_slice()[..block as usize], last * block) {
                    t.backup_ok = Some(parttable::check_backup(&one.as_slice()[..m], last));
                }
            }
            c.table = Some(t);
            c.partitions = parts;
        }
    }
    // tail: md 0.90 / 1.0 live at the end
    let tail_len = (MIB.min(size) / block * block) as usize;
    let tail_off = (size / block * block).saturating_sub(tail_len as u64);
    let mut tail = ioctl::AlignedBuf::new(tail_len);
    if let Ok(m) = ioctl::read_full_at(file, &mut tail.as_mut_slice()[..tail_len], tail_off) {
        sigs.extend(signatures::detect_tail(&tail.as_slice()[..m], tail_off, size));
    }
    // each partition's first MiB
    let mut pbuf = ioctl::AlignedBuf::new(MIB as usize);
    for p in c.partitions.iter().take(MAX_PART_SCAN) {
        let off = p.first_lba.saturating_mul(block);
        if off + block > size || p.last_lba < p.first_lba {
            continue;
        }
        let want = ((p.last_lba - p.first_lba + 1).saturating_mul(block)).min(MIB).min(size - off) / block * block;
        if want == 0 {
            continue;
        }
        if let Ok(m) = ioctl::read_full_at(file, &mut pbuf.as_mut_slice()[..want as usize], off) {
            for mut s in signatures::detect(&pbuf.as_slice()[..m]) {
                s.offset += off;
                sigs.push(s);
            }
        }
    }
    sigs.sort_by(|a, b| a.offset.cmp(&b.offset).then(a.kind.cmp(&b.kind)));
    sigs.dedup_by(|a, b| a.offset == b.offset && a.kind == b.kind);
    c.signatures = sigs;
    c
}

type CacheKey = (String, String);
static CACHE: OnceLock<Mutex<HashMap<CacheKey, (Instant, u64, Content)>>> = OnceLock::new();

fn cache() -> &'static Mutex<HashMap<CacheKey, (Instant, u64, Content)>> {
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Forget cached content of a disk (called after a write).
pub fn invalidate(name: &str) {
    if let Ok(mut m) = cache().lock() {
        m.retain(|k, _| k.1 != name);
    }
}

fn content_for(ctx: &ProbeCtx, name: &str, size: u64, block: u32) -> Content {
    let live = ctx.root == Path::new("/");
    let key = (ctx.root.to_string_lossy().into_owned(), name.to_string());
    if live {
        if let Ok(m) = cache().lock() {
            if let Some((t, sz, c)) = m.get(&key) {
                if *sz == size && t.elapsed() < Duration::from_secs(10) {
                    return c.clone();
                }
            }
        }
    }
    let c = match ioctl::open(&ctx.path(&format!("/dev/{}", name)), false, false, true) {
        Ok(f) => read_content(&f, size, block),
        Err(_) => Content::default(),
    };
    if live {
        if let Ok(mut m) = cache().lock() {
            m.insert(key, (Instant::now(), size, c.clone()));
        }
    }
    c
}

// ---------------------------------------------------------------------------------------------------------------
// sysfs identity

/// Canonical sysfs path with the fixture root stripped (e.g. "/devices/pci0000:00/.../block/sda").
pub fn real_sys_path(ctx: &ProbeCtx, sys_path: &str) -> Option<String> {
    let real = std::fs::canonicalize(ctx.path(sys_path)).ok()?;
    let root = std::fs::canonicalize(&ctx.root).ok()?;
    let rel = real.strip_prefix(&root).ok()?;
    Some(format!("/{}", rel.to_string_lossy()))
}

fn seg_is(seg: &str, prefix: &str) -> bool {
    seg.strip_prefix(prefix).map(|r| r.is_empty() || r.as_bytes()[0].is_ascii_digit()).unwrap_or(false)
}

/// Transport from the canonical sysfs path segments; `None` when no segment decides.
pub fn kind_from_path(path: &str) -> Option<DiskKind> {
    let segs: Vec<&str> = path.split('/').collect();
    if segs.iter().any(|s| seg_is(s, "usb")) {
        Some(DiskKind::Usb)
    } else if segs.iter().any(|s| s.starts_with("nvme")) {
        Some(DiskKind::Nvme)
    } else if segs.iter().any(|s| seg_is(s, "virtio")) {
        Some(DiskKind::Virtio)
    } else if segs.iter().any(|s| seg_is(s, "ata")) {
        Some(DiskKind::Sata)
    } else if segs.iter().any(|s| s.starts_with("mmc")) {
        Some(DiskKind::Mmc)
    } else if segs.iter().any(|s| seg_is(s, "host")) {
        Some(DiskKind::Scsi)
    } else {
        None
    }
}

/// Kind from the name only (fallback).
pub fn kind_of(name: &str) -> DiskKind {
    if name.starts_with("nvme") {
        DiskKind::Nvme
    } else if name.starts_with("vd") {
        DiskKind::Virtio
    } else if name.starts_with("mmcblk") {
        DiskKind::Mmc
    } else if name.starts_with("sd") {
        DiskKind::Scsi
    } else {
        DiskKind::Other
    }
}

/// SCSI VPD page 0x80 (unit serial number): `[type, 0x80, len_hi, len_lo, serial...]`.
pub fn parse_vpd80(b: &[u8]) -> Option<String> {
    if b.len() < 5 || b[1] != 0x80 {
        return None;
    }
    let len = u16::from_be_bytes([b[2], b[3]]) as usize;
    let payload = b.get(4..(4 + len).min(b.len()))?;
    clean_serial(&String::from_utf8_lossy(payload))
}

/// Trim and reject empty / non-printable serials.
pub fn clean_serial(s: &str) -> Option<String> {
    let t = s.trim_matches(|c: char| c.is_whitespace() || c == '\0').to_string();
    if t.is_empty() || !t.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        None
    } else {
        Some(t)
    }
}

fn usb_ancestor_serial(ctx: &ProbeCtx, real: &str) -> Option<String> {
    let mut p = real.to_string();
    while let Some(i) = p.rfind('/') {
        p.truncate(i);
        if p.is_empty() {
            break;
        }
        if ctx.path(&format!("{}/idVendor", p)).exists() {
            return ctx.read_opt(&format!("{}/serial", p)).and_then(|s| clean_serial(&s));
        }
    }
    None
}

/// Resolve the serial and where it came from: NVMe `device/serial`, virtio `serial`, SCSI VPD 0x80, mmc
/// `device/serial`, then the iSerial of the ancestor USB device. (ATA IDENTIFY via SAT is not issued: libata
/// already exports the ATA serial as VPD 0x80.)
pub fn resolve_serial(ctx: &ProbeCtx, name: &str, kind: DiskKind, real: Option<&str>) -> (Option<String>, Option<SerialSource>) {
    let r = |f: &str| ctx.read_opt(&format!("/sys/block/{}/{}", name, f)).and_then(|s| clean_serial(&s));
    if kind == DiskKind::Nvme {
        if let Some(s) = r("device/serial") {
            return (Some(s), Some(SerialSource::Nvme));
        }
    }
    if kind == DiskKind::Virtio {
        if let Some(s) = r("serial") {
            return (Some(s), Some(SerialSource::Virtio));
        }
    }
    if let Ok(b) = std::fs::read(ctx.path(&format!("/sys/block/{}/device/vpd_pg80", name))) {
        if let Some(s) = parse_vpd80(&b) {
            return (Some(s), Some(SerialSource::Vpd80));
        }
    }
    if kind == DiskKind::Mmc {
        if let Some(s) = r("device/serial") {
            return (Some(s), Some(SerialSource::Mmc));
        }
    }
    if let Some(s) = r("device/serial") {
        // unknown transport exposing device/serial
        return (Some(s), Some(if kind == DiskKind::Nvme { SerialSource::Nvme } else { SerialSource::Vpd80 }));
    }
    if let Some(s) = real.and_then(|p| usb_ancestor_serial(ctx, p)) {
        return (Some(s), Some(SerialSource::Usb));
    }
    (None, None)
}

// ---------------------------------------------------------------------------------------------------------------
// mounts, holders, swap

#[derive(Clone, Debug, PartialEq)]
pub struct MountEntry {
    pub devno: (u32, u32),
    pub mountpoint: String,
    pub fstype: String,
    pub source: String,
}

fn unescape_mount(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            let v = (b[i + 1] - b'0') as u32 * 64 + (b[i + 2] - b'0') as u32 * 8 + (b[i + 3] - b'0') as u32;
            out.push(v as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse /proc/self/mountinfo.
pub fn parse_mountinfo(text: &str) -> Vec<MountEntry> {
    let mut v = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let Some(dash) = f.iter().position(|x| *x == "-") else { continue };
        if f.len() < 6 || f.len() < dash + 3 {
            continue;
        }
        let Some((a, b)) = f[2].split_once(':') else { continue };
        let (Ok(a), Ok(b)) = (a.parse(), b.parse()) else { continue };
        v.push(MountEntry { devno: (a, b), mountpoint: unescape_mount(f[4]), fstype: f[dash + 1].to_string(), source: unescape_mount(f[dash + 2]) });
    }
    v
}

/// Parse /proc/swaps: the file names of active swap areas.
pub fn parse_swaps(text: &str) -> Vec<String> {
    text.lines().skip(1).filter_map(|l| l.split_whitespace().next()).map(unescape_mount).collect()
}

/// A mount point that means the running system lives here.
pub fn is_system_mount(mp: &str) -> bool {
    mp == "/" || mp == "/run/i7lab" || mp.starts_with("/run/i7lab/")
}

/// Partition kernel names of a disk and their device numbers, from sysfs.
fn sysfs_partitions(ctx: &ProbeCtx, name: &str) -> Vec<(String, (u32, u32))> {
    let mut v = Vec::new();
    for e in ctx.list_dir(&format!("/sys/block/{}", name)).unwrap_or_default() {
        if e.starts_with(name) && ctx.path(&format!("/sys/block/{}/{}/partition", name, e)).exists() {
            if let Some(d) = parse_devno(ctx.read_opt(&format!("/sys/block/{}/{}/dev", name, e)).as_deref()) {
                v.push((e, d));
            }
        }
    }
    v
}

fn parse_devno(s: Option<&str>) -> Option<(u32, u32)> {
    let (a, b) = s?.split_once(':')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

/// Mounts / holders / swap state of a disk and its partitions.
pub struct Usage {
    pub mounts: Vec<String>,
    pub holders: Vec<String>,
    pub swap: bool,
}

pub fn usage(ctx: &ProbeCtx, name: &str, devno: (u32, u32)) -> Usage {
    let parts = sysfs_partitions(ctx, name);
    let mut devs = vec![devno];
    devs.extend(parts.iter().map(|p| p.1));
    let mut mounts: Vec<String> = Vec::new();
    if let Ok(t) = std::fs::read_to_string(ctx.path("/proc/self/mountinfo")) {
        for m in parse_mountinfo(&t) {
            if devs.contains(&m.devno) && !mounts.contains(&m.mountpoint) {
                mounts.push(m.mountpoint);
            }
        }
    }
    let mut holders = Vec::new();
    let mut dirs = vec![format!("/sys/block/{}/holders", name)];
    dirs.extend(parts.iter().map(|p| format!("/sys/block/{}/{}/holders", name, p.0)));
    for d in dirs {
        for h in ctx.list_dir(&d).unwrap_or_default() {
            if !holders.contains(&h) {
                holders.push(h);
            }
        }
    }
    let mut names: Vec<String> = parts.iter().map(|p| p.0.clone()).collect();
    names.push(name.to_string());
    let mut swap = false;
    if let Ok(t) = std::fs::read_to_string(ctx.path("/proc/swaps")) {
        for f in parse_swaps(&t) {
            let real = std::fs::canonicalize(ctx.path(&f)).ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
            let base = Path::new(&f).file_name().map(|n| n.to_string_lossy().into_owned());
            if [real, base].into_iter().flatten().any(|n| names.contains(&n)) {
                swap = true;
            }
        }
    }
    Usage { mounts, holders, swap }
}

// ---------------------------------------------------------------------------------------------------------------

/// Boot media: the disk's devno is the cached boot disk, or any partition carries the cached boot PARTUUID.
/// Labels are never used.
pub fn is_boot_media(ctx: &ProbeCtx, devno: (u32, u32), partitions: &[Partition]) -> bool {
    if ctx.boot_disk == Some(devno) {
        return true;
    }
    match &ctx.boot_partuuid {
        Some(u) => partitions.iter().any(|p| p.part_uuid.as_deref().map(|x| x.eq_ignore_ascii_case(u)).unwrap_or(false)),
        None => false,
    }
}

/// Find the whole disk carrying `partuuid` (GPT unique GUID or MBR `<sig>-<nn>`), once at daemon start. Scans every
/// disk's partition table (no udev in the image, so /dev/disk/by-partuuid does not exist).
pub fn resolve_boot_disk(ctx: &ProbeCtx, partuuid: &str) -> Option<(u32, u32)> {
    for name in ctx.list_dir("/sys/block").ok()? {
        if ["loop", "ram", "zram", "dm-", "md", "nbd"].iter().any(|p| name.starts_with(p)) {
            continue;
        }
        let Some(devno) = parse_devno(ctx.read_opt(&format!("/sys/block/{}/dev", name)).as_deref()) else { continue };
        let Ok(f) = ioctl::open(&ctx.path(&format!("/dev/{}", name)), false, false, true) else { continue };
        let size = ioctl::size_bytes(&f).unwrap_or(0);
        let block = ioctl::logical_block(&f).unwrap_or(512) as u64;
        // 192 KiB covers LBA 0..=33 at 512 and 4096 bytes per sector
        let want = (192 * 1024).min(size / block * block) as usize;
        if want < (block as usize) * 2 {
            continue;
        }
        let mut head = ioctl::AlignedBuf::new(want);
        let Ok(n) = ioctl::read_full_at(&f, &mut head.as_mut_slice()[..want], 0) else { continue };
        if let Some((_, parts)) = parttable::parse(&head.as_slice()[..n], block as u32) {
            if parts.iter().any(|p| p.part_uuid.as_deref().map(|x| x.eq_ignore_ascii_case(partuuid)).unwrap_or(false)) {
                return Some(devno);
            }
        }
    }
    None
}

/// Full description of one disk including its write-safety verdict.
pub fn describe(ctx: &ProbeCtx, name: &str) -> Result<BlockDevice, ProbeError> {
    let mut d = describe_basic(ctx, name)?;
    let c = content_for(ctx, name, d.size_bytes, d.logical_block);
    apply_content(&mut d, c);
    finish(ctx, &mut d);
    Ok(d)
}

/// Same, with content read from an already open fd (the write gate's locked fd).
pub fn describe_from(ctx: &ProbeCtx, name: &str, file: &File) -> Result<(BlockDevice, bool), ProbeError> {
    let mut d = describe_basic(ctx, name)?;
    if let Ok(sz) = ioctl::size_bytes(file) {
        d.size_bytes = sz;
    }
    if let Some(b) = ioctl::logical_block(file) {
        d.logical_block = b;
    }
    if ioctl::read_only(file) {
        d.read_only = true;
    }
    let c = read_content(file, d.size_bytes, d.logical_block);
    let ok = c.read_ok;
    apply_content(&mut d, c);
    finish(ctx, &mut d);
    Ok((d, ok))
}

fn apply_content(d: &mut BlockDevice, c: Content) {
    d.partition_table = c.table;
    d.partitions = c.partitions;
    d.signatures = c.signatures;
}

fn finish(ctx: &ProbeCtx, d: &mut BlockDevice) {
    let u = usage(ctx, &d.name, d.devno);
    d.mounts = u.mounts;
    d.holders = u.holders;
    d.swap = u.swap;
    d.boot_media = is_boot_media(ctx, d.devno, &d.partitions);
    d.write_safety = super::guard::assess(ctx, d);
}

/// Everything sysfs knows (no device reads).
pub fn describe_basic(ctx: &ProbeCtx, name: &str) -> Result<BlockDevice, ProbeError> {
    if !ctx.path(&format!("/sys/block/{}", name)).exists() {
        return Err(ProbeError::NotFound(name.to_string()));
    }
    let r = |f: &str| ctx.read_opt(&format!("/sys/block/{}/{}", name, f));
    let devno = parse_devno(r("dev").as_deref()).unwrap_or((0, 0));
    let real = real_sys_path(ctx, &format!("/sys/block/{}", name));
    let kind = real.as_deref().and_then(kind_from_path).unwrap_or_else(|| kind_of(name));
    let (serial, serial_source) = resolve_serial(ctx, name, kind, real.as_deref());
    Ok(BlockDevice {
        name: name.to_string(),
        devno,
        size_bytes: r("size").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0) * 512,
        logical_block: r("queue/logical_block_size").and_then(|s| s.parse().ok()).unwrap_or(512),
        physical_block: r("queue/physical_block_size").and_then(|s| s.parse().ok()).unwrap_or(512),
        kind,
        model: r("device/model"),
        vendor: r("device/vendor"),
        serial,
        serial_source,
        wwid: r("wwid").or_else(|| r("device/wwid")).and_then(|s| clean_serial(&s)),
        firmware_rev: r("device/firmware_rev").or_else(|| r("device/rev")),
        rotational: r("queue/rotational").as_deref() == Some("1"),
        removable: r("removable").as_deref() == Some("1"),
        // optical drives are read-only whatever sysfs says
        read_only: r("ro").as_deref() == Some("1") || name.starts_with("sr"),
        partition_table: None,
        partitions: vec![],
        signatures: vec![],
        mounts: vec![],
        holders: vec![],
        swap: false,
        boot_media: false,
        write_safety: Default::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_from_paths() {
        let k = |p| kind_from_path(p);
        assert_eq!(k("/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0/host6/target6:0:0/6:0:0:0/block/sdb"), Some(DiskKind::Usb));
        assert_eq!(k("/devices/pci0000:00/0000:00:1d.0/0000:3d:00.0/nvme/nvme0/nvme0n1"), Some(DiskKind::Nvme));
        assert_eq!(k("/devices/pci0000:00/0000:00:03.0/virtio0/block/vda"), Some(DiskKind::Virtio));
        assert_eq!(k("/devices/pci0000:00/0000:00:17.0/ata3/host2/target2:0:0/2:0:0:0/block/sda"), Some(DiskKind::Sata));
        assert_eq!(k("/devices/pci0000:00/0000:00:1e.4/mmc_host/mmc0/mmc0:0001/block/mmcblk0"), Some(DiskKind::Mmc));
        assert_eq!(k("/devices/pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block/sda"), Some(DiskKind::Scsi));
        assert_eq!(k("/devices/virtual/block/loop0"), None);
    }

    #[test]
    fn vpd80() {
        let mut b = vec![0u8, 0x80, 0, 8];
        b.extend_from_slice(b"  WD1234 ");
        b.truncate(12);
        assert_eq!(parse_vpd80(&b).as_deref(), Some("WD1234"));
        assert_eq!(parse_vpd80(&[0, 0x83, 0, 1, b'x']), None);
        assert_eq!(parse_vpd80(&[0, 0x80, 0, 2, 0, 0]), None);
    }

    #[test]
    fn mountinfo_and_swaps() {
        let t = "36 35 98:0 /mnt1 /mnt/with\\040space rw,noatime master:1 - ext3 /dev/root rw,errors=continue\n\
                 25 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
                 bogus line\n";
        let m = parse_mountinfo(t);
        assert_eq!(m.len(), 2);
        assert_eq!((m[0].devno, m[0].mountpoint.as_str(), m[0].fstype.as_str()), ((98, 0), "/mnt/with space", "ext3"));
        assert_eq!(m[1].source, "/dev/sda1");
        assert!(is_system_mount("/") && is_system_mount("/run/i7lab/blk") && !is_system_mount("/mnt"));
        assert_eq!(parse_swaps("Filename Type Size Used Priority\n/dev/sda2 partition 1024 0 -2\n"), vec!["/dev/sda2".to_string()]);
    }

    #[test]
    fn serial_cleanup() {
        assert_eq!(clean_serial("  S4EVNX0M \n").as_deref(), Some("S4EVNX0M"));
        assert_eq!(clean_serial("   "), None);
        assert_eq!(clean_serial("a\u{1}b"), None);
    }
}
