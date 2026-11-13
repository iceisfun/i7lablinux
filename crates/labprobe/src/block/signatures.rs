//! Filesystem / RAID / LVM / LUKS / swap signature detection on raw bytes. Pure. Owner: P4.
//!
//! `detect` looks at the head of a device (or partition) and gives byte offsets relative to the buffer start; the
//! caller adds the base offset. `detect_tail` covers formats whose metadata sits at the end (md 0.90 / 1.0).
//! No match means "no known signature", never "blank": the gate also refuses by partition table and the operator
//! needs `--destructive --serial` for anything that carries a structure.

use labproto::json::{JsonWriter, ToJson};

#[derive(Clone, Debug, PartialEq)]
pub struct Signature {
    /// "ext2" "ext3" "ext4" "xfs" "btrfs" "vfat" "exfat" "ntfs" "bitlocker" "iso9660" "udf" "squashfs" "erofs"
    /// "luks" "lvm2" "swap" "linux_raid_member" "zfs_member" "bcachefs" "f2fs" "hfsplus"
    pub kind: String,
    /// byte offset on the device where the magic was found
    pub offset: u64,
    pub label: Option<String>,
    pub uuid: Option<String>,
}

fn at(h: &[u8], off: usize, n: usize) -> Option<&[u8]> {
    h.get(off..off.checked_add(n)?)
}

fn has(h: &[u8], off: usize, magic: &[u8]) -> bool {
    at(h, off, magic.len()) == Some(magic)
}

/// Text field: bytes up to the first NUL, trailing spaces/NULs trimmed, `None` if empty or not printable.
fn text(h: &[u8], off: usize, n: usize) -> Option<String> {
    let b = at(h, off, n)?;
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    let s = String::from_utf8_lossy(&b[..end]).trim_end().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn uuid16(h: &[u8], off: usize) -> Option<String> {
    let b = at(h, off, 16)?;
    if b.iter().all(|x| *x == 0) {
        return None;
    }
    let hex: Vec<String> = b.iter().map(|x| format!("{:02x}", x)).collect();
    let s = hex.concat();
    Some(format!("{}-{}-{}-{}-{}", &s[0..8], &s[8..12], &s[12..16], &s[16..20], &s[20..32]))
}

fn sig(kind: &str, offset: usize, label: Option<String>, uuid: Option<String>) -> Signature {
    Signature { kind: kind.into(), offset: offset as u64, label, uuid }
}

/// Look for signatures in `head` (the first bytes of a device or partition, at least 1 MiB when available).
pub fn detect(h: &[u8]) -> Vec<Signature> {
    let mut v = Vec::new();

    // ext2/3/4: superblock at 1024, magic 0xEF53 at +56
    if has(h, 0x438, &[0x53, 0xEF]) {
        let compat = at(h, 0x45C, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).unwrap_or(0);
        let incompat = at(h, 0x460, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).unwrap_or(0);
        let kind = if incompat & (0x40 | 0x80 | 0x200) != 0 {
            "ext4"
        } else if compat & 0x4 != 0 {
            "ext3"
        } else {
            "ext2"
        };
        v.push(sig(kind, 0x438, text(h, 0x478, 16), uuid16(h, 0x468)));
    }
    if has(h, 0, b"XFSB") {
        v.push(sig("xfs", 0, text(h, 108, 12), uuid16(h, 32)));
    }
    if has(h, 0x10040, b"_BHRfS_M") {
        v.push(sig("btrfs", 0x10040, text(h, 0x1012b, 256), uuid16(h, 0x10020)));
    }
    // FAT family: boot signature + type string
    if has(h, 510, &[0x55, 0xAA]) {
        if has(h, 0x52, b"FAT32   ") {
            let id = at(h, 0x43, 4).map(|b| format!("{:02X}{:02X}-{:02X}{:02X}", b[3], b[2], b[1], b[0]));
            v.push(sig("vfat", 0x52, text(h, 0x47, 11), id));
        } else if has(h, 0x36, b"FAT16   ") || has(h, 0x36, b"FAT12   ") || has(h, 0x36, b"FAT     ") {
            let id = at(h, 0x27, 4).map(|b| format!("{:02X}{:02X}-{:02X}{:02X}", b[3], b[2], b[1], b[0]));
            v.push(sig("vfat", 0x36, text(h, 0x2B, 11), id));
        }
    }
    if has(h, 3, b"EXFAT   ") {
        v.push(sig("exfat", 3, None, None));
    }
    if has(h, 3, b"NTFS    ") {
        let id = at(h, 0x48, 8).map(|b| b.iter().rev().map(|x| format!("{:02X}", x)).collect::<String>());
        v.push(sig("ntfs", 3, None, id));
    }
    if has(h, 3, b"-FVE-FS-") {
        v.push(sig("bitlocker", 3, None, None));
    }
    if has(h, 0x8001, b"CD001") {
        v.push(sig("iso9660", 0x8001, text(h, 0x8028, 32), None));
    }
    if has(h, 0x8001, b"BEA01") {
        v.push(sig("udf", 0x8001, None, None));
    }
    if has(h, 0, b"hsqs") {
        v.push(sig("squashfs", 0, None, None));
    }
    if has(h, 1024, &[0xE2, 0xE1, 0xF5, 0xE0]) {
        v.push(sig("erofs", 1024, None, None));
    }
    if has(h, 1024, &[0x10, 0x20, 0xF5, 0xF2]) {
        v.push(sig("f2fs", 1024, None, uuid16(h, 1024 + 108)));
    }
    if has(h, 1024, b"H+") || has(h, 1024, b"HX") {
        v.push(sig("hfsplus", 1024, None, None));
    }
    if has(h, 0, b"LUKS\xba\xbe") || has(h, 0, b"SKUL\xba\xbe") {
        v.push(sig("luks", 0, None, text(h, 168, 40)));
    }
    for sector in [0usize, 512, 1024, 1536] {
        if has(h, sector, b"LABELONE") && has(h, sector + 24, b"LVM2 001") {
            v.push(sig("lvm2", sector, None, None));
            break;
        }
    }
    for page in [4096usize, 8192, 16384, 65536] {
        if page < 10 || h.len() < page {
            continue;
        }
        if has(h, page - 10, b"SWAPSPACE2") || has(h, page - 10, b"SWAP-SPACE") {
            v.push(sig("swap", page - 10, text(h, 0x41c, 16), uuid16(h, 0x40c)));
            break;
        }
    }
    // md superblocks: v1.1 at 0, v1.2 at 4096 (magic a92b4efc LE)
    for off in [0usize, 4096] {
        if has(h, off, &[0xFC, 0x4E, 0x2B, 0xA9]) {
            v.push(sig("linux_raid_member", off, text(h, off + 32, 32), None));
            break;
        }
    }
    // zfs: uberblock magic 0x00bab10c (LE) in the uberblock ring at 128 KiB, slots 1 KiB apart (ashift 9)
    for slot in 0..16usize {
        if has(h, 0x20000 + slot * 1024, &[0x0C, 0xB1, 0xBA, 0x00]) {
            v.push(sig("zfs_member", 0x20000 + slot * 1024, None, None));
            break;
        }
    }
    if has(h, 0x1018, &[0xC6, 0x85, 0x73, 0xF6, 0x4E, 0x1A, 0x45, 0xCA, 0x82, 0x65, 0xF5, 0x7F, 0x48, 0xBA, 0x6D, 0x81]) {
        v.push(sig("bcachefs", 0x1018, None, None));
    }
    v
}

/// md 0.90 (superblock in the last 64 KiB-aligned 64 KiB) and 1.0 (4 KiB-aligned, 8 KiB from the end).
/// `tail` is the last bytes of the device starting at device offset `tail_off`; `size` is the device size.
pub fn detect_tail(tail: &[u8], tail_off: u64, size: u64) -> Vec<Signature> {
    let magic = [0xFC, 0x4E, 0x2B, 0xA9];
    let mut cands: Vec<u64> = Vec::new();
    if size >= 128 * 1024 {
        cands.push((size & !(64 * 1024 - 1)) - 64 * 1024); // 0.90
    }
    if size >= 16 * 1024 {
        cands.push((size - 8 * 1024) & !4095); // 1.0
    }
    for off in cands {
        if off >= tail_off {
            let rel = (off - tail_off) as usize;
            if has(tail, rel, &magic) {
                return vec![Signature { kind: "linux_raid_member".into(), offset: off, label: text(tail, rel + 32, 32), uuid: None }];
            }
        }
    }
    Vec::new()
}

impl ToJson for Signature {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_str("kind", &self.kind);
        w.field_u64("offset", self.offset);
        w.field_opt_str("label", self.label.as_deref());
        w.field_opt_str("uuid", self.uuid.as_deref());
        w.end_object();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(b: &mut Vec<u8>, off: usize, data: &[u8]) {
        if b.len() < off + data.len() {
            b.resize(off + data.len(), 0);
        }
        b[off..off + data.len()].copy_from_slice(data);
    }

    fn kinds(b: &[u8]) -> Vec<String> {
        detect(b).into_iter().map(|s| s.kind).collect()
    }

    #[test]
    fn blank_is_empty() {
        assert!(detect(&vec![0u8; 1 << 20]).is_empty());
        assert!(detect(&[]).is_empty());
        assert!(detect(&vec![0xFFu8; 1 << 20]).is_empty());
    }

    #[test]
    fn ext_variants_with_label_uuid() {
        let mut b = vec![0u8; 1 << 20];
        put(&mut b, 0x438, &[0x53, 0xEF]);
        put(&mut b, 0x478, b"rootfs");
        put(&mut b, 0x468, &[0xAB; 16]);
        let s = &detect(&b)[0];
        assert_eq!((s.kind.as_str(), s.label.as_deref()), ("ext2", Some("rootfs")));
        assert_eq!(s.uuid.as_deref(), Some("abababab-abab-abab-abab-abababababab"));
        put(&mut b, 0x45C, &4u32.to_le_bytes());
        assert_eq!(kinds(&b), ["ext3"]);
        put(&mut b, 0x460, &0x40u32.to_le_bytes());
        assert_eq!(kinds(&b), ["ext4"]);
    }

    #[test]
    fn fat_ntfs_exfat_xfs() {
        let mut b = vec![0u8; 1 << 20];
        put(&mut b, 510, &[0x55, 0xAA]);
        put(&mut b, 0x52, b"FAT32   ");
        put(&mut b, 0x47, b"ESP        ");
        put(&mut b, 0x43, &[0x78, 0x56, 0x34, 0x12]);
        let s = &detect(&b)[0];
        assert_eq!((s.kind.as_str(), s.label.as_deref(), s.uuid.as_deref()), ("vfat", Some("ESP"), Some("1234-5678")));
        let mut n = vec![0u8; 4096];
        put(&mut n, 3, b"NTFS    ");
        assert_eq!(kinds(&n), ["ntfs"]);
        let mut e = vec![0u8; 4096];
        put(&mut e, 3, b"EXFAT   ");
        assert_eq!(kinds(&e), ["exfat"]);
        let mut x = vec![0u8; 4096];
        put(&mut x, 0, b"XFSB");
        assert_eq!(kinds(&x), ["xfs"]);
        // FAT string without the boot signature is not enough
        let mut f = vec![0u8; 4096];
        put(&mut f, 0x52, b"FAT32   ");
        assert!(kinds(&f).is_empty());
    }

    #[test]
    fn deep_offsets_btrfs_iso_zfs_bcachefs() {
        let mut b = vec![0u8; 1 << 20];
        put(&mut b, 0x10040, b"_BHRfS_M");
        put(&mut b, 0x1012b, b"pool");
        put(&mut b, 0x8001, b"CD001");
        put(&mut b, 0x20000, &[0x0C, 0xB1, 0xBA, 0x00]);
        put(&mut b, 0x1018, &[0xC6, 0x85, 0x73, 0xF6, 0x4E, 0x1A, 0x45, 0xCA, 0x82, 0x65, 0xF5, 0x7F, 0x48, 0xBA, 0x6D, 0x81]);
        let k = kinds(&b);
        for want in ["btrfs", "iso9660", "zfs_member", "bcachefs"] {
            assert!(k.iter().any(|x| x == want), "{want} in {k:?}");
        }
        assert_eq!(detect(&b).iter().find(|s| s.kind == "btrfs").unwrap().label.as_deref(), Some("pool"));
    }

    #[test]
    fn luks_lvm_swap_md() {
        let mut b = vec![0u8; 1 << 20];
        put(&mut b, 0, b"LUKS\xba\xbe");
        assert_eq!(kinds(&b), ["luks"]);
        let mut l = vec![0u8; 4096];
        put(&mut l, 512, b"LABELONE");
        put(&mut l, 512 + 24, b"LVM2 001");
        assert_eq!(kinds(&l), ["lvm2"]);
        let mut s = vec![0u8; 8192];
        put(&mut s, 0xff6, b"SWAPSPACE2");
        assert_eq!(kinds(&s), ["swap"]);
        let mut m = vec![0u8; 8192];
        put(&mut m, 4096, &[0xFC, 0x4E, 0x2B, 0xA9]);
        assert_eq!(kinds(&m), ["linux_raid_member"]);
    }

    #[test]
    fn md_tail_formats() {
        let size: u64 = 10 << 20;
        let tail_off = size - (1 << 20);
        let mut t = vec![0u8; 1 << 20];
        let off10 = ((size - 8192) & !4095) - tail_off;
        put(&mut t, off10 as usize, &[0xFC, 0x4E, 0x2B, 0xA9]);
        let s = detect_tail(&t, tail_off, size);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].offset, (size - 8192) & !4095);
        let mut t = vec![0u8; 1 << 20];
        put(&mut t, ((size & !0xFFFF) - 65536 - tail_off) as usize, &[0xFC, 0x4E, 0x2B, 0xA9]);
        assert_eq!(detect_tail(&t, tail_off, size).len(), 1);
        assert!(detect_tail(&vec![0u8; 1 << 20], tail_off, size).is_empty());
    }
}
