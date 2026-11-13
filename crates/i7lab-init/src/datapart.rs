//! Optional data partition by filesystem label (`i7lab.data=LABEL[,rw]`, default label I7LABDATA, mounted on /data
//! nodev,nosuid,noexec, read-only unless `,rw`). No udev: labels are read from the superblocks of the block devices.
//! Only ext2/3/4 and FAT are recognised. Reading a superblock never writes to the device.

use crate::ffi;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fs {
    Ext,
    Vfat,
}

impl Fs {
    pub fn kernel_name(self) -> &'static str {
        match self {
            Fs::Ext => "ext4",
            Fs::Vfat => "vfat",
        }
    }
}

/// Bytes needed from the start of the device.
pub const HEAD: usize = 2048;

fn trim_label(b: &[u8], space_padded: bool) -> String {
    let end = if space_padded { b.iter().rposition(|&c| c != b' ' && c != 0).map(|i| i + 1).unwrap_or(0) } else { b.iter().position(|&c| c == 0).unwrap_or(b.len()) };
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// Identify a filesystem and its label from the first `HEAD` bytes.
pub fn identify(head: &[u8]) -> Option<(Fs, String)> {
    // ext2/3/4: superblock at 1024, magic 0xEF53 at +56, label (16 bytes) at +120
    if head.len() >= 1024 + 136 && head[1024 + 56] == 0x53 && head[1024 + 57] == 0xEF {
        return Some((Fs::Ext, trim_label(&head[1024 + 120..1024 + 136], false)));
    }
    // FAT: 0x55AA at 510, then the BPB. FAT32 has "FAT32   " at 82 and the label at 71; FAT12/16 "FAT" at 54, label at 43.
    if head.len() >= 512 && head[510] == 0x55 && head[511] == 0xAA {
        if &head[82..87] == b"FAT32" {
            return Some((Fs::Vfat, trim_label(&head[71..82], true)));
        }
        if &head[54..57] == b"FAT" {
            return Some((Fs::Vfat, trim_label(&head[43..54], true)));
        }
    }
    None
}

/// Block devices worth probing: partitions and whole disks, not loop/ram/zram/dm/optical/md/nbd.
pub fn candidate(name: &str) -> bool {
    const SKIP: &[&str] = &["loop", "ram", "zram", "dm-", "sr", "md", "nbd", "fd"];
    !SKIP.iter().any(|p| name.starts_with(p))
}

fn read_head(dev: &str) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(format!("/dev/{}", dev)).ok()?;
    let mut buf = vec![0u8; HEAD];
    let mut n = 0;
    while n < HEAD {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => break,
        }
    }
    buf.truncate(n);
    Some(buf)
}

/// Find the first device carrying `label`: (device name, filesystem).
pub fn find(label: &str) -> Option<(String, Fs)> {
    let mut names: Vec<String> = std::fs::read_dir("/sys/class/block").ok()?.flatten().filter_map(|e| e.file_name().into_string().ok()).filter(|n| candidate(n)).collect();
    names.sort();
    for n in names {
        if let Some((fs, l)) = read_head(&n).and_then(|h| identify(&h)) {
            if l == label {
                return Some((n, fs));
            }
        }
    }
    None
}

/// Mount `label` on /data. Returns the device name when mounted.
pub fn mount_by_label(label: &str, rw: bool) -> Option<String> {
    let (dev, fs) = find(label)?;
    let _ = std::fs::create_dir_all("/data");
    let mut flags = ffi::MS_NOSUID | ffi::MS_NODEV | ffi::MS_NOEXEC | ffi::MS_NOATIME;
    if !rw {
        flags |= ffi::MS_RDONLY;
    }
    match ffi::do_mount(&format!("/dev/{}", dev), "/data", fs.kernel_name(), flags, None) {
        Ok(()) => Some(dev),
        Err(e) => {
            crate::logf!("data partition {dev} ({}): mount failed: {e}", fs.kernel_name());
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(label: &str) -> Vec<u8> {
        let mut b = vec![0u8; HEAD];
        b[1024 + 56] = 0x53;
        b[1024 + 57] = 0xEF;
        b[1024 + 120..1024 + 120 + label.len()].copy_from_slice(label.as_bytes());
        b
    }
    fn fat32(label: &str) -> Vec<u8> {
        let mut b = vec![0u8; HEAD];
        b[510] = 0x55;
        b[511] = 0xAA;
        b[82..90].copy_from_slice(b"FAT32   ");
        let mut l = label.as_bytes().to_vec();
        l.resize(11, b' ');
        b[71..82].copy_from_slice(&l);
        b
    }

    #[test]
    fn ext_label() {
        assert_eq!(identify(&ext("I7LABDATA")), Some((Fs::Ext, "I7LABDATA".into())));
        assert_eq!(identify(&ext("")), Some((Fs::Ext, String::new())));
    }
    #[test]
    fn fat32_label_is_space_trimmed() {
        assert_eq!(identify(&fat32("I7LABESP")), Some((Fs::Vfat, "I7LABESP".into())));
    }
    #[test]
    fn fat16_label() {
        let mut b = vec![0u8; HEAD];
        b[510] = 0x55;
        b[511] = 0xAA;
        b[54..62].copy_from_slice(b"FAT16   ");
        b[43..54].copy_from_slice(b"SCRATCH    ");
        assert_eq!(identify(&b), Some((Fs::Vfat, "SCRATCH".into())));
    }
    #[test]
    fn unknown_and_short() {
        assert_eq!(identify(&vec![0u8; HEAD]), None);
        assert_eq!(identify(&[1, 2, 3]), None);
    }
    #[test]
    fn candidates() {
        assert!(candidate("sda1") && candidate("nvme0n1p2") && candidate("vda"));
        assert!(!candidate("loop0") && !candidate("sr0") && !candidate("dm-0") && !candidate("zram0"));
    }
}
