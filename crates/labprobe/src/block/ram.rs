//! "Is this host fully RAM-resident?" (the only case in which the boot media may be overwritten, see
//! docs/PLAN.md section 6 and docs/I7LABCTL.md `--allow-boot-media`). Pure: everything is passed in as text, so the
//! policy is host-testable with synthetic `/proc/self/mountinfo`.

use super::enumerate::{parse_mountinfo, parse_swaps, MountEntry};
use super::BlockDevice;

/// Does the kernel name `n` (`sda1`, `nvme0n1p3`, `/dev/sda1`) denote the disk `disk` or one of its partitions?
pub fn names_disk(n: &str, disk: &str) -> bool {
    let base = n.strip_prefix("/dev/").unwrap_or(n);
    let Some(rest) = base.strip_prefix(disk) else { return false };
    if rest.is_empty() {
        return true;
    }
    // a disk whose name ends in a digit (nvme0n1, mmcblk0, loop0) separates the partition number with a 'p'
    let digits = if disk.ends_with(|c: char| c.is_ascii_digit()) { rest.strip_prefix('p') } else { Some(rest) };
    matches!(digits, Some(d) if !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

fn on_disk(m: &MountEntry, dev: &BlockDevice, devnos: &[(u32, u32)]) -> bool {
    m.devno == dev.devno || devnos.contains(&m.devno) || names_disk(&m.source, &dev.name)
}

/// `Ok(())` only if the running system lives entirely in RAM as far as `dev` is concerned:
/// * the root filesystem (the last mount on `/`) is rootfs, tmpfs or ramfs;
/// * no mount at all has its source on `dev` or any of its partitions (`devnos`: the device numbers of the disk and
///   its partitions);
/// * `dev` has no holders (device-mapper, md, loop) and is not an active swap area (`/proc/swaps`);
/// * `exe_path` (the daemon's own `/proc/self/exe`) is not on `dev`.
/// Every failed condition is listed. Unknown input (no root mount, empty exe path) fails closed.
pub fn ram_resident(proc_mountinfo: &str, exe_path: &str, swaps: &str, dev: &BlockDevice, devnos: &[(u32, u32)]) -> Result<(), Vec<String>> {
    let mut why = Vec::new();
    let mounts = parse_mountinfo(proc_mountinfo);
    match mounts.iter().rev().find(|m| m.mountpoint == "/") {
        Some(r) if matches!(r.fstype.as_str(), "rootfs" | "tmpfs" | "ramfs") => {
            if on_disk(r, dev, devnos) {
                why.push(format!("root {} source {} is on the disk", r.fstype, r.source));
            }
        }
        Some(r) => why.push(format!("root filesystem is {} on {}, not rootfs/tmpfs/ramfs", r.fstype, r.source)),
        None => why.push("no root mount found in mountinfo".to_string()),
    }
    for m in mounts.iter().filter(|m| on_disk(m, dev, devnos)) {
        why.push(format!("{} is mounted from the disk ({} {})", m.mountpoint, m.fstype, m.source));
    }
    for h in &dev.holders {
        why.push(format!("held by {}", h));
    }
    if dev.swap || parse_swaps(swaps).iter().any(|s| names_disk(s, &dev.name)) {
        why.push("swap on the disk".to_string());
    }
    let exe = exe_path.strip_suffix(" (deleted)").unwrap_or(exe_path);
    if !exe.starts_with('/') {
        why.push("the daemon's own executable path is unknown".to_string());
    } else {
        // the mount covering the executable: longest mount point that is a path prefix, later entries win
        let cover = mounts
            .iter()
            .filter(|m| m.mountpoint == "/" || exe == m.mountpoint || exe.starts_with(&format!("{}/", m.mountpoint.trim_end_matches('/'))))
            .fold(None::<&MountEntry>, |best, m| match best {
                Some(b) if b.mountpoint.len() > m.mountpoint.len() => Some(b),
                _ => Some(m),
            });
        match cover {
            Some(m) if on_disk(m, dev, devnos) => why.push(format!("the daemon's executable {} is on the disk", exe)),
            Some(_) => {}
            None => why.push("the daemon's executable is on no known mount".to_string()),
        }
    }
    if why.is_empty() {
        Ok(())
    } else {
        Err(why)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{DiskKind, WriteSafety};

    fn dev(name: &str) -> BlockDevice {
        BlockDevice {
            name: name.into(),
            devno: (259, 0),
            size_bytes: 1 << 30,
            logical_block: 512,
            physical_block: 512,
            kind: DiskKind::Nvme,
            model: None,
            vendor: None,
            serial: Some("S".into()),
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
            boot_media: true,
            ram_resident: false,
            write_safety: WriteSafety::default(),
        }
    }

    const PARTS: &[(u32, u32)] = &[(259, 0), (259, 1), (259, 3)];
    const RAM: &str = "1 1 0:2 / / rw - rootfs rootfs rw\n20 1 0:19 / /run/i7lab rw - tmpfs tmpfs rw\n21 1 0:5 / /proc rw - proc proc rw\n";
    const SWAPS: &str = "Filename Type Size Used Priority\n";
    const EXE: &str = "/usr/sbin/i7labd";

    fn r(mi: &str, exe: &str, sw: &str, d: &BlockDevice) -> Result<(), Vec<String>> {
        ram_resident(mi, exe, sw, d, PARTS)
    }

    #[test]
    fn root_on_rootfs_or_tmpfs_is_resident() {
        let d = dev("nvme0n1");
        assert_eq!(r(RAM, EXE, SWAPS, &d), Ok(()));
        assert_eq!(r("2 1 0:21 / / rw - tmpfs tmpfs rw\n", EXE, SWAPS, &d), Ok(()));
        assert_eq!(r("2 1 0:21 / / rw - ramfs ramfs rw\n", EXE, SWAPS, &d), Ok(()));
        // unrelated disk mounted somewhere is fine
        let mi = format!("{}40 1 8:17 / /mnt rw - ext4 /dev/sdb1 rw\n", RAM);
        assert_eq!(r(&mi, EXE, SWAPS, &d), Ok(()));
    }

    #[test]
    fn root_on_the_disk_is_refused() {
        let d = dev("nvme0n1");
        let e = r("1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n", EXE, SWAPS, &d).unwrap_err();
        assert!(e.iter().any(|x| x.contains("not rootfs/tmpfs/ramfs")), "{e:?}");
        assert!(e.iter().any(|x| x.contains("mounted from the disk")), "{e:?}");
        // root on any non-RAM filesystem is refused even when it is another disk
        assert!(r("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n", EXE, SWAPS, &d).is_err());
        // no root mount at all fails closed
        assert!(r("21 1 0:5 / /proc rw - proc proc rw\n", EXE, SWAPS, &d).is_err());
        assert!(r("", EXE, SWAPS, &d).is_err());
    }

    #[test]
    fn any_mount_from_the_disk_is_refused() {
        let d = dev("nvme0n1");
        // by device number
        let by_dev = format!("{}40 1 259:1 / /boot/efi rw - vfat /dev/xyz rw\n", RAM);
        assert!(r(&by_dev, EXE, SWAPS, &d).unwrap_err()[0].contains("/boot/efi"));
        // by source name only (devno unknown to us)
        let by_name = format!("{}40 1 259:9 / /data rw - ext4 /dev/nvme0n1p9 rw\n", RAM);
        assert!(r(&by_name, EXE, SWAPS, &d).is_err());
        // a bind mount of a subdirectory still names the device
        let bind = format!("{}40 1 259:3 /var/lib /srv rw - ext4 /dev/nvme0n1p3 rw\n", RAM);
        assert!(r(&bind, EXE, SWAPS, &d).is_err());
        // nvme0n10 is another disk, not a partition of nvme0n1
        let other = format!("{}40 1 259:90 / /x rw - ext4 /dev/nvme0n10p1 rw\n", RAM);
        assert_eq!(r(&other, EXE, SWAPS, &d), Ok(()));
    }

    #[test]
    fn own_executable_on_the_disk_is_refused() {
        let d = dev("nvme0n1");
        let mi = format!("{}41 1 259:1 / /opt rw - ext4 /dev/nvme0n1p1 rw\n", RAM);
        // the mount is itself refused; the exe finding is reported in addition
        let e = r(&mi, "/opt/i7lab/i7labd", SWAPS, &d).unwrap_err();
        assert!(e.iter().any(|x| x.contains("executable")), "{e:?}");
        // exe under a different mount point of the same disk, and with a (deleted) suffix
        let e = r(&mi, "/opt/i7labd (deleted)", SWAPS, &d).unwrap_err();
        assert!(e.iter().any(|x| x.contains("executable /opt/i7labd")), "{e:?}");
        // /optional is not under /opt
        let e = r(&mi, "/optional/i7labd", SWAPS, &d).unwrap_err();
        assert!(!e.iter().any(|x| x.contains("executable")), "{e:?}");
        assert!(r(RAM, "", SWAPS, &d).is_err(), "unknown exe fails closed");
    }

    #[test]
    fn swap_on_the_disk_is_refused() {
        let d = dev("nvme0n1");
        let sw = "Filename Type Size Used Priority\n/dev/nvme0n1p2 partition 1024 0 -2\n";
        assert!(r(RAM, EXE, sw, &d).unwrap_err()[0].contains("swap"));
        let mut s = dev("nvme0n1");
        s.swap = true;
        assert!(r(RAM, EXE, SWAPS, &s).is_err());
        let other = "Filename Type Size Used Priority\n/dev/sdb2 partition 1024 0 -2\n";
        assert_eq!(r(RAM, EXE, other, &d), Ok(()));
    }

    #[test]
    fn dm_md_loop_holders_are_refused() {
        for h in ["dm-0", "md0", "loop0"] {
            let mut d = dev("nvme0n1");
            d.holders.push(h.into());
            assert!(r(RAM, EXE, SWAPS, &d).unwrap_err()[0].contains(h));
        }
    }

    #[test]
    fn names() {
        assert!(names_disk("/dev/sda", "sda") && names_disk("sda12", "sda") && names_disk("nvme0n1p3", "nvme0n1"));
        assert!(!names_disk("sdab1", "sda") && !names_disk("nvme0n12", "nvme0n1") && !names_disk("sdb1", "sda") && !names_disk("sda1x", "sda"));
    }
}
