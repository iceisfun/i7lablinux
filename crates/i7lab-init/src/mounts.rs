//! The early mount table. Pure data + a tiny driver, so the table is host-testable.

use crate::ffi;

pub struct MountSpec {
    pub src: &'static str,
    pub target: &'static str,
    pub fstype: &'static str,
    pub flags: u64,
    pub data: Option<&'static str>,
    /// only mount when this path exists (efivarfs needs /sys/firmware/efi, configfs its directory)
    pub needs: Option<&'static str>,
    /// a failed mount is logged only when required (absent kernel features are not errors)
    pub required: bool,
}

const NSD: u64 = ffi::MS_NOSUID | ffi::MS_NODEV;

/// Order matters: parents before children.
pub static TABLE: &[MountSpec] = &[
    MountSpec { src: "proc", target: "/proc", fstype: "proc", flags: NSD | ffi::MS_NOEXEC, data: None, needs: None, required: true },
    MountSpec { src: "sysfs", target: "/sys", fstype: "sysfs", flags: NSD | ffi::MS_NOEXEC, data: None, needs: None, required: true },
    MountSpec { src: "devtmpfs", target: "/dev", fstype: "devtmpfs", flags: ffi::MS_NOSUID, data: Some("mode=0755"), needs: None, required: true },
    MountSpec { src: "devpts", target: "/dev/pts", fstype: "devpts", flags: ffi::MS_NOSUID | ffi::MS_NOEXEC, data: Some("mode=0620,ptmxmode=0666"), needs: None, required: true },
    MountSpec { src: "tmpfs", target: "/dev/shm", fstype: "tmpfs", flags: NSD | ffi::MS_NOEXEC, data: Some("mode=1777"), needs: None, required: false },
    MountSpec { src: "tmpfs", target: "/run", fstype: "tmpfs", flags: NSD, data: Some("mode=0755,size=64m"), needs: None, required: true },
    MountSpec { src: "tmpfs", target: "/tmp", fstype: "tmpfs", flags: NSD, data: Some("mode=1777,size=256m"), needs: None, required: false },
    MountSpec { src: "efivarfs", target: "/sys/firmware/efi/efivars", fstype: "efivarfs", flags: NSD | ffi::MS_NOEXEC | ffi::MS_RDONLY, data: None, needs: Some("/sys/firmware/efi"), required: false },
    MountSpec { src: "configfs", target: "/sys/kernel/config", fstype: "configfs", flags: NSD | ffi::MS_NOEXEC, data: None, needs: Some("/sys/kernel/config"), required: false },
];

/// Plain directories the image does not ship (initramfs may already have them).
pub const DIRS: &[&str] = &["/proc", "/sys", "/dev", "/run", "/tmp", "/etc", "/root", "/data", "/mnt", "/var", "/var/log"];

pub fn mount_all() {
    for d in DIRS {
        let _ = std::fs::create_dir_all(d);
    }
    for m in TABLE {
        if let Some(n) = m.needs {
            if !std::path::Path::new(n).exists() {
                continue;
            }
        }
        let _ = std::fs::create_dir_all(m.target);
        if let Err(e) = ffi::do_mount(m.src, m.target, m.fstype, m.flags, m.data) {
            // EBUSY: already mounted (re-entry after a boot panic)
            if e.raw_os_error() != Some(16) && m.required {
                crate::logf!("mount {} on {}: {}", m.fstype, m.target, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parents_come_before_children() {
        for (i, m) in TABLE.iter().enumerate() {
            for earlier in &TABLE[..i] {
                assert_ne!(earlier.target, m.target, "duplicate target {}", m.target);
            }
            // every mount below another table entry's target must come after it
            for (j, p) in TABLE.iter().enumerate() {
                if j > i && m.target.starts_with(&format!("{}/", p.target)) {
                    panic!("{} is mounted before its parent {}", m.target, p.target);
                }
            }
        }
    }
    #[test]
    fn efivarfs_is_readonly_and_conditional() {
        let e = TABLE.iter().find(|m| m.fstype == "efivarfs").unwrap();
        assert!(e.flags & ffi::MS_RDONLY != 0 && e.needs.is_some() && !e.required);
    }
}
