//! udev-less device nodes. devtmpfs creates nodes by itself; this is the safety net for nodes the kernel did not
//! create (late module loads on a kernel without DEVTMPFS_MOUNT races) by walking sysfs `dev` files.

use std::path::Path;

/// "259:1\n" -> (259, 1)
pub fn parse_devno(s: &str) -> Option<(u32, u32)> {
    let (a, b) = s.trim().split_once(':')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

/// DEVNAME= value of a uevent file (the node name below /dev, may contain a slash: "nvme0n1", "bus/usb/001/002").
pub fn parse_devname(uevent: &str) -> Option<String> {
    let n = uevent.lines().find_map(|l| l.strip_prefix("DEVNAME="))?.trim();
    let safe = !n.is_empty() && !n.starts_with('/') && !n.split('/').any(|c| c.is_empty() || c == "." || c == "..");
    safe.then(|| n.to_string())
}

/// Create every missing node for the classes that matter to a lab host. Returns the number created.
pub fn create_missing() -> usize {
    let mut made = 0;
    for (class_dir, block) in [("/sys/class/block", true), ("/sys/class/tty", false), ("/sys/class/misc", false), ("/sys/class/net", false)] {
        if class_dir.ends_with("net") {
            continue; // net devices have no nodes
        }
        let Ok(rd) = std::fs::read_dir(class_dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let Some((maj, min)) = std::fs::read_to_string(p.join("dev")).ok().and_then(|s| parse_devno(&s)) else { continue };
            let name = std::fs::read_to_string(p.join("uevent")).ok().and_then(|u| parse_devname(&u)).or_else(|| e.file_name().to_str().map(str::to_string));
            let Some(name) = name else { continue };
            let node = format!("/dev/{}", name);
            if Path::new(&node).exists() {
                continue;
            }
            if let Some(parent) = Path::new(&node).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if crate::ffi::do_mknod(&node, block, maj, min).is_ok() {
                made += 1;
            }
        }
    }
    made
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn devno() {
        assert_eq!(parse_devno("259:1\n"), Some((259, 1)));
        assert_eq!(parse_devno("8:0"), Some((8, 0)));
        assert_eq!(parse_devno("junk"), None);
        assert_eq!(parse_devno("8:"), None);
    }
    #[test]
    fn devname_is_confined_below_dev() {
        assert_eq!(parse_devname("MAJOR=8\nMINOR=0\nDEVNAME=sda\nDEVTYPE=disk\n").as_deref(), Some("sda"));
        assert_eq!(parse_devname("DEVNAME=bus/usb/001/002").as_deref(), Some("bus/usb/001/002"));
        assert_eq!(parse_devname("DEVNAME=../etc/passwd"), None);
        assert_eq!(parse_devname("DEVNAME=/etc/passwd"), None);
        assert_eq!(parse_devname("DEVNAME=a//b"), None);
        assert_eq!(parse_devname("MAJOR=1"), None);
    }
}
