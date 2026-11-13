//! `lab-boot --jetkvm HOST --image PATH`: boot a host from lab linux through hwlabd (PLAN.md decision 8, behind
//! `HWLAB=`). i7labctl never speaks JetKVM JSON-RPC itself: it builds `hwlabctl` command lines (pure, tested),
//! runs them, and then waits for the host's beacon. Owner: P9.
//!
//! UNVERIFIED: `hwlabctl power HOST cycle` is the documented, working call. The virtual media subcommands
//! (`media mount|unmount`) are the planned hwlabd interface; virtual media was never exercised on a real
//! device (docs/OPERATOR-NOTES-JETKVM.md), so the exact hwlabctl syntax is a first guess that the first real run
//! must confirm. Override the whole media command with `I7LABCTL_HWLAB_MEDIA` if it differs.

use std::path::Path;

use crate::ClientError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaMode {
    CdRom,
    Disk,
}

impl MediaMode {
    pub fn parse(s: &str) -> Option<MediaMode> {
        match s.to_ascii_lowercase().as_str() {
            "cdrom" | "cd" | "iso" => Some(MediaMode::CdRom),
            "disk" | "img" => Some(MediaMode::Disk),
            _ => None,
        }
    }
    /// The word JetKVM's media/mount API uses.
    pub fn api_name(self) -> &'static str {
        match self {
            MediaMode::CdRom => "CDROM",
            MediaMode::Disk => "Disk",
        }
    }
    pub fn from_extension(path: &Path) -> MediaMode {
        match path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).as_deref() {
            Some("iso") => MediaMode::CdRom,
            _ => MediaMode::Disk,
        }
    }
}

/// hwlab CLI command words from `HWLAB` (default `hwlabctl`), split on whitespace.
pub fn hwlab_cmd(env_value: Option<&str>) -> Vec<String> {
    let v = env_value.map(str::trim).filter(|v| !v.is_empty()).unwrap_or("hwlabctl");
    v.split_whitespace().map(String::from).collect()
}

/// The ordered command lines of the sequence (each starts with the hwlab CLI words).
pub fn plan(hwlab: &[String], host: &str, image: &Path, mode: MediaMode) -> Result<Vec<Vec<String>>, ClientError> {
    if host.is_empty() || host.starts_with('-') || host.contains(char::is_whitespace) {
        return Err(ClientError::Usage(format!("bad hwlab host name '{}'", host)));
    }
    let img = image.to_string_lossy().into_owned();
    let mk = |rest: &[&str]| -> Vec<String> { hwlab.iter().cloned().chain(rest.iter().map(|s| s.to_string())).collect() };
    Ok(vec![
        mk(&["power", host, "off"]),
        mk(&["media", "mount", host, "--file", &img, "--mode", mode.api_name()]),
        mk(&["power", host, "on"]),
    ])
}

pub fn render(cmds: &[Vec<String>]) -> String {
    cmds.iter().map(|c| c.iter().map(|w| shell_quote(w)).collect::<Vec<_>>().join(" ")).collect::<Vec<_>>().join("\n")
}

fn shell_quote(w: &str) -> String {
    if !w.is_empty() && w.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./=:,".contains(&b)) {
        w.to_string()
    } else {
        format!("'{}'", w.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_for_iso_and_img() {
        let hw = hwlab_cmd(None);
        let p = plan(&hw, "nova", Path::new("out/i7lablinux.iso"), MediaMode::from_extension(Path::new("out/i7lablinux.iso"))).unwrap();
        assert_eq!(p[0], vec!["hwlabctl", "power", "nova", "off"]);
        assert_eq!(p[1], vec!["hwlabctl", "media", "mount", "nova", "--file", "out/i7lablinux.iso", "--mode", "CDROM"]);
        assert_eq!(p[2], vec!["hwlabctl", "power", "nova", "on"]);
        assert_eq!(MediaMode::from_extension(Path::new("a.img")), MediaMode::Disk);
        assert_eq!(MediaMode::parse("cd"), Some(MediaMode::CdRom));
        assert!(MediaMode::parse("floppy").is_none());
    }

    #[test]
    fn hwlab_env_and_quoting() {
        assert_eq!(hwlab_cmd(Some("ssh labhost hwlabctl")), vec!["ssh", "labhost", "hwlabctl"]);
        assert_eq!(hwlab_cmd(Some("  ")), vec!["hwlabctl"]);
        assert!(plan(&hwlab_cmd(None), "-x", Path::new("a.img"), MediaMode::Disk).is_err());
        assert!(plan(&hwlab_cmd(None), "a b", Path::new("a.img"), MediaMode::Disk).is_err());
        let p = plan(&hwlab_cmd(None), "nova", Path::new("my image.img"), MediaMode::Disk).unwrap();
        assert!(render(&p).contains("'my image.img'"));
    }
}
