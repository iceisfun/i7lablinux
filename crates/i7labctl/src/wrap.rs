//! Wrappers that run other programs: `image ...` (scripts/), `ssh` (system ssh with pinned host keys). Owner: P9.

use std::path::{Path, PathBuf};

/// Directory with the build scripts: `$I7LABCTL_SCRIPTS`, else `<cwd or a parent>/scripts` that has `build-image`,
/// else next to the binary (`<exe dir>/../scripts`, `<exe dir>/../../scripts`).
pub fn find_scripts_dir() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("I7LABCTL_SCRIPTS").map(PathBuf::from) {
        return Some(d);
    }
    let ok = |d: &Path| d.join("build-image").is_file();
    let mut starts: Vec<PathBuf> = Vec::new();
    if let Ok(c) = std::env::current_dir() {
        starts.push(c);
    }
    if let Ok(e) = std::env::current_exe() {
        if let Some(p) = e.parent() {
            starts.push(p.to_path_buf());
        }
    }
    for s in starts {
        for anc in s.ancestors().take(5) {
            let d = anc.join("scripts");
            if ok(&d) {
                return Some(d);
            }
        }
    }
    None
}

/// `image <verb>` -> (script file name, fixed leading args).
pub fn image_script(verb: &str) -> Option<&'static str> {
    Some(match verb {
        "build" => "build-image",
        "write" => "build-usb-drive",
        "bake" => "bake-keys",
        "keys" => "gen-keys",
        "test" => "qemu-test",
        _ => return None,
    })
}

/// Pinned-host-key, no-forwarding ssh command line (everything before the destination).
pub fn ssh_base_args(known_hosts: &Path, identity: Option<&Path>) -> Vec<String> {
    let mut a: Vec<String> = [
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes", "-o", "ForwardX11=no", "-o", "IdentitiesOnly=yes",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    a.push("-o".into());
    a.push(format!("UserKnownHostsFile={}", known_hosts.display()));
    if let Some(i) = identity {
        a.push("-i".into());
        a.push(i.display().to_string());
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_args_pin_and_forward_nothing() {
        let a = ssh_base_args(Path::new("/h/kh"), Some(Path::new("/h/id")));
        let j = a.join(" ");
        for must in ["BatchMode=yes", "StrictHostKeyChecking=yes", "ForwardAgent=no", "ClearAllForwardings=yes", "UserKnownHostsFile=/h/kh", "GlobalKnownHostsFile=/dev/null", "-i /h/id"] {
            assert!(j.contains(must), "{} missing in {}", must, j);
        }
    }

    #[test]
    fn image_verbs() {
        assert_eq!(image_script("write"), Some("build-usb-drive"));
        assert_eq!(image_script("bake"), Some("bake-keys"));
        assert_eq!(image_script("info"), None);
    }
}
