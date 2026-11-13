//! Fake sysfs + /dev tree builder shared by the block integration tests. A disk is a sparse regular file under
//! `<root>/dev/<name>` plus the sysfs files the probe reads; `ProbeCtx::fixture(root)` runs the real code paths.

#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use labprobe::ProbeCtx;

static N: AtomicU32 = AtomicU32::new(0);

pub struct Fx {
    pub root: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub struct DiskSpec<'a> {
    pub name: &'a str,
    pub size: u64,
    /// sysfs device path below /sys/devices (decides the transport)
    pub devpath: &'a str,
    pub major: u32,
    pub minor: u32,
    pub ro: bool,
    /// (relative sysfs file, content)
    pub files: Vec<(&'a str, &'a str)>,
}

impl<'a> DiskSpec<'a> {
    pub fn virtio(name: &'a str, size: u64, minor: u32, serial: &'a str) -> DiskSpec<'a> {
        DiskSpec {
            name,
            size,
            devpath: "pci0000:00/0000:00:03.0/virtio0/block",
            major: 252,
            minor,
            ro: false,
            files: vec![("serial", serial)],
        }
    }
}

impl Fx {
    pub fn new(label: &str) -> Fx {
        let root = std::env::temp_dir().join(format!("i7ll-{}-{}-{}", label, std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        fs::create_dir_all(root.join("sys/block")).unwrap();
        fs::create_dir_all(root.join("dev")).unwrap();
        fs::create_dir_all(root.join("proc/self")).unwrap();
        fs::write(root.join("proc/self/mountinfo"), "").unwrap();
        fs::write(root.join("proc/swaps"), "Filename Type Size Used Priority\n").unwrap();
        Fx { root }
    }

    pub fn ctx(&self) -> ProbeCtx {
        ProbeCtx::fixture(&self.root)
    }

    pub fn write(&self, rel: &str, content: &str) {
        let p = self.root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }

    pub fn dev(&self, name: &str) -> PathBuf {
        self.root.join("dev").join(name)
    }

    /// Create the disk (sparse file, all zero) and its sysfs entry; returns the `/dev` path.
    pub fn disk(&self, d: &DiskSpec) -> PathBuf {
        let real = self.root.join("sys/devices").join(d.devpath).join(d.name);
        fs::create_dir_all(real.join("queue")).unwrap();
        fs::create_dir_all(real.join("holders")).unwrap();
        fs::write(real.join("dev"), format!("{}:{}\n", d.major, d.minor)).unwrap();
        fs::write(real.join("size"), format!("{}\n", d.size / 512)).unwrap();
        fs::write(real.join("ro"), if d.ro { "1\n" } else { "0\n" }).unwrap();
        fs::write(real.join("removable"), "0\n").unwrap();
        fs::write(real.join("queue/logical_block_size"), "512\n").unwrap();
        fs::write(real.join("queue/physical_block_size"), "512\n").unwrap();
        fs::write(real.join("queue/rotational"), "0\n").unwrap();
        for (f, c) in &d.files {
            let p = real.join(f);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, c).unwrap();
        }
        let depth = Path::new("devices").join(d.devpath).components().count();
        let _ = depth;
        let target = Path::new("../devices").join(d.devpath).join(d.name);
        symlink(target, self.root.join("sys/block").join(d.name)).unwrap();
        let f = fs::File::create(self.dev(d.name)).unwrap();
        f.set_len(d.size).unwrap();
        self.dev(d.name)
    }

    /// Add a partition entry to a disk's sysfs dir.
    pub fn partition(&self, disk: &str, part: &str, major: u32, minor: u32) {
        self.write(&format!("sys/block/{}/{}/dev", disk, part), &format!("{}:{}\n", major, minor));
        self.write(&format!("sys/block/{}/{}/partition", disk, part), "1\n");
        self.write(&format!("sys/class/block/{}/partition", part), "1\n");
    }

    pub fn put(&self, dev: &str, off: u64, data: &[u8]) {
        use std::os::unix::fs::FileExt;
        let f = fs::OpenOptions::new().write(true).open(self.dev(dev)).unwrap();
        f.write_all_at(data, off).unwrap();
    }

    pub fn get(&self, dev: &str, off: u64, len: usize) -> Vec<u8> {
        use std::os::unix::fs::FileExt;
        let f = fs::File::open(self.dev(dev)).unwrap();
        let mut b = vec![0u8; len];
        f.read_exact_at(&mut b, off).unwrap();
        b
    }

    pub fn mountinfo(&self, lines: &str) {
        self.write("proc/self/mountinfo", lines);
    }

    pub fn audit_log(&self) -> String {
        fs::read_to_string(self.root.join("run/i7lab/audit.log")).unwrap_or_default()
    }
}
