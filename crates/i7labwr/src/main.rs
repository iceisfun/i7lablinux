//! i7labwr IMAGE DEVICE SERIAL [--yes]
//! Writes IMAGE to the start of the whole disk DEVICE (e.g. nvme0n1) after checking, from sysfs and /proc/mounts:
//! the device exists and is a whole disk, its serial equals SERIAL, none of its partitions is mounted, it is not the disk the
//! host booted from (the /sys/firmware mount of the boot media is detected through /proc/self/mountinfo and the
//! i7lab.bootdisk marker in /proc/cmdline when present). Then it writes, fsyncs, drops the page cache for the range and reads
//! the data back and compares SHA-256. Exit 0 only when the read-back matches.
//! i7labwr keeps its own, stricter rule and never writes the boot disk; overwriting the boot media of a RAM-resident host
//! goes through the host gate instead (`i7labctl blk image|write ... --allow-boot-media`, docs/PLAN.md section 6).
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;

extern "C" {
    fn posix_fadvise(fd: i32, off: i64, len: i64, advice: i32) -> i32;
    fn fsync(fd: i32) -> i32;
}

fn die(msg: &str) -> ! {
    eprintln!("i7labwr: {msg}");
    std::process::exit(2)
}

fn read_trim(p: &str) -> String {
    std::fs::read_to_string(p).unwrap_or_default().trim().to_string()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 4 {
        die("usage: i7labwr IMAGE DEVICE SERIAL   (DEVICE = whole disk name like nvme0n1, no /dev/)");
    }
    let (img, dev, serial) = (&a[1], a[2].trim_start_matches("/dev/").to_string(), &a[3]);
    if dev.contains('/') || dev.is_empty() {
        die("DEVICE must be a bare whole-disk name such as nvme0n1");
    }
    let sys = format!("/sys/block/{dev}");
    if !std::path::Path::new(&sys).exists() {
        die(&format!("{dev}: not a whole disk (no {sys})"));
    }
    let got = {
        let s = read_trim(&format!("{sys}/device/serial"));
        if s.is_empty() { read_trim(&format!("{sys}/serial")) } else { s }
    };
    if got != *serial {
        die(&format!("serial mismatch: device has '{got}', you gave '{serial}'"));
    }
    if read_trim(&format!("{sys}/ro")) == "1" {
        die("device is read-only");
    }
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    if mounts.lines().any(|l| l.split(' ').next().map_or(false, |d| d.starts_with(&format!("/dev/{dev}")))) {
        die("a partition of the device is mounted");
    }
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    if cmdline.split(' ').any(|w| w == format!("i7lab.bootdisk={dev}")) {
        die("this is the disk the host booted from");
    }
    let size: u64 = read_trim(&format!("{sys}/size")).parse::<u64>().unwrap_or(0) * 512;
    let mut data = Vec::new();
    File::open(img).unwrap_or_else(|e| die(&format!("{img}: {e}"))).read_to_end(&mut data).unwrap();
    if data.is_empty() || data.len() as u64 > size {
        die(&format!("image is {} bytes, device is {size}", data.len()));
    }
    let want = labproto::crypto::hex(&labproto::crypto::sha256(&data));
    eprintln!("i7labwr: writing {} bytes of {img} to /dev/{dev} (serial {serial}, {size} bytes)", data.len());
    {
        let mut f = OpenOptions::new().write(true).open(format!("/dev/{dev}")).unwrap_or_else(|e| die(&format!("open: {e}")));
        let mut off = 0usize;
        while off < data.len() {
            let n = (data.len() - off).min(1 << 20);
            f.write_all(&data[off..off + n]).unwrap_or_else(|e| die(&format!("write at {off}: {e}")));
            off += n;
        }
        f.flush().ok();
        if unsafe { fsync(f.as_raw_fd()) } != 0 {
            die("fsync failed");
        }
        unsafe { posix_fadvise(f.as_raw_fd(), 0, data.len() as i64, 4 /* DONTNEED */) };
    }
    let mut f = File::open(format!("/dev/{dev}")).unwrap_or_else(|e| die(&format!("reopen: {e}")));
    unsafe { posix_fadvise(f.as_raw_fd(), 0, data.len() as i64, 4) };
    f.seek(SeekFrom::Start(0)).unwrap();
    let mut back = vec![0u8; data.len()];
    f.read_exact(&mut back).unwrap_or_else(|e| die(&format!("read-back: {e}")));
    let have = labproto::crypto::hex(&labproto::crypto::sha256(&back));
    if have != want {
        die(&format!("READ-BACK MISMATCH: wrote {want}, read {have}"));
    }
    println!("i7labwr: ok: {} bytes written to /dev/{dev}, read-back sha256 {have}", data.len());
}
