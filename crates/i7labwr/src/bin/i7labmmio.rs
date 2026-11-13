//! i7labmmio RESOURCE_FILE OFFSET LEN [WIDTH]
//! READ-ONLY dump of a PCI memory BAR through its sysfs resource file (e.g. /sys/bus/pci/devices/0000:2e:00.0/resource2):
//! opens O_RDONLY, mmaps PROT_READ|MAP_SHARED and prints LEN bytes from OFFSET as hex, WIDTH (1,2,4) bytes per read,
//! with volatile reads of exactly that width. It never writes. Reads of some registers can have side effects on some
//! devices (read-to-clear); the caller chooses the range. LEN is capped at 4096, OFFSET+LEN must lie inside the BAR.
use std::os::unix::io::AsRawFd;

extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn munmap(addr: *mut u8, len: usize) -> i32;
}

fn die(m: &str) -> ! {
    eprintln!("i7labmmio: {m}");
    std::process::exit(2)
}

fn parse(s: &str) -> usize {
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x") { usize::from_str_radix(h, 16).unwrap_or_else(|_| die("bad number")) } else { t.parse().unwrap_or_else(|_| die("bad number")) }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 4 {
        die("usage: i7labmmio RESOURCE_FILE OFFSET LEN [WIDTH]");
    }
    let (off, len) = (parse(&a[2]), parse(&a[3]));
    let width = a.get(4).map(|s| parse(s)).unwrap_or(4);
    if ![1, 2, 4].contains(&width) || len == 0 || len > 4096 || off % width != 0 || len % width != 0 {
        die("need WIDTH in 1,2,4; 0 < LEN <= 4096; OFFSET and LEN multiples of WIDTH");
    }
    let f = std::fs::OpenOptions::new().read(true).open(&a[1]).unwrap_or_else(|e| die(&format!("open {}: {e}", a[1])));
    let size = f.metadata().map(|m| m.len() as usize).unwrap_or(0);
    let size = if size == 0 { 4096 } else { size };
    if off + len > size {
        die(&format!("range {off:#x}+{len:#x} is outside the BAR ({size:#x} bytes)"));
    }
    let map_len = (off + len + 4095) & !4095;
    let p = unsafe { mmap(std::ptr::null_mut(), map_len, 1 /* PROT_READ */, 1 /* MAP_SHARED */, f.as_raw_fd(), 0) };
    if p as isize == -1 {
        die("mmap failed");
    }
    let mut i = 0;
    while i < len {
        let mut line = format!("{:04x}:", off + i);
        for k in 0..(16 / width).min((len - i) / width) {
            let at = unsafe { p.add(off + i + k * width) };
            let v: u32 = unsafe {
                match width {
                    1 => std::ptr::read_volatile(at) as u32,
                    2 => std::ptr::read_volatile(at as *const u16) as u32,
                    _ => std::ptr::read_volatile(at as *const u32),
                }
            };
            line.push_str(&format!(" {:0w$x}", v, w = width * 2));
        }
        println!("{line}");
        i += 16.min(len - i);
    }
    unsafe { munmap(p, map_len) };
}
