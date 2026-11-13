//! Private libc FFI of PID 1 (hand-written `extern "C"`, no libc crate). Every `unsafe` of i7lab-init lives here
//! behind a safe function. Layouts are x86_64 Linux, identical for musl and glibc for these calls.
//!
//! This is the private-FFI escape hatch of `labproto::sys` docs: when labproto::sys grows the same wrappers
//! (reboot, finit_module, ...) the matching functions here can be replaced by them.

use std::ffi::CString;
use std::io;
use std::os::raw::{c_char, c_int, c_long, c_ulong, c_void};
use std::path::Path;

extern "C" {
    fn mount(src: *const c_char, target: *const c_char, fstype: *const c_char, flags: c_ulong, data: *const c_void) -> c_int;
    fn umount2(target: *const c_char, flags: c_int) -> c_int;
    fn sethostname(name: *const c_char, len: usize) -> c_int;
    fn syscall(num: c_long, ...) -> c_long;
    fn ioctl(fd: c_int, req: c_ulong, ...) -> c_int;
    fn reboot(cmd: c_int) -> c_int;
    fn sync();
    fn waitpid(pid: c_int, status: *mut c_int, opts: c_int) -> c_int;
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn signal(sig: c_int, h: usize) -> usize;
    fn poll(fds: *mut c_void, n: c_ulong, ms: c_int) -> c_int;
    fn mknod(path: *const c_char, mode: u32, dev: u64) -> c_int;
    fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    fn dup2(a: c_int, b: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn setsid() -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn klogctl(ty: c_int, buf: *mut c_char, len: c_int) -> c_int;
    fn socket(domain: c_int, ty: c_int, proto: c_int) -> c_int;
    fn getpid() -> c_int;
    fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
}

pub const O_RDWR: c_int = 2;
pub const O_NOCTTY: c_int = 0o400;
pub const O_CLOEXEC: c_int = 0o2000000;
pub const SIGINT: c_int = 2;
pub const SIGKILL: c_int = 9;
pub const SIGUSR1: c_int = 10;
pub const SIGUSR2: c_int = 12;
pub const SIGTERM: c_int = 15;
pub const MS_RDONLY: u64 = 1;
pub const MS_NOSUID: u64 = 2;
pub const MS_NODEV: u64 = 4;
pub const MS_NOEXEC: u64 = 8;
pub const MS_NOATIME: u64 = 1024;
const SYS_FINIT_MODULE: c_long = 313;
const MODULE_INIT_COMPRESSED_FILE: c_int = 4;
const RB_AUTOBOOT: c_int = 0x0123_4567;
const RB_HALT_SYSTEM: c_int = 0xCDEF_0123u32 as c_int;
const RB_POWER_OFF: c_int = 0x4321_FEDC;
const RB_DISABLE_CAD: c_int = 0;
const TIOCSCTTY: c_ulong = 0x540E;
const VT_ACTIVATE: c_ulong = 0x5606;
const WNOHANG: c_int = 1;
const SIOCGIFFLAGS: c_ulong = 0x8913;
const SIOCSIFFLAGS: c_ulong = 0x8914;
const WDIOC_SETTIMEOUT: c_ulong = 0xC004_5706;

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn cvt(r: c_int) -> io::Result<()> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn pid() -> i32 {
    // SAFETY: no arguments.
    unsafe { getpid() }
}

pub fn do_mount(src: &str, target: &str, fstype: &str, flags: u64, data: Option<&str>) -> io::Result<()> {
    let (s, t, f) = (cstr(src)?, cstr(target)?, cstr(fstype)?);
    let d = data.map(cstr).transpose()?;
    let dp = d.as_ref().map(|c| c.as_ptr() as *const c_void).unwrap_or(std::ptr::null());
    // SAFETY: all pointers are valid NUL-terminated strings (or null data) for the duration of the call.
    cvt(unsafe { mount(s.as_ptr(), t.as_ptr(), f.as_ptr(), flags as c_ulong, dp) })
}

pub fn do_umount(target: &str) -> io::Result<()> {
    let t = cstr(target)?;
    // SAFETY: valid C string.
    cvt(unsafe { umount2(t.as_ptr(), 0) })
}

pub fn set_hostname(n: &str) -> io::Result<()> {
    // SAFETY: pointer and length describe `n`.
    cvt(unsafe { sethostname(n.as_ptr() as *const c_char, n.len()) })
}

/// finit_module(2). Err carries the errno (EEXIST = already loaded). Compressed `.ko.zst/.xz/.gz` files are passed
/// with MODULE_INIT_COMPRESSED_FILE (the kernel decompresses them).
pub fn finit_module(path: &Path) -> Result<(), i32> {
    use std::os::unix::io::AsRawFd;
    let f = std::fs::File::open(path).map_err(|e| e.raw_os_error().unwrap_or(5))?;
    let compressed = matches!(path.extension().and_then(|e| e.to_str()), Some("zst" | "xz" | "gz"));
    let flags = if compressed { MODULE_INIT_COMPRESSED_FILE } else { 0 };
    // SAFETY: valid fd, empty NUL-terminated parameter string.
    let r = unsafe { syscall(SYS_FINIT_MODULE, f.as_raw_fd() as c_long, b"\0".as_ptr() as *const c_char, flags) };
    if r < 0 {
        Err(io::Error::last_os_error().raw_os_error().unwrap_or(5))
    } else {
        Ok(())
    }
}

pub fn sys_sync() {
    // SAFETY: no arguments.
    unsafe { sync() }
}

pub fn disable_cad() {
    // SAFETY: plain integer argument; makes ctrl-alt-del a SIGINT to init instead of an immediate reboot.
    unsafe { reboot(RB_DISABLE_CAD) };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Power {
    Reboot,
    Halt,
    Off,
}

/// reboot(2). Does not return on success.
pub fn power(p: Power) -> io::Error {
    let c = match p {
        Power::Reboot => RB_AUTOBOOT,
        Power::Halt => RB_HALT_SYSTEM,
        Power::Off => RB_POWER_OFF,
    };
    // SAFETY: plain integer argument.
    unsafe { reboot(c) };
    io::Error::last_os_error()
}

/// Non-blocking reap of any child: (pid, raw wait status).
pub fn reap_one() -> Option<(i32, i32)> {
    let mut st: c_int = 0;
    // SAFETY: `st` is a valid out pointer.
    let r = unsafe { waitpid(-1, &mut st, WNOHANG) };
    if r > 0 {
        Some((r, st))
    } else {
        None
    }
}

pub fn send_signal(pid: i32, sig: i32) {
    // SAFETY: plain integers.
    unsafe { kill(pid, sig) };
}

pub fn kill_all(sig: i32) {
    // SAFETY: pid -1 = every process we may signal; as PID 1 this skips ourselves.
    unsafe { kill(-1, sig) };
}

pub fn on_signal(sig: i32, h: extern "C" fn(c_int)) {
    // SAFETY: `h` only stores into an atomic (async-signal-safe).
    unsafe { signal(sig, h as usize) };
}

pub fn sleep_ms(ms: i32) {
    // SAFETY: zero fds, null array.
    unsafe { poll(std::ptr::null_mut(), 0, ms) };
}

/// Linux `makedev`.
pub fn makedev(major: u32, minor: u32) -> u64 {
    let (ma, mi) = (major as u64, minor as u64);
    ((ma & 0xfff) << 8) | (mi & 0xff) | ((mi & !0xff) << 12) | ((ma & !0xfff) << 32)
}

/// mknod(2). `block` selects S_IFBLK vs S_IFCHR; mode 0600.
pub fn do_mknod(path: &str, block: bool, major: u32, minor: u32) -> io::Result<()> {
    let p = cstr(path)?;
    let ty: u32 = if block { 0o060000 } else { 0o020000 };
    // SAFETY: valid C string.
    cvt(unsafe { mknod(p.as_ptr(), ty | 0o600, makedev(major, minor)) })
}

/// Is `fd` an open descriptor.
pub fn fd_open(fd: i32) -> bool {
    // SAFETY: F_GETFD takes no pointer.
    unsafe { fcntl(fd, 1) >= 0 }
}

/// Point fds 0-2 at /dev/console; any of them still closed afterwards goes to /dev/null so that nothing opened later
/// can be handed fd 0-2 by accident.
pub fn open_console() {
    if let Ok(p) = cstr("/dev/console") {
        // SAFETY: valid C string; dup2/close on the fd we just opened.
        unsafe {
            let fd = open(p.as_ptr(), O_RDWR | O_NOCTTY);
            if fd >= 0 {
                for t in 0..3 {
                    dup2(fd, t);
                }
                if fd > 2 {
                    close(fd);
                }
                return;
            }
        }
    }
    if let Ok(n) = cstr("/dev/null") {
        for t in 0..3 {
            if !fd_open(t) {
                // SAFETY: valid C string; fds are ours.
                unsafe {
                    let nfd = open(n.as_ptr(), O_RDWR);
                    if nfd >= 0 && nfd != t {
                        dup2(nfd, t);
                        close(nfd);
                    }
                }
            }
        }
    }
}

/// Set the console loglevel (klogctl SYSLOG_ACTION_CONSOLE_LEVEL = 8). Level 1 = panics only, 7 = everything.
pub fn console_loglevel(level: i32) {
    // SAFETY: this action ignores the buffer.
    unsafe { klogctl(8, std::ptr::null_mut(), level) };
}

/// Child-side of a console shell: new session, `tty` as controlling terminal and as fds 0-2. Meant for
/// `CommandExt::pre_exec`, so it must not allocate: `tty` is a prebuilt C string.
///
/// # Safety
/// Only call between fork and exec.
pub unsafe fn become_tty_session_leader(tty: &CString) -> io::Result<()> {
    setsid();
    let fd = open(tty.as_ptr(), O_RDWR);
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    ioctl(fd, TIOCSCTTY, 1 as c_long);
    for t in 0..3 {
        dup2(fd, t);
    }
    if fd > 2 {
        close(fd);
    }
    signal(SIGINT, 0); // SIG_DFL: the shell resets it itself, children of the shell must not start ignoring it
    Ok(())
}

/// Make VT `n` the visible one (needs an open console fd). Best effort.
pub fn activate_vt(n: i32) {
    if let Ok(p) = cstr("/dev/tty0") {
        // SAFETY: valid C string; the fd is closed again.
        unsafe {
            let fd = open(p.as_ptr(), O_RDWR | O_NOCTTY | O_CLOEXEC);
            if fd >= 0 {
                ioctl(fd, VT_ACTIVATE, n as c_long);
                close(fd);
            }
        }
    }
}

/// Bring a network interface up with SIOCSIFFLAGS (used for `lo` only; i7labd owns all other networking).
pub fn if_up(name: &str) -> io::Result<()> {
    #[repr(C)]
    struct Ifreq {
        name: [u8; 16],
        data: [u8; 24],
    }
    let b = name.as_bytes();
    if b.is_empty() || b.len() > 15 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let mut r = Ifreq { name: [0; 16], data: [0; 24] };
    r.name[..b.len()].copy_from_slice(b);
    // SAFETY: AF_INET datagram socket, closed below; `r` matches struct ifreq (40 bytes).
    unsafe {
        let s = socket(2, 2 | O_CLOEXEC, 0);
        if s < 0 {
            return Err(io::Error::last_os_error());
        }
        let res = (|| {
            cvt(ioctl(s, SIOCGIFFLAGS, &mut r as *mut Ifreq))?;
            let f = u16::from_ne_bytes([r.data[0], r.data[1]]) | 1;
            r.data[0..2].copy_from_slice(&f.to_ne_bytes());
            cvt(ioctl(s, SIOCSIFFLAGS, &mut r as *mut Ifreq))
        })();
        close(s);
        res
    }
}

/// An armed hardware watchdog (`/dev/watchdog0`). Dropping it WITHOUT `disarm` leaves the dog running.
pub struct Dog {
    fd: c_int,
}

impl Dog {
    pub fn open(path: &str, timeout_s: i32) -> io::Result<Dog> {
        let p = cstr(path)?;
        // SAFETY: valid C string; opening starts the watchdog.
        let fd = unsafe { open(p.as_ptr(), 1 /* O_WRONLY */ | O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut t: c_int = timeout_s;
        // SAFETY: `t` is the int the ioctl reads and writes. Failure (fixed-timeout drivers) is fine.
        unsafe { ioctl(fd, WDIOC_SETTIMEOUT, &mut t as *mut c_int) };
        Ok(Dog { fd })
    }
    pub fn pet(&self) {
        // SAFETY: one byte from a static.
        unsafe { write(self.fd, b"\0".as_ptr() as *const c_void, 1) };
    }
    /// Magic close: the kernel stops the dog (when the driver allows nowayout=0).
    pub fn disarm(self) {
        // SAFETY: writes the magic 'V' then closes our fd.
        unsafe {
            write(self.fd, b"V".as_ptr() as *const c_void, 1);
            close(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn makedev_matches_kernel_encoding() {
        assert_eq!(makedev(8, 0), 0x800);
        assert_eq!(makedev(259, 1), (259 << 8) | 1);
        assert_eq!(makedev(1, 256), (1 << 8) | ((256 & !0xff) << 12));
    }
}
