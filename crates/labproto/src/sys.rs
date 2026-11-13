//! Hand-written libc FFI (x86_64 Linux; identical for musl and glibc for these calls). No `libc` crate.
//! Port of the earlier lab-proxy prototype. Owner: P2. Add wrappers as needed; keep every `unsafe`
//! inside this module behind a safe, io::Result-returning function.
//!
//! First P2 push delivers this agreed wrapper list (review feasibility F7), so no other lane writes FFI:
//! * tty/process: termios get/set (cfmakeraw), TIOCGWINSZ/TIOCSWINSZ, TIOCSCTTY, openpty, setsid, poll, pipe2,
//!   sigaction (flag-only handler), kill/killpg, waitpid, dup2, execve helpers, prctl(PR_SET_PDEATHSIG)
//! * block/file: BLKGETSIZE64 BLKSSZGET BLKPBSZGET BLKROGET BLKFLSBUF BLKRRPART, SG_IO, NVME_IOCTL_ADMIN_CMD,
//!   O_DIRECT|O_EXCL open, aligned buffer, flock, FS_IOC_GETFLAGS/SETFLAGS (efivars), openat2 (RESOLVE_*)
//! * sockets: SIOCETHTOOL, socket/bind/sendto/recvmsg with cmsg, setsockopt (SO_REUSEADDR, IP_ADD_MEMBERSHIP)
//! * console/misc: KDSETLED/KDSKBLED, VT_ACTIVATE, klogctl, getrandom, statfs, mount/umount, reboot,
//!   finit_module, kexec_file_load, clock_settime
//! Until a wrapper lands, a lane may keep private FFI in its own `crate::ffi` (not `pub` outside the crate) and
//! migrates when P2's wrapper exists.

use std::ffi::CString;
use std::io;
use std::path::Path;

pub type RawFd = i32;

mod ffi {
    extern "C" {
        pub fn mount(src: *const i8, target: *const i8, fstype: *const i8, flags: u64, data: *const u8) -> i32;
        pub fn umount2(target: *const i8, flags: i32) -> i32;
        pub fn ioctl(fd: i32, req: u64, ...) -> i32;
        pub fn sync();
        pub fn getrandom(buf: *mut u8, len: usize, flags: u32) -> isize;
        pub fn flock(fd: i32, op: i32) -> i32;
        pub fn syscall(num: i64, ...) -> i64;
        pub fn socket(domain: i32, ty: i32, proto: i32) -> i32;
        pub fn bind(fd: i32, addr: *const u8, len: u32) -> i32;
        pub fn setsockopt(fd: i32, level: i32, name: i32, val: *const u8, len: u32) -> i32;
    }
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn check(rc: i32) -> io::Result<i32> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

pub mod mount_flags {
    pub const MS_RDONLY: u64 = 1;
    pub const MS_NOSUID: u64 = 2;
    pub const MS_NODEV: u64 = 4;
    pub const MS_NOEXEC: u64 = 8;
    pub const MS_NOATIME: u64 = 1024;
}

pub fn mount(src: &str, target: &str, fstype: &str, flags: u64, data: Option<&str>) -> io::Result<()> {
    let (s, t, f) = (cstr(src)?, cstr(target)?, cstr(fstype)?);
    let d = data.map(cstr).transpose()?;
    let dp = d.as_ref().map(|c| c.as_ptr() as *const u8).unwrap_or(std::ptr::null());
    // SAFETY: all pointers are valid NUL-terminated strings (or null for data) for the duration of the call.
    check(unsafe { ffi::mount(s.as_ptr(), t.as_ptr(), f.as_ptr(), flags, dp) }).map(|_| ())
}

pub fn umount(target: &str, flags: i32) -> io::Result<()> {
    let t = cstr(target)?;
    // SAFETY: valid C string.
    check(unsafe { ffi::umount2(t.as_ptr(), flags) }).map(|_| ())
}

pub fn sync() {
    // SAFETY: no arguments.
    unsafe { ffi::sync() }
}

/// ioctl with a pointer argument. The caller guarantees `arg` points to a buffer of the size the request expects.
///
/// # Safety
/// `arg` must be valid for reads and writes of the size encoded in `req`.
pub unsafe fn ioctl_ptr(fd: RawFd, req: u64, arg: *mut u8) -> io::Result<i32> {
    check(ffi::ioctl(fd, req, arg))
}

/// getrandom(2) with flags 0: blocks until the kernel pool is initialised; retries EINTR and short reads.
pub fn getrandom_blocking(buf: &mut [u8]) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        // SAFETY: the pointer/length pair describes the unfilled tail of `buf`.
        let n = unsafe { ffi::getrandom(buf[done..].as_mut_ptr(), buf.len() - done, 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        done += n as usize;
    }
    Ok(())
}

pub mod flock_op {
    pub const LOCK_SH: i32 = 1;
    pub const LOCK_EX: i32 = 2;
    pub const LOCK_NB: i32 = 4;
    pub const LOCK_UN: i32 = 8;
}

/// flock(2) on an open file (the cross-process "under test" lock of the write gate uses LOCK_EX|LOCK_NB).
pub fn flock(fd: RawFd, op: i32) -> io::Result<()> {
    // SAFETY: plain integer arguments.
    check(unsafe { ffi::flock(fd, op) }).map(|_| ())
}

pub mod resolve {
    pub const RESOLVE_NO_XDEV: u64 = 0x01;
    pub const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    pub const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    pub const RESOLVE_BENEATH: u64 = 0x08;
}

/// Open `rel` (relative, no leading '/') read-only beneath the directory `root` with openat2(2) and the given
/// RESOLVE_* flags. This is how i7labd serves `get`/`fs.*` (PLAN.md C22): never by string prefix alone.
/// Uses syscall 437 with `struct open_how { flags: O_RDONLY|O_CLOEXEC, mode: 0, resolve }`.
pub fn openat2_beneath(root: &Path, rel: &Path, resolve_flags: u64) -> io::Result<std::fs::File> {
    use std::os::unix::io::{AsRawFd, FromRawFd};
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    const SYS_OPENAT2: i64 = 437;
    const O_RDONLY_CLOEXEC: u64 = 0o2000000;
    let dir = std::fs::File::open(root)?;
    let rel_c = CString::new(rel.as_os_str().as_encoded_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let how = OpenHow { flags: O_RDONLY_CLOEXEC, mode: 0, resolve: resolve_flags };
    // SAFETY: dir fd is open, rel_c is NUL-terminated, `how` is a valid open_how of the size passed.
    let fd = unsafe { ffi::syscall(SYS_OPENAT2, dir.as_raw_fd() as i64, rel_c.as_ptr(), &how as *const OpenHow, std::mem::size_of::<OpenHow>()) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor we own.
    Ok(unsafe { std::fs::File::from_raw_fd(fd as i32) })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RebootCmd {
    Restart,
    PowerOff,
    Halt,
    Kexec,
}

/// reboot(2). Syncs first. On success a restart/poweroff does not return in practice.
pub fn reboot(cmd: RebootCmd) -> io::Result<()> {
    const SYS_REBOOT: i64 = 169;
    const MAGIC1: i64 = 0xfee1_dead;
    const MAGIC2: i64 = 672_274_793;
    let c: i64 = match cmd {
        RebootCmd::Restart => 0x0123_4567,
        RebootCmd::Halt => 0xCDEF_0123,
        RebootCmd::PowerOff => 0x4321_FEDC,
        RebootCmd::Kexec => 0x4558_4543,
    };
    sync();
    // SAFETY: plain integer arguments.
    let rc = unsafe { ffi::syscall(SYS_REBOOT, MAGIC1, MAGIC2, c, 0i64) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// finit_module(2): load the .ko at `path` with module parameters `params` (may be empty).
pub fn finit_module(path: &Path, params: &str) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    const SYS_FINIT_MODULE: i64 = 313;
    let f = std::fs::File::open(path)?;
    let p = cstr(params)?;
    // SAFETY: fd open, params NUL-terminated.
    let rc = unsafe { ffi::syscall(SYS_FINIT_MODULE, f.as_raw_fd() as i64, p.as_ptr(), 0i64) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// struct ifreq as far as flags go: 16 name bytes + a 24-byte union (the flags short is its first member).
#[repr(C)]
struct IfReqFlags {
    name: [u8; 16],
    flags: i16,
    pad: [u8; 22],
}

fn ifreq_flags(name: &str) -> io::Result<IfReqFlags> {
    if name.is_empty() || name.len() >= 16 || name.contains('\0') {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let mut r = IfReqFlags { name: [0; 16], flags: 0, pad: [0; 22] };
    r.name[..name.len()].copy_from_slice(name.as_bytes());
    Ok(r)
}

/// Bring an interface up (SIOCGIFFLAGS / SIOCSIFFLAGS |= IFF_UP). Idempotent.
pub fn if_up(name: &str) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    const SIOCGIFFLAGS: u64 = 0x8913;
    const SIOCSIFFLAGS: u64 = 0x8914;
    const IFF_UP: i16 = 1;
    let mut r = ifreq_flags(name)?;
    let sock = std::net::UdpSocket::bind("127.0.0.1:0")?;
    // SAFETY: r is a valid ifreq-sized buffer.
    check(unsafe { ffi::ioctl(sock.as_raw_fd(), SIOCGIFFLAGS, &mut r as *mut IfReqFlags) })?;
    if r.flags & IFF_UP == 0 {
        r.flags |= IFF_UP;
        // SAFETY: as above.
        check(unsafe { ffi::ioctl(sock.as_raw_fd(), SIOCSIFFLAGS, &mut r as *mut IfReqFlags) })?;
    }
    Ok(())
}

pub fn if_flags(name: &str) -> io::Result<u32> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{}/flags", name))?;
    u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
}

/// A UDP socket bound to 0.0.0.0:`port` with SO_REUSEADDR set before bind, so several processes share one
/// multicast test segment.
pub fn udp_reuse_socket(port: u16) -> io::Result<std::net::UdpSocket> {
    use std::os::unix::io::FromRawFd;
    const AF_INET: i32 = 2;
    const SOCK_DGRAM_CLOEXEC: i32 = 2 | 0o2000000;
    const SOL_SOCKET: i32 = 1;
    const SO_REUSEADDR: i32 = 2;
    // SAFETY: plain socket(2).
    let fd = check(unsafe { ffi::socket(AF_INET, SOCK_DGRAM_CLOEXEC, 0) })?;
    // SAFETY: we own fd; the UdpSocket closes it on drop (also on the error paths below).
    let sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    let one: i32 = 1;
    // SAFETY: val points at a live i32.
    check(unsafe { ffi::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one as *const i32 as *const u8, 4) })?;
    let mut sa = [0u8; 16];
    sa[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    sa[2..4].copy_from_slice(&port.to_be_bytes());
    // SAFETY: sa is a valid sockaddr_in.
    check(unsafe { ffi::bind(fd, sa.as_ptr(), 16) })?;
    Ok(sock)
}

/// Milliseconds since boot (CLOCK_BOOTTIME semantics via /proc/uptime until P2 adds clock_gettime).
pub fn uptime_ms() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().and_then(|x| x.parse::<f64>().ok()))
        .map(|x| (x * 1000.0) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn getrandom_fills() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        super::getrandom_blocking(&mut a).unwrap();
        super::getrandom_blocking(&mut b).unwrap();
        assert_ne!(a, b);
    }
}
