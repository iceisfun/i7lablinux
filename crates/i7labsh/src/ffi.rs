//! Private libc FFI of i7labsh (hand-written `extern "C"`, no libc crate), x86_64 Linux, musl and glibc alike.
//! Every `unsafe` of the crate except the `pre_exec` hooks lives here behind safe functions.

use std::ffi::CString;
use std::io;
use std::os::raw::{c_char, c_int, c_long, c_ulong, c_void};
use std::sync::atomic::{AtomicBool, Ordering};

extern "C" {
    fn mount(src: *const c_char, target: *const c_char, fstype: *const c_char, flags: c_ulong, data: *const c_void) -> c_int;
    fn umount2(target: *const c_char, flags: c_int) -> c_int;
    fn syscall(num: c_long, ...) -> c_long;
    fn ioctl(fd: c_int, req: c_ulong, ...) -> c_int;
    fn sync();
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn sigaction(sig: c_int, act: *const SigAction, old: *mut SigAction) -> c_int;
    fn statfs(path: *const c_char, buf: *mut StatFs) -> c_int;
    fn getpid() -> c_int;
}

pub const SIGINT: i32 = 2;
pub const SIGUSR1: i32 = 10;
pub const SIGUSR2: i32 = 12;
pub const SIGTERM: i32 = 15;
const SYS_FINIT_MODULE: c_long = 313;
const TCGETS: c_ulong = 0x5401;
const TCSETS: c_ulong = 0x5402;

pub mod mount_flags {
    pub const MS_RDONLY: u64 = 1;
    pub const MS_NOSUID: u64 = 2;
    pub const MS_NODEV: u64 = 4;
    pub const MS_NOEXEC: u64 = 8;
    pub const MS_REMOUNT: u64 = 32;
    pub const MS_NOATIME: u64 = 1024;
    pub const MS_BIND: u64 = 4096;
}

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

pub fn do_mount(src: &str, target: &str, fstype: &str, flags: u64, data: &str) -> io::Result<()> {
    let (s, t, f, d) = (cstr(src)?, cstr(target)?, cstr(fstype)?, cstr(data)?);
    // SAFETY: valid NUL-terminated strings for the duration of the call.
    cvt(unsafe { mount(s.as_ptr(), t.as_ptr(), f.as_ptr(), flags as c_ulong, d.as_ptr() as *const c_void) })
}

pub fn do_umount(target: &str, lazy: bool) -> io::Result<()> {
    let t = cstr(target)?;
    // SAFETY: valid C string. MNT_DETACH = 2.
    cvt(unsafe { umount2(t.as_ptr(), if lazy { 2 } else { 0 }) })
}

pub fn do_sync() {
    // SAFETY: no arguments.
    unsafe { sync() }
}

pub fn send_signal(pid: i32, sig: i32) -> io::Result<()> {
    // SAFETY: plain integers.
    cvt(unsafe { kill(pid, sig) })
}

/// finit_module(2) with a parameter string; compressed module files are flagged for in-kernel decompression.
pub fn finit_module(path: &str, params: &str) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let f = std::fs::File::open(path)?;
    let p = cstr(params)?;
    let compressed = path.ends_with(".zst") || path.ends_with(".xz") || path.ends_with(".gz");
    // SAFETY: valid fd and C string.
    let r = unsafe { syscall(SYS_FINIT_MODULE, f.as_raw_fd() as c_long, p.as_ptr(), if compressed { 4 } else { 0 } as c_int) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------- SIGINT without SA_RESTART

#[repr(C)]
struct SigAction {
    handler: usize,
    mask: [u64; 16],
    flags: c_int,
    restorer: usize,
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigint(_: c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

/// Interactive shells: SIGINT sets a flag (builtins poll it) instead of killing the shell. Blocking syscalls return
/// EINTR (no SA_RESTART). Children are unaffected: handlers are reset by exec.
pub fn install_sigint_flag() {
    let act = SigAction { handler: on_sigint as *const () as usize, mask: [0; 16], flags: 0, restorer: 0 };
    // SAFETY: `act` is a valid struct sigaction for this libc on x86_64; the handler is async-signal-safe.
    unsafe { sigaction(SIGINT, &act, std::ptr::null_mut()) };
}

pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

pub fn take_interrupt() -> bool {
    INTERRUPTED.swap(false, Ordering::SeqCst)
}

// ---------------------------------------------------------------- terminal

/// Kernel/libc `struct termios` on x86_64 (60 bytes; the kernel only touches the first 36).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Termios {
    iflag: u32,
    oflag: u32,
    cflag: u32,
    lflag: u32,
    line: u8,
    cc: [u8; 32],
    ispeed: u32,
    ospeed: u32,
}

const ICANON: u32 = 0o2;
const ECHO: u32 = 0o10;
const ISIG: u32 = 0o1;
const IEXTEN: u32 = 0o100000;
const ICRNL: u32 = 0o400;
const IXON: u32 = 0o2000;
const VTIME: usize = 5;
const VMIN: usize = 6;

pub fn get_termios(fd: i32) -> Option<Termios> {
    let mut t = Termios { iflag: 0, oflag: 0, cflag: 0, lflag: 0, line: 0, cc: [0; 32], ispeed: 0, ospeed: 0 };
    // SAFETY: `t` is at least as large as the kernel's struct termios.
    (unsafe { ioctl(fd, TCGETS, &mut t as *mut Termios) } >= 0).then_some(t)
}

pub fn set_termios(fd: i32, t: &Termios) -> io::Result<()> {
    // SAFETY: `t` is a valid struct termios.
    cvt(unsafe { ioctl(fd, TCSETS, t as *const Termios) })
}

impl Termios {
    /// Raw-ish mode for the line editor: no canonical mode, no echo, no signal keys, no XON/XOFF, CR not mapped;
    /// output processing stays on so "\n" still returns the carriage.
    pub fn raw(mut self) -> Termios {
        self.lflag &= !(ICANON | ECHO | ISIG | IEXTEN);
        self.iflag &= !(ICRNL | IXON);
        self.cc[VMIN] = 1;
        self.cc[VTIME] = 0;
        self
    }
}

pub fn is_tty(fd: i32) -> bool {
    get_termios(fd).is_some()
}

// ---------------------------------------------------------------- statfs

#[repr(C)]
struct StatFs {
    f_type: i64,
    f_bsize: i64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [i32; 2],
    f_namelen: i64,
    f_frsize: i64,
    f_flags: i64,
    f_spare: [i64; 4],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FsUsage {
    pub total: u64,
    pub free: u64,
    pub avail: u64,
}

pub fn fs_usage(path: &str) -> io::Result<FsUsage> {
    let p = cstr(path)?;
    let mut s = StatFs { f_type: 0, f_bsize: 0, f_blocks: 0, f_bfree: 0, f_bavail: 0, f_files: 0, f_ffree: 0, f_fsid: [0; 2], f_namelen: 0, f_frsize: 0, f_flags: 0, f_spare: [0; 4] };
    // SAFETY: valid C string and out buffer of the kernel layout.
    cvt(unsafe { statfs(p.as_ptr(), &mut s) })?;
    let bs = if s.f_frsize > 0 { s.f_frsize } else { s.f_bsize } as u64;
    Ok(FsUsage { total: s.f_blocks * bs, free: s.f_bfree * bs, avail: s.f_bavail * bs })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn termios_is_at_least_kernel_size() {
        assert_eq!(std::mem::size_of::<Termios>(), 60);
        assert_eq!(std::mem::size_of::<SigAction>(), 152);
        assert_eq!(std::mem::size_of::<StatFs>(), 120);
    }
    #[test]
    fn statfs_of_root_works() {
        let u = fs_usage("/").unwrap();
        assert!(u.total > 0 && u.avail <= u.total);
    }
    #[test]
    fn raw_clears_the_line_discipline_bits() {
        let t = Termios { iflag: ICRNL | IXON, oflag: 0, cflag: 0, lflag: ICANON | ECHO | ISIG | IEXTEN, line: 0, cc: [0; 32], ispeed: 0, ospeed: 0 };
        let r = t.raw();
        assert_eq!(r.lflag, 0);
        assert_eq!(r.iflag, 0);
        assert_eq!(r.cc[VMIN], 1);
    }
}
