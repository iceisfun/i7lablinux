//! Crate-private libc FFI for the terminal (raw mode, window size, non-blocking stdin). std has no safe API for
//! these; the unsafe surface is the four functions below. PLAN.md F-F7 allows a crate-private `ffi` until
//! labproto::sys grows these wrappers.

use std::io;

#[repr(C)]
#[derive(Clone, Copy)]
struct Termios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_line: u8,
    c_cc: [u8; 32],
    c_ispeed: u32,
    c_ospeed: u32,
}

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[repr(C)]
#[derive(Default)]
struct Winsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

extern "C" {
    fn isatty(fd: i32) -> i32;
    fn tcgetattr(fd: i32, t: *mut Termios) -> i32;
    fn tcsetattr(fd: i32, act: i32, t: *const Termios) -> i32;
    fn poll(fds: *mut PollFd, n: u64, timeout: i32) -> i32;
    fn ioctl(fd: i32, req: u64, ...) -> i32;
    fn read(fd: i32, buf: *mut std::ffi::c_void, n: usize) -> isize;
}

extern "C" {
    fn signal(signum: i32, handler: usize) -> usize;
}

static INTERRUPTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn on_sigint(_: i32) {
    INTERRUPTED.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// While alive, SIGINT sets a flag instead of killing the process, so a streaming ether call can CANCEL the
/// remote command and exit 130 cleanly. The previous (default) disposition is restored on drop.
pub struct InterruptGuard {
    prev: usize,
}

impl InterruptGuard {
    pub fn install() -> InterruptGuard {
        INTERRUPTED.store(false, std::sync::atomic::Ordering::SeqCst);
        // SAFETY: on_sigint only stores to an atomic (async-signal-safe).
        let prev = unsafe { signal(2, on_sigint as extern "C" fn(i32) as usize) };
        InterruptGuard { prev }
    }
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        // SAFETY: restores the handler value signal() returned (SIG_DFL = 0 for a normal process).
        unsafe { signal(2, self.prev) };
    }
}

pub fn interrupted() -> bool {
    INTERRUPTED.load(std::sync::atomic::Ordering::SeqCst)
}

const POLLIN: i16 = 1;
const TCSAFLUSH: i32 = 2;
const TIOCGWINSZ: u64 = 0x5413;

pub fn is_tty(fd: i32) -> bool {
    // SAFETY: plain integer argument.
    unsafe { isatty(fd) == 1 }
}

/// (columns, rows) of the terminal on `fd`.
pub fn winsize(fd: i32) -> Option<(u16, u16)> {
    let mut w = Winsize::default();
    // SAFETY: TIOCGWINSZ writes a struct winsize into the pointer.
    let r = unsafe { ioctl(fd, TIOCGWINSZ, &mut w as *mut Winsize) };
    if r == 0 && w.ws_col > 0 && w.ws_row > 0 {
        Some((w.ws_col, w.ws_row))
    } else {
        None
    }
}

/// Raw terminal mode on stdin until dropped.
pub struct RawMode {
    saved: Termios,
}

impl RawMode {
    pub fn enter() -> io::Result<RawMode> {
        let mut t = Termios { c_iflag: 0, c_oflag: 0, c_cflag: 0, c_lflag: 0, c_line: 0, c_cc: [0; 32], c_ispeed: 0, c_ospeed: 0 };
        // SAFETY: t is a valid, writable termios-sized buffer.
        if unsafe { tcgetattr(0, &mut t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let saved = t;
        // cfmakeraw
        t.c_iflag &= !(0o1 | 0o2 | 0o10 | 0o40 | 0o100 | 0o200 | 0o400 | 0o2000); // IGNBRK BRKINT PARMRK ISTRIP INLCR IGNCR ICRNL IXON
        t.c_oflag &= !0o1; // OPOST
        t.c_lflag &= !(0o10 | 0o100 | 0o2 | 0o1 | 0o100000); // ECHO ECHONL ICANON ISIG IEXTEN
        t.c_cflag &= !(0o60 | 0o400); // CSIZE PARENB
        t.c_cflag |= 0o60; // CS8
        t.c_cc[6] = 1; // VMIN
        t.c_cc[5] = 0; // VTIME
        // SAFETY: t is a valid termios.
        if unsafe { tcsetattr(0, TCSAFLUSH, &t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(RawMode { saved })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: restoring the termios we saved.
        unsafe { tcsetattr(0, TCSAFLUSH, &self.saved) };
    }
}

/// Read up to `buf.len()` bytes from stdin if any are ready within `timeout_ms`. `Ok(None)` = nothing yet,
/// `Ok(Some(0))` = EOF.
pub fn read_stdin_ready(buf: &mut [u8], timeout_ms: i32) -> io::Result<Option<usize>> {
    let mut p = PollFd { fd: 0, events: POLLIN, revents: 0 };
    // SAFETY: one valid pollfd.
    let r = unsafe { poll(&mut p, 1, timeout_ms) };
    if r < 0 {
        let e = io::Error::last_os_error();
        return if e.kind() == io::ErrorKind::Interrupted { Ok(None) } else { Err(e) };
    }
    if r == 0 {
        return Ok(None);
    }
    // SAFETY: buf is valid for buf.len() bytes.
    let n = unsafe { read(0, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        let e = io::Error::last_os_error();
        return if e.kind() == io::ErrorKind::Interrupted { Ok(None) } else { Err(e) };
    }
    Ok(Some(n as usize))
}
