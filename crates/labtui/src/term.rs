//! Raw terminal mode on a tty fd (termios via hand-written libc FFI, no crates). Owner: P5.
//!
//! Restore happens on `restore()`, on Drop, from a panic hook (`install_panic_hook`) and, through the signal
//! flags, when the event loop sees SIGTERM/SIGHUP. SIGWINCH only sets a flag (async-signal-safe).

use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Mutex;

pub type RawFd = i32;

pub(crate) mod ffi {
    pub use std::ffi::c_void;
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Termios {
        pub c_iflag: u32,
        pub c_oflag: u32,
        pub c_cflag: u32,
        pub c_lflag: u32,
        pub c_line: u8,
        pub c_cc: [u8; 32],
        pub c_ispeed: u32,
        pub c_ospeed: u32,
        /// slack so a libc with a larger struct cannot write past the end
        pub _pad: [u32; 8],
    }
    #[repr(C)]
    #[derive(Default)]
    pub struct Winsize {
        pub ws_row: u16,
        pub ws_col: u16,
        pub ws_xpixel: u16,
        pub ws_ypixel: u16,
    }
    #[repr(C)]
    pub struct PollFd {
        pub fd: i32,
        pub events: i16,
        pub revents: i16,
    }
    extern "C" {
        pub fn tcgetattr(fd: i32, t: *mut Termios) -> i32;
        pub fn tcsetattr(fd: i32, actions: i32, t: *const Termios) -> i32;
        pub fn ioctl(fd: i32, req: u64, ...) -> i32;
        pub fn signal(sig: i32, handler: usize) -> usize;
        pub fn poll(fds: *mut PollFd, n: u64, timeout_ms: i32) -> i32;
        pub fn read(fd: i32, buf: *mut c_void, n: usize) -> isize;
        pub fn write(fd: i32, buf: *const c_void, n: usize) -> isize;
        pub fn pipe2(fds: *mut i32, flags: i32) -> i32;
        pub fn close(fd: i32) -> i32;
        pub fn isatty(fd: i32) -> i32;
    }
    pub const ICANON: u32 = 0o2;
    pub const ECHO: u32 = 0o10;
    pub const ISIG: u32 = 0o1;
    pub const IEXTEN: u32 = 0o100000;
    pub const IXON: u32 = 0o2000;
    pub const ICRNL: u32 = 0o400;
    pub const INLCR: u32 = 0o100;
    pub const IGNCR: u32 = 0o200;
    pub const BRKINT: u32 = 0o2;
    pub const INPCK: u32 = 0o20;
    pub const ISTRIP: u32 = 0o40;
    pub const OPOST: u32 = 0o1;
    pub const CSIZE: u32 = 0o60;
    pub const CS8: u32 = 0o60;
    pub const PARENB: u32 = 0o400;
    pub const VTIME: usize = 5;
    pub const VMIN: usize = 6;
    pub const TCSAFLUSH: i32 = 2;
    pub const TIOCGWINSZ: u64 = 0x5413;
    pub const POLLIN: i16 = 1;
    pub const SIGHUP: i32 = 1;
    pub const SIGTERM: i32 = 15;
    pub const SIGWINCH: i32 = 28;
    pub const O_NONBLOCK: i32 = 0o4000;
    pub const O_CLOEXEC: i32 = 0o2000000;
}

/// Set by the SIGWINCH handler, cleared by the event loop.
pub(crate) static WINCH: AtomicBool = AtomicBool::new(false);
/// Set by the SIGTERM / SIGHUP handler.
pub(crate) static TERMINATE: AtomicBool = AtomicBool::new(false);
static ALT_SCREEN: AtomicBool = AtomicBool::new(false);
static RAW_FD: AtomicI32 = AtomicI32::new(-1);
static SAVED: Mutex<Option<ffi::Termios>> = Mutex::new(None);

extern "C" fn on_winch(_: i32) {
    WINCH.store(true, Ordering::SeqCst);
}
extern "C" fn on_term(_: i32) {
    TERMINATE.store(true, Ordering::SeqCst);
}

pub(crate) fn install_signal_handlers() {
    // SAFETY: the handlers only store to an AtomicBool, which is async-signal-safe.
    unsafe {
        ffi::signal(ffi::SIGWINCH, on_winch as *const () as usize);
        ffi::signal(ffi::SIGTERM, on_term as *const () as usize);
        ffi::signal(ffi::SIGHUP, on_term as *const () as usize);
    }
}

/// Bytes that undo what the screen set up: attributes, cursor, line wrap, alternate screen.
pub fn leave_sequence(alt_screen: bool) -> Vec<u8> {
    let mut v = b"\x1b[0m\x1b[?25h\x1b[?7h".to_vec();
    if alt_screen {
        v.extend_from_slice(b"\x1b[?1049l");
    } else {
        v.extend_from_slice(b"\x1b[2J\x1b[H");
    }
    v
}

/// Write all bytes to fd with one or more write(2) calls (handles partial writes and EINTR; EAGAIN waits).
pub fn write_all(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: buf is a valid slice for its length.
        let n = unsafe { ffi::write(fd, buf.as_ptr() as *const ffi::c_void, buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {
                    let mut p = ffi::PollFd { fd, events: 4 /* POLLOUT */, revents: 0 };
                    // SAFETY: p is a valid pollfd.
                    unsafe { ffi::poll(&mut p, 1, 100) };
                    continue;
                }
                _ => return Err(e),
            }
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

/// Window size from the kernel (cols, rows); None when fd is not a tty or reports 0x0.
pub fn winsize(fd: RawFd) -> Option<(u16, u16)> {
    let mut ws = ffi::Winsize::default();
    // SAFETY: TIOCGWINSZ writes a winsize struct into ws.
    let r = unsafe { ffi::ioctl(fd, ffi::TIOCGWINSZ, &mut ws as *mut ffi::Winsize) };
    (r == 0 && ws.ws_col > 0 && ws.ws_row > 0).then_some((ws.ws_col, ws.ws_row))
}

/// Pure: termios flags for raw mode, from the saved ones. Exposed for unit tests.
pub(crate) fn make_raw(t: &mut ffi::Termios) {
    use ffi::*;
    t.c_iflag &= !(IXON | ICRNL | INLCR | IGNCR | BRKINT | INPCK | ISTRIP);
    t.c_oflag &= !OPOST;
    t.c_lflag &= !(ICANON | ECHO | ISIG | IEXTEN);
    t.c_cflag &= !(CSIZE | PARENB);
    t.c_cflag |= CS8;
    t.c_cc[VMIN] = 0;
    t.c_cc[VTIME] = 1;
}

/// Terminal in raw mode; restores the saved state on `restore()` and on Drop.
pub struct RawTerm {
    fd: RawFd,
    saved: ffi::Termios,
    active: bool,
    alt: bool,
}

impl RawTerm {
    /// tcgetattr, raw mode (no ICANON/ECHO/ISIG/IEXTEN/IXON/ICRNL/OPOST, CS8), VMIN=0 VTIME=1 (100 ms ticks).
    /// Fails with an OS error when `fd` is not a terminal.
    pub fn enter(fd: RawFd) -> io::Result<RawTerm> {
        // SAFETY: Termios is plain data; tcgetattr fills it.
        let mut saved: ffi::Termios = unsafe { std::mem::zeroed() };
        if unsafe { ffi::tcgetattr(fd, &mut saved) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = saved;
        make_raw(&mut raw);
        if unsafe { ffi::tcsetattr(fd, ffi::TCSAFLUSH, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        *SAVED.lock().unwrap_or_else(|e| e.into_inner()) = Some(saved);
        RAW_FD.store(fd, Ordering::SeqCst);
        install_signal_handlers();
        Ok(RawTerm { fd, saved, active: true, alt: false })
    }
    /// TIOCGWINSZ, fallback $COLUMNS/$LINES, then 80x25. Returns (cols, rows).
    pub fn size(&self) -> (u16, u16) {
        if let Some(s) = winsize(self.fd) {
            return s;
        }
        let env = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<u16>().ok()).filter(|v| *v > 0);
        (env("COLUMNS").unwrap_or(80), env("LINES").unwrap_or(25))
    }
    pub fn fd(&self) -> RawFd {
        self.fd
    }
    /// Remember that the alternate screen is in use so restore (also from the panic hook) leaves it.
    pub fn set_alt_screen(&mut self, on: bool) {
        self.alt = on;
        ALT_SCREEN.store(on, Ordering::SeqCst);
    }
    /// Put the terminal back: cooked mode, attributes reset, cursor shown, wrap on. Idempotent.
    pub fn restore(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let _ = write_all(self.fd, &leave_sequence(self.alt));
        // SAFETY: saved came from tcgetattr on this fd.
        unsafe { ffi::tcsetattr(self.fd, ffi::TCSAFLUSH, &self.saved) };
        RAW_FD.store(-1, Ordering::SeqCst);
    }
    /// Leave raw mode temporarily, e.g. to run `i7labsh` on the tty (F10). Pair with `resume`.
    pub fn suspend(&mut self) {
        self.restore();
    }
    /// Re-enter raw mode after `suspend`. The caller must `Screen::invalidate` afterwards.
    pub fn resume(&mut self) -> io::Result<()> {
        let mut raw = self.saved;
        make_raw(&mut raw);
        // SAFETY: valid termios.
        if unsafe { ffi::tcsetattr(self.fd, ffi::TCSAFLUSH, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        self.active = true;
        RAW_FD.store(self.fd, Ordering::SeqCst);
        Ok(())
    }
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Drop for RawTerm {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Restore the terminal from a panic hook (chains to the previous hook afterwards), so a crash in the TUI
/// never leaves the console in raw mode with a hidden cursor.
pub fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        emergency_restore();
        prev(info);
    }));
}

/// Best-effort restore from outside the RawTerm owner (panic hook, signal-driven shutdown).
pub fn emergency_restore() {
    let fd = RAW_FD.swap(-1, Ordering::SeqCst);
    if fd < 0 {
        return;
    }
    let saved = SAVED.lock().map(|g| *g).unwrap_or_else(|e| *e.into_inner());
    let _ = write_all(fd, &leave_sequence(ALT_SCREEN.load(Ordering::SeqCst)));
    if let Some(t) = saved {
        // SAFETY: t came from tcgetattr.
        unsafe { ffi::tcsetattr(fd, ffi::TCSAFLUSH, &t) };
    }
}

/// True when SIGTERM or SIGHUP arrived (the app should save nothing and exit).
pub fn terminate_requested() -> bool {
    TERMINATE.load(Ordering::SeqCst)
}

/// Escape sequence asking the terminal for its size on a line without SIGWINCH (serial): park the cursor far
/// bottom-right, then request a cursor position report. The answer decodes as `Key::CursorReport`.
pub fn size_query() -> &'static [u8] {
    b"\x1b[s\x1b[999;999H\x1b[6n\x1b[u"
}

pub fn is_tty(fd: RawFd) -> bool {
    // SAFETY: isatty has no memory effects.
    unsafe { ffi::isatty(fd) == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_flags() {
        let mut t: ffi::Termios = unsafe { std::mem::zeroed() };
        t.c_lflag = ffi::ICANON | ffi::ECHO | ffi::ISIG | ffi::IEXTEN;
        t.c_iflag = ffi::IXON | ffi::ICRNL;
        t.c_oflag = ffi::OPOST;
        make_raw(&mut t);
        assert_eq!(t.c_lflag, 0);
        assert_eq!(t.c_iflag, 0);
        assert_eq!(t.c_oflag, 0);
        assert_eq!(t.c_cflag & ffi::CS8, ffi::CS8);
        assert_eq!((t.c_cc[ffi::VMIN], t.c_cc[ffi::VTIME]), (0, 1));
    }
    #[test]
    fn non_tty_is_an_error() {
        // /dev/null is not a terminal
        use std::os::fd::AsRawFd;
        let f = std::fs::File::open("/dev/null").unwrap();
        assert!(RawTerm::enter(f.as_raw_fd()).is_err());
        assert!(!is_tty(f.as_raw_fd()));
        assert!(winsize(f.as_raw_fd()).is_none());
    }
    #[test]
    fn leave_sequence_shape() {
        assert!(leave_sequence(true).ends_with(b"\x1b[?1049l"));
        assert!(leave_sequence(false).ends_with(b"\x1b[H"));
    }
}
