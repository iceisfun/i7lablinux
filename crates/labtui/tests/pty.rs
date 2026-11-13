//! Real-tty smoke test: a pseudo terminal pair, RawTerm / EventLoop / Screen on the slave side, the test acts as
//! the terminal on the master side. One test function only: the SIGWINCH flag is process-global.

use std::ffi::{c_char, c_void, CStr};
use std::time::Duration;

use labtui::{term, App, Caps, ColorMode, Event, EventLoop, Key, Options, RawTerm, Screen};

extern "C" {
    fn posix_openpt(flags: i32) -> i32;
    fn grantpt(fd: i32) -> i32;
    fn unlockpt(fd: i32) -> i32;
    fn ptsname(fd: i32) -> *const c_char;
    fn open(path: *const c_char, flags: i32, ...) -> i32;
    fn ioctl(fd: i32, req: u64, ...) -> i32;
    fn read(fd: i32, buf: *mut c_void, n: usize) -> isize;
    fn write(fd: i32, buf: *const c_void, n: usize) -> isize;
    fn close(fd: i32) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn getpid() -> i32;
    fn tcgetattr(fd: i32, t: *mut [u8; 128]) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
}

const O_RDWR: i32 = 2;
const O_NOCTTY: i32 = 0o400;
const TIOCSWINSZ: u64 = 0x5414;
const SIGWINCH: i32 = 28;
const F_SETFL: i32 = 4;
const O_NONBLOCK: i32 = 0o4000;

#[repr(C)]
struct Winsize {
    row: u16,
    col: u16,
    x: u16,
    y: u16,
}

fn termios_bytes(fd: i32) -> [u8; 128] {
    let mut b = [0u8; 128];
    assert_eq!(unsafe { tcgetattr(fd, &mut b) }, 0);
    // only the 4 flag words matter for the comparison
    let mut out = [0u8; 128];
    out[..16].copy_from_slice(&b[..16]);
    out
}

fn drain(master: i32) -> Vec<u8> {
    let mut all = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { read(master, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        all.extend_from_slice(&buf[..n as usize]);
    }
    all
}

#[test]
fn raw_mode_keys_resize_and_screen_on_a_pty() {
    unsafe {
        let master = posix_openpt(O_RDWR | O_NOCTTY);
        assert!(master >= 0);
        assert_eq!(grantpt(master), 0);
        assert_eq!(unlockpt(master), 0);
        let name = CStr::from_ptr(ptsname(master)).to_owned();
        let slave = open(name.as_ptr(), O_RDWR | O_NOCTTY);
        assert!(slave >= 0);
        let ws = Winsize { row: 30, col: 100, x: 0, y: 0 };
        assert_eq!(ioctl(master, TIOCSWINSZ, &ws as *const Winsize), 0);
        fcntl(master, F_SETFL, O_NONBLOCK);

        let before = termios_bytes(slave);
        let mut raw = RawTerm::enter(slave).expect("enter raw mode on a pty");
        assert!(term::is_tty(slave));
        assert_eq!(raw.size(), (100, 30));
        let during = termios_bytes(slave);
        assert_ne!(before, during, "raw mode changed the line discipline");

        // screen output reaches the terminal side as one frame
        let caps = Caps { color: ColorMode::Ansi16, unicode: true, alt_screen: true };
        let mut screen = Screen::new(&raw, caps);
        screen.begin(&mut raw).unwrap();
        let mut app = App::new(Options::default());
        app.set_data(std::sync::Arc::new(labtui::sample::demo_data()));
        app.draw(screen.buffer());
        screen.present().unwrap();
        let out = drain(master);
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("\x1b[?1049h"), "alternate screen entered");
        assert!(text.contains("\x1b[?25l"), "cursor hidden");
        assert!(text.contains("i7lablinux"));
        assert!(text.contains("Overview"));

        // keys typed on the terminal side arrive decoded, in raw mode (no echo, no line buffering)
        let mut ev = EventLoop::new(slave);
        let keys = b"a\x1b[B\x1bOP";
        assert_eq!(write(master, keys.as_ptr() as *const c_void, keys.len()), keys.len() as isize);
        assert_eq!(ev.next(Duration::from_secs(2)), Event::Key(Key::Char('a')));
        assert_eq!(ev.next(Duration::from_secs(2)), Event::Key(Key::Down));
        assert_eq!(ev.next(Duration::from_secs(2)), Event::Key(Key::F(1)));
        assert!(drain(master).is_empty(), "raw mode: the kernel did not echo");
        // a lone ESC resolves after the timeout
        write(master, b"\x1b".as_ptr() as *const c_void, 1);
        assert_eq!(ev.next(Duration::from_secs(2)), Event::Key(Key::Esc));

        // resize: new size on the master, SIGWINCH to ourselves
        let ws = Winsize { row: 43, col: 132, x: 0, y: 0 };
        assert_eq!(ioctl(master, TIOCSWINSZ, &ws as *const Winsize), 0);
        kill(getpid(), SIGWINCH);
        assert_eq!(ev.next(Duration::from_secs(2)), Event::Resize(132, 43));
        screen.resize(132, 43);
        app.draw(screen.buffer());
        screen.present().unwrap();
        assert!(String::from_utf8_lossy(&drain(master)).contains("i7lablinux"));

        // the waker interrupts a long wait
        let w = ev.waker();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            w.wake();
        });
        let t0 = std::time::Instant::now();
        assert_eq!(ev.next(Duration::from_secs(5)), Event::Tick);
        assert!(t0.elapsed() < Duration::from_secs(2));
        t.join().unwrap();

        // restore: cooked mode back, screen reset sequences sent
        raw.restore();
        let after = termios_bytes(slave);
        assert_eq!(before, after, "line discipline restored");
        let leave = String::from_utf8_lossy(&drain(master)).to_string();
        assert!(leave.contains("\x1b[?25h"), "cursor shown again");
        assert!(leave.contains("\x1b[?1049l"), "alternate screen left");
        close(slave);
        close(master);
    }
}
