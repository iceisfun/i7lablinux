//! Event loop: poll(2) on the tty, SIGWINCH flag, self-pipe wake-ups from the data thread. Owner: P5.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::input::{Decoder, Key};
use crate::term::{self, ffi};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Key(Key),
    /// (cols, rows)
    Resize(u16, u16),
    /// timeout, or the data thread called `Waker::wake` (new snapshot to show)
    Tick,
    /// SIGTERM / SIGHUP arrived: leave the UI now
    Quit,
}

/// How long to wait for the byte after an ESC before calling it a lone Escape.
pub const ESC_TIMEOUT: Duration = Duration::from_millis(50);

/// Pure input pump: bytes in, queued events out. Separated from the fd so tests need no tty.
#[derive(Default)]
pub struct Pump {
    dec: Decoder,
    queue: VecDeque<Event>,
}

impl Pump {
    pub fn new() -> Pump {
        Pump::default()
    }
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        for k in self.dec.feed_all(bytes) {
            self.queue.push_back(Event::Key(k));
        }
    }
    /// Call when the ESC timeout expired without more input.
    pub fn timeout(&mut self) {
        if let Some(k) = self.dec.flush_escape() {
            self.queue.push_back(Event::Key(k));
        }
    }
    pub fn pending_escape(&self) -> bool {
        self.dec.has_pending()
    }
    pub fn pop(&mut self) -> Option<Event> {
        self.queue.pop_front()
    }
}

/// Handle the data thread uses to wake the loop (writes one byte to the self-pipe). Cheap to clone.
#[derive(Clone, Copy, Debug)]
pub struct Waker {
    fd: i32,
}

impl Waker {
    pub fn wake(&self) {
        let b = 1u8;
        // SAFETY: one byte from a valid pointer; the pipe is non-blocking, a full pipe already means "awake".
        unsafe { ffi::write(self.fd, &b as *const u8 as *const ffi::c_void, 1) };
    }
}

pub struct EventLoop {
    fd: i32,
    pipe_r: i32,
    pipe_w: i32,
    pump: Pump,
}

impl EventLoop {
    /// `tty_fd` is the terminal to read keys from. Installs the SIGWINCH / SIGTERM handlers.
    pub fn new(tty_fd: i32) -> EventLoop {
        term::install_signal_handlers();
        let mut fds = [-1i32; 2];
        // SAFETY: fds has room for two ints.
        let r = unsafe { ffi::pipe2(fds.as_mut_ptr(), ffi::O_NONBLOCK | ffi::O_CLOEXEC) };
        if r != 0 {
            fds = [-1, -1];
        }
        EventLoop { fd: tty_fd, pipe_r: fds[0], pipe_w: fds[1], pump: Pump::new() }
    }

    pub fn waker(&self) -> Waker {
        Waker { fd: self.pipe_w }
    }

    /// Wait up to `timeout` for the next event. Resize and Quit take priority over keys.
    pub fn next(&mut self, timeout: Duration) -> Event {
        let deadline = Instant::now() + timeout;
        let mut polled = false;
        loop {
            if term::TERMINATE.load(Ordering::SeqCst) {
                return Event::Quit;
            }
            if term::WINCH.swap(false, Ordering::SeqCst) {
                if let Some((w, h)) = term::winsize(self.fd) {
                    return Event::Resize(w, h);
                }
            }
            if let Some(e) = self.pump.pop() {
                return e;
            }
            let now = Instant::now();
            // the flags above are re-checked after every poll: a signal delivered to another thread does not
            // interrupt our poll, so a resize is noticed at the latest when the poll times out
            if polled && now >= deadline {
                return Event::Tick;
            }
            polled = true;
            let mut wait = deadline.saturating_duration_since(now);
            let esc = self.pump.pending_escape();
            if esc {
                wait = wait.min(ESC_TIMEOUT);
            }
            match self.poll(wait) {
                Ok((tty_ready, pipe_ready)) => {
                    if pipe_ready {
                        self.drain_pipe();
                        return Event::Tick;
                    }
                    if tty_ready {
                        let mut buf = [0u8; 256];
                        // SAFETY: buf is valid for 256 bytes.
                        let n = unsafe { ffi::read(self.fd, buf.as_mut_ptr() as *mut ffi::c_void, buf.len()) };
                        if n > 0 {
                            self.pump.push_bytes(&buf[..n as usize]);
                        } else if n == 0 {
                            // EOF / hangup on the tty: nothing more will ever arrive
                            return Event::Quit;
                        }
                        continue;
                    }
                    if esc {
                        self.pump.timeout();
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue, // SIGWINCH etc.: loop re-checks flags
                Err(_) => return Event::Tick,
            }
        }
    }

    fn poll(&self, wait: Duration) -> io::Result<(bool, bool)> {
        let mut fds = [ffi::PollFd { fd: self.fd, events: ffi::POLLIN, revents: 0 }, ffi::PollFd { fd: self.pipe_r, events: ffi::POLLIN, revents: 0 }];
        let ms = wait.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: fds is a valid array of 2 pollfds (a negative fd is ignored by poll).
        let n = unsafe { ffi::poll(fds.as_mut_ptr(), 2, ms) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        // POLLHUP / POLLERR (8 / 16) on the tty also mean "readable": the read reports EOF or the error
        Ok((fds[0].revents != 0, fds[1].revents & ffi::POLLIN != 0))
    }

    fn drain_pipe(&self) {
        let mut buf = [0u8; 64];
        // SAFETY: valid buffer; non-blocking pipe.
        while unsafe { ffi::read(self.pipe_r, buf.as_mut_ptr() as *mut ffi::c_void, buf.len()) } > 0 {}
    }
}

impl Drop for EventLoop {
    fn drop(&mut self) {
        // SAFETY: closing our own pipe ends (skipped when pipe2 failed).
        unsafe {
            if self.pipe_r >= 0 {
                ffi::close(self.pipe_r);
                ffi::close(self.pipe_w);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pump_decodes_and_times_out_escape() {
        let mut p = Pump::new();
        p.push_bytes(b"a\x1b[B\x1b");
        assert_eq!(p.pop(), Some(Event::Key(Key::Char('a'))));
        assert_eq!(p.pop(), Some(Event::Key(Key::Down)));
        assert_eq!(p.pop(), None);
        assert!(p.pending_escape());
        p.timeout();
        assert_eq!(p.pop(), Some(Event::Key(Key::Esc)));
        assert!(!p.pending_escape());
    }
    #[test]
    fn waker_wakes_the_loop() {
        // fd 0 is whatever the test harness has; use /dev/null as a quiet "tty" (poll on it is always readable
        // with EOF, so use a pipe pair instead)
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { ffi::pipe2(fds.as_mut_ptr(), ffi::O_CLOEXEC) }, 0);
        let mut el = EventLoop::new(fds[0]);
        let w = el.waker();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            w.wake();
        });
        let t0 = Instant::now();
        assert_eq!(el.next(Duration::from_secs(5)), Event::Tick);
        assert!(t0.elapsed() < Duration::from_secs(2));
        // key bytes on the "tty" arrive as key events
        unsafe { ffi::write(fds[1], b"q".as_ptr() as *const ffi::c_void, 1) };
        assert_eq!(el.next(Duration::from_secs(2)), Event::Key(Key::Char('q')));
        // lone ESC resolves after the timeout
        unsafe { ffi::write(fds[1], b"\x1b".as_ptr() as *const ffi::c_void, 1) };
        assert_eq!(el.next(Duration::from_secs(2)), Event::Key(Key::Esc));
        // idle: tick at the timeout
        assert_eq!(el.next(Duration::from_millis(20)), Event::Tick);
        unsafe {
            ffi::close(fds[0]);
            ffi::close(fds[1]);
        }
    }
}
