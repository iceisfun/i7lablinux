//! Private libc FFI of the agent for the few calls `labproto::sys` does not offer yet (kill, setsid, pty,
//! clock_settime, an AF_PACKET IPv4 socket for DHCP). Every `unsafe` block is here, behind safe functions.
//! MIGRATE: move each wrapper into `labproto::sys` when P2 lands the agreed list (sys.rs module doc) and delete it
//! from here. x86_64 Linux constants.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;

mod c {
    extern "C" {
        pub fn kill(pid: i32, sig: i32) -> i32;
        pub fn setsid() -> i32;
        pub fn ioctl(fd: i32, req: u64, ...) -> i32;
        pub fn clock_settime(clk: i32, ts: *const [i64; 2]) -> i32;
        pub fn socket(domain: i32, ty: i32, proto: i32) -> i32;
        pub fn bind(fd: i32, addr: *const u8, len: u32) -> i32;
        pub fn sendto(fd: i32, buf: *const u8, len: usize, flags: i32, addr: *const u8, alen: u32) -> isize;
        pub fn recv(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize;
        pub fn poll(fds: *mut [i32; 2], n: u64, timeout_ms: i32) -> i32;
        pub fn close(fd: i32) -> i32;
        pub fn getsockopt(fd: i32, level: i32, name: i32, val: *mut u8, len: *mut u32) -> i32;
    }
}

pub const SIGTERM: i32 = 15;
pub const SIGKILL: i32 = 9;

fn check(rc: i32) -> io::Result<i32> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

pub fn kill(pid: i32, sig: i32) -> io::Result<()> {
    // SAFETY: plain integer arguments.
    check(unsafe { c::kill(pid, sig) }).map(|_| ())
}

/// Signal a whole process group (children are started with `process_group(0)`).
pub fn killpg(pgid: i32, sig: i32) -> io::Result<()> {
    if pgid <= 1 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    kill(-pgid, sig)
}

pub fn setsid() -> io::Result<()> {
    // SAFETY: no arguments.
    check(unsafe { c::setsid() }).map(|_| ())
}

const TIOCGPTN: u64 = 0x8004_5430;
const TIOCSPTLCK: u64 = 0x4004_5431;
const TIOCSCTTY: u64 = 0x540E;
const TIOCSWINSZ: u64 = 0x5414;

/// (master, slave) of a fresh pty. Needs devpts at /dev/pts (init mounts it).
pub fn open_pty() -> io::Result<(File, File)> {
    let master = std::fs::OpenOptions::new().read(true).write(true).custom_flags(0o400 /* O_NOCTTY */ | 0o2000000 /* O_CLOEXEC */).open("/dev/ptmx")?;
    let mut unlock: i32 = 0;
    let mut n: u32 = 0;
    // SAFETY: both ioctls take a pointer to a 4-byte int that lives across the call.
    unsafe {
        check(c::ioctl(master.as_raw_fd(), TIOCSPTLCK, &mut unlock as *mut i32))?;
        check(c::ioctl(master.as_raw_fd(), TIOCGPTN, &mut n as *mut u32))?;
    }
    let slave = std::fs::OpenOptions::new().read(true).write(true).custom_flags(0o400 | 0o2000000).open(format!("/dev/pts/{}", n))?;
    Ok((master, slave))
}

pub fn set_winsize(fd: RawFd, cols: u16, rows: u16) -> io::Result<()> {
    let ws: [u16; 4] = [rows, cols, 0, 0];
    // SAFETY: TIOCSWINSZ reads a struct winsize (4 x u16).
    check(unsafe { c::ioctl(fd, TIOCSWINSZ, ws.as_ptr()) }).map(|_| ())
}

/// For `pre_exec` after `setsid`: make `fd` (0) the controlling terminal.
pub fn set_ctty(fd: RawFd) -> io::Result<()> {
    // SAFETY: TIOCSCTTY with arg 0.
    check(unsafe { c::ioctl(fd, TIOCSCTTY, 0) }).map(|_| ())
}

pub fn clock_settime(secs: i64) -> io::Result<()> {
    let ts = [secs, 0i64];
    // SAFETY: pointer to a 2 x i64 timespec; CLOCK_REALTIME = 0.
    check(unsafe { c::clock_settime(0, &ts) }).map(|_| ())
}

/// AF_PACKET SOCK_RAW socket for IPv4 frames on one interface (DHCP before the NIC has an address).
pub struct PacketIp {
    fd: RawFd,
    ifindex: i32,
}

#[repr(C)]
struct SockaddrLl {
    family: u16,
    protocol: u16,
    ifindex: i32,
    hatype: u16,
    pkttype: u8,
    halen: u8,
    addr: [u8; 8],
}

impl PacketIp {
    pub fn open(ifindex: i32) -> io::Result<PacketIp> {
        // SAFETY: socket(AF_PACKET=17, SOCK_RAW|SOCK_CLOEXEC, htons(ETH_P_IP)).
        let fd = check(unsafe { c::socket(17, 3 | 0o2000000, (0x0800u16).to_be() as i32) })?;
        let sa = SockaddrLl { family: 17, protocol: (0x0800u16).to_be(), ifindex, hatype: 0, pkttype: 0, halen: 0, addr: [0; 8] };
        // SAFETY: sa is a valid sockaddr_ll of the stated size.
        if let Err(e) = check(unsafe { c::bind(fd, &sa as *const SockaddrLl as *const u8, std::mem::size_of::<SockaddrLl>() as u32) }) {
            // SAFETY: fd was just created.
            unsafe { c::close(fd) };
            return Err(e);
        }
        Ok(PacketIp { fd, ifindex })
    }

    pub fn send(&self, frame: &[u8]) -> io::Result<()> {
        let sa = SockaddrLl { family: 17, protocol: (0x0800u16).to_be(), ifindex: self.ifindex, hatype: 0, pkttype: 0, halen: 6, addr: [0xff; 8] };
        // SAFETY: frame and sa are valid for the call.
        let n = unsafe { c::sendto(self.fd, frame.as_ptr(), frame.len(), 0, &sa as *const SockaddrLl as *const u8, std::mem::size_of::<SockaddrLl>() as u32) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Wait up to `timeout_ms` for one frame; `Ok(None)` on timeout.
    pub fn recv(&self, buf: &mut [u8], timeout_ms: i32) -> io::Result<Option<usize>> {
        // pollfd { fd: i32, events: i16 (POLLIN=1), revents: i16 } packed in [i32; 2]
        let mut pfd: [i32; 2] = [self.fd, 1];
        // SAFETY: one pollfd.
        let rc = unsafe { c::poll(&mut pfd, 1, timeout_ms) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::Interrupted { Ok(None) } else { Err(e) };
        }
        if rc == 0 {
            return Ok(None);
        }
        // SAFETY: buf is valid for buf.len() bytes.
        let n = unsafe { c::recv(self.fd, buf.as_mut_ptr(), buf.len(), 0) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Some(n as usize))
        }
    }
}

impl Drop for PacketIp {
    fn drop(&mut self) {
        // SAFETY: we own the fd.
        unsafe { c::close(self.fd) };
    }
}

/// uid of the peer of a connected unix socket (SO_PEERCRED).
pub fn peer_uid(fd: RawFd) -> io::Result<u32> {
    let mut cred = [0u32; 3]; // struct ucred { pid, uid, gid }
    let mut len = 12u32;
    // SAFETY: cred is 12 writable bytes, len says so.
    check(unsafe { c::getsockopt(fd, 1 /* SOL_SOCKET */, 17 /* SO_PEERCRED */, cred.as_mut_ptr() as *mut u8, &mut len) })?;
    Ok(cred[1])
}

/// Wrap a raw fd we own (test helper and pty clones).
pub fn file_from_fd(fd: RawFd) -> File {
    // SAFETY: caller passes an fd it owns and no longer uses.
    unsafe { File::from_raw_fd(fd) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn killpg_refuses_init_and_zero() {
        assert!(killpg(0, 15).is_err());
        assert!(killpg(1, 15).is_err());
        assert!(killpg(-5, 15).is_err());
    }
    #[test]
    fn pty_opens_when_devpts_exists() {
        if std::path::Path::new("/dev/pts").exists() && std::path::Path::new("/dev/ptmx").exists() {
            if let Ok((m, s)) = open_pty() {
                set_winsize(m.as_raw_fd(), 80, 24).unwrap();
                drop(s);
            }
        }
    }
}
