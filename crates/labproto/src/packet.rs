//! AF_PACKET link with a classic-BPF filter for 0x88B5/0x88B6 (plain or behind one 802.1Q/802.1ad tag) and
//! PACKET_AUXDATA VLAN recovery. Port of the earlier lab-proxy prototype (hand-written FFI, no libc crate).
//!
//! One ETH_P_ALL socket is used (not a protocol-bound one): the kernel strips a hardware-accelerated 802.1Q tag
//! before protocol-specific sockets run, but ETH_P_ALL taps still see it through PACKET_AUXDATA. Frames the host sent
//! itself (PACKET_OUTGOING) are dropped, so an interface never answers its own transmissions.

use std::io;
use std::os::unix::io::RawFd;
use std::time::Duration;

use crate::link::{Link, RecvMeta};
use crate::mac::Mac;

mod ffi {
    extern "C" {
        pub fn socket(domain: i32, ty: i32, proto: i32) -> i32;
        pub fn bind(fd: i32, addr: *const u8, len: u32) -> i32;
        pub fn sendto(fd: i32, buf: *const u8, len: usize, flags: i32, addr: *const u8, alen: u32) -> isize;
        pub fn recvmsg(fd: i32, msg: *mut Msghdr, flags: i32) -> isize;
        pub fn setsockopt(fd: i32, level: i32, name: i32, val: *const u8, len: u32) -> i32;
        pub fn poll(fds: *mut PollFd, n: u64, ms: i32) -> i32;
        pub fn close(fd: i32) -> i32;
    }
    #[repr(C)]
    pub struct Iovec {
        pub base: *mut u8,
        pub len: usize,
    }
    #[repr(C)]
    pub struct Msghdr {
        pub name: *mut u8,
        pub namelen: u32,
        pub iov: *mut Iovec,
        pub iovlen: usize,
        pub control: *mut u8,
        pub controllen: usize,
        pub flags: i32,
    }
    #[repr(C)]
    pub struct PollFd {
        pub fd: i32,
        pub events: i16,
        pub revents: i16,
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SockaddrLl {
    family: u16,
    protocol: u16,
    ifindex: i32,
    hatype: u16,
    pkttype: u8,
    halen: u8,
    addr: [u8; 8],
}

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const AF_PACKET: i32 = 17;
const SOCK_RAW: i32 = 3;
const SOCK_CLOEXEC: i32 = 0o2000000;
const ETH_P_ALL: u16 = 3;
const SOL_SOCKET: i32 = 1;
const SO_ATTACH_FILTER: i32 = 26;
const SOL_PACKET: i32 = 263;
const PACKET_AUXDATA: i32 = 8;
const PACKET_OUTGOING: u8 = 4;
const TP_STATUS_VLAN_VALID: u32 = 1 << 4;
const TP_STATUS_VLAN_TPID_VALID: u32 = 1 << 6;
const POLLIN: i16 = 1;

/// The classic BPF program: accept 0x88B5/0x88B6 at the ethertype offset, directly or after one 0x8100 / 0x88A8 tag.
fn program() -> Vec<SockFilter> {
    let f = |code: u16, jt: u8, jf: u8, k: u32| SockFilter { code, jt, jf, k };
    // ethertype = A. Accept when A in {0x88b5, 0x88b6}. Else when A is a TPID, look at [16] the same way.
    vec![
        f(0x28, 0, 0, 12),     //  0 ldh [12]
        f(0x15, 8, 0, 0x88b5), //  1 jeq 88b5 -> accept (pc 10)
        f(0x15, 7, 0, 0x88b6), //  2 jeq 88b6 -> accept (pc 10)
        f(0x15, 2, 0, 0x8100), //  3 jeq 8100 -> tag (pc 6)
        f(0x15, 1, 0, 0x88a8), //  4 jeq 88a8 -> tag (pc 6)
        f(0x06, 0, 0, 0),      //  5 reject
        f(0x28, 0, 0, 16),     //  6 ldh [16]
        f(0x15, 2, 0, 0x88b5), //  7 jeq 88b5 -> accept (pc 10)
        f(0x15, 1, 0, 0x88b6), //  8 jeq 88b6 -> accept (pc 10)
        f(0x06, 0, 0, 0),      //  9 reject
        f(0x06, 0, 0, 0xffff), // 10 accept
    ]
}

pub struct PacketLink {
    fd: RawFd,
    /// (name, ifindex) the link serves; empty set = every Ethernet interface that is not a VLAN sub-interface.
    ifaces: Vec<(String, i32)>,
    all: bool,
}

impl PacketLink {
    /// Open one socket receiving the lab ethertypes on `ifaces` (empty = every Ethernet NIC). Needs CAP_NET_RAW.
    pub fn open(ifaces: &[String]) -> io::Result<PacketLink> {
        let mut list = Vec::new();
        let all = ifaces.is_empty();
        let names = if all { ethernet_ifaces()? } else { ifaces.to_vec() };
        for n in names {
            if all && is_vlan_subif(&n) {
                continue;
            }
            let idx = PacketLink::ifindex(&n)?;
            list.push((n, idx));
        }
        // SAFETY: plain socket(2).
        let fd = unsafe { ffi::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, (ETH_P_ALL.to_be()) as i32) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let link = PacketLink { fd, ifaces: list, all };
        link.setup()?;
        Ok(link)
    }

    fn setup(&self) -> io::Result<()> {
        let prog = program();
        let fp = SockFprog { len: prog.len() as u16, filter: prog.as_ptr() };
        // SAFETY: fp and the program outlive the call; the kernel copies the filter.
        let rc = unsafe { ffi::setsockopt(self.fd, SOL_SOCKET, SO_ATTACH_FILTER, &fp as *const SockFprog as *const u8, std::mem::size_of::<SockFprog>() as u32) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let one: i32 = 1;
        // SAFETY: val points at a live i32.
        let rc = unsafe { ffi::setsockopt(self.fd, SOL_PACKET, PACKET_AUXDATA, &one as *const i32 as *const u8, 4) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        // Bind to the first interface only when exactly one is served (cheaper); otherwise filter in user space.
        if self.ifaces.len() == 1 && !self.all {
            let sa = SockaddrLl { family: AF_PACKET as u16, protocol: ETH_P_ALL.to_be(), ifindex: self.ifaces[0].1, ..Default::default() };
            // SAFETY: sa is a valid sockaddr_ll.
            let rc = unsafe { ffi::bind(self.fd, &sa as *const SockaddrLl as *const u8, std::mem::size_of::<SockaddrLl>() as u32) };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub fn ifindex(name: &str) -> io::Result<i32> {
        let p = format!("/sys/class/net/{}/ifindex", name);
        std::fs::read_to_string(p)?.trim().parse().map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
    }

    pub fn ifaces(&self) -> &[(String, i32)] {
        &self.ifaces
    }

    fn serves(&self, ifindex: i32) -> bool {
        self.ifaces.iter().any(|(_, i)| *i == ifindex)
    }
}

impl Drop for PacketLink {
    fn drop(&mut self) {
        // SAFETY: we own the fd.
        unsafe { ffi::close(self.fd) };
    }
}

/// Walk a control-message buffer for SOL_PACKET/PACKET_AUXDATA (struct tpacket_auxdata) and return (TPID, TCI)
/// when the kernel stripped a tag (TP_STATUS_VLAN_VALID). 64-bit cmsghdr layout (len: usize, level: i32, type: i32).
pub fn parse_auxdata(ctrl: &[u8]) -> Option<(u16, u16)> {
    let mut off = 0usize;
    while off + 16 <= ctrl.len() {
        let len = usize::from_ne_bytes(ctrl[off..off + 8].try_into().ok()?);
        if len < 16 || off + len > ctrl.len() {
            return None;
        }
        let level = i32::from_ne_bytes(ctrl[off + 8..off + 12].try_into().ok()?);
        let ty = i32::from_ne_bytes(ctrl[off + 12..off + 16].try_into().ok()?);
        let d = &ctrl[off + 16..off + len];
        if level == SOL_PACKET && ty == PACKET_AUXDATA && d.len() >= 20 {
            // tpacket_auxdata: status u32, len u32, snaplen u32, mac u16, net u16, vlan_tci u16, vlan_tpid u16, ...
            let status = u32::from_ne_bytes(d[0..4].try_into().ok()?);
            if status & TP_STATUS_VLAN_VALID != 0 {
                let tci = u16::from_ne_bytes(d[16..18].try_into().ok()?);
                let tpid = if status & TP_STATUS_VLAN_TPID_VALID != 0 { u16::from_ne_bytes(d[18..20].try_into().ok()?) } else { 0x8100 };
                return Some((tpid, tci));
            }
            return None;
        }
        off += (len + 7) & !7;
    }
    None
}

impl Link for PacketLink {
    fn send(&mut self, ifindex: i32, frame: &[u8]) -> io::Result<()> {
        if frame.len() < 14 {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let mut sa = SockaddrLl { family: AF_PACKET as u16, protocol: ETH_P_ALL.to_be(), ifindex, halen: 6, ..Default::default() };
        sa.addr[..6].copy_from_slice(&frame[..6]);
        // SAFETY: frame and sa are valid for the call.
        let r = unsafe { ffi::sendto(self.fd, frame.as_ptr(), frame.len(), 0, &sa as *const SockaddrLl as *const u8, std::mem::size_of::<SockaddrLl>() as u32) };
        if r < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn recv(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<RecvMeta>> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let mut p = ffi::PollFd { fd: self.fd, events: POLLIN, revents: 0 };
            // SAFETY: one valid pollfd.
            let rc = unsafe { ffi::poll(&mut p, 1, left.as_millis().min(i32::MAX as u128) as i32) };
            if rc < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if rc == 0 {
                return Ok(None);
            }
            let mut sa = SockaddrLl::default();
            let mut ctrl = [0u64; 16];
            let mut iov = ffi::Iovec { base: buf.as_mut_ptr(), len: buf.len() };
            let mut m = ffi::Msghdr {
                name: &mut sa as *mut SockaddrLl as *mut u8,
                namelen: std::mem::size_of::<SockaddrLl>() as u32,
                iov: &mut iov,
                iovlen: 1,
                control: ctrl.as_mut_ptr() as *mut u8,
                controllen: std::mem::size_of_val(&ctrl),
                flags: 0,
            };
            // SAFETY: all msghdr pointers reference live buffers of the stated sizes.
            let r = unsafe { ffi::recvmsg(self.fd, &mut m, 0) };
            if r < 0 {
                let e = io::Error::last_os_error();
                if matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock) {
                    continue;
                }
                return Err(e);
            }
            if sa.pkttype == PACKET_OUTGOING || !self.serves(sa.ifindex) {
                if std::time::Instant::now() >= deadline {
                    return Ok(None);
                }
                continue;
            }
            let cl = m.controllen.min(std::mem::size_of_val(&ctrl));
            let cbytes: Vec<u8> = ctrl.iter().flat_map(|w| w.to_ne_bytes()).take(cl).collect();
            return Ok(Some(RecvMeta { len: (r as usize).min(buf.len()), ifindex: sa.ifindex, aux_tag: parse_auxdata(&cbytes) }));
        }
    }

    fn local_mac(&self, ifindex: i32) -> io::Result<Mac> {
        let name = self
            .ifaces
            .iter()
            .find(|(_, i)| *i == ifindex)
            .map(|(n, _)| n.clone())
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        let s = std::fs::read_to_string(format!("/sys/class/net/{}/address", name))?;
        Mac::parse(s.trim()).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
    }
}

fn is_vlan_subif(name: &str) -> bool {
    std::path::Path::new(&format!("/proc/net/vlan/{}", name)).exists()
}

/// Every Ethernet (ARPHRD_ETHER = 1) interface except `lo`, physical or VLAN, sorted by name.
pub fn ethernet_ifaces() -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir("/sys/class/net")? {
        let name = e?.file_name().to_string_lossy().into_owned();
        let ty = std::fs::read_to_string(format!("/sys/class/net/{}/type", name)).unwrap_or_default();
        if name != "lo" && ty.trim() == "1" {
            out.push(name);
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmsg(level: i32, ty: i32, data: &[u8]) -> Vec<u8> {
        let len = 16 + data.len();
        let mut v = Vec::new();
        v.extend_from_slice(&len.to_ne_bytes());
        v.extend_from_slice(&level.to_ne_bytes());
        v.extend_from_slice(&ty.to_ne_bytes());
        v.extend_from_slice(data);
        while v.len() % 8 != 0 {
            v.push(0);
        }
        v
    }
    fn aux(status: u32, tci: u16, tpid: u16) -> Vec<u8> {
        let mut d = vec![0u8; 24];
        d[0..4].copy_from_slice(&status.to_ne_bytes());
        d[16..18].copy_from_slice(&tci.to_ne_bytes());
        d[18..20].copy_from_slice(&tpid.to_ne_bytes());
        d
    }

    #[test]
    fn auxdata_vlan_valid() {
        assert_eq!(parse_auxdata(&cmsg(263, 8, &aux(TP_STATUS_VLAN_VALID | 1, 0x600e, 0))), Some((0x8100, 0x600e)));
        assert_eq!(parse_auxdata(&cmsg(263, 8, &aux(TP_STATUS_VLAN_VALID | TP_STATUS_VLAN_TPID_VALID, 7, 0x88a8))), Some((0x88a8, 7)));
    }
    #[test]
    fn auxdata_not_valid_or_other_cmsg() {
        assert_eq!(parse_auxdata(&cmsg(263, 8, &aux(0, 14, 0))), None);
        assert_eq!(parse_auxdata(&cmsg(1, 8, &aux(TP_STATUS_VLAN_VALID, 14, 0))), None);
        assert_eq!(parse_auxdata(&[]), None);
        assert_eq!(parse_auxdata(&[0xff; 40]), None, "bogus length is rejected, not a panic");
    }
    #[test]
    fn auxdata_after_another_cmsg() {
        let mut c = cmsg(1, 29, &[1, 2, 3, 4]);
        c.extend(cmsg(263, 8, &aux(TP_STATUS_VLAN_VALID, 14, 0)));
        assert_eq!(parse_auxdata(&c), Some((0x8100, 14)));
    }

    /// Interpret the classic BPF program on a frame (only the opcodes it uses) to check it without a socket.
    fn run(prog: &[SockFilter], frame: &[u8]) -> u32 {
        let (mut a, mut pc) = (0u32, 0usize);
        loop {
            let i = &prog[pc];
            pc += 1;
            match i.code {
                0x28 => {
                    let o = i.k as usize;
                    a = if o + 2 <= frame.len() { u16::from_be_bytes([frame[o], frame[o + 1]]) as u32 } else { return 0 };
                }
                0x15 => {
                    pc += if a == i.k { i.jt } else { i.jf } as usize;
                }
                0x06 => return i.k,
                c => panic!("opcode {c:#x}"),
            }
        }
    }
    fn fr(tags: &[u16], et: u16) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        for t in tags {
            f.extend_from_slice(&t.to_be_bytes());
            f.extend_from_slice(&[0, 5]);
        }
        f.extend_from_slice(&et.to_be_bytes());
        f.extend_from_slice(&[0; 20]);
        f
    }
    #[test]
    fn bpf_accepts_lab_frames_plain_or_tagged() {
        let p = program();
        for et in [0x88b5u16, 0x88b6] {
            assert_ne!(run(&p, &fr(&[], et)), 0);
            assert_ne!(run(&p, &fr(&[0x8100], et)), 0);
            assert_ne!(run(&p, &fr(&[0x88a8], et)), 0);
        }
        for et in [0x0800u16, 0x0806, 0x86dd, 0x88b7] {
            assert_eq!(run(&p, &fr(&[], et)), 0);
            assert_eq!(run(&p, &fr(&[0x8100], et)), 0);
        }
        assert_eq!(run(&p, &[0u8; 10]), 0, "short frame");
    }
}
