//! Raw Ethernet frame transports. Owner: P2.
//! `PacketLink` (labproto::packet) for real NICs, `UdpLink` for QEMU `-netdev dgram` (one frame per datagram),
//! and `MemLink` pairs for in-process tests of the session code.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;

use crate::mac::Mac;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecvMeta {
    pub len: usize,
    pub ifindex: i32,
    /// (TPID, TCI) recovered from PACKET_AUXDATA when the kernel stripped the outer tag (TP_STATUS_VLAN_VALID).
    /// In-band tags stay in the frame bytes. Session code builds the canonical stack with
    /// `frame::canonical_tags(aux_tag, &eth.tags)` (review security F12).
    pub aux_tag: Option<(u16, u16)>,
}

pub trait Link: Send {
    /// Send one complete Ethernet frame (no FCS) out of `ifindex`.
    fn send(&mut self, ifindex: i32, frame: &[u8]) -> io::Result<()>;
    /// Receive one frame into `buf`; `Ok(None)` on timeout.
    fn recv(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<RecvMeta>>;
    fn local_mac(&self, ifindex: i32) -> io::Result<Mac>;
}

/// One Ethernet frame per UDP datagram (QEMU `-netdev dgram,local=...,remote=...`). ifindex is always 1.
pub struct UdpLink {
    sock: UdpSocket,
    remote: SocketAddr,
    mac: Mac,
}

impl UdpLink {
    pub fn new(local: SocketAddr, remote: SocketAddr, mac: Mac) -> io::Result<UdpLink> {
        let sock = UdpSocket::bind(local)?;
        Ok(UdpLink { sock, remote, mac })
    }

    /// Shared test segment: QEMU `-netdev dgram,id=l2,remote.type=inet,remote.host=GROUP,remote.port=PORT`
    /// (no local). Binds 0.0.0.0:PORT with SO_REUSEADDR, joins GROUP, sends to GROUP:PORT, so several i7labctl
    /// processes (discover --watch next to a command) see the same segment (review feasibility F25).
    /// Multicast loopback delivers our own frames too: callers drop frames whose source MAC is `mac`.
    pub fn multicast(group: std::net::Ipv4Addr, port: u16, mac: Mac) -> io::Result<UdpLink> {
        let sock = crate::sys::udp_reuse_socket(port)?;
        sock.join_multicast_v4(&group, &std::net::Ipv4Addr::UNSPECIFIED)?;
        sock.set_multicast_loop_v4(true)?;
        Ok(UdpLink { sock, remote: SocketAddr::from((group, port)), mac })
    }
}

impl Link for UdpLink {
    fn send(&mut self, _ifindex: i32, frame: &[u8]) -> io::Result<()> {
        self.sock.send_to(frame, self.remote).map(|_| ())
    }
    fn recv(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<RecvMeta>> {
        self.sock.set_read_timeout(Some(timeout.max(Duration::from_millis(1))))?;
        match self.sock.recv_from(buf) {
            Ok((len, _)) => Ok(Some(RecvMeta { len, ifindex: 1, aux_tag: None })),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn local_mac(&self, _ifindex: i32) -> io::Result<Mac> {
        Ok(self.mac)
    }
}

/// In-memory link for tests; `MemLink::pair` gives two connected ends. Loss/reorder injection is P1/P2 test code.
pub struct MemLink {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    mac: Mac,
}

impl MemLink {
    pub fn pair(a: Mac, b: Mac) -> (MemLink, MemLink) {
        let (t1, r1) = channel();
        let (t2, r2) = channel();
        (MemLink { tx: t1, rx: r2, mac: a }, MemLink { tx: t2, rx: r1, mac: b })
    }
}

impl Link for MemLink {
    fn send(&mut self, _ifindex: i32, frame: &[u8]) -> io::Result<()> {
        self.tx.send(frame.to_vec()).map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }
    fn recv(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<RecvMeta>> {
        match self.rx.recv_timeout(timeout) {
            Ok(f) => {
                let n = f.len().min(buf.len());
                buf[..n].copy_from_slice(&f[..n]);
                Ok(Some(RecvMeta { len: n, ifindex: 1, aux_tag: None }))
            }
            Err(_) => Ok(None),
        }
    }
    fn local_mac(&self, _ifindex: i32) -> io::Result<Mac> {
        Ok(self.mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mem_pair() {
        let (mut a, mut b) = MemLink::pair(Mac([2, 0, 0, 0, 0, 1]), Mac([2, 0, 0, 0, 0, 2]));
        a.send(1, b"hello").unwrap();
        let mut buf = [0u8; 64];
        let m = b.recv(&mut buf, Duration::from_millis(100)).unwrap().unwrap();
        assert_eq!(&buf[..m.len], b"hello");
    }
}
