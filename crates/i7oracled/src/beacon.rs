//! Discovery beacon: one small UDP broadcast every few seconds so the lab side finds the machine without knowing its
//! DHCP address. Text lines, no secrets. The optional `tag` lets a holder of the ro key check it came from a machine
//! that was given that key set (same derivation as the i7lablinux beacon, different label); it is replayable.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::crypto::{hex, hmac_sha256};
use crate::state::Shared;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adapter {
    pub name: String,
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
}

pub fn mac_string(m: &[u8; 6]) -> String {
    m.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
}

pub fn directed_broadcast(ip: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip) | !u32::from(mask))
}

pub struct Beacon<'a> {
    pub host: &'a str,
    pub adapter: &'a Adapter,
    pub port: u16,
    pub kid: &'a str,
    pub os: &'a str,
    pub up_s: u64,
    pub seq: u64,
    pub boot: &'a str,
    pub mode: &'a str,
}

/// Text of the datagram, tag included when a beacon key is available.
pub fn build(b: &Beacon, beacon_key: Option<&[u8; 32]>) -> String {
    let clean = |s: &str| s.chars().filter(|c| !c.is_control()).collect::<String>();
    let mut s = format!(
        "I7ORACLE1\nhost={}\nip={}\nmac={}\napi={}\nkid={}\nos={}\nmode={}\nboot={}\nup={}\nseq={}\n",
        clean(b.host),
        b.adapter.ip,
        mac_string(&b.adapter.mac),
        b.port,
        clean(b.kid),
        clean(b.os),
        b.mode,
        b.boot,
        b.up_s,
        b.seq
    );
    if let Some(k) = beacon_key {
        let mac = hmac_sha256(k, &[b"i7oracle-beacon\0", s.as_bytes()]);
        s.push_str(&format!("tag={}\n", hex(&mac[..16])));
    }
    s
}

pub fn verify(text: &str, beacon_key: &[u8; 32]) -> bool {
    let Some(i) = text.rfind("tag=") else { return false };
    let (body, tag) = text.split_at(i);
    let mac = hmac_sha256(beacon_key, &[b"i7oracle-beacon\0", body.as_bytes()]);
    crate::crypto::ct_eq(tag.trim_start_matches("tag=").trim().as_bytes(), hex(&mac[..16]).as_bytes())
}

/// Runs until `stop`. Sends from every adapter that has an address, to 255.255.255.255 and to its subnet broadcast.
pub fn run(sh: Arc<Shared>) {
    if !sh.cfg.beacon {
        return;
    }
    let bkey = sh.keys.beacon_key();
    let host = crate::plat::hostname();
    let os = crate::plat::os_short();
    let kid = sh.keys.kid_summary();
    let mut seq = 0u64;
    while !sh.stop.load(Ordering::SeqCst) {
        for a in crate::plat::adapters() {
            seq += 1;
            let text = build(
                &Beacon { host: &host, adapter: &a, port: sh.cfg.port, kid: &kid, os: &os, up_s: sh.started.elapsed().as_secs(), seq, boot: &sh.boot_id, mode: sh.mode.name() },
                bkey.as_ref(),
            );
            if let Ok(sock) = UdpSocket::bind(SocketAddr::from((a.ip, 0))) {
                let _ = sock.set_broadcast(true);
                for dst in [Ipv4Addr::BROADCAST, directed_broadcast(a.ip, a.mask)] {
                    let _ = sock.send_to(text.as_bytes(), SocketAddr::from((dst, sh.cfg.beacon_port)));
                }
            }
        }
        for _ in 0..sh.cfg.beacon_interval_s * 5 {
            if sh.stop.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> Adapter {
        Adapter { name: "eth".into(), mac: [0x02, 0, 0, 0xab, 0xcd, 0xef], ip: Ipv4Addr::new(192, 0, 2, 40), mask: Ipv4Addr::new(255, 255, 255, 0) }
    }

    #[test]
    fn format_and_tag() {
        let a = adapter();
        let key = [5u8; 32];
        let t = build(&Beacon { host: "WIN\n10", adapter: &a, port: 8765, kid: "a:11223344,r:55667788", os: "Windows 10 22H2 19045", up_s: 7, seq: 3, boot: "ff", mode: "service" }, Some(&key));
        assert!(t.starts_with("I7ORACLE1\nhost=WIN10\nip=192.0.2.40\nmac=02:00:00:ab:cd:ef\napi=8765\n"));
        assert!(t.lines().last().unwrap().starts_with("tag="));
        assert!(verify(&t, &key));
        assert!(!verify(&t, &[6u8; 32]));
        assert!(!verify(&t.replace("up=7", "up=8"), &key));
        let nt = build(&Beacon { host: "h", adapter: &a, port: 1, kid: "", os: "", up_s: 0, seq: 0, boot: "", mode: "console" }, None);
        assert!(!nt.contains("tag="));
        assert!(t.len() < 400);
    }

    #[test]
    fn broadcast_math() {
        assert_eq!(directed_broadcast(Ipv4Addr::new(192, 0, 2, 40), Ipv4Addr::new(255, 255, 255, 0)), Ipv4Addr::new(192, 0, 2, 255));
        assert_eq!(directed_broadcast(Ipv4Addr::new(10, 1, 2, 3), Ipv4Addr::new(255, 255, 0, 0)), Ipv4Addr::new(10, 1, 255, 255));
    }
}
