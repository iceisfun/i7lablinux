//! Beacon listener, active PROBE, address hints, `wait` state machine. Owner: P9.
//! Reader rules follow PROTOCOL.md 10.2: one frame per 500 ms per source MAC, at most 10 new hosts per second
//! (burst 50), registry cap 1024, `mac=` must equal the Ethernet source (else flagged by the registry).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use labproto::beacon::{Beacon, Hint};
use labproto::frame::{self, FrameType, Header, TagKey};
use labproto::link::{Link, RecvMeta};
use labproto::Mac;

use crate::hosts::{HostEntry, ObserveMeta};
use crate::ClientError;

/// A raw-Ethernet link plus the lab-side interfaces it covers: (name, ifindex).
pub struct LinkSet {
    pub link: Box<dyn Link>,
    pub ifaces: Vec<(String, i32)>,
}

impl LinkSet {
    pub fn iface_name(&self, ifindex: i32) -> String {
        self.ifaces.iter().find(|(_, i)| *i == ifindex).map(|(n, _)| n.clone()).unwrap_or_else(|| format!("if{}", ifindex))
    }
}

#[derive(Clone, Debug)]
pub struct Sighting {
    pub beacon: Beacon,
    pub meta: ObserveMeta,
    pub ifindex: i32,
    /// outer tag stack of the frame, for replies on the same VLAN
    pub tags: Vec<(u16, u16)>,
    pub from_probe: bool,
    pub src: Mac,
}

/// VLAN id (1..=4094) of the outermost tag, if any.
pub fn vlan_of(tags: &[(u16, u16)]) -> Option<u16> {
    tags.first().map(|(_, tci)| tci & 0x0fff).filter(|v| *v != 0)
}

/// Decode one received frame into a beacon sighting (beacon frames on 0x88B5, PROBE_REPLY on 0x88B6).
pub fn parse_frame(buf: &[u8], meta: &RecvMeta, iface_of: &dyn Fn(i32) -> String, beacon_key: Option<&[u8; 32]>) -> Option<Sighting> {
    let (eth, payload) = frame::eth_parse(buf)?;
    let tags = frame::canonical_tags(meta.aux_tag, &eth.tags)?;
    let (beacon_bytes, from_probe): (&[u8], bool) = match eth.ethertype {
        frame::ETHERTYPE_BEACON => (payload, false),
        frame::ETHERTYPE_CTL => {
            let f = frame::open(payload).ok()?;
            if f.hdr.ftype != FrameType::ProbeReply as u8 {
                return None;
            }
            (f.payload, true)
        }
        _ => return None,
    };
    let beacon = Beacon::parse(beacon_bytes).ok()?;
    let tag_ok = match (beacon.version, beacon_key) {
        (2, Some(k)) => Some(Beacon::tag_ok(beacon_bytes, k, &eth.src)),
        _ => None,
    };
    let vlan = vlan_of(&tags);
    Some(Sighting {
        meta: ObserveMeta { iface: iface_of(meta.ifindex), src_mac: Some(eth.src), vlan, tag_ok },
        beacon,
        ifindex: meta.ifindex,
        tags,
        from_probe,
        src: eth.src,
    })
}

/// Reader-side admission limits (PROTOCOL 10.2).
pub struct Limiter {
    last: HashMap<[u8; 6], u64>,
    tokens: f64,
    refilled_ms: u64,
}

pub const PER_SRC_MS: u64 = 500;
const NEW_BURST: f64 = 50.0;
const NEW_PER_SEC: f64 = 10.0;
const SRC_MAX: usize = 4096;

impl Default for Limiter {
    fn default() -> Self {
        Limiter { last: HashMap::new(), tokens: NEW_BURST, refilled_ms: 0 }
    }
}

impl Limiter {
    pub fn allow(&mut self, src: [u8; 6], is_new: bool, now_ms: u64) -> bool {
        if let Some(t) = self.last.get(&src) {
            if now_ms.saturating_sub(*t) < PER_SRC_MS {
                return false;
            }
        }
        self.tokens = (self.tokens + now_ms.saturating_sub(self.refilled_ms) as f64 / 1000.0 * NEW_PER_SEC).min(NEW_BURST);
        self.refilled_ms = now_ms;
        if is_new {
            if self.tokens < 1.0 {
                return false;
            }
            self.tokens -= 1.0;
        }
        if self.last.len() >= SRC_MAX {
            let cutoff = now_ms.saturating_sub(PER_SRC_MS);
            self.last.retain(|_, t| *t >= cutoff);
            if self.last.len() >= SRC_MAX {
                self.last.clear();
            }
        }
        self.last.insert(src, now_ms);
        true
    }
}

pub struct Listener {
    pub set: LinkSet,
    pub beacon_key: Option<[u8; 32]>,
    pub limiter: Limiter,
    pub started: Instant,
    buf: Vec<u8>,
}

impl Listener {
    pub fn new(set: LinkSet, beacon_key: Option<[u8; 32]>) -> Listener {
        Listener { set, beacon_key, limiter: Limiter::default(), started: Instant::now(), buf: vec![0u8; 4096] }
    }

    /// Wait up to `wait` for one admissible beacon. `known(mac)` tells the limiter whether a source is new.
    pub fn poll(&mut self, wait: Duration, known: &dyn Fn(&Mac) -> bool) -> Result<Option<Sighting>, ClientError> {
        let meta = match self.set.link.recv(&mut self.buf, wait) {
            Ok(Some(m)) => m,
            Ok(None) => return Ok(None),
            Err(e) => return Err(ClientError::Transport(format!("receive failed: {}", e))),
        };
        let ifaces = self.set.ifaces.clone();
        let name = move |i: i32| ifaces.iter().find(|(_, x)| *x == i).map(|(n, _)| n.clone()).unwrap_or_else(|| format!("if{}", i));
        let Some(s) = parse_frame(&self.buf[..meta.len], &meta, &name, self.beacon_key.as_ref()) else { return Ok(None) };
        let claimed = s.beacon.get("mac").and_then(Mac::parse);
        let is_new = claimed.is_some_and(|m| !known(&m));
        let now_ms = self.started.elapsed().as_millis() as u64;
        // probe replies are solicited: they bypass the per-source beacon spacing
        if !s.from_probe && !self.limiter.allow(s.src.0, is_new, now_ms) {
            return Ok(None);
        }
        Ok(Some(s))
    }
}

/// PROBE frame (type 16 on 0x88B6), broadcast, with an optional 802.1Q tag; payload = 8 byte nonce.
pub fn probe_frame(src: Mac, vlan: Option<u16>, nonce: [u8; 8]) -> Vec<u8> {
    let hdr = Header {
        ver: frame::VERSION,
        ftype: FrameType::Probe as u8,
        flags: 0,
        chan: 0,
        cmd: 0,
        session: 0,
        req_id: 0,
        ctr: 0,
        msg_len: 8,
        off: 0,
        plen: 8,
        win: 0,
        status: 0,
    };
    let body = frame::seal(&hdr, &nonce, TagKey::None);
    let eth = frame::EthHeader { dst: Mac::BROADCAST, src, tags: crate::ether::vlan_tags(vlan), ethertype: frame::ETHERTYPE_CTL };
    frame::eth_build(&eth, &body)
}

/// `MAC=IP/PFX[/GW]` for `discover --assign`.
pub fn parse_assign(s: &str) -> Result<Hint, String> {
    let (m, rest) = s.split_once('=').ok_or("--assign needs MAC=IP/PREFIX[/GATEWAY]")?;
    let target = Mac::parse(m).ok_or_else(|| format!("bad MAC '{}' in --assign", m))?;
    let mut it = rest.split('/');
    let ip = parse_v4(it.next().unwrap_or(""))?;
    let prefix: u8 = it.next().and_then(|p| p.parse().ok()).filter(|p| *p <= 32).ok_or("--assign needs a prefix length 0-32 after the address")?;
    let gw = match it.next() {
        Some(g) if !g.is_empty() => Some(parse_v4(g)?),
        _ => None,
    };
    if it.next().is_some() {
        return Err("too many '/' parts in --assign".into());
    }
    Ok(Hint { target, ip, prefix, gw, vlan: None, boot: None, seq: 1 })
}

fn parse_v4(s: &str) -> Result<[u8; 4], String> {
    let p: Vec<&str> = s.split('.').collect();
    if p.len() != 4 {
        return Err(format!("bad IPv4 address '{}'", s));
    }
    let mut o = [0u8; 4];
    for (i, x) in p.iter().enumerate() {
        o[i] = x.parse().map_err(|_| format!("bad IPv4 address '{}'", s))?;
    }
    Ok(o)
}

/// Frame carrying an address hint to `s`'s source, on the interface and VLAN the beacon came from.
/// v2 hosts get I7LR2 (signed with the admin key), v1 sticks I7LR1.
pub fn hint_frame(hint: &Hint, s: &Sighting, src_mac: Mac, admin: Option<&[u8; 32]>) -> Option<Vec<u8>> {
    let mut h = hint.clone();
    h.vlan = vlan_of(&s.tags).or(h.vlan);
    h.boot = s.beacon.get("boot").map(String::from);
    let payload = if s.beacon.version == 2 { h.encode_v2(admin?) } else { h.encode_v1() };
    if payload.is_empty() {
        return None;
    }
    let eth = frame::EthHeader { dst: s.src, src: src_mac, tags: s.tags.clone(), ethertype: frame::ETHERTYPE_BEACON };
    Some(frame::eth_build(&eth, &payload))
}

// ---------------------------------------------------------------- wait

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitKind {
    Up,
    Down,
    Ready,
    Reboot,
}

impl WaitKind {
    pub fn parse(s: &str) -> Option<WaitKind> {
        Some(match s {
            "up" => WaitKind::Up,
            "down" => WaitKind::Down,
            "ready" => WaitKind::Ready,
            "reboot" => WaitKind::Reboot,
            _ => return None,
        })
    }
}

/// `wait` state machine: feed it sightings and clock ticks (seconds since start).
pub struct Waiter {
    pub kind: WaitKind,
    pub macs: Vec<String>,
    pub boot_id: Option<String>,
    last_seen: Option<u64>,
    started: u64,
    pub last_beacon: Option<Beacon>,
}

pub const DOWN_AFTER_SECS: u64 = 15;

impl Waiter {
    pub fn new(kind: WaitKind, macs: Vec<String>, boot_id: Option<String>, started_s: u64) -> Waiter {
        Waiter { kind, macs, boot_id, last_seen: None, started: started_s, last_beacon: None }
    }

    /// Some(()) when the awaited condition holds.
    pub fn feed(&mut self, b: &Beacon, now_s: u64) -> Option<()> {
        let mac = b.get("mac").unwrap_or("").to_ascii_lowercase();
        if !self.macs.contains(&mac) {
            return None;
        }
        self.last_seen = Some(now_s);
        self.last_beacon = Some(b.clone());
        let boot = b.get("boot").map(String::from);
        let state = b.get("state").unwrap_or("");
        match self.kind {
            WaitKind::Up => Some(()),
            WaitKind::Ready => (state == "ready").then_some(()),
            WaitKind::Down => (state == "shutdown").then_some(()),
            WaitKind::Reboot => {
                match (&self.boot_id, &boot) {
                    (None, Some(_)) => self.boot_id = boot, // first sighting defines the baseline
                    (Some(old), Some(new)) if old != new => return Some(()),
                    _ => {}
                }
                None
            }
        }
    }

    pub fn tick(&mut self, now_s: u64) -> Option<()> {
        if self.kind == WaitKind::Down {
            let since = self.last_seen.unwrap_or(self.started);
            if now_s.saturating_sub(since) >= DOWN_AFTER_SECS {
                return Some(());
            }
        }
        None
    }
}

/// MACs that belong to the same machine as `entry` (same non-empty board serial), including its own.
pub fn sibling_macs(entry: &HostEntry, all: &crate::hosts::Registry) -> Vec<String> {
    let mut v = vec![entry.mac.clone()];
    if !entry.board_serial.is_empty() {
        v.extend(all.hosts.values().filter(|h| h.board_serial == entry.board_serial && h.mac != entry.mac).map(|h| h.mac.clone()));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use labproto::link::MemLink;

    fn beacon(extra: &[(&str, &str)]) -> Beacon {
        let mut b = Beacon { version: 2, fields: vec![] };
        b.set("mac", "52:54:00:17:00:01");
        b.set("boot", "aa");
        b.set("state", "ready");
        for (k, v) in extra {
            b.set(k, v);
        }
        b
    }

    fn beacon_frame(b: &Beacon, src: Mac, tags: Vec<(u16, u16)>, key: Option<&[u8; 32]>) -> Vec<u8> {
        let eth = frame::EthHeader { dst: Mac::BROADCAST, src, tags, ethertype: frame::ETHERTYPE_BEACON };
        frame::eth_build(&eth, &b.encode_v2(key, &src))
    }

    #[test]
    fn parses_beacons_plain_tagged_and_checks_tag() {
        let src = Mac([0x52, 0x54, 0, 0x17, 0, 1]);
        let key = [9u8; 32];
        let f = beacon_frame(&beacon(&[]), src, vec![(0x8100, 13)], Some(&key));
        let meta = RecvMeta { len: f.len(), ifindex: 3, aux_tag: None };
        let s = parse_frame(&f, &meta, &|i| format!("eth{}", i), Some(&key)).unwrap();
        assert_eq!(s.meta.vlan, Some(13));
        assert_eq!(s.meta.tag_ok, Some(true));
        assert_eq!(s.meta.iface, "eth3");
        assert!(!s.from_probe);
        // wrong key: displayed as unverified, still accepted
        let s = parse_frame(&f, &meta, &|_| String::new(), Some(&[1u8; 32])).unwrap();
        assert_eq!(s.meta.tag_ok, Some(false));
        // no key known: unknown
        assert_eq!(parse_frame(&f, &meta, &|_| String::new(), None).unwrap().meta.tag_ok, None);
        // kernel-stripped outer tag arrives as auxdata
        let f = beacon_frame(&beacon(&[]), src, vec![], None);
        let meta = RecvMeta { len: f.len(), ifindex: 1, aux_tag: Some((0x8100, 0x2005)) };
        assert_eq!(parse_frame(&f, &meta, &|_| String::new(), None).unwrap().meta.vlan, Some(5));
        // garbage and foreign ethertypes are ignored
        assert!(parse_frame(&[0u8; 10], &meta, &|_| String::new(), None).is_none());
        let eth = frame::EthHeader { dst: Mac::BROADCAST, src, tags: vec![], ethertype: 0x0800 };
        let f = frame::eth_build(&eth, b"I7LP2\nmac=52:54:00:17:00:01\n");
        assert!(parse_frame(&f, &meta, &|_| String::new(), None).is_none());
    }

    #[test]
    fn limiter_spacing_and_new_host_cap() {
        let mut l = Limiter::default();
        let a = [2, 0, 0, 0, 0, 1];
        assert!(l.allow(a, true, 1000));
        assert!(!l.allow(a, false, 1200));
        assert!(l.allow(a, false, 1600));
        // a flood of new MACs is cut once the burst is used
        let mut l = Limiter::default();
        let admitted = (0..200u8).filter(|i| l.allow([2, 0, 0, 0, 1, *i], true, 5000)).count();
        assert_eq!(admitted, 50);
    }

    #[test]
    fn probe_frame_shape() {
        let f = probe_frame(Mac([2, 0, 0, 0, 0, 7]), Some(13), [1; 8]);
        let (eth, payload) = frame::eth_parse(&f).unwrap();
        assert_eq!(eth.dst, Mac::BROADCAST);
        assert_eq!(eth.ethertype, frame::ETHERTYPE_CTL);
        assert_eq!(eth.tags, vec![(0x8100, 13)]);
        let fr = frame::open(payload).unwrap();
        assert_eq!(fr.hdr.ftype, FrameType::Probe as u8);
        assert_eq!(fr.payload, &[1; 8]);
    }

    #[test]
    fn probe_reply_is_a_sighting() {
        let src = Mac([0x52, 0x54, 0, 0x17, 0, 1]);
        let hdr = Header { ver: 1, ftype: FrameType::ProbeReply as u8, flags: 0, chan: 0, cmd: 0, session: 0, req_id: 0, ctr: 0, msg_len: 0, off: 0, plen: 0, win: 0, status: 0 };
        let text = beacon(&[]).encode_v2(None, &src);
        let hdr = Header { msg_len: text.len() as u32, plen: text.len() as u16, ..hdr };
        let body = frame::seal(&hdr, &text, TagKey::None);
        let eth = frame::EthHeader { dst: Mac([2, 0, 0, 0, 0, 9]), src, tags: vec![], ethertype: frame::ETHERTYPE_CTL };
        let f = frame::eth_build(&eth, &body);
        let meta = RecvMeta { len: f.len(), ifindex: 1, aux_tag: None };
        let s = parse_frame(&f, &meta, &|_| String::new(), None).unwrap();
        assert!(s.from_probe);
        assert_eq!(s.beacon.get("state"), Some("ready"));
    }

    #[test]
    fn listener_over_memlink() {
        let (a, mut b) = MemLink::pair(Mac([2, 0, 0, 0, 0, 1]), Mac([2, 0, 0, 0, 0, 2]));
        let src = Mac([0x52, 0x54, 0, 0x17, 0, 1]);
        b.send(1, &beacon_frame(&beacon(&[]), src, vec![], None)).unwrap();
        b.send(1, &beacon_frame(&beacon(&[]), src, vec![], None)).unwrap(); // too soon: limited
        let mut l = Listener::new(LinkSet { link: Box::new(a), ifaces: vec![("eth0".into(), 1)] }, None);
        let s = l.poll(Duration::from_millis(100), &|_| false).unwrap().unwrap();
        assert_eq!(s.meta.iface, "eth0");
        assert!(l.poll(Duration::from_millis(20), &|_| true).unwrap().is_none());
    }

    #[test]
    fn assign_parsing() {
        let h = parse_assign("02:00:00:9d:01:57=192.0.2.195/24/192.0.2.1").unwrap();
        assert_eq!((h.ip, h.prefix, h.gw), ([192, 0, 2, 195], 24, Some([192, 0, 2, 1])));
        assert!(parse_assign("02:00:00:9d:01:57=192.0.2.195").is_err());
        assert!(parse_assign("nonsense").is_err());
        assert!(parse_assign("02:00:00:9d:01:57=300.1.1.1/24").is_err());
        assert!(parse_assign("02:00:00:9d:01:57=1.1.1.1/33").is_err());
    }

    #[test]
    fn waiter_states() {
        let mac = vec!["52:54:00:17:00:01".to_string()];
        let mut w = Waiter::new(WaitKind::Up, mac.clone(), None, 0);
        assert!(w.feed(&beacon(&[("mac", "aa:bb:cc:dd:ee:01")]), 1).is_none());
        assert!(w.feed(&beacon(&[]), 1).is_some());

        let mut w = Waiter::new(WaitKind::Ready, mac.clone(), None, 0);
        assert!(w.feed(&beacon(&[("state", "booting")]), 1).is_none());
        assert!(w.feed(&beacon(&[]), 2).is_some());

        let mut w = Waiter::new(WaitKind::Reboot, mac.clone(), None, 0);
        assert!(w.feed(&beacon(&[]), 1).is_none()); // baseline boot=aa
        assert!(w.feed(&beacon(&[]), 2).is_none());
        assert!(w.feed(&beacon(&[("boot", "bb")]), 3).is_some());
        let mut w = Waiter::new(WaitKind::Reboot, mac.clone(), Some("aa".into()), 0);
        assert!(w.feed(&beacon(&[("boot", "cc")]), 1).is_some());

        let mut w = Waiter::new(WaitKind::Down, mac, None, 0);
        assert!(w.feed(&beacon(&[]), 3).is_none());
        assert!(w.tick(10).is_none());
        assert!(w.tick(18).is_some());
        assert!(w.feed(&beacon(&[("state", "shutdown")]), 19).is_some());
    }
}
