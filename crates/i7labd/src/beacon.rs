//! L2 beacons (v2 + compat v1), PROBE replies and address hints (PROTOCOL.md section 10). Owner: P6b.
//!
//! This module is pure scheduling and message building: `ether.rs` owns the socket loop and calls
//! `Scheduler::due` / `probe_reply` / `hint_*` with the clock injected, so everything here is host-testable.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use labproto::beacon::Beacon;
use labproto::crypto::hex;
use labproto::frame::{self, EthHeader, FrameType, Header, TagKey, ETHERTYPE_BEACON, ETHERTYPE_CTL};
use labproto::Mac;

use crate::daemon::Daemon;

/// A NIC the agent serves (physical or VLAN sub-interface).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nic {
    pub name: String,
    pub ifindex: i32,
    pub mac: Mac,
    pub carrier: bool,
    pub operstate: String,
    /// first IPv4 address as "A.B.C.D/N"
    pub ipv4: Option<String>,
    /// 802.1Q id for a VLAN sub-interface, 0 otherwise
    pub vlan: u16,
}

/// Source of the NIC list (re-read every beacon round): sysfs on hardware, fixed in tests.
pub trait Nics: Send {
    fn list(&mut self) -> Vec<Nic>;
}

pub struct StaticNics(pub Vec<Nic>);
impl Nics for StaticNics {
    fn list(&mut self) -> Vec<Nic> {
        self.0.clone()
    }
}

/// Reads sysfs / labprobe / rtnetlink for the interfaces in `names`.
pub struct SysNics {
    pub names: Vec<String>,
}

impl Nics for SysNics {
    fn list(&mut self) -> Vec<Nic> {
        let ctx = labprobe::ProbeCtx::live();
        let report = labprobe::net::probe(&ctx).unwrap_or_default();
        let addrs = labproto::netlink::get_addrs().unwrap_or_default();
        let mut out = Vec::new();
        for name in &self.names {
            let rd = |f: &str| std::fs::read_to_string(format!("/sys/class/net/{}/{}", name, f)).unwrap_or_default().trim().to_string();
            let Some(mac) = Mac::parse(&rd("address")) else { continue };
            let Ok(ifindex) = rd("ifindex").parse::<i32>() else { continue };
            let info = report.ifaces.iter().find(|i| &i.name == name);
            let ipv4 = addrs
                .iter()
                .find(|a| a.ifindex == ifindex && a.addr.len() == 4)
                .map(|a| format!("{}.{}.{}.{}/{}", a.addr[0], a.addr[1], a.addr[2], a.addr[3], a.prefix))
                .or_else(|| info.and_then(|i| i.ipv4.first().cloned()));
            out.push(Nic {
                name: name.clone(),
                ifindex,
                mac,
                carrier: rd("carrier") == "1",
                operstate: rd("operstate"),
                ipv4,
                vlan: info.and_then(|i| i.vlan_id).unwrap_or(0),
            });
        }
        out
    }
}

/// Facts that never change while the host is up (DMI, kernel), read once.
#[derive(Clone, Debug, Default)]
pub struct Identity {
    pub product: String,
    pub vendor: String,
    pub serial: String,
    pub board: String,
    pub board_serial: String,
    pub kernel: String,
}

impl Identity {
    pub fn load() -> Identity {
        let dmi = labprobe::dmi::probe(&labprobe::ProbeCtx::live()).unwrap_or_default();
        let g = |k: &str| dmi.get(k).unwrap_or("").to_string();
        Identity {
            product: g("product_name"),
            vendor: g("sys_vendor"),
            serial: g("product_serial"),
            board: g("board_name"),
            board_serial: g("board_serial"),
            kernel: std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim().to_string(),
        }
    }
}

/// Beacon fields for one NIC: the v1 keys first in v1 order, then the v2 keys (PROTOCOL.md 10.2).
pub fn build(daemon: &Daemon, nic: &Nic, gen: u64) -> Beacon {
    let mut b = Beacon { version: 2, fields: Vec::new() };
    let id = &daemon.ident;
    b.set("mac", &nic.mac.to_string());
    b.set("iface", &nic.name);
    b.set("host", &daemon.config.hostname);
    b.set("product", &id.product);
    b.set("vendor", &id.vendor);
    b.set("serial", &id.serial);
    b.set("board", &id.board);
    b.set("board_serial", &id.board_serial);
    b.set("kernel", &id.kernel);
    b.set("link", &format!("{}({})", if nic.carrier { "up" } else { "down" }, nic.operstate));
    b.set("ip", nic.ipv4.as_deref().unwrap_or(""));
    b.set("v", "2");
    b.set("proto", "1");
    b.set("ctl", if daemon.flags.ether_up() { "88b6" } else { "" });
    b.set("boot", &hex(&daemon.boot_id));
    b.set("up", &(labproto::sys::uptime_ms() / 1000).to_string());
    b.set("gen", &gen.to_string());
    b.set("state", &daemon.state_str());
    b.set("build", &daemon.config.image_build);
    b.set("kid", &daemon.kid());
    b.set("caps", &format!("{:x}", labproto::catalog::caps_bits()));
    b.set("http", &daemon.flags.http_port().map(|p| p.to_string()).unwrap_or_default());
    b.set("ssh", "0");
    b.set("vlan", &nic.vlan.to_string());
    b
}

/// Full Ethernet frame carrying `payload` as a beacon broadcast from `nic`.
pub fn beacon_frame(nic: &Nic, payload: &[u8]) -> Vec<u8> {
    frame::eth_build(&EthHeader { dst: Mac::BROADCAST, src: nic.mac, tags: vec![], ethertype: ETHERTYPE_BEACON }, payload)
}

pub const PERIOD: Duration = Duration::from_millis(2000);
pub const JITTER_MS: i64 = 250;
pub const BURST_COUNT: u32 = 5;
pub const BURST_GAP: Duration = Duration::from_millis(200);
/// Hard cap per NIC: 5 frames per second.
pub const MIN_SPACING: Duration = Duration::from_millis(200);

#[derive(Default)]
struct PerNic {
    next_v2: Option<Instant>,
    next_v1: Option<Instant>,
    burst_left: u32,
    last_sent: Option<Instant>,
    last_state: Option<(bool, Option<String>)>,
    shutdown_sent: bool,
    gen: u64,
}

/// Decides when each NIC sends which beacon. Pure: the caller passes `now`, the NIC list and a jitter source.
pub struct Scheduler {
    nics: HashMap<i32, PerNic>,
    compat_v1: bool,
}

pub struct Due {
    pub nic: Nic,
    pub gen: u64,
    pub v1: bool,
}

impl Scheduler {
    pub fn new(compat_v1: bool) -> Scheduler {
        Scheduler { nics: HashMap::new(), compat_v1 }
    }

    /// Beacons to send now. `shutdown` = the host is going down: one last frame per NIC, then silence.
    /// `jitter(max_ms)` returns a value in `-max_ms..=max_ms`.
    pub fn due(&mut self, now: Instant, nics: &[Nic], shutdown: bool, jitter: &mut dyn FnMut(i64) -> i64) -> Vec<Due> {
        let mut out = Vec::new();
        let live: Vec<i32> = nics.iter().map(|n| n.ifindex).collect();
        self.nics.retain(|i, _| live.contains(i));
        for nic in nics {
            let st = self.nics.entry(nic.ifindex).or_default();
            if !nic.carrier && !shutdown {
                st.last_state = Some((false, nic.ipv4.clone()));
                st.next_v2 = None;
                continue;
            }
            if shutdown {
                if !st.shutdown_sent {
                    st.shutdown_sent = true;
                    st.gen += 1;
                    out.push(Due { nic: nic.clone(), gen: st.gen, v1: false });
                }
                continue;
            }
            // link-up or address change: a burst of 5 frames at 200 ms spacing
            let cur = (nic.carrier, nic.ipv4.clone());
            if st.last_state.as_ref() != Some(&cur) {
                st.last_state = Some(cur);
                st.burst_left = BURST_COUNT;
                st.next_v2 = Some(now);
            }
            let spaced = st.last_sent.map(|t| now.duration_since(t) >= MIN_SPACING).unwrap_or(true);
            let v2_due = st.next_v2.map(|t| now >= t).unwrap_or(true);
            if v2_due && spaced {
                st.gen += 1;
                out.push(Due { nic: nic.clone(), gen: st.gen, v1: false });
                st.last_sent = Some(now);
                let next = if st.burst_left > 1 {
                    st.burst_left -= 1;
                    BURST_GAP
                } else {
                    st.burst_left = 0;
                    Duration::from_millis((PERIOD.as_millis() as i64 + jitter(JITTER_MS)).max(500) as u64)
                };
                st.next_v2 = Some(now + next);
                if self.compat_v1 {
                    st.next_v1 = Some(now + Duration::from_secs(1));
                }
            } else if self.compat_v1 && spaced && st.next_v1.map(|t| now >= t).unwrap_or(false) {
                out.push(Due { nic: nic.clone(), gen: st.gen, v1: true });
                st.last_sent = Some(now);
                st.next_v1 = None;
            }
        }
        out
    }

    /// Earliest time `due` can have something to send (for the receive timeout).
    pub fn next_deadline(&self) -> Option<Instant> {
        self.nics.values().flat_map(|s| [s.next_v2, s.next_v1]).flatten().min()
    }
}

/// Payload bytes of a due beacon: v2 with the tag when a beacon key exists, or the v1 subset.
pub fn encode(daemon: &Daemon, due: &Due) -> Vec<u8> {
    let b = build(daemon, &due.nic, due.gen);
    if due.v1 {
        b.encode_v1()
    } else {
        let key = daemon.keys.read().unwrap().beacon_key();
        b.encode_v2(key.as_ref(), &due.nic.mac)
    }
}

/// PROBE (frame type 16) -> PROBE_REPLY (type 17): unicast to the prober, body = the beacon-v2 text, tag zero.
pub fn probe_reply(daemon: &Daemon, nic: &Nic, prober: Mac, tags: &[(u16, u16)], probe_hdr: &Header, gen: u64) -> Vec<u8> {
    let body = {
        let b = build(daemon, nic, gen);
        let key = daemon.keys.read().unwrap().beacon_key();
        b.encode_v2(key.as_ref(), &nic.mac)
    };
    let hdr = Header { ver: frame::VERSION, ftype: FrameType::ProbeReply as u8, req_id: probe_hdr.req_id, plen: body.len() as u16, ..Default::default() };
    let payload = frame::seal(&hdr, &body, TagKey::None);
    frame::eth_build(&EthHeader { dst: prober, src: nic.mac, tags: tags.to_vec(), ethertype: ETHERTYPE_CTL }, &payload)
}

/// At most 2 PROBE_REPLY per second per NIC (PROTOCOL 10.4).
#[derive(Default)]
pub struct ProbeLimiter {
    sent: HashMap<i32, Vec<Instant>>,
}

impl ProbeLimiter {
    pub fn allow(&mut self, ifindex: i32, now: Instant) -> bool {
        let v = self.sent.entry(ifindex).or_default();
        v.retain(|t| now.duration_since(*t) < Duration::from_secs(1));
        if v.len() >= 2 {
            return false;
        }
        v.push(now);
        true
    }
}

/// Hint bookkeeping: v2 `seq` must grow (RAM only), v1 applies at most once per NIC and only while address-less.
#[derive(Default)]
pub struct HintState {
    last_seq: HashMap<i32, u32>,
    v1_applied: HashMap<i32, bool>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HintVerdict {
    Apply,
    Reject(&'static str),
}

impl HintState {
    /// Checks everything except the HMAC (which `labproto::beacon::Hint::parse` verified): target, boot id, seq,
    /// address sanity (unicast /8../30, gateway inside the subnet).
    pub fn judge(&mut self, nic: &Nic, hint: &labproto::beacon::Hint, v2: bool, boot_hex: &str, accept_v1: bool) -> HintVerdict {
        if hint.target != nic.mac {
            return HintVerdict::Reject("not for this NIC");
        }
        let ip = u32::from_be_bytes(hint.ip);
        if hint.prefix < 8 || hint.prefix > 30 || hint.ip[0] == 0 || hint.ip[0] >= 224 || hint.ip[0] == 127 {
            return HintVerdict::Reject("address not a usable unicast /8../30");
        }
        let mask = u32::MAX << (32 - hint.prefix as u32);
        if ip & !mask == 0 || ip & !mask == !mask {
            return HintVerdict::Reject("network or broadcast address");
        }
        if let Some(gw) = hint.gw {
            if u32::from_be_bytes(gw) & mask != ip & mask {
                return HintVerdict::Reject("gateway outside the subnet");
            }
        }
        if v2 {
            if hint.boot.as_deref() != Some(boot_hex) {
                return HintVerdict::Reject("stale boot id");
            }
            if self.last_seq.get(&nic.ifindex).is_some_and(|s| hint.seq <= *s) {
                return HintVerdict::Reject("seq not increasing");
            }
            self.last_seq.insert(nic.ifindex, hint.seq);
        } else {
            if !accept_v1 {
                return HintVerdict::Reject("v1 hints are disabled");
            }
            if nic.ipv4.is_some() || self.v1_applied.get(&nic.ifindex).copied().unwrap_or(false) {
                return HintVerdict::Reject("v1 hint only applies once, to an address-less NIC");
            }
            self.v1_applied.insert(nic.ifindex, true);
        }
        HintVerdict::Apply
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests_support::test_daemon;

    fn nic(i: i32, carrier: bool, ip: Option<&str>) -> Nic {
        Nic { name: format!("eth{}", i), ifindex: i, mac: Mac([2, 0, 0, 0, 0, i as u8]), carrier, operstate: "up".into(), ipv4: ip.map(str::to_string), vlan: 0 }
    }

    fn no_jitter(_: i64) -> i64 {
        0
    }

    #[test]
    fn burst_then_steady_period_and_v1_offset() {
        let mut s = Scheduler::new(true);
        let n = [nic(1, true, Some("10.0.0.2/24"))];
        let t0 = Instant::now();
        let mut v2_at = vec![];
        let mut v1_at = vec![];
        let mut t = t0;
        while t < t0 + Duration::from_secs(6) {
            for d in s.due(t, &n, false, &mut no_jitter) {
                if d.v1 { v1_at.push(t - t0) } else { v2_at.push(t - t0) }
            }
            t += Duration::from_millis(50);
        }
        // 5 frames at 200 ms spacing right after link-up
        assert_eq!(&v2_at[..5], &[0, 200, 400, 600, 800].map(Duration::from_millis));
        // then every 2 s
        assert_eq!(v2_at[5], Duration::from_millis(800 + 2000));
        assert!(!v1_at.is_empty());
        // v1 follows a v2 frame by about 1 s once spacing allows; never in the same instant
        assert!(v1_at.iter().all(|t| !v2_at.contains(t)));
    }

    #[test]
    fn no_carrier_no_beacon_and_cap_per_nic() {
        let mut s = Scheduler::new(false);
        let t0 = Instant::now();
        assert!(s.due(t0, &[nic(1, false, None)], false, &mut no_jitter).is_empty());
        // link comes up: burst; two polls inside 200 ms yield one frame (5 frames/s cap)
        let up = [nic(1, true, None)];
        assert_eq!(s.due(t0, &up, false, &mut no_jitter).len(), 1);
        assert_eq!(s.due(t0 + Duration::from_millis(100), &up, false, &mut no_jitter).len(), 0);
        // an address change restarts a burst
        let with_ip = [nic(1, true, Some("10.0.0.9/24"))];
        let d = s.due(t0 + Duration::from_millis(300), &with_ip, false, &mut no_jitter);
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn shutdown_frame_once() {
        let mut s = Scheduler::new(true);
        let n = [nic(1, true, None), nic(2, true, None)];
        let t0 = Instant::now();
        assert_eq!(s.due(t0, &n, true, &mut no_jitter).len(), 2);
        assert!(s.due(t0 + Duration::from_secs(5), &n, true, &mut no_jitter).is_empty());
    }

    #[test]
    fn built_beacon_has_v1_keys_first_and_parses() {
        let d = test_daemon();
        d.set_state("ready");
        let n = nic(1, true, Some("10.1.2.3/24"));
        let b = build(&d, &n, 7);
        let keys: Vec<&str> = b.fields.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(&keys[..11], &labproto::beacon::V1_KEYS[..]);
        assert_eq!(b.get("gen"), Some("7"));
        assert_eq!(b.get("state"), Some("ready"));
        assert_eq!(b.get("link"), Some("up(up)"));
        let raw = encode(&d, &Due { nic: n.clone(), gen: 7, v1: false });
        assert_eq!(Beacon::parse(&raw).unwrap().get("mac"), Some("02:00:00:00:00:01"));
        let v1 = Beacon::parse(&encode(&d, &Due { nic: n.clone(), gen: 7, v1: true })).unwrap();
        assert_eq!(v1.version, 1);
        assert!(v1.get("boot").is_none() && v1.get("mac").is_some());
        let f = beacon_frame(&n, &raw);
        let (eth, payload) = frame::eth_parse(&f).unwrap();
        assert_eq!((eth.dst, eth.ethertype), (Mac::BROADCAST, ETHERTYPE_BEACON));
        assert!(payload.starts_with(b"I7LP2\n"));
    }

    #[test]
    fn busy_state_while_a_write_test_runs() {
        let d = test_daemon();
        d.set_state("ready");
        let _g = d.limits.blk_write.try_acquire().unwrap();
        assert_eq!(build(&d, &nic(1, true, None), 1).get("state"), Some("busy"));
    }

    #[test]
    fn probe_reply_is_a_unicast_ctl_frame() {
        let d = test_daemon();
        let n = nic(1, true, None);
        let prober = Mac([2, 9, 9, 9, 9, 9]);
        let probe_hdr = Header { ver: 1, ftype: FrameType::Probe as u8, req_id: 77, ..Default::default() };
        let f = probe_reply(&d, &n, prober, &[], &probe_hdr, 1);
        let (eth, payload) = frame::eth_parse(&f).unwrap();
        assert_eq!((eth.dst, eth.ethertype), (prober, ETHERTYPE_CTL));
        let fr = frame::open(payload).unwrap();
        assert_eq!(fr.hdr.ftype, FrameType::ProbeReply as u8);
        assert!(fr.payload.starts_with(b"I7LP2\n"));
    }

    #[test]
    fn probe_limiter_two_per_second_per_nic() {
        let mut l = ProbeLimiter::default();
        let t = Instant::now();
        assert!(l.allow(1, t) && l.allow(1, t) && !l.allow(1, t));
        assert!(l.allow(2, t), "per NIC");
        assert!(l.allow(1, t + Duration::from_millis(1100)));
    }

    fn hint(target: Mac, ip: [u8; 4], prefix: u8, gw: Option<[u8; 4]>, boot: Option<&str>, seq: u32) -> labproto::beacon::Hint {
        labproto::beacon::Hint { target, ip, prefix, gw, vlan: None, boot: boot.map(str::to_string), seq }
    }

    #[test]
    fn hint_rules() {
        let n = nic(1, true, None);
        let mut s = HintState::default();
        let ok = hint(n.mac, [10, 0, 0, 5], 24, Some([10, 0, 0, 1]), Some("abcd"), 5);
        assert_eq!(s.judge(&n, &ok, true, "abcd", false), HintVerdict::Apply);
        assert!(matches!(s.judge(&n, &ok, true, "abcd", false), HintVerdict::Reject(r) if r.contains("seq")), "replay of the same seq");
        let stale = hint(n.mac, [10, 0, 0, 5], 24, None, Some("0000"), 9);
        assert!(matches!(s.judge(&n, &stale, true, "abcd", false), HintVerdict::Reject(r) if r.contains("boot")));
        let other = hint(Mac([2, 0, 0, 0, 0, 99]), [10, 0, 0, 5], 24, None, Some("abcd"), 10);
        assert!(matches!(s.judge(&n, &other, true, "abcd", false), HintVerdict::Reject(_)));
        for bad in [hint(n.mac, [10, 0, 0, 5], 31, None, Some("abcd"), 11), hint(n.mac, [224, 0, 0, 5], 24, None, Some("abcd"), 12), hint(n.mac, [10, 0, 0, 0], 24, None, Some("abcd"), 13), hint(n.mac, [10, 0, 0, 5], 24, Some([192, 168, 0, 1]), Some("abcd"), 14)] {
            assert!(matches!(s.judge(&n, &bad, true, "abcd", false), HintVerdict::Reject(_)), "{:?}", bad);
        }
        // v1: off by default, once, only without an address
        let mut s = HintState::default();
        let v1 = hint(n.mac, [10, 0, 0, 5], 24, None, None, 0);
        assert!(matches!(s.judge(&n, &v1, false, "abcd", false), HintVerdict::Reject(_)));
        assert_eq!(s.judge(&n, &v1, false, "abcd", true), HintVerdict::Apply);
        assert!(matches!(s.judge(&n, &v1, false, "abcd", true), HintVerdict::Reject(_)));
        let has_ip = nic(2, true, Some("10.0.0.2/24"));
        let v1b = hint(has_ip.mac, [10, 0, 0, 5], 24, None, None, 0);
        assert!(matches!(s.judge(&has_ip, &v1b, false, "abcd", true), HintVerdict::Reject(_)));
    }
}
