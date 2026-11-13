//! Network configuration (no `ip` binary): links up, static addresses/routes and VLAN sub-interfaces through
//! `labproto::netlink`, the `net.set --confirm` revert timer, address hints, and the per-NIC DHCP driver around
//! the pure `dhcp` state machine. Owner: P6b.
//!
//! All kernel access goes through the `NetOps` trait, so the logic (flush/replace, revert, vlan lookup) is
//! tested with a recording mock; `Netlink` is the production implementation.

use std::collections::HashSet;
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use labproto::netlink::{AddrInfo, LinkInfo, RouteInfo};

use crate::daemon::Daemon;
use crate::dhcp::{self, Action, Fsm, Lease};
use crate::events::Event;

pub trait NetOps: Send + Sync {
    fn links(&self) -> io::Result<Vec<LinkInfo>>;
    fn addrs(&self) -> io::Result<Vec<AddrInfo>>;
    fn routes(&self) -> io::Result<Vec<RouteInfo>>;
    fn add_addr(&self, ifindex: i32, addr: &[u8], prefix: u8) -> io::Result<()>;
    fn del_addr(&self, ifindex: i32, addr: &[u8], prefix: u8) -> io::Result<()>;
    fn add_route(&self, r: &RouteInfo) -> io::Result<()>;
    fn del_route(&self, r: &RouteInfo) -> io::Result<()>;
    fn link_up(&self, ifindex: i32, up: bool) -> io::Result<()>;
    fn set_mtu(&self, ifindex: i32, mtu: u32) -> io::Result<()>;
    fn add_vlan(&self, parent: i32, vid: u16) -> io::Result<i32>;
    fn del_link(&self, ifindex: i32) -> io::Result<()>;
}

/// rtnetlink (`labproto::netlink`).
pub struct Netlink;

impl NetOps for Netlink {
    fn links(&self) -> io::Result<Vec<LinkInfo>> {
        labproto::netlink::get_links()
    }
    fn addrs(&self) -> io::Result<Vec<AddrInfo>> {
        labproto::netlink::get_addrs()
    }
    fn routes(&self) -> io::Result<Vec<RouteInfo>> {
        labproto::netlink::get_routes()
    }
    fn add_addr(&self, i: i32, a: &[u8], p: u8) -> io::Result<()> {
        labproto::netlink::add_addr(i, a, p)
    }
    fn del_addr(&self, i: i32, a: &[u8], p: u8) -> io::Result<()> {
        labproto::netlink::del_addr(i, a, p)
    }
    fn add_route(&self, r: &RouteInfo) -> io::Result<()> {
        labproto::netlink::add_route(r)
    }
    fn del_route(&self, r: &RouteInfo) -> io::Result<()> {
        labproto::netlink::del_route(r)
    }
    fn link_up(&self, i: i32, up: bool) -> io::Result<()> {
        labproto::netlink::link_set_up(i, up)
    }
    fn set_mtu(&self, i: i32, m: u32) -> io::Result<()> {
        labproto::netlink::set_mtu(i, m)
    }
    fn add_vlan(&self, p: i32, v: u16) -> io::Result<i32> {
        labproto::netlink::add_vlan(p, v)
    }
    fn del_link(&self, i: i32) -> io::Result<()> {
        labproto::netlink::del_link(i)
    }
}

pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    s.parse::<Ipv4Addr>().ok().map(|a| a.octets())
}

/// "A.B.C.D/N", N in 1..=32.
pub fn parse_cidr(s: &str) -> Option<([u8; 4], u8)> {
    let (a, p) = s.split_once('/')?;
    let p: u8 = p.parse().ok()?;
    (1..=32).contains(&p).then_some(())?;
    Some((parse_ipv4(a)?, p))
}

pub fn ifindex_of(name: &str) -> io::Result<i32> {
    labproto::packet::PacketLink::ifindex(name)
}

/// Interface names we may reconfigure: Ethernet netdevs only.
pub fn valid_iface(name: &str) -> bool {
    !name.is_empty() && name.len() < 16 && name != "lo" && !name.contains(['/', '\0', ' ']) && std::path::Path::new(&format!("/sys/class/net/{}", name)).exists()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticCfg {
    pub addr: [u8; 4],
    pub prefix: u8,
    pub gw: Option<[u8; 4]>,
    pub mtu: Option<u32>,
}

/// What an interface had before `apply_static` (for the revert timer).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Saved {
    pub addrs: Vec<([u8; 4], u8)>,
    pub gw: Option<[u8; 4]>,
    pub mtu: Option<u32>,
}

fn default_route(gw: &[u8; 4], oif: i32) -> RouteInfo {
    RouteInfo { dst: vec![0, 0, 0, 0], prefix: 0, gateway: Some(gw.to_vec()), oif: Some(oif) }
}

fn v4(a: &[u8]) -> Option<[u8; 4]> {
    a.try_into().ok()
}

pub fn current_gw(ops: &dyn NetOps, ifindex: i32) -> Option<[u8; 4]> {
    ops.routes().ok()?.into_iter().find(|r| r.prefix == 0 && r.dst.len() == 4 && r.oif == Some(ifindex)).and_then(|r| r.gateway.as_deref().and_then(v4))
}

pub fn current_addrs(ops: &dyn NetOps, ifindex: i32) -> Vec<([u8; 4], u8)> {
    ops.addrs().unwrap_or_default().into_iter().filter(|a| a.ifindex == ifindex).filter_map(|a| Some((v4(&a.addr)?, a.prefix))).collect()
}

/// Replace the IPv4 configuration of `ifindex`: old addresses and default route removed, new ones added, link up.
pub fn apply_static(ops: &dyn NetOps, ifindex: i32, cfg: &StaticCfg) -> io::Result<Saved> {
    let saved = Saved { addrs: current_addrs(ops, ifindex), gw: current_gw(ops, ifindex), mtu: None };
    if let Some(gw) = &saved.gw {
        let _ = ops.del_route(&default_route(gw, ifindex));
    }
    for (a, p) in &saved.addrs {
        let _ = ops.del_addr(ifindex, a, *p);
    }
    let r = (|| {
        ops.link_up(ifindex, true)?;
        if let Some(m) = cfg.mtu {
            ops.set_mtu(ifindex, m)?;
        }
        ops.add_addr(ifindex, &cfg.addr, cfg.prefix)?;
        if let Some(gw) = &cfg.gw {
            ops.add_route(&default_route(gw, ifindex))?;
        }
        Ok(())
    })();
    if let Err(e) = r {
        restore(ops, ifindex, cfg, &saved); // never leave the NIC half configured
        return Err(e);
    }
    Ok(saved)
}

/// Undo `apply_static(cfg)` and put `saved` back.
pub fn restore(ops: &dyn NetOps, ifindex: i32, cfg: &StaticCfg, saved: &Saved) {
    if let Some(gw) = &cfg.gw {
        let _ = ops.del_route(&default_route(gw, ifindex));
    }
    let _ = ops.del_addr(ifindex, &cfg.addr, cfg.prefix);
    for (a, p) in &saved.addrs {
        let _ = ops.add_addr(ifindex, a, *p);
    }
    if let Some(gw) = &saved.gw {
        let _ = ops.add_route(&default_route(gw, ifindex));
    }
    if let (Some(m), true) = (saved.mtu, cfg.mtu.is_some()) {
        let _ = ops.set_mtu(ifindex, m);
    }
}

/// Create `<parent>.<vid>` and bring it up; returns its name and ifindex.
pub fn vlan_add(ops: &dyn NetOps, parent: i32, vid: u16) -> io::Result<(String, i32)> {
    if vid == 0 || vid > 4094 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "vlan id must be 1..4094"));
    }
    let idx = ops.add_vlan(parent, vid)?;
    ops.link_up(idx, true)?;
    let name = ops.links()?.into_iter().find(|l| l.ifindex == idx).map(|l| l.name).unwrap_or_else(|| format!("vlan{}", idx));
    Ok((name, idx))
}

pub fn vlan_del(ops: &dyn NetOps, parent: i32, vid: u16) -> io::Result<()> {
    let l = ops.links()?.into_iter().find(|l| l.kind.as_deref() == Some("vlan") && l.vlan == Some((parent, vid)));
    match l {
        Some(l) => ops.del_link(l.ifindex),
        None => Err(io::Error::new(io::ErrorKind::NotFound, "no such vlan interface")),
    }
}

struct Pending {
    token: u64,
    ifindex: i32,
    cfg: StaticCfg,
    saved: Saved,
}

/// Mutable network facts of the agent: the pending `--confirm` revert and which NICs have a static config / DHCP.
#[derive(Default)]
pub struct NetState {
    pending: Arc<Mutex<Option<Pending>>>,
    token: AtomicU64,
    statics: Arc<Mutex<HashSet<String>>>,
    dhcp_running: Mutex<HashSet<String>>,
    dhcp_wanted: Mutex<HashSet<String>>,
}

impl NetState {
    pub fn is_static(&self, iface: &str) -> bool {
        self.statics.lock().unwrap().contains(iface)
    }
    pub fn mark_static(&self, iface: &str, on: bool) {
        let mut s = self.statics.lock().unwrap();
        if on {
            s.insert(iface.to_string());
        } else {
            s.remove(iface);
        }
    }
    /// `net.set --dhcp`: the net duty (which owns an `Arc<Daemon>`) starts the runner within 2 s.
    pub fn want_dhcp(&self, iface: &str) {
        self.mark_static(iface, false);
        self.dhcp_wanted.lock().unwrap().insert(iface.to_string());
    }
    pub fn take_dhcp_wanted(&self) -> Vec<String> {
        self.dhcp_wanted.lock().unwrap().drain().collect()
    }
    pub fn pending_confirm(&self) -> bool {
        self.pending.lock().unwrap().is_some()
    }

    /// Apply `cfg`; with `confirm` a timer reverts it unless `confirm()` is called first.
    pub fn set_static(&self, ops: Arc<dyn NetOps>, ifname: &str, ifindex: i32, cfg: StaticCfg, confirm: Option<Duration>) -> io::Result<()> {
        if self.pending_confirm() {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "a previous net.set is still waiting for net.confirm"));
        }
        let saved = apply_static(&*ops, ifindex, &cfg)?;
        self.mark_static(ifname, true);
        if let Some(wait) = confirm {
            let token = self.token.fetch_add(1, Ordering::SeqCst) + 1;
            *self.pending.lock().unwrap() = Some(Pending { token, ifindex, cfg, saved });
            let (pending, statics, name) = (self.pending.clone(), self.statics.clone(), ifname.to_string());
            std::thread::spawn(move || {
                let deadline = Instant::now() + wait;
                while Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(20));
                    if pending.lock().unwrap().as_ref().map(|p| p.token) != Some(token) {
                        return; // confirmed or superseded
                    }
                }
                let mut g = pending.lock().unwrap();
                if g.as_ref().map(|p| p.token) == Some(token) {
                    let p = g.take().unwrap();
                    restore(&*ops, p.ifindex, &p.cfg, &p.saved);
                    let mut s = statics.lock().unwrap();
                    if p.saved.addrs.is_empty() {
                        s.remove(&name);
                    } else {
                        s.insert(name);
                    }
                }
            });
        }
        Ok(())
    }

    /// `net.confirm`: keep the change. Returns false when nothing was pending (already reverted).
    pub fn confirm(&self) -> bool {
        self.pending.lock().unwrap().take().is_some()
    }
}

/// Apply an authenticated/accepted address hint: optional VLAN sub-interface, then the static address.
pub fn apply_hint(daemon: &Daemon, ops: Arc<dyn NetOps>, nic: &crate::beacon::Nic, hint: &labproto::beacon::Hint) -> io::Result<()> {
    let (name, idx) = match hint.vlan {
        Some(v) if v != 0 => vlan_add(&*ops, nic.ifindex, v)?,
        _ => (nic.name.clone(), nic.ifindex),
    };
    let cfg = StaticCfg { addr: hint.ip, prefix: hint.prefix, gw: hint.gw, mtu: None };
    daemon.net.set_static(ops, &name, idx, cfg, None)?;
    daemon.events.publish(Event::Link(name));
    Ok(())
}

// ------------------------------------------------------------------------------------------------ DHCP driver

fn now_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

fn seed(mac: [u8; 6]) -> u32 {
    let mut b = [0u8; 4];
    let _ = labproto::crypto::random_bytes(&mut b);
    u32::from_be_bytes(b) ^ u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]])
}

/// Applies FSM actions to the interface through `NetOps`. Pure enough to test with a mock.
pub struct DhcpApplier<'a> {
    pub ops: &'a dyn NetOps,
    pub ifindex: i32,
    pub ours: Option<(Ipv4Addr, u8)>,
}

impl DhcpApplier<'_> {
    pub fn configure(&mut self, l: &Lease) -> io::Result<()> {
        let prefix = dhcp::prefix_len(l.mask).unwrap_or(24);
        if self.ours.map(|(a, p)| (a, p)) != Some((l.ip, prefix)) {
            self.deconfigure();
            self.ops.link_up(self.ifindex, true)?;
            self.ops.add_addr(self.ifindex, &l.ip.octets(), prefix)?;
            if let Some(gw) = l.router {
                let _ = self.ops.add_route(&default_route(&gw.octets(), self.ifindex));
            }
            self.ours = Some((l.ip, prefix));
        }
        Ok(())
    }

    pub fn deconfigure(&mut self) {
        if let Some((a, p)) = self.ours.take() {
            if let Some(gw) = current_gw(self.ops, self.ifindex) {
                let _ = self.ops.del_route(&default_route(&gw, self.ifindex));
            }
            let _ = self.ops.del_addr(self.ifindex, &a.octets(), p);
        }
    }
}

/// DHCP on one interface until it disappears, gets a static configuration, or `daemon` says stop.
pub fn run_dhcp_iface(daemon: Arc<Daemon>, ops: Arc<dyn NetOps>, name: String) {
    let read = |f: &str| std::fs::read_to_string(format!("/sys/class/net/{}/{}", name, f)).unwrap_or_default().trim().to_string();
    let Some(mac) = labproto::Mac::parse(&read("address")) else { return };
    let Ok(ifindex) = read("ifindex").parse::<i32>() else { return };
    let sock = match crate::ffi::PacketIp::open(ifindex) {
        Ok(s) => s,
        Err(e) => {
            daemon.log(&format!("dhcp {}: packet socket: {}", name, e));
            return;
        }
    };
    let mut fsm = Fsm::new(mac.0, seed(mac.0));
    let mut ap = DhcpApplier { ops: &*ops, ifindex, ours: None };
    let mut buf = [0u8; 2048];
    loop {
        if !std::path::Path::new(&format!("/sys/class/net/{}", name)).exists() || daemon.net.is_static(&name) {
            ap.deconfigure();
            return;
        }
        let acts = fsm.tick(now_ms());
        exec_actions(&daemon, &mut ap, &sock, &fsm, &name, acts);
        let wait = fsm.deadline().saturating_sub(now_ms()).clamp(1, 1000) as i32;
        match sock.recv(&mut buf, wait) {
            Ok(Some(n)) => {
                if let Ok(rx) = dhcp::decode_frame(&buf[..n]) {
                    let acts = fsm.on_rx(now_ms(), &rx);
                    exec_actions(&daemon, &mut ap, &sock, &fsm, &name, acts);
                }
            }
            Ok(None) => {}
            Err(_) => std::thread::sleep(Duration::from_secs(1)),
        }
    }
}

fn exec_actions(daemon: &Daemon, ap: &mut DhcpApplier, sock: &crate::ffi::PacketIp, fsm: &Fsm, name: &str, acts: Vec<Action>) {
    for a in acts {
        match a {
            Action::Send(o) => {
                let dst_ip = o.unicast_to.unwrap_or(Ipv4Addr::BROADCAST);
                let dst_mac = if o.unicast_to.is_some() { fsm.server_mac().unwrap_or(dhcp::BCAST_MAC) } else { dhcp::BCAST_MAC };
                let payload = dhcp::encode(&o, fsm.xid(), fsm.mac(), &daemon.config.hostname);
                let f = dhcp::build_frame(fsm.mac(), dst_mac, o.ciaddr, dst_ip, &payload);
                let _ = sock.send(&f);
            }
            Action::Configure(l) => match ap.configure(&l) {
                Ok(()) => {
                    daemon.log(&format!("dhcp {}: {}/{} gw {}", name, l.ip, dhcp::prefix_len(l.mask).unwrap_or(24), l.router.map(|r| r.to_string()).unwrap_or_default()));
                    daemon.events.publish(Event::Link(name.to_string()));
                }
                Err(e) => daemon.log(&format!("dhcp {}: cannot apply {}: {}", name, l.ip, e)),
            },
            Action::Deconfigure => {
                ap.deconfigure();
                daemon.events.publish(Event::Link(name.to_string()));
            }
        }
    }
}

/// Start DHCP on `name` unless a runner exists. Returns true when a new runner started.
pub fn start_dhcp(daemon: &Arc<Daemon>, ops: Arc<dyn NetOps>, name: &str) -> bool {
    if !daemon.net.dhcp_running.lock().unwrap().insert(name.to_string()) {
        return false;
    }
    daemon.net.mark_static(name, false);
    let (d, n) = (daemon.clone(), name.to_string());
    std::thread::spawn(move || {
        run_dhcp_iface(d.clone(), ops, n.clone());
        d.net.dhcp_running.lock().unwrap().remove(&n);
    });
    true
}

/// The net duty: every 2 s bring Ethernet links up and start DHCP on carrier NICs without an address.
pub fn run(daemon: Arc<Daemon>) -> io::Result<()> {
    let ops: Arc<dyn NetOps> = Arc::new(Netlink);
    let mut last: std::collections::HashMap<String, (bool, bool)> = Default::default();
    let _ = ops.link_up(1, true); // lo is ifindex 1 on Linux
    loop {
        let names = labproto::packet::ethernet_ifaces().unwrap_or_default();
        for w in daemon.net.take_dhcp_wanted() {
            start_dhcp(&daemon, ops.clone(), &w);
        }
        let mut nics = crate::beacon::SysNics { names: names.clone() };
        use crate::beacon::Nics;
        for n in nics.list() {
            let flags = labproto::sys::if_flags(&n.name).unwrap_or(1);
            if flags & 1 == 0 {
                let _ = ops.link_up(n.ifindex, true);
            }
            let cur = (n.carrier, n.ipv4.is_some());
            if last.insert(n.name.clone(), cur) != Some(cur) {
                daemon.events.publish(Event::Link(n.name.clone()));
            }
            if daemon.config.dhcp && n.carrier && n.ipv4.is_none() && !daemon.net.is_static(&n.name) {
                start_dhcp(&daemon, ops.clone(), &n.name);
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

#[cfg(test)]
pub mod mock {
    use super::*;

    /// Recording in-memory netlink: one set of addresses and routes.
    #[derive(Default)]
    pub struct MockNet {
        pub addrs: Mutex<Vec<AddrInfo>>,
        pub routes: Mutex<Vec<RouteInfo>>,
        pub links: Mutex<Vec<LinkInfo>>,
        pub up: Mutex<Vec<i32>>,
        pub log: Mutex<Vec<String>>,
        pub fail_add_route: std::sync::atomic::AtomicBool,
    }

    impl NetOps for MockNet {
        fn links(&self) -> io::Result<Vec<LinkInfo>> {
            Ok(self.links.lock().unwrap().clone())
        }
        fn addrs(&self) -> io::Result<Vec<AddrInfo>> {
            Ok(self.addrs.lock().unwrap().clone())
        }
        fn routes(&self) -> io::Result<Vec<RouteInfo>> {
            Ok(self.routes.lock().unwrap().clone())
        }
        fn add_addr(&self, i: i32, a: &[u8], p: u8) -> io::Result<()> {
            self.log.lock().unwrap().push(format!("add_addr {} {:?}/{}", i, a, p));
            self.addrs.lock().unwrap().push(AddrInfo { ifindex: i, addr: a.to_vec(), prefix: p });
            Ok(())
        }
        fn del_addr(&self, i: i32, a: &[u8], p: u8) -> io::Result<()> {
            self.log.lock().unwrap().push(format!("del_addr {} {:?}/{}", i, a, p));
            self.addrs.lock().unwrap().retain(|x| !(x.ifindex == i && x.addr == a && x.prefix == p));
            Ok(())
        }
        fn add_route(&self, r: &RouteInfo) -> io::Result<()> {
            if self.fail_add_route.load(Ordering::SeqCst) {
                return Err(io::Error::from(io::ErrorKind::Other));
            }
            self.log.lock().unwrap().push(format!("add_route {:?}", r.gateway));
            self.routes.lock().unwrap().push(r.clone());
            Ok(())
        }
        fn del_route(&self, r: &RouteInfo) -> io::Result<()> {
            self.log.lock().unwrap().push(format!("del_route {:?}", r.gateway));
            self.routes.lock().unwrap().retain(|x| x != r);
            Ok(())
        }
        fn link_up(&self, i: i32, up: bool) -> io::Result<()> {
            if up {
                self.up.lock().unwrap().push(i);
            }
            Ok(())
        }
        fn set_mtu(&self, i: i32, m: u32) -> io::Result<()> {
            self.log.lock().unwrap().push(format!("mtu {} {}", i, m));
            Ok(())
        }
        fn add_vlan(&self, parent: i32, vid: u16) -> io::Result<i32> {
            let idx = 100 + vid as i32;
            self.links.lock().unwrap().push(LinkInfo { ifindex: idx, name: format!("eth{}.{}", parent, vid), mac: None, flags: 0, mtu: 1500, kind: Some("vlan".into()), vlan: Some((parent, vid)) });
            Ok(idx)
        }
        fn del_link(&self, i: i32) -> io::Result<()> {
            self.links.lock().unwrap().retain(|l| l.ifindex != i);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockNet;
    use super::*;

    #[test]
    fn cidr_parsing() {
        assert_eq!(parse_cidr("10.1.2.3/24"), Some(([10, 1, 2, 3], 24)));
        for bad in ["10.1.2.3", "10.1.2.3/0", "10.1.2.3/33", "10.1.2/24", "x/24", "10.1.2.3/ 24", ""] {
            assert_eq!(parse_cidr(bad), None, "{}", bad);
        }
        assert_eq!(parse_ipv4("192.168.0.1"), Some([192, 168, 0, 1]));
    }

    fn cfg(ip: [u8; 4], gw: Option<[u8; 4]>) -> StaticCfg {
        StaticCfg { addr: ip, prefix: 24, gw, mtu: None }
    }

    #[test]
    fn apply_replaces_and_restore_puts_back() {
        let m = MockNet::default();
        m.addrs.lock().unwrap().push(AddrInfo { ifindex: 2, addr: vec![192, 168, 1, 5], prefix: 24 });
        m.routes.lock().unwrap().push(default_route(&[192, 168, 1, 1], 2));
        let new = cfg([10, 0, 0, 5], Some([10, 0, 0, 1]));
        let saved = apply_static(&m, 2, &new).unwrap();
        assert_eq!(saved.addrs, vec![([192, 168, 1, 5], 24)]);
        assert_eq!(saved.gw, Some([192, 168, 1, 1]));
        assert_eq!(current_addrs(&m, 2), vec![([10, 0, 0, 5], 24)]);
        assert_eq!(current_gw(&m, 2), Some([10, 0, 0, 1]));
        assert!(m.up.lock().unwrap().contains(&2));
        restore(&m, 2, &new, &saved);
        assert_eq!(current_addrs(&m, 2), vec![([192, 168, 1, 5], 24)]);
        assert_eq!(current_gw(&m, 2), Some([192, 168, 1, 1]));
    }

    #[test]
    fn failed_apply_rolls_back() {
        let m = MockNet::default();
        m.addrs.lock().unwrap().push(AddrInfo { ifindex: 2, addr: vec![192, 168, 1, 5], prefix: 24 });
        m.fail_add_route.store(true, Ordering::SeqCst);
        assert!(apply_static(&m, 2, &cfg([10, 0, 0, 5], Some([10, 0, 0, 1]))).is_err());
        assert_eq!(current_addrs(&m, 2), vec![([192, 168, 1, 5], 24)], "old address is back");
    }

    #[test]
    fn confirm_timer_reverts_unless_confirmed() {
        let st = Arc::new(NetState::default());
        let m = Arc::new(MockNet::default());
        m.addrs.lock().unwrap().push(AddrInfo { ifindex: 2, addr: vec![192, 168, 1, 5], prefix: 24 });
        let ops: Arc<dyn NetOps> = m.clone();
        st.set_static(ops.clone(), "eth0", 2, cfg([10, 0, 0, 5], None), Some(Duration::from_millis(150))).unwrap();
        assert!(st.pending_confirm() && st.is_static("eth0"));
        assert!(st.set_static(ops.clone(), "eth0", 2, cfg([10, 0, 0, 6], None), None).is_err(), "one pending change at a time");
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(current_addrs(&*m, 2), vec![([192, 168, 1, 5], 24)], "reverted");
        assert!(!st.pending_confirm());
        // confirmed change stays
        st.set_static(ops, "eth0", 2, cfg([10, 0, 0, 7], None), Some(Duration::from_millis(150))).unwrap();
        assert!(st.confirm());
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(current_addrs(&*m, 2), vec![([10, 0, 0, 7], 24)]);
        assert!(!st.confirm());
    }

    #[test]
    fn vlan_add_and_del() {
        let m = MockNet::default();
        assert!(vlan_add(&m, 2, 0).is_err() && vlan_add(&m, 2, 4095).is_err());
        let (name, idx) = vlan_add(&m, 2, 30).unwrap();
        assert_eq!((name.as_str(), idx), ("eth2.30", 130));
        assert!(m.up.lock().unwrap().contains(&130));
        vlan_del(&m, 2, 30).unwrap();
        assert!(vlan_del(&m, 2, 30).is_err());
    }

    #[test]
    fn dhcp_applier_configures_and_removes() {
        let m = MockNet::default();
        let mut ap = DhcpApplier { ops: &m, ifindex: 3, ours: None };
        let lease = Lease { ip: Ipv4Addr::new(10, 9, 8, 7), mask: Ipv4Addr::new(255, 255, 255, 0), router: Some(Ipv4Addr::new(10, 9, 8, 1)), server: Ipv4Addr::new(10, 9, 8, 1), lease_secs: 3600 };
        ap.configure(&lease).unwrap();
        assert_eq!(current_addrs(&m, 3), vec![([10, 9, 8, 7], 24)]);
        assert_eq!(current_gw(&m, 3), Some([10, 9, 8, 1]));
        ap.configure(&lease).unwrap(); // renewal: no churn
        assert_eq!(m.log.lock().unwrap().iter().filter(|l| l.starts_with("add_addr")).count(), 1);
        ap.deconfigure();
        assert!(current_addrs(&m, 3).is_empty() && current_gw(&m, 3).is_none());
    }
}
