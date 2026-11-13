//! rtnetlink client (NETLINK_ROUTE): the single netlink encoder/decoder of the workspace (review feasibility F9).
//! Users: i7labd netcfg (P6b: addresses, routes, VLAN sub-interfaces), i7labsh `ip` builtin (P8), labprobe net
//! (P3: addresses/routes for the report). Owner: P2. Encoder tests use captured byte vectors.

use std::io;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkInfo {
    pub ifindex: i32,
    pub name: String,
    pub mac: Option<crate::Mac>,
    pub flags: u32,
    pub mtu: u32,
    /// kind from IFLA_LINKINFO ("vlan", ...), with the parent ifindex and VLAN id for "vlan"
    pub kind: Option<String>,
    pub vlan: Option<(i32, u16)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrInfo {
    pub ifindex: i32,
    /// IPv4 (4 bytes) or IPv6 (16 bytes)
    pub addr: Vec<u8>,
    pub prefix: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteInfo {
    pub dst: Vec<u8>,
    pub prefix: u8,
    pub gateway: Option<Vec<u8>>,
    pub oif: Option<i32>,
}

mod ffi {
    extern "C" {
        pub fn socket(domain: i32, ty: i32, proto: i32) -> i32;
        pub fn bind(fd: i32, addr: *const u8, len: u32) -> i32;
        pub fn sendto(fd: i32, buf: *const u8, len: usize, flags: i32, addr: *const u8, alen: u32) -> isize;
        pub fn recv(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize;
        pub fn setsockopt(fd: i32, level: i32, name: i32, val: *const u8, len: u32) -> i32;
        pub fn close(fd: i32) -> i32;
    }
}

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const AF_UNSPEC: u8 = 0;

const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINK: u16 = 5;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const IFLA_VLAN_ID: u16 = 1;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_TABLE: u16 = 15;
const IFF_UP: u32 = 1;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Message builder: nlmsghdr + fixed header + attributes; `finish` patches the length.
struct Msg {
    buf: Vec<u8>,
}

impl Msg {
    fn new(ty: u16, flags: u16, seq: u32, fixed: &[u8]) -> Msg {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&ty.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(fixed);
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
        Msg { buf }
    }
    fn attr(&mut self, ty: u16, data: &[u8]) {
        self.buf.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(data);
        while self.buf.len() % 4 != 0 {
            self.buf.push(0);
        }
    }
    /// Start a nested attribute; returns the offset to pass to `end_nest`.
    fn begin_nest(&mut self, ty: u16) -> usize {
        let at = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        at
    }
    fn end_nest(&mut self, at: usize) {
        let len = (self.buf.len() - at) as u16;
        self.buf[at..at + 2].copy_from_slice(&len.to_ne_bytes());
    }
    fn finish(mut self) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

fn ifinfomsg(index: i32, flags: u32, change: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[4..8].copy_from_slice(&index.to_ne_bytes());
    b[8..12].copy_from_slice(&flags.to_ne_bytes());
    b[12..16].copy_from_slice(&change.to_ne_bytes());
    b
}

fn family_of(addr: &[u8]) -> io::Result<u8> {
    match addr.len() {
        4 => Ok(AF_INET),
        16 => Ok(AF_INET6),
        _ => Err(io::Error::from(io::ErrorKind::InvalidInput)),
    }
}

fn addr_msg(ty: u16, flags: u16, ifindex: i32, addr: &[u8], prefix: u8) -> io::Result<Vec<u8>> {
    let fam = family_of(addr)?;
    if prefix as usize > addr.len() * 8 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let mut fixed = [0u8; 8];
    fixed[0] = fam;
    fixed[1] = prefix;
    fixed[4..8].copy_from_slice(&(ifindex as u32).to_ne_bytes());
    let mut m = Msg::new(ty, flags, 1, &fixed);
    m.attr(IFA_LOCAL, addr);
    m.attr(IFA_ADDRESS, addr);
    Ok(m.finish())
}

fn route_msg(ty: u16, flags: u16, r: &RouteInfo) -> io::Result<Vec<u8>> {
    let fam = if r.dst.is_empty() { r.gateway.as_deref().map(family_of).transpose()?.unwrap_or(AF_INET) } else { family_of(&r.dst)? };
    let mut fixed = [0u8; 12];
    fixed[0] = fam;
    fixed[1] = r.prefix;
    fixed[4] = 254; // RT_TABLE_MAIN
    fixed[5] = 3; // RTPROT_BOOT
    fixed[6] = 0; // RT_SCOPE_UNIVERSE
    if r.gateway.is_none() {
        fixed[6] = 253; // RT_SCOPE_LINK
    }
    fixed[7] = 1; // RTN_UNICAST
    let mut m = Msg::new(ty, flags, 1, &fixed);
    if r.prefix > 0 {
        m.attr(RTA_DST, &r.dst);
    }
    if let Some(g) = &r.gateway {
        m.attr(RTA_GATEWAY, g);
    }
    if let Some(o) = r.oif {
        m.attr(RTA_OIF, &(o as u32).to_ne_bytes());
    }
    m.attr(RTA_TABLE, &254u32.to_ne_bytes());
    Ok(m.finish())
}

struct Attrs<'a>(&'a [u8]);

impl<'a> Iterator for Attrs<'a> {
    type Item = (u16, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        if self.0.len() < 4 {
            return None;
        }
        let len = u16::from_ne_bytes([self.0[0], self.0[1]]) as usize;
        let ty = u16::from_ne_bytes([self.0[2], self.0[3]]) & 0x3fff; // strip NLA_F_NESTED / byte-order flags
        if len < 4 || len > self.0.len() {
            self.0 = &[];
            return None;
        }
        let data = &self.0[4..len];
        let adv = align4(len).min(self.0.len());
        self.0 = &self.0[adv..];
        Some((ty, data))
    }
}

/// Split a receive buffer into (type, payload-after-nlmsghdr) messages.
fn messages(buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 16 <= buf.len() {
        let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
        if len < 16 || off + len > buf.len() {
            break;
        }
        out.push((ty, &buf[off + 16..off + len]));
        off += align4(len);
    }
    out
}

fn parse_link(p: &[u8]) -> Option<LinkInfo> {
    if p.len() < 16 {
        return None;
    }
    let ifindex = i32::from_ne_bytes(p[4..8].try_into().ok()?);
    let flags = u32::from_ne_bytes(p[8..12].try_into().ok()?);
    let mut li = LinkInfo { ifindex, name: String::new(), mac: None, flags, mtu: 0, kind: None, vlan: None };
    let mut parent = None;
    for (ty, d) in Attrs(&p[16..]) {
        match ty {
            IFLA_IFNAME => li.name = String::from_utf8_lossy(d.split(|b| *b == 0).next().unwrap_or(&[])).into_owned(),
            IFLA_ADDRESS if d.len() == 6 => li.mac = Some(crate::Mac([d[0], d[1], d[2], d[3], d[4], d[5]])),
            IFLA_MTU if d.len() >= 4 => li.mtu = u32::from_ne_bytes(d[0..4].try_into().ok()?),
            IFLA_LINK if d.len() >= 4 => parent = Some(i32::from_ne_bytes(d[0..4].try_into().ok()?)),
            IFLA_LINKINFO => {
                let mut vid = None;
                for (t2, d2) in Attrs(d) {
                    if t2 == IFLA_INFO_KIND {
                        li.kind = Some(String::from_utf8_lossy(d2.split(|b| *b == 0).next().unwrap_or(&[])).into_owned());
                    } else if t2 == IFLA_INFO_DATA {
                        for (t3, d3) in Attrs(d2) {
                            if t3 == IFLA_VLAN_ID && d3.len() >= 2 {
                                vid = Some(u16::from_ne_bytes([d3[0], d3[1]]));
                            }
                        }
                    }
                }
                if let (Some(v), true) = (vid, li.kind.as_deref() == Some("vlan")) {
                    li.vlan = Some((0, v));
                }
            }
            _ => {}
        }
    }
    if let Some((_, v)) = li.vlan {
        li.vlan = Some((parent.unwrap_or(0), v));
    }
    Some(li)
}

fn parse_addr(p: &[u8]) -> Option<AddrInfo> {
    if p.len() < 8 || !(p[0] == AF_INET || p[0] == AF_INET6) {
        return None;
    }
    let prefix = p[1];
    let ifindex = u32::from_ne_bytes(p[4..8].try_into().ok()?) as i32;
    let (mut local, mut addr) = (None, None);
    for (ty, d) in Attrs(&p[8..]) {
        match ty {
            IFA_LOCAL => local = Some(d.to_vec()),
            IFA_ADDRESS => addr = Some(d.to_vec()),
            _ => {}
        }
    }
    local.or(addr).map(|addr| AddrInfo { ifindex, addr, prefix })
}

fn parse_route(p: &[u8]) -> Option<RouteInfo> {
    if p.len() < 12 || !(p[0] == AF_INET || p[0] == AF_INET6) {
        return None;
    }
    let (prefix, mut table, rtype) = (p[1], p[4] as u32, p[7]);
    let mut r = RouteInfo { dst: Vec::new(), prefix, gateway: None, oif: None };
    for (ty, d) in Attrs(&p[12..]) {
        match ty {
            RTA_DST => r.dst = d.to_vec(),
            RTA_GATEWAY => r.gateway = Some(d.to_vec()),
            RTA_OIF if d.len() >= 4 => r.oif = Some(i32::from_ne_bytes(d[0..4].try_into().ok()?)),
            RTA_TABLE if d.len() >= 4 => table = u32::from_ne_bytes(d[0..4].try_into().ok()?),
            _ => {}
        }
    }
    if table != 254 || rtype != 1 {
        return None;
    }
    if r.dst.is_empty() {
        r.dst = vec![0; if p[0] == AF_INET { 4 } else { 16 }];
    }
    Some(r)
}

struct Sock(i32);

impl Sock {
    fn open() -> io::Result<Sock> {
        // AF_NETLINK=16, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE=0
        // SAFETY: plain socket(2).
        let fd = unsafe { ffi::socket(16, 3 | 0o2000000, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let s = Sock(fd);
        let sa = [16u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // sockaddr_nl{AF_NETLINK, pid 0, groups 0}
        // SAFETY: sa is a valid sockaddr_nl.
        if unsafe { ffi::bind(fd, sa.as_ptr(), 12) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let tmo = [5i64.to_ne_bytes(), 0i64.to_ne_bytes()].concat();
        // SOL_SOCKET=1, SO_RCVTIMEO=20: never hang on the kernel
        // SAFETY: tmo is a valid timeval.
        unsafe { ffi::setsockopt(fd, 1, 20, tmo.as_ptr(), 16) };
        Ok(s)
    }
    fn send(&self, msg: &[u8]) -> io::Result<()> {
        let sa = [16u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        // SAFETY: msg and sa are valid for the call.
        let r = unsafe { ffi::sendto(self.0, msg.as_ptr(), msg.len(), 0, sa.as_ptr(), 12) };
        if r < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: buf is a valid writable buffer.
        let r = unsafe { ffi::recv(self.0, buf.as_mut_ptr(), buf.len(), 0) };
        if r < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(r as usize)
        }
    }
}

impl Drop for Sock {
    fn drop(&mut self) {
        // SAFETY: we own the fd.
        unsafe { ffi::close(self.0) };
    }
}

/// Send one request and collect every payload until DONE (dump) or the ACK (change request).
fn transact(req: &[u8], dump: bool) -> io::Result<Vec<(u16, Vec<u8>)>> {
    let s = Sock::open()?;
    s.send(req)?;
    let mut out = Vec::new();
    let mut buf = vec![0u8; 1 << 17];
    loop {
        let n = s.recv(&mut buf)?;
        for (ty, p) in messages(&buf[..n]) {
            match ty {
                NLMSG_DONE => return Ok(out),
                NLMSG_ERROR => {
                    let code = if p.len() >= 4 { i32::from_ne_bytes(p[0..4].try_into().unwrap()) } else { -22 };
                    if code == 0 {
                        return Ok(out);
                    }
                    return Err(io::Error::from_raw_os_error(-code));
                }
                _ => out.push((ty, p.to_vec())),
            }
        }
        if !dump && !out.is_empty() {
            return Ok(out);
        }
    }
}

fn dump_req(ty: u16, fixed: &[u8]) -> Vec<u8> {
    Msg::new(ty, NLM_F_REQUEST | NLM_F_DUMP, 1, fixed).finish()
}

pub fn get_links() -> io::Result<Vec<LinkInfo>> {
    let r = transact(&dump_req(RTM_GETLINK, &ifinfomsg(0, 0, 0)), true)?;
    Ok(r.iter().filter(|(t, _)| *t == RTM_NEWLINK).filter_map(|(_, p)| parse_link(p)).collect())
}
pub fn get_addrs() -> io::Result<Vec<AddrInfo>> {
    let r = transact(&dump_req(RTM_GETADDR, &[AF_UNSPEC, 0, 0, 0, 0, 0, 0, 0]), true)?;
    Ok(r.iter().filter(|(t, _)| *t == RTM_NEWADDR).filter_map(|(_, p)| parse_addr(p)).collect())
}
pub fn get_routes() -> io::Result<Vec<RouteInfo>> {
    let r = transact(&dump_req(RTM_GETROUTE, &[AF_UNSPEC; 12]), true)?;
    Ok(r.iter().filter(|(t, _)| *t == RTM_NEWROUTE).filter_map(|(_, p)| parse_route(p)).collect())
}
pub fn add_addr(ifindex: i32, addr: &[u8], prefix: u8) -> io::Result<()> {
    let m = addr_msg(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, ifindex, addr, prefix)?;
    transact(&m, false).map(|_| ())
}
pub fn del_addr(ifindex: i32, addr: &[u8], prefix: u8) -> io::Result<()> {
    let m = addr_msg(RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK, ifindex, addr, prefix)?;
    transact(&m, false).map(|_| ())
}
pub fn add_route(r: &RouteInfo) -> io::Result<()> {
    let m = route_msg(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, r)?;
    transact(&m, false).map(|_| ())
}
pub fn del_route(r: &RouteInfo) -> io::Result<()> {
    let m = route_msg(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, r)?;
    transact(&m, false).map(|_| ())
}
pub fn link_set_up(ifindex: i32, up: bool) -> io::Result<()> {
    let m = Msg::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, 1, &ifinfomsg(ifindex, if up { IFF_UP } else { 0 }, IFF_UP)).finish();
    transact(&m, false).map(|_| ())
}
pub fn set_mtu(ifindex: i32, mtu: u32) -> io::Result<()> {
    let mut m = Msg::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, 1, &ifinfomsg(ifindex, 0, 0));
    m.attr(IFLA_MTU, &mtu.to_ne_bytes());
    transact(&m.finish(), false).map(|_| ())
}

fn vlan_msg(parent: i32, vid: u16, name: &str) -> Vec<u8> {
    let mut m = Msg::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, 1, &ifinfomsg(0, 0, 0));
    m.attr(IFLA_LINK, &(parent as u32).to_ne_bytes());
    let mut n = name.as_bytes().to_vec();
    n.push(0);
    m.attr(IFLA_IFNAME, &n);
    let li = m.begin_nest(IFLA_LINKINFO);
    m.attr(IFLA_INFO_KIND, b"vlan\0");
    let di = m.begin_nest(IFLA_INFO_DATA);
    m.attr(IFLA_VLAN_ID, &vid.to_ne_bytes());
    m.end_nest(di);
    m.end_nest(li);
    m.finish()
}

/// Create `<parent>.<vid>` (kind vlan, 802.1Q); returns the new ifindex.
pub fn add_vlan(parent: i32, vid: u16) -> io::Result<i32> {
    let links = get_links()?;
    let pname = links.iter().find(|l| l.ifindex == parent).map(|l| l.name.clone()).ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let name = format!("{}.{}", pname, vid);
    if name.len() > 15 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    transact(&vlan_msg(parent, vid, &name), false)?;
    get_links()?.into_iter().find(|l| l.name == name).map(|l| l.ifindex).ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
}
pub fn del_link(ifindex: i32) -> io::Result<()> {
    let m = Msg::new(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, 1, &ifinfomsg(ifindex, 0, 0)).finish();
    transact(&m, false).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_message_bytes() {
        let m = addr_msg(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, 2, &[10, 0, 0, 5], 24).unwrap();
        // header(16) + ifaddrmsg(8) + two 8-byte attrs
        assert_eq!(m.len(), 16 + 8 + 16);
        assert_eq!(u32::from_ne_bytes(m[0..4].try_into().unwrap()), 40);
        assert_eq!(u16::from_ne_bytes(m[4..6].try_into().unwrap()), 20);
        assert_eq!(&m[16..20], &[2, 24, 0, 0]);
        assert_eq!(u32::from_ne_bytes(m[20..24].try_into().unwrap()), 2);
        assert_eq!(&m[24..32], &[8, 0, 2, 0, 10, 0, 0, 5]);
        assert!(addr_msg(RTM_NEWADDR, 0, 2, &[1, 2, 3], 8).is_err());
        assert!(addr_msg(RTM_NEWADDR, 0, 2, &[1, 2, 3, 4], 33).is_err());
    }

    #[test]
    fn default_route_message() {
        let r = RouteInfo { dst: vec![0; 4], prefix: 0, gateway: Some(vec![10, 0, 0, 1]), oif: Some(3) };
        let m = route_msg(RTM_NEWROUTE, NLM_F_REQUEST, &r).unwrap();
        let attrs: Vec<_> = Attrs(&m[16 + 12..]).collect();
        assert_eq!(attrs[0], (RTA_GATEWAY, &[10u8, 0, 0, 1][..]));
        assert!(attrs.iter().all(|(t, _)| *t != RTA_DST), "no RTA_DST for a /0 route");
        assert_eq!(m[16 + 6], 0, "scope universe with a gateway");
    }

    #[test]
    fn vlan_message_nests() {
        let m = vlan_msg(2, 100, "eth0.100");
        let attrs: Vec<_> = Attrs(&m[16 + 16..]).collect();
        assert_eq!(attrs[0].0, IFLA_LINK);
        assert_eq!(attrs[1], (IFLA_IFNAME, &b"eth0.100\0"[..]));
        assert_eq!(attrs[2].0, IFLA_LINKINFO);
        let inner: Vec<_> = Attrs(attrs[2].1).collect();
        assert_eq!(inner[0], (IFLA_INFO_KIND, &b"vlan\0"[..]));
        let data: Vec<_> = Attrs(inner[1].1).collect();
        assert_eq!(data[0], (IFLA_VLAN_ID, &100u16.to_ne_bytes()[..]));
    }

    #[test]
    fn parse_vlan_link() {
        let m = vlan_msg(2, 100, "eth0.100");
        // reuse the encoder's body as a RTM_NEWLINK payload
        let li = parse_link(&m[16..]).unwrap();
        assert_eq!(li.name, "eth0.100");
        assert_eq!(li.kind.as_deref(), Some("vlan"));
        assert_eq!(li.vlan, Some((2, 100)));
    }

    #[test]
    fn route_parse_filters_table_and_type() {
        let r = RouteInfo { dst: vec![10, 1, 0, 0], prefix: 16, gateway: None, oif: Some(2) };
        let m = route_msg(RTM_NEWROUTE, 0, &r).unwrap();
        assert_eq!(parse_route(&m[16..]), Some(r));
        let mut other = m.clone();
        other[16 + 7] = 2; // RTN_LOCAL
        assert_eq!(parse_route(&other[16..]), None);
    }

    #[test]
    fn attrs_reject_truncated() {
        assert_eq!(Attrs(&[8, 0, 1, 0, 1]).count(), 0);
        assert_eq!(Attrs(&[2, 0, 1, 0]).count(), 0);
    }

    #[test]
    fn messages_split_and_bounds() {
        let a = Msg::new(RTM_NEWADDR, 0, 1, &[0u8; 8]).finish();
        let mut two = a.clone();
        two.extend_from_slice(&a);
        assert_eq!(messages(&two).len(), 2);
        assert_eq!(messages(&two[..20]).len(), 0);
    }

    /// Needs no privileges: a dump of links works for any user and always contains the loopback.
    #[test]
    fn live_dump_contains_lo() {
        match get_links() {
            Ok(l) => assert!(l.iter().any(|x| x.name == "lo" && x.ifindex == 1)),
            Err(e) => eprintln!("netlink not available here: {}", e),
        }
        let _ = get_addrs();
        let _ = get_routes();
    }
}
