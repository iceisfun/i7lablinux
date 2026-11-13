//! `ip`: link/addr/route show and set over `labproto::netlink` (the workspace's only netlink code). Until the netlink
//! client answers, `ip link show` falls back to /sys/class/net; changes need netlink.

use std::net::{Ipv4Addr, Ipv6Addr};

use labproto::netlink::{self, AddrInfo, LinkInfo, RouteInfo};
use labproto::Mac;

use super::{fail, usage};
use crate::{Io, Shell};

#[derive(Debug, PartialEq, Eq)]
pub enum IpCmd {
    AddrShow(Option<String>),
    LinkShow(Option<String>),
    RouteShow,
    AddrAdd { cidr: String, dev: String },
    AddrDel { cidr: String, dev: String },
    LinkSet { dev: String, up: Option<bool>, mtu: Option<u32> },
    RouteAdd(RouteSpec),
    RouteDel(RouteSpec),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RouteSpec {
    /// None = default route
    pub dst: Option<String>,
    pub via: Option<String>,
    pub dev: Option<String>,
}

/// `10.0.0.1/24` / `fe80::1/64` -> (address bytes, prefix). A bare address gets a host prefix.
pub fn parse_cidr(s: &str) -> Option<(Vec<u8>, u8)> {
    let (a, p) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
        None => (s, None),
    };
    if let Ok(v4) = a.parse::<Ipv4Addr>() {
        let p = p.unwrap_or(32);
        return (p <= 32).then(|| (v4.octets().to_vec(), p));
    }
    let v6: Ipv6Addr = a.parse().ok()?;
    let p = p.unwrap_or(128);
    (p <= 128).then(|| (v6.octets().to_vec(), p))
}

pub fn fmt_addr(b: &[u8]) -> String {
    match b.len() {
        4 => Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
        16 => Ipv6Addr::from(<[u8; 16]>::try_from(b).unwrap()).to_string(),
        _ => "?".into(),
    }
}

const IFF: &[(u32, &str)] = &[(0x1, "UP"), (0x2, "BROADCAST"), (0x8, "LOOPBACK"), (0x10, "POINTOPOINT"), (0x40, "RUNNING"), (0x100, "PROMISC"), (0x1000, "MULTICAST"), (0x10000, "LOWER_UP")];

pub fn flag_names(flags: u32) -> String {
    IFF.iter().filter(|(b, _)| flags & b != 0).map(|(_, n)| *n).collect::<Vec<_>>().join(",")
}

pub fn parse_ip(args: &[String]) -> Result<IpCmd, String> {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let Some((&obj, rest)) = a.split_first() else { return Ok(IpCmd::AddrShow(None)) };
    let dev_arg = |r: &[&str]| -> Option<String> {
        match r {
            [] => None,
            ["dev", d] | [d] if *d != "dev" => Some(d.to_string()),
            _ => None,
        }
    };
    match obj {
        "addr" | "address" | "a" => match rest {
            [] | ["show"] | ["list"] => Ok(IpCmd::AddrShow(None)),
            [s, r @ ..] if matches!(*s, "show" | "list") => Ok(IpCmd::AddrShow(Some(dev_arg(r).ok_or("usage: ip addr show [dev IF]")?))),
            ["add", cidr, "dev", dev] => Ok(IpCmd::AddrAdd { cidr: cidr.to_string(), dev: dev.to_string() }),
            ["del", cidr, "dev", dev] | ["delete", cidr, "dev", dev] => Ok(IpCmd::AddrDel { cidr: cidr.to_string(), dev: dev.to_string() }),
            _ => Err("usage: ip addr [show [dev IF]] | add|del A/P dev IF".into()),
        },
        "link" | "l" => match rest {
            [] | ["show"] | ["list"] => Ok(IpCmd::LinkShow(None)),
            [s, r @ ..] if matches!(*s, "show" | "list") => Ok(IpCmd::LinkShow(Some(dev_arg(r).ok_or("usage: ip link show [IF]")?))),
            ["set", r @ ..] => {
                let (dev, opts) = match r {
                    ["dev", d, o @ ..] => (d.to_string(), o),
                    [d, o @ ..] => (d.to_string(), o),
                    [] => return Err("usage: ip link set IF up|down|mtu N".into()),
                };
                let (mut up, mut mtu) = (None, None);
                let mut it = opts.iter();
                while let Some(o) = it.next() {
                    match *o {
                        "up" => up = Some(true),
                        "down" => up = Some(false),
                        "mtu" => mtu = Some(it.next().and_then(|v| v.parse::<u32>().ok()).filter(|m| (68..=65535).contains(m)).ok_or("bad mtu")?),
                        other => return Err(format!("unknown link option '{other}'")),
                    }
                }
                if up.is_none() && mtu.is_none() {
                    return Err("usage: ip link set IF up|down|mtu N".into());
                }
                Ok(IpCmd::LinkSet { dev, up, mtu })
            }
            _ => Err("usage: ip link [show [IF]] | set IF up|down|mtu N".into()),
        },
        "route" | "r" => match rest {
            [] | ["show"] | ["list"] => Ok(IpCmd::RouteShow),
            [verb @ ("add" | "del" | "delete"), r @ ..] => {
                let Some((first, opts)) = r.split_first() else { return Err("usage: ip route add default|NET/P [via GW] [dev IF]".into()) };
                let mut spec = RouteSpec { dst: (*first != "default").then(|| first.to_string()), via: None, dev: None };
                let mut it = opts.iter();
                while let Some(o) = it.next() {
                    match *o {
                        "via" => spec.via = Some(it.next().ok_or("via needs an address")?.to_string()),
                        "dev" => spec.dev = Some(it.next().ok_or("dev needs an interface")?.to_string()),
                        other => return Err(format!("unknown route option '{other}'")),
                    }
                }
                Ok(if *verb == "add" { IpCmd::RouteAdd(spec) } else { IpCmd::RouteDel(spec) })
            }
            _ => Err("usage: ip route [show] | add|del default|NET/P [via GW] [dev IF]".into()),
        },
        other => Err(format!("unknown object '{other}' (addr, link, route)")),
    }
}

/// Fallback link list from /sys/class/net, used until the netlink client is available.
fn sysfs_links() -> Vec<LinkInfo> {
    let mut v = Vec::new();
    let Ok(rd) = std::fs::read_dir("/sys/class/net") else { return v };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let rd = |f: &str| std::fs::read_to_string(e.path().join(f)).ok().map(|s| s.trim().to_string());
        v.push(LinkInfo {
            ifindex: rd("ifindex").and_then(|s| s.parse().ok()).unwrap_or(0),
            name,
            mac: rd("address").and_then(|s| Mac::parse(&s)),
            flags: rd("flags").and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok()).unwrap_or(0),
            mtu: rd("mtu").and_then(|s| s.parse().ok()).unwrap_or(0),
            kind: None,
            vlan: None,
        });
    }
    v.sort_by_key(|l| l.ifindex);
    v
}

fn links() -> (Vec<LinkInfo>, bool) {
    match netlink::get_links() {
        Ok(l) => (l, true),
        Err(_) => (sysfs_links(), false),
    }
}

fn find_if(links: &[LinkInfo], name: &str) -> Result<i32, String> {
    links.iter().find(|l| l.name == name).map(|l| l.ifindex).ok_or_else(|| format!("Cannot find device \"{name}\""))
}

fn fmt_link(l: &LinkInfo) -> String {
    let state = if l.flags & 0x40 != 0 { "UP" } else { "DOWN" };
    let mut s = format!("{}: {}: <{}> mtu {} state {}", l.ifindex, l.name, flag_names(l.flags), l.mtu, state);
    if let Some((parent, vid)) = l.vlan {
        s.push_str(&format!(" vlan {vid} parent #{parent}"));
    }
    s.push('\n');
    if let Some(m) = l.mac {
        s.push_str(&format!("    link/ether {m}\n"));
    }
    s
}

fn fmt_route(r: &RouteInfo, links: &[LinkInfo]) -> String {
    let mut s = if r.prefix == 0 { "default".to_string() } else { format!("{}/{}", fmt_addr(&r.dst), r.prefix) };
    if let Some(g) = &r.gateway {
        s.push_str(&format!(" via {}", fmt_addr(g)));
    }
    if let Some(o) = r.oif {
        if let Some(l) = links.iter().find(|l| l.ifindex == o) {
            s.push_str(&format!(" dev {}", l.name));
        }
    }
    s
}

fn route_info(spec: &RouteSpec, links: &[LinkInfo]) -> Result<RouteInfo, String> {
    let (dst, prefix) = match &spec.dst {
        None => (vec![0u8; if spec.via.as_deref().map(|v| v.contains(':')).unwrap_or(false) { 16 } else { 4 }], 0),
        Some(d) => parse_cidr(d).ok_or_else(|| format!("bad prefix '{d}'"))?,
    };
    let gateway = match &spec.via {
        Some(v) => Some(parse_cidr(v).filter(|(_, p)| *p == 32 || *p == 128).ok_or_else(|| format!("bad gateway '{v}'"))?.0),
        None => None,
    };
    let oif = match &spec.dev {
        Some(d) => Some(find_if(links, d)?),
        None => None,
    };
    if gateway.is_none() && oif.is_none() {
        return Err("route needs via GW and/or dev IF".into());
    }
    Ok(RouteInfo { dst, prefix, gateway, oif })
}

fn run_ip(cmd: IpCmd, io: &mut Io) -> Result<(), String> {
    let nl = |e: std::io::Error| match e.kind() {
        std::io::ErrorKind::Unsupported => "netlink client not available in this build".to_string(),
        _ => e.to_string(),
    };
    match cmd {
        IpCmd::LinkShow(dev) => {
            let (ls, _) = links();
            for l in ls.iter().filter(|l| dev.as_deref().map(|d| d == l.name).unwrap_or(true)) {
                io.out(&fmt_link(l));
            }
            if let Some(d) = dev {
                find_if(&ls, &d)?;
            }
        }
        IpCmd::AddrShow(dev) => {
            let (ls, have_nl) = links();
            let addrs: Vec<AddrInfo> = if have_nl { netlink::get_addrs().map_err(nl)? } else { Vec::new() };
            if let Some(d) = &dev {
                find_if(&ls, d)?;
            }
            for l in ls.iter().filter(|l| dev.as_deref().map(|d| d == l.name).unwrap_or(true)) {
                io.out(&fmt_link(l));
                for a in addrs.iter().filter(|a| a.ifindex == l.ifindex) {
                    io.out(&format!("    {} {}/{}\n", if a.addr.len() == 4 { "inet" } else { "inet6" }, fmt_addr(&a.addr), a.prefix));
                }
            }
            if !have_nl {
                io.err("ip: addresses unavailable (netlink client not available in this build)\n");
            }
        }
        IpCmd::RouteShow => {
            let (ls, _) = links();
            for r in netlink::get_routes().map_err(nl)? {
                io.out(&format!("{}\n", fmt_route(&r, &ls)));
            }
        }
        IpCmd::AddrAdd { cidr, dev } => {
            let (ls, _) = links();
            let (a, p) = parse_cidr(&cidr).ok_or_else(|| format!("bad address '{cidr}'"))?;
            netlink::add_addr(find_if(&ls, &dev)?, &a, p).map_err(nl)?;
        }
        IpCmd::AddrDel { cidr, dev } => {
            let (ls, _) = links();
            let (a, p) = parse_cidr(&cidr).ok_or_else(|| format!("bad address '{cidr}'"))?;
            netlink::del_addr(find_if(&ls, &dev)?, &a, p).map_err(nl)?;
        }
        IpCmd::LinkSet { dev, up, mtu } => {
            let (ls, _) = links();
            let idx = find_if(&ls, &dev)?;
            if let Some(m) = mtu {
                netlink::set_mtu(idx, m).map_err(nl)?;
            }
            if let Some(u) = up {
                netlink::link_set_up(idx, u).map_err(nl)?;
            }
        }
        IpCmd::RouteAdd(spec) => {
            let (ls, _) = links();
            netlink::add_route(&route_info(&spec, &ls)?).map_err(nl)?;
        }
        IpCmd::RouteDel(spec) => {
            let (ls, _) = links();
            netlink::del_route(&route_info(&spec, &ls)?).map_err(nl)?;
        }
    }
    Ok(())
}

pub fn ip(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    match parse_ip(args) {
        Ok(cmd) => match run_ip(cmd, io) {
            Ok(()) => 0,
            Err(e) => fail(io, "ip", e),
        },
        Err(e) => {
            if e.starts_with("usage") {
                io.err(&format!("{e}\n"));
                usage(io, "ip")
            } else {
                fail(io, "ip", e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn cidr() {
        assert_eq!(parse_cidr("10.0.0.2/24"), Some((vec![10, 0, 0, 2], 24)));
        assert_eq!(parse_cidr("10.0.0.2"), Some((vec![10, 0, 0, 2], 32)));
        assert_eq!(parse_cidr("::1/128").map(|(a, p)| (a.len(), p)), Some((16, 128)));
        assert_eq!(parse_cidr("10.0.0.2/33"), None);
        assert_eq!(parse_cidr("nonsense"), None);
        assert_eq!(parse_cidr("10.0.0.2/x"), None);
        assert_eq!(fmt_addr(&[192, 168, 1, 5]), "192.168.1.5");
        assert_eq!(fmt_addr(&Ipv6Addr::LOCALHOST.octets()), "::1");
    }

    #[test]
    fn flags() {
        assert_eq!(flag_names(0x1 | 0x40 | 0x1000 | 0x10000), "UP,RUNNING,MULTICAST,LOWER_UP");
        assert_eq!(flag_names(0), "");
    }

    #[test]
    fn show_forms() {
        assert_eq!(parse_ip(&v("")), Ok(IpCmd::AddrShow(None)));
        assert_eq!(parse_ip(&v("a")), Ok(IpCmd::AddrShow(None)));
        assert_eq!(parse_ip(&v("addr show dev eth0")), Ok(IpCmd::AddrShow(Some("eth0".into()))));
        assert_eq!(parse_ip(&v("link")), Ok(IpCmd::LinkShow(None)));
        assert_eq!(parse_ip(&v("link show eth1")), Ok(IpCmd::LinkShow(Some("eth1".into()))));
        assert_eq!(parse_ip(&v("route")), Ok(IpCmd::RouteShow));
        assert_eq!(parse_ip(&v("r list")), Ok(IpCmd::RouteShow));
    }

    #[test]
    fn set_forms() {
        assert_eq!(parse_ip(&v("link set eth0 up")), Ok(IpCmd::LinkSet { dev: "eth0".into(), up: Some(true), mtu: None }));
        assert_eq!(parse_ip(&v("link set dev eth0 down mtu 9000")), Ok(IpCmd::LinkSet { dev: "eth0".into(), up: Some(false), mtu: Some(9000) }));
        assert!(parse_ip(&v("link set eth0 mtu 10")).is_err());
        assert!(parse_ip(&v("link set eth0")).is_err());
        assert!(parse_ip(&v("link set eth0 sideways")).is_err());
        assert_eq!(parse_ip(&v("addr add 10.0.0.2/24 dev eth0")), Ok(IpCmd::AddrAdd { cidr: "10.0.0.2/24".into(), dev: "eth0".into() }));
        assert_eq!(parse_ip(&v("addr del 10.0.0.2/24 dev eth0")), Ok(IpCmd::AddrDel { cidr: "10.0.0.2/24".into(), dev: "eth0".into() }));
        assert!(parse_ip(&v("addr add 10.0.0.2/24")).is_err());
    }

    #[test]
    fn route_forms() {
        assert_eq!(parse_ip(&v("route add default via 10.0.0.1 dev eth0")), Ok(IpCmd::RouteAdd(RouteSpec { dst: None, via: Some("10.0.0.1".into()), dev: Some("eth0".into()) })));
        assert_eq!(parse_ip(&v("route del 10.1.0.0/16 dev eth0")), Ok(IpCmd::RouteDel(RouteSpec { dst: Some("10.1.0.0/16".into()), via: None, dev: Some("eth0".into()) })));
        assert!(parse_ip(&v("route add")).is_err());
        assert!(parse_ip(&v("route add default via")).is_err());
        assert!(parse_ip(&v("neigh")).is_err());
    }

    #[test]
    fn route_info_needs_gateway_or_device() {
        let ls = vec![LinkInfo { ifindex: 2, name: "eth0".into(), mac: None, flags: 0, mtu: 1500, kind: None, vlan: None }];
        let r = route_info(&RouteSpec { dst: None, via: Some("10.0.0.1".into()), dev: None }, &ls).unwrap();
        assert_eq!((r.dst, r.prefix, r.gateway, r.oif), (vec![0; 4], 0, Some(vec![10, 0, 0, 1]), None));
        let r = route_info(&RouteSpec { dst: Some("10.1.0.0/16".into()), via: None, dev: Some("eth0".into()) }, &ls).unwrap();
        assert_eq!((r.prefix, r.oif), (16, Some(2)));
        assert!(route_info(&RouteSpec { dst: None, via: None, dev: None }, &ls).is_err());
        assert!(route_info(&RouteSpec { dst: None, via: None, dev: Some("nope".into()) }, &ls).unwrap_err().contains("Cannot find device"));
        assert!(route_info(&RouteSpec { dst: None, via: Some("10.0.0.0/8".into()), dev: None }, &ls).is_err());
    }

    #[test]
    fn route_formatting() {
        let ls = vec![LinkInfo { ifindex: 2, name: "eth0".into(), mac: None, flags: 0, mtu: 1500, kind: None, vlan: None }];
        let d = RouteInfo { dst: vec![0; 4], prefix: 0, gateway: Some(vec![10, 0, 0, 1]), oif: Some(2) };
        assert_eq!(fmt_route(&d, &ls), "default via 10.0.0.1 dev eth0");
        let n = RouteInfo { dst: vec![10, 1, 0, 0], prefix: 16, gateway: None, oif: Some(2) };
        assert_eq!(fmt_route(&n, &ls), "10.1.0.0/16 dev eth0");
    }

    #[test]
    fn link_formatting() {
        let l = LinkInfo { ifindex: 3, name: "eth0.7".into(), mac: Mac::parse("02:00:00:00:00:01"), flags: 0x1 | 0x40, mtu: 1500, kind: Some("vlan".into()), vlan: Some((2, 7)) };
        let s = fmt_link(&l);
        assert!(s.starts_with("3: eth0.7: <UP,RUNNING> mtu 1500 state UP vlan 7"), "{s}");
        assert!(s.contains("link/ether 02:00:00:00:00:01"));
    }
}
