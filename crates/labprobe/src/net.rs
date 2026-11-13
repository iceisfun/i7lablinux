//! net: /sys/class/net + SIOCETHTOOL + rtnetlink addresses. Owner: P3.

use labproto::json::{JsonWriter, ToJson};

use crate::ctx::{ProbeCtx, ProbeError};

#[derive(Clone, Debug, Default)]
pub struct NetIface {
    pub name: String,
    pub mac: Option<String>,
    pub perm_mac: Option<String>,
    pub driver: Option<String>,
    pub bus_info: Option<String>,
    pub operstate: String,
    pub carrier: Option<bool>,
    pub speed_mbps: Option<u64>,
    pub duplex: Option<String>,
    pub mtu: u32,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    /// parent iface for a VLAN sub-interface
    pub vlan_of: Option<String>,
    pub vlan_id: Option<u16>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub carrier_changes: u64,
}

#[derive(Clone, Debug, Default)]
pub struct NetReport {
    pub ifaces: Vec<NetIface>,
}

/// "192.0.2.1"
pub fn fmt_ipv4(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// RFC 5952 text of 16 address bytes (longest run of zero groups of length >= 2 becomes "::").
pub fn fmt_ipv6(b: &[u8]) -> String {
    let g: Vec<u16> = (0..8).map(|i| u16::from_be_bytes([b[i * 2], b[i * 2 + 1]])).collect();
    let (mut best, mut best_len, mut i) = (usize::MAX, 0, 0);
    while i < 8 {
        if g[i] == 0 {
            let s = i;
            while i < 8 && g[i] == 0 {
                i += 1;
            }
            if i - s > best_len && i - s >= 2 {
                best = s;
                best_len = i - s;
            }
        } else {
            i += 1;
        }
    }
    let mut out = String::new();
    let mut i = 0;
    while i < 8 {
        if i == best {
            out.push_str("::");
            i += best_len;
            continue;
        }
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        out.push_str(&format!("{:x}", g[i]));
        i += 1;
    }
    out
}

/// /proc/net/if_inet6: "fe80000000000000021122fffe334455 02 40 20 80 eth0" -> (iface, "fe80::211:22ff:fe33:4455/64").
pub fn parse_if_inet6(text: &str) -> Vec<(String, String)> {
    let mut v = Vec::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 6 || f[0].len() != 32 {
            continue;
        }
        let bytes: Option<Vec<u8>> = (0..16).map(|i| u8::from_str_radix(&f[0][i * 2..i * 2 + 2], 16).ok()).collect();
        let (Some(b), Ok(plen)) = (bytes, u32::from_str_radix(f[2], 16)) else { continue };
        v.push((f[5].to_string(), format!("{}/{}", fmt_ipv6(&b), plen)));
    }
    v
}

/// /proc/net/vlan/config rows: (device, vlan id, parent).
pub fn parse_vlan_config(text: &str) -> Vec<(String, u16, String)> {
    let mut v = Vec::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split('|').map(str::trim).collect();
        if f.len() == 3 {
            if let Ok(id) = f[1].parse() {
                v.push((f[0].to_string(), id, f[2].to_string()));
            }
        }
    }
    v
}

/// Merge netlink address records into the interfaces (`ifindex` from sysfs).
pub fn merge_addrs(ifaces: &mut [(NetIface, i32)], addrs: &[labproto::netlink::AddrInfo]) {
    for a in addrs {
        let Some((i, _)) = ifaces.iter_mut().find(|(_, idx)| *idx == a.ifindex) else { continue };
        match a.addr.len() {
            4 => i.ipv4.push(format!("{}/{}", fmt_ipv4(&a.addr), a.prefix)),
            16 => {
                let s = format!("{}/{}", fmt_ipv6(&a.addr), a.prefix);
                if !i.ipv6.contains(&s) {
                    i.ipv6.push(s);
                }
            }
            _ => {}
        }
    }
}

fn mac_ok(s: &str) -> Option<String> {
    let s = s.trim();
    (s.len() == 17 && s != "00:00:00:00:00:00").then(|| s.to_string())
}

pub fn probe(ctx: &ProbeCtx) -> Result<NetReport, ProbeError> {
    let live = ctx.root == std::path::Path::new("/");
    let vlans = ctx.read_trim("/proc/net/vlan/config").map(|t| parse_vlan_config(&t)).unwrap_or_default();
    let inet6 = ctx.read_trim("/proc/net/if_inet6").map(|t| parse_if_inet6(&t)).unwrap_or_default();
    let mut ifaces: Vec<(NetIface, i32)> = Vec::new();
    for name in ctx.list_dir("/sys/class/net")? {
        if name == "lo" {
            continue;
        }
        let base = format!("/sys/class/net/{}", name);
        let r = |f: &str| ctx.read_opt(&format!("{}/{}", base, f));
        let n = |f: &str| r(f).and_then(|v| v.parse::<u64>().ok());
        let mac = r("address").and_then(|a| mac_ok(&a));
        let mut i = NetIface {
            perm_mac: if r("addr_assign_type").as_deref() == Some("0") { mac.clone() } else { None },
            mac,
            driver: ctx.link_name(&format!("{}/device/driver", base)),
            bus_info: ctx.link_name(&format!("{}/device", base)),
            operstate: r("operstate").unwrap_or_default(),
            carrier: n("carrier").map(|c| c == 1),
            speed_mbps: r("speed").and_then(|v| v.parse::<i64>().ok()).filter(|s| *s > 0).map(|s| s as u64),
            duplex: r("duplex"),
            mtu: n("mtu").unwrap_or(0) as u32,
            rx_bytes: n("statistics/rx_bytes").unwrap_or(0),
            tx_bytes: n("statistics/tx_bytes").unwrap_or(0),
            rx_errors: n("statistics/rx_errors").unwrap_or(0),
            tx_errors: n("statistics/tx_errors").unwrap_or(0),
            carrier_changes: n("carrier_changes").unwrap_or(0),
            ipv6: inet6.iter().filter(|(d, _)| *d == name).map(|(_, a)| a.clone()).collect(),
            name,
            ..Default::default()
        };
        if let Some((_, id, parent)) = vlans.iter().find(|(d, _, _)| *d == i.name) {
            i.vlan_of = Some(parent.clone());
            i.vlan_id = Some(*id);
            if i.driver.is_none() {
                i.driver = Some("802.1Q VLAN Support".into());
            }
        }
        // permanent address of a NIC whose MAC was changed: ETHTOOL_GPERMADDR (live, needs no privilege to read)
        if live && i.perm_mac.is_none() {
            i.perm_mac = ethtool_perm_addr(&i.name).ok().and_then(|m| mac_ok(&m));
        }
        let idx = r("ifindex").and_then(|v| v.parse().ok()).unwrap_or(-1);
        ifaces.push((i, idx));
    }
    if live {
        if let Ok(addrs) = labproto::netlink::get_addrs() {
            merge_addrs(&mut ifaces, &addrs);
        }
    }
    Ok(NetReport { ifaces: ifaces.into_iter().map(|x| x.0).collect() })
}

impl ToJson for NetReport {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_u64("v", crate::SCHEMA_V);
        w.key("ifaces");
        w.begin_array();
        for i in &self.ifaces {
            w.begin_object();
            w.field_str("name", &i.name);
            w.field_opt_str("mac", i.mac.as_deref());
            w.field_opt_str("perm_mac", i.perm_mac.as_deref());
            w.field_opt_str("driver", i.driver.as_deref());
            w.field_opt_str("bus_info", i.bus_info.as_deref());
            w.field_str("operstate", &i.operstate);
            w.key("carrier");
            match i.carrier {
                Some(c) => w.bool(c),
                None => w.null(),
            }
            w.field_opt_u64("speed_mbps", i.speed_mbps);
            w.field_opt_str("duplex", i.duplex.as_deref());
            w.field_u64("mtu", i.mtu as u64);
            w.key("ipv4");
            w.value(&i.ipv4);
            w.key("ipv6");
            w.value(&i.ipv6);
            w.field_opt_str("vlan_of", i.vlan_of.as_deref());
            w.field_opt_u64("vlan_id", i.vlan_id.map(u64::from));
            w.field_u64("rx_bytes", i.rx_bytes);
            w.field_u64("tx_bytes", i.tx_bytes);
            w.field_u64("rx_errors", i.rx_errors);
            w.field_u64("tx_errors", i.tx_errors);
            w.field_u64("carrier_changes", i.carrier_changes);
            w.end_object();
        }
        w.end_array();
        w.end_object();
    }
}

// ---------------------------------------------------------------------------------------------------------------
// SIOCETHTOOL (the only unsafe here): a datagram socket from std supplies the fd.

#[repr(C)]
struct Ifreq {
    name: [u8; 16],
    data: *mut u8,
    pad: [u8; 16],
}

const SIOCETHTOOL: u64 = 0x8946;
const ETHTOOL_GPERMADDR: u32 = 0x20;
const ETHTOOL_PHYS_ID: u32 = 0x1c;

fn ethtool_call(iface: &str, data: *mut u8) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let bytes = iface.as_bytes();
    if bytes.is_empty() || bytes.len() > 15 || bytes.contains(&0) || bytes.contains(&b'/') {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    let sock = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let mut req = Ifreq { name: [0; 16], data, pad: [0; 16] };
    req.name[..bytes.len()].copy_from_slice(bytes);
    // SAFETY: `req` is a live, correctly laid out struct ifreq whose data pointer references a buffer the caller
    // sized for the ethtool command it put in the first u32.
    unsafe { labproto::sys::ioctl_ptr(sock.as_raw_fd(), SIOCETHTOOL, &mut req as *mut Ifreq as *mut u8) }.map(|_| ())
}

/// Permanent MAC (ETHTOOL_GPERMADDR) as text.
pub fn ethtool_perm_addr(iface: &str) -> std::io::Result<String> {
    let mut buf = [0u8; 8 + 32];
    buf[..4].copy_from_slice(&ETHTOOL_GPERMADDR.to_ne_bytes());
    buf[4..8].copy_from_slice(&32u32.to_ne_bytes());
    ethtool_call(iface, buf.as_mut_ptr())?;
    let size = u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    if size != 6 {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
    }
    Ok(buf[8..14].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":"))
}

/// ETHTOOL_PHYS_ID: blink the port LED for `seconds`. The call blocks for that long (run it on a worker thread);
/// needs CAP_NET_ADMIN and a driver that supports it (EOPNOTSUPP otherwise).
pub fn ethtool_phys_id(iface: &str, seconds: u32) -> std::io::Result<()> {
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(&ETHTOOL_PHYS_ID.to_ne_bytes());
    buf[4..8].copy_from_slice(&seconds.to_ne_bytes());
    ethtool_call(iface, buf.as_mut_ptr())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_text() {
        let b = |s: &str| -> Vec<u8> { (0..16).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()).collect() };
        assert_eq!(fmt_ipv6(&b("fe800000000000000211 22fffe334455".replace(' ', "").as_str())), "fe80::211:22ff:fe33:4455");
        assert_eq!(fmt_ipv6(&b("00000000000000000000000000000001")), "::1");
        assert_eq!(fmt_ipv6(&b("20010db8000000000000000000000000")), "2001:db8::");
        assert_eq!(fmt_ipv6(&b("20010db8000000010000000100000001")), "2001:db8:0:1:0:1:0:1"); // lone zeros are not compressed
        assert_eq!(fmt_ipv6(&b("00000000000000000000000000000000")), "::");
        assert_eq!(fmt_ipv4(&[192, 0, 2, 7]), "192.0.2.7");
    }

    #[test]
    fn proc_parsers() {
        let v = parse_if_inet6("fe80000000000000021122fffe334455 02 40 20 80 eth0\nbad line\n");
        assert_eq!(v, vec![("eth0".to_string(), "fe80::211:22ff:fe33:4455/64".to_string())]);
        let vl = parse_vlan_config("VLAN Dev name\t | VLAN ID\nName-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\neth0.13       | 13  | eth0\n");
        assert_eq!(vl, vec![("eth0.13".to_string(), 13, "eth0".to_string())]);
    }

    #[test]
    fn netlink_merge() {
        let mut v = vec![(NetIface { name: "eth0".into(), ..Default::default() }, 2)];
        merge_addrs(
            &mut v,
            &[
                labproto::netlink::AddrInfo { ifindex: 2, addr: vec![10, 0, 0, 5], prefix: 24 },
                labproto::netlink::AddrInfo { ifindex: 9, addr: vec![10, 0, 0, 6], prefix: 24 },
            ],
        );
        assert_eq!(v[0].0.ipv4, ["10.0.0.5/24"]);
    }

    #[test]
    fn bad_iface_names_rejected_before_ioctl() {
        assert!(ethtool_phys_id("", 1).is_err());
        assert!(ethtool_phys_id("a/b", 1).is_err());
        assert!(ethtool_phys_id("0123456789abcdef", 1).is_err());
    }
}
