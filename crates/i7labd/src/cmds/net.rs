//! net.set, net.vlan, net.confirm, net.link (net.ls lives with the probes). Kernel access: `Daemon::netops`.

use std::time::Duration;

use labproto::json::JsonWriter;
use labproto::Status;

use crate::events::Event;
use crate::netcfg::{self, StaticCfg};
use crate::opts_or_bad;
use crate::registry::{Ctx, Handler, Reply};

pub const TABLE: &[(&str, Handler)] =
    &[("net.set", set), ("net.vlan", vlan), ("net.confirm", confirm), ("net.link", link)];

fn iface_or_err(name: Option<&String>) -> Result<(String, i32), Reply> {
    let Some(n) = name else { return Err(Reply::error(Status::BadArgs, "IFACE is required")) };
    if !netcfg::valid_iface(n) {
        return Err(Reply::error(Status::NotFound, &format!("no such interface {}", labproto::text::sanitize(n))));
    }
    netcfg::ifindex_of(n).map(|i| (n.clone(), i)).map_err(|e| Reply::error(Status::NotFound, &e.to_string()))
}

fn io_status(e: &std::io::Error) -> Status {
    match e.kind() {
        std::io::ErrorKind::Unsupported => Status::Unsupported,
        std::io::ErrorKind::NotFound => Status::NotFound,
        std::io::ErrorKind::AlreadyExists => Status::Exists,
        std::io::ErrorKind::PermissionDenied => Status::Eperm,
        std::io::ErrorKind::InvalidInput => Status::BadArgs,
        std::io::ErrorKind::WouldBlock => Status::Busy,
        _ => Status::Io,
    }
}

fn ok_json(f: impl FnOnce(&mut JsonWriter)) -> Reply {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_u64("v", 1);
    f(&mut w);
    w.end_object();
    Reply::json(w.finish())
}

fn write_resolv(ctx: &Ctx, dns: &str) -> Result<(), Reply> {
    let mut out = String::new();
    for s in dns.split(',') {
        let a = netcfg::parse_ipv4(s.trim()).ok_or_else(|| Reply::error(Status::BadArgs, "bad --dns (comma separated IPv4)"))?;
        out.push_str(&format!("nameserver {}.{}.{}.{}\n", a[0], a[1], a[2], a[3]));
    }
    std::fs::write(&ctx.daemon.config.resolv_conf, out).map_err(|e| Reply::error(Status::Io, &format!("resolv.conf: {}", e)))
}

/// `IFACE (--dhcp | --ip A.B.C.D/N [--gw A.B.C.D] [--dns A,..]) [--mtu N] [--confirm S]`
fn set(ctx: &mut Ctx) -> Reply {
    let o = opts_or_bad!(ctx, &["dhcp"], &["ip", "gw", "dns", "mtu", "confirm"]);
    let (name, idx) = match iface_or_err(o.positional().first()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if o.positional().len() > 1 || (o.flag("dhcp") && o.value("ip").is_some()) {
        return Reply::error(Status::BadArgs, "usage: net.set IFACE (--dhcp | --ip A.B.C.D/N [--gw ..]) [--mtu N] [--confirm S]");
    }
    let mtu = match o.value("mtu").map(|m| m.parse::<u32>()) {
        Some(Ok(m)) if (576..=9216).contains(&m) => Some(m),
        Some(_) => return Reply::error(Status::BadArgs, "bad --mtu (576..9216)"),
        None => None,
    };
    let confirm = match o.value("confirm").map(|c| c.parse::<u64>()) {
        Some(Ok(s)) if (1..=3600).contains(&s) => Some(Duration::from_secs(s)),
        Some(_) => return Reply::error(Status::BadArgs, "bad --confirm (1..3600 seconds)"),
        None => None,
    };
    let gw = match o.value("gw").map(netcfg::parse_ipv4) {
        Some(None) => return Reply::error(Status::BadArgs, "bad --gw"),
        Some(Some(g)) => Some(g),
        None => None,
    };
    if let Some(d) = o.value("dns") {
        if let Err(r) = write_resolv(ctx, d) {
            return r;
        }
    }
    let ops = ctx.daemon.netops.clone();
    if o.flag("dhcp") {
        // drop the static configuration, then the net duty starts the DHCP client within 2 s
        let saved = netcfg::current_addrs(&*ops, idx);
        for (a, p) in saved {
            let _ = ops.del_addr(idx, &a, p);
        }
        if let Some(g) = netcfg::current_gw(&*ops, idx) {
            let _ = ops.del_route(&labproto::netlink::RouteInfo { dst: vec![0; 4], prefix: 0, gateway: Some(g.to_vec()), oif: Some(idx) });
        }
        if let Some(m) = mtu {
            let _ = ops.set_mtu(idx, m);
        }
        ctx.daemon.net.want_dhcp(&name);
        ctx.daemon.events.publish(Event::Link(name.clone()));
        return ok_json(|w| {
            w.field_str("iface", &name);
            w.field_str("mode", "dhcp");
        });
    }
    let Some(ipstr) = o.value("ip") else {
        // --mtu alone
        return match mtu {
            Some(m) => match ops.set_mtu(idx, m) {
                Ok(()) => ok_json(|w| {
                    w.field_str("iface", &name);
                    w.field_u64("mtu", m as u64);
                }),
                Err(e) => Reply::error(io_status(&e), &e.to_string()),
            },
            None => Reply::error(Status::BadArgs, "one of --dhcp, --ip or --mtu is required"),
        };
    };
    let Some((addr, prefix)) = netcfg::parse_cidr(ipstr) else { return Reply::error(Status::BadArgs, "bad --ip (A.B.C.D/N)") };
    if addr[0] == 0 || addr[0] >= 224 || addr[0] == 127 {
        return Reply::error(Status::BadArgs, "--ip must be a unicast address");
    }
    match ctx.daemon.net.set_static(ops, &name, idx, StaticCfg { addr, prefix, gw, mtu }, confirm) {
        Ok(()) => {
            ctx.daemon.events.publish(Event::Link(name.clone()));
            ok_json(|w| {
                w.field_str("iface", &name);
                w.field_str("ip", ipstr);
                match confirm {
                    Some(c) => w.field_u64("confirm_s", c.as_secs()),
                    None => w.field_opt_u64("confirm_s", None),
                }
            })
        }
        Err(e) => Reply::error(io_status(&e), &e.to_string()),
    }
}

/// `add IFACE VID [--ip A.B.C.D/N] | del IFACE VID`
fn vlan(ctx: &mut Ctx) -> Reply {
    let o = opts_or_bad!(ctx, &[], &["ip", "gw"]);
    let p = o.positional();
    let (verb, iface, vid) = match (p.first().map(String::as_str), p.get(1), p.get(2).and_then(|v| v.parse::<u16>().ok())) {
        (Some(v @ ("add" | "del")), Some(i), Some(vid)) if p.len() == 3 => (v, i, vid),
        _ => return Reply::error(Status::BadArgs, "usage: net.vlan add IFACE VID [--ip A.B.C.D/N] | del IFACE VID"),
    };
    let (_, pidx) = match iface_or_err(Some(iface)) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let ops = ctx.daemon.netops.clone();
    if verb == "del" {
        return match netcfg::vlan_del(&*ops, pidx, vid) {
            Ok(()) => {
                ctx.daemon.events.publish(Event::Link(format!("{}.{}", iface, vid)));
                Reply::ok_empty()
            }
            Err(e) => Reply::error(io_status(&e), &e.to_string()),
        };
    }
    let (name, idx) = match netcfg::vlan_add(&*ops, pidx, vid) {
        Ok(x) => x,
        Err(e) => return Reply::error(io_status(&e), &e.to_string()),
    };
    if let Some(ip) = o.value("ip") {
        let Some((addr, prefix)) = netcfg::parse_cidr(ip) else { return Reply::error(Status::BadArgs, "bad --ip") };
        let gw = o.value("gw").and_then(netcfg::parse_ipv4);
        if let Err(e) = ctx.daemon.net.set_static(ops, &name, idx, StaticCfg { addr, prefix, gw, mtu: None }, None) {
            return Reply::error(io_status(&e), &e.to_string());
        }
    }
    ctx.daemon.events.publish(Event::Link(name.clone()));
    ok_json(|w| {
        w.field_str("iface", &name);
        w.field_u64("ifindex", idx as u64);
    })
}

fn confirm(ctx: &mut Ctx) -> Reply {
    if ctx.daemon.net.confirm() {
        Reply::ok_empty()
    } else {
        Reply::error(Status::NotFound, "nothing is waiting for confirmation (already reverted?)")
    }
}

fn link(ctx: &mut Ctx) -> Reply {
    let o = opts_or_bad!(ctx, &[], &[]);
    let p = o.positional();
    let up = match p.get(1).map(String::as_str) {
        Some("up") if p.len() == 2 => true,
        Some("down") if p.len() == 2 => false,
        _ => return Reply::error(Status::BadArgs, "usage: net.link IFACE up|down"),
    };
    let (name, idx) = match iface_or_err(p.first()) {
        Ok(x) => x,
        Err(r) => return r,
    };
    match ctx.daemon.netops.link_up(idx, up) {
        Ok(()) => {
            ctx.daemon.events.publish(Event::Link(name));
            Reply::ok_empty()
        }
        Err(e) => Reply::error(io_status(&e), &e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netcfg::mock::MockNet;
    use crate::registry::tests_support::*;
    use labproto::keys::Role;
    use std::sync::Arc;

    /// "lo" is the one interface every Linux box has under /sys/class/net, but `valid_iface` refuses it; the
    /// first non-lo interface is used when present, else the tests that need a real name are skipped.
    fn real_iface() -> Option<String> {
        std::fs::read_dir("/sys/class/net").ok()?.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).find(|n| n != "lo")
    }

    #[test]
    fn argument_errors_and_unknown_interface() {
        let d = test_daemon();
        for (args, st) in [
            (vec![], Status::BadArgs),
            (vec!["nosuchif0", "--ip", "10.0.0.2/24"], Status::NotFound),
        ] {
            assert_eq!(run_with(&d, Role::Admin, "net.set", &args).0.status, st, "{:?}", args);
        }
        assert_eq!(run_with(&d, Role::Admin, "net.link", &["nosuchif0", "up"]).0.status, Status::NotFound);
        assert_eq!(run_with(&d, Role::Admin, "net.vlan", &["add", "x"]).0.status, Status::BadArgs);
        assert_eq!(run_with(&d, Role::Admin, "net.confirm", &[]).0.status, Status::NotFound);
        assert_eq!(run_with(&d, Role::Ro, "net.set", &["eth0", "--dhcp"]).0.status, Status::Eperm);
    }

    #[test]
    fn set_vlan_confirm_flow_with_mock_netlink() {
        let Some(nic) = real_iface() else { return };
        let mut d = test_daemon();
        let mock = Arc::new(MockNet::default());
        d.netops = mock.clone();
        let idx = netcfg::ifindex_of(&nic).unwrap();
        let r = run_with(&d, Role::Admin, "net.set", &[&nic, "--ip", "10.77.0.2/24", "--gw", "10.77.0.1", "--confirm", "30", "--dns", "10.77.0.1"]).0;
        assert_eq!(r.status, Status::Ok, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(netcfg::current_addrs(&*mock, idx), vec![([10, 77, 0, 2], 24)]);
        assert_eq!(std::fs::read_to_string(&d.config.resolv_conf).unwrap(), "nameserver 10.77.0.1\n");
        assert!(d.net.pending_confirm());
        assert_eq!(run_with(&d, Role::Admin, "net.confirm", &[]).0.status, Status::Ok);
        let r = run_with(&d, Role::Admin, "net.vlan", &["add", &nic, "42", "--ip", "10.42.0.2/24"]).0;
        assert_eq!(r.status, Status::Ok, "{}", String::from_utf8_lossy(&r.body));
        assert!(String::from_utf8_lossy(&r.body).contains(".42"));
        assert_eq!(run_with(&d, Role::Admin, "net.vlan", &["add", &nic, "9999"]).0.status, Status::BadArgs);
        assert_eq!(run_with(&d, Role::Admin, "net.vlan", &["del", &nic, "42"]).0.status, Status::Ok);
        assert_eq!(run_with(&d, Role::Admin, "net.vlan", &["del", &nic, "42"]).0.status, Status::NotFound);
        assert_eq!(run_with(&d, Role::Admin, "net.set", &[&nic, "--ip", "224.0.0.1/24"]).0.status, Status::BadArgs);
        // --dhcp drops the static config and asks the net duty for a client
        assert_eq!(run_with(&d, Role::Admin, "net.set", &[&nic, "--dhcp"]).0.status, Status::Ok);
        assert!(netcfg::current_addrs(&*mock, idx).is_empty());
        assert_eq!(d.net.take_dhcp_wanted(), vec![nic.clone()]);
    }
}
