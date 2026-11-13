//! Non-Windows stand-ins so the pure logic builds, tests and even serves (without power control) on Linux.

use std::net::{Ipv4Addr, UdpSocket};
use std::sync::Arc;

use crate::beacon::Adapter;
use crate::power::PowerReq;
use crate::state::Shared;

pub fn hostname() -> String {
    std::env::var("HOSTNAME").ok().or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string())).unwrap_or_else(|| "unknown".into())
}

pub fn os_short() -> String {
    format!("{} (not Windows: stub)", std::env::consts::OS)
}

pub fn info_json() -> String {
    format!("{{\"stub\":true,\"os\":{},\"host\":{}}}", crate::evlog::json_str(std::env::consts::OS), crate::evlog::json_str(&hostname()))
}

pub fn sample_json() -> String {
    "{\"stub\":true}".into()
}

pub fn adapters() -> Vec<Adapter> {
    // the address the kernel would use towards a non-routable documentation address; nothing is sent
    let ip = UdpSocket::bind("0.0.0.0:0").and_then(|s| s.connect("192.0.2.1:9").map(|_| s)).and_then(|s| s.local_addr()).ok();
    match ip {
        Some(std::net::SocketAddr::V4(a)) if !a.ip().is_unspecified() => vec![Adapter { name: "stub".into(), mac: [0; 6], ip: *a.ip(), mask: Ipv4Addr::new(255, 255, 255, 0) }],
        _ => Vec::new(),
    }
}

pub fn power_supported() -> bool {
    false
}

pub fn power_action(_sh: &Arc<Shared>, _req: &PowerReq) -> Result<String, String> {
    Err("not Windows".into())
}

pub fn start_recorders(sh: &Arc<Shared>) {
    sh.emit("stub", "monitor_ready", "{\"note\":\"no power monitor on this OS\"}");
}

pub fn run_service() -> Result<(), String> {
    Err("`run` (service entry) only exists on Windows; use `console`".into())
}
