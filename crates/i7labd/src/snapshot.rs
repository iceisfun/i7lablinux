//! The 2 s snapshot thread (review F8): one place that reads the hardware for the overview, so the console TUI,
//! SSE and the beacon never probe on their own. Cheap sections refresh every round, disk and PCIe every 30 s
//! (block detection reads device heads). Owner: P6a.

use std::sync::Arc;
use std::time::{Duration, Instant};

use labproto::json::JsonWriter;
use labprobe::{inventory, Section};

use crate::daemon::Daemon;
use crate::events::Snapshot;

pub const FAST: &[Section] = &[Section::System, Section::Cpu, Section::Mem, Section::Thermal, Section::Net];
pub const SLOW: &[Section] = &[Section::Block, Section::Pci];

fn merge(w: &mut JsonWriter, inv: &labprobe::Inventory) {
    for (s, r) in &inv.sections {
        w.key(s.name());
        match r {
            Ok(j) => w.raw(j),
            Err(e) => {
                w.begin_object();
                w.field_str("error", e.code());
                w.field_str("message", &e.to_string());
                w.end_object();
            }
        }
    }
}

/// Overview JSON from two inventories (fast + slow part) plus agent facts.
pub fn overview(d: &Daemon, fast: &labprobe::Inventory, slow: &labprobe::Inventory, taken_ms: u64) -> String {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_u64("v", 1);
    w.field_u64("taken_ms", taken_ms);
    w.field_str("hostname", &d.config.hostname);
    w.field_str("state", &d.state_str());
    w.field_str("build", &d.config.image_build);
    w.field_str("kid", &d.kid());
    w.field_bool("demo_keys", d.policy.demo);
    w.field_bool("vm", d.policy.vm);
    merge(&mut w, fast);
    merge(&mut w, slow);
    w.end_object();
    w.finish()
}

/// Strings for the console banner and SPA header, most severe first.
pub fn attention(d: &Daemon, net: &[crate::beacon::Nic], pci_json: Option<&str>) -> Vec<String> {
    let mut v = Vec::new();
    if let Some(b) = d.policy.banner() {
        v.push(b.to_string());
    }
    if d.keys.read().unwrap().admin.is_none() {
        v.push("NO ADMIN KEY: the host cannot be controlled (bake keys with scripts/bake-keys)".into());
    }
    if !net.iter().any(|n| n.carrier) {
        v.push("NO CARRIER on any Ethernet port".into());
    } else if !net.iter().any(|n| n.carrier && n.ipv4.is_some()) {
        v.push("no IPv4 address yet (L2 control works without one)".into());
    }
    if let Some(j) = pci_json {
        // labprobe pci JSON: unbound class-02 devices are the "NO CONTROL PATH" case
        if j.contains("\"class_name\":\"Ethernet controller\"") && j.contains("\"driver\":null") {
            v.push("an Ethernet controller has no driver bound: no control path through it".into());
        }
    }
    v
}

pub fn build(d: &Daemon, nics: &mut dyn crate::beacon::Nics, slow: &labprobe::Inventory, started: Instant) -> Snapshot {
    let fast = inventory(&d.probe, FAST);
    let taken_ms = started.elapsed().as_millis() as u64;
    let list = nics.list();
    let pci = slow.sections.iter().find(|(s, _)| *s == Section::Pci).and_then(|(_, r)| r.as_ref().ok().cloned());
    let sessions = d.sessions_open.load(std::sync::atomic::Ordering::Relaxed);
    Snapshot {
        taken_ms,
        overview_json: overview(d, &fast, slow, taken_ms),
        attention: attention(d, &list, pci.as_deref()),
        state: d.state_str(),
        links: list.iter().map(|n| (n.name.clone(), n.mac.to_string(), n.ipv4.iter().cloned().collect())).collect(),
        sessions: if sessions > 0 { vec![format!("{} ether session(s)", sessions)] } else { vec![] },
        stats_json: d.stats.to_json(sessions),
    }
}

pub fn run(d: Arc<Daemon>) -> std::io::Result<()> {
    let started = Instant::now();
    let names = labproto::packet::ethernet_ifaces().unwrap_or_default();
    let mut nics = crate::beacon::SysNics { names };
    let mut slow = inventory(&d.probe, SLOW);
    let mut slow_at = Instant::now();
    loop {
        if slow_at.elapsed() > Duration::from_secs(30) {
            slow = inventory(&d.probe, SLOW);
            slow_at = Instant::now();
        }
        nics.names = labproto::packet::ethernet_ifaces().unwrap_or_default();
        d.snapshot.set(build(&d, &mut nics, &slow, started));
        std::thread::sleep(Duration::from_secs(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::{Nic, StaticNics};
    use crate::registry::tests_support::test_daemon;
    use labproto::Mac;

    #[test]
    fn overview_is_valid_json_with_sections() {
        let d = test_daemon();
        let fast = inventory(&d.probe, &[Section::System]);
        let slow = inventory(&d.probe, &[]);
        let j = overview(&d, &fast, &slow, 5);
        assert!(j.starts_with("{\"v\":1,\"taken_ms\":5,\"hostname\":\"i7lab\"") && j.contains("\"system\":{"), "{}", &j[..j.len().min(200)]);
    }

    #[test]
    fn attention_lists_missing_things() {
        let d = test_daemon();
        let up = Nic { name: "eth0".into(), ifindex: 2, mac: Mac([2, 0, 0, 0, 0, 1]), carrier: true, operstate: "up".into(), ipv4: None, vlan: 0 };
        let a = attention(&d, &[up.clone()], None);
        assert!(a.iter().any(|s| s.contains("NO ADMIN KEY")) && a.iter().any(|s| s.contains("no IPv4")));
        assert!(attention(&d, &[], None).iter().any(|s| s.contains("NO CARRIER")));
        let snap = build(&d, &mut StaticNics(vec![up]), &inventory(&d.probe, &[]), Instant::now());
        assert_eq!(snap.links.len(), 1);
        assert!(snap.stats_json.contains("\"frames_rx\""));
    }
}
