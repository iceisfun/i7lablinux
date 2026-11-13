//! What the pages show: one immutable `ViewData` assembled by the data thread from labprobe reports (plus a few
//! host facts) and handed to the UI as an `Arc`. Probes never run on the render thread. Owner: P5.

use std::collections::HashMap;

use labprobe::block::{smart::SmartAll, test::Progress, BlockReport};
use labprobe::cpu::CpuInfo;
use labprobe::dmi::DmiInfo;
use labprobe::firmware::FirmwareInfo;
use labprobe::kmsg::KmsgReport;
use labprobe::mem::MemInfo;
use labprobe::net::NetReport;
use labprobe::pci::{NicKind, PciReport};
use labprobe::system::SystemInfo;
use labprobe::thermal::ThermalReport;
use labprobe::usb::UsbReport;

/// Facts about this host and the lab software that are not hardware probes.
#[derive(Clone, Debug, Default)]
pub struct Identity {
    /// `0.1.0`
    pub version: String,
    pub build_id: Option<String>,
    /// overrides `SystemInfo::hostname` when set
    pub hostname: String,
    /// addresses of the control interfaces, first one is shown in the header
    pub ips: Vec<String>,
    pub mac: Option<String>,
    /// `key_summary()` of the daemon: roles + fingerprints, never key material
    pub key_summary: String,
    /// red banners: `NO KEYS: ...` (the host decides the wording)
    pub banners: Vec<String>,
    /// `i7lab.console=locked`: the TUI is read-only and cannot open a shell
    pub console_locked: bool,
}

/// A running block test (read-only in v0.1) shown on the Storage page.
#[derive(Clone, Debug)]
pub struct TestView {
    pub dev: String,
    /// "read" | "write" | "verify"
    pub mode: String,
    pub progress: Progress,
    pub errors: u64,
    /// latency histogram: (bucket label, count)
    pub latency: Vec<(String, u64)>,
}

#[derive(Clone, Debug, Default)]
pub struct ViewData {
    pub identity: Identity,
    pub system: Option<SystemInfo>,
    pub cpu: Option<CpuInfo>,
    pub mem: Option<MemInfo>,
    pub dmi: Option<DmiInfo>,
    pub pci: Option<PciReport>,
    pub usb: Option<UsbReport>,
    pub block: Option<BlockReport>,
    pub net: Option<NetReport>,
    pub thermal: Option<ThermalReport>,
    pub firmware: Option<FirmwareInfo>,
    pub smart: Option<SmartAll>,
    pub kmsg: Option<KmsgReport>,
    /// last audit entries, oldest first (`who did what`)
    pub audit: Vec<String>,
    /// sample history for sparklines, oldest first: `temp:<hwmon>/<label>`, `rx:<iface>`, `tx:<iface>` (bytes/s)
    pub series: HashMap<String, Vec<f32>>,
    /// extra attention lines supplied by the daemon (job failures, watchdog ...)
    pub extra_attention: Vec<String>,
    pub test: Option<TestView>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Bad,
    Warn,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attention {
    pub severity: Severity,
    pub text: String,
}

impl ViewData {
    pub fn hostname(&self) -> &str {
        if !self.identity.hostname.is_empty() {
            &self.identity.hostname
        } else {
            self.system.as_ref().map(|s| s.hostname.as_str()).filter(|h| !h.is_empty()).unwrap_or("?")
        }
    }

    /// Items that need an operator's eye, worst first (Overview, key bar counter).
    pub fn attention(&self) -> Vec<Attention> {
        let mut v: Vec<Attention> = Vec::new();
        let mut add = |severity, text: String| v.push(Attention { severity, text });
        if let Some(pci) = &self.pci {
            for d in &pci.devices {
                if let Some(l) = &d.link {
                    if l.degraded {
                        add(Severity::Warn, format!("PCIe {} link degraded: {}", d.bdf, crate::fmt::pcie_link(l)));
                    }
                }
                if let Some(a) = &d.aer {
                    if a.fatal > 0 {
                        add(Severity::Bad, format!("PCIe {} AER fatal errors: {}", d.bdf, a.fatal));
                    } else if a.nonfatal > 0 {
                        add(Severity::Warn, format!("PCIe {} AER non-fatal errors: {}", d.bdf, a.nonfatal));
                    } else if a.correctable > 0 {
                        add(Severity::Warn, format!("PCIe {} AER correctable errors: {}", d.bdf, a.correctable));
                    }
                }
            }
            for d in pci.unbound_ethernet() {
                add(Severity::Bad, format!("NIC {} has no driver ({})", d.bdf, d.device_name.as_deref().unwrap_or("unknown")));
            }
            for d in pci.unbound_wifi() {
                add(
                    Severity::Warn,
                    format!(
                        "Wi-Fi adapter {} ({:04x}:{:04x}) has no Linux driver bound in this image",
                        d.device_name.as_deref().unwrap_or("unknown"),
                        d.vendor,
                        d.device
                    ),
                );
            }
        }
        if let Some(s) = &self.smart {
            for r in &s.devices {
                match r.verdict.as_str() {
                    "fail" => add(Severity::Bad, format!("SMART {}: FAIL {}", r.dev, r.reasons.join("; "))),
                    "warn" => add(Severity::Warn, format!("SMART {}: warning {}", r.dev, r.reasons.join("; "))),
                    _ => {}
                }
            }
        }
        if let Some(t) = &self.thermal {
            for h in &t.hwmon {
                for s in &h.temps {
                    if s.crit.map(|c| s.value >= c).unwrap_or(false) {
                        add(Severity::Bad, format!("{} {} at {:.0} C (critical)", h.name, s.label, s.value));
                    } else if s.max.map(|m| s.value >= m).unwrap_or(false) {
                        add(Severity::Warn, format!("{} {} at {:.0} C (over max)", h.name, s.label, s.value));
                    }
                }
            }
            for a in &t.alarms {
                add(Severity::Warn, format!("thermal alarm: {}", a));
            }
        }
        if let Some(m) = &self.mem {
            for e in &m.edac {
                if e.ue_count > 0 {
                    add(Severity::Bad, format!("memory {}: {} uncorrectable ECC errors", e.name, e.ue_count));
                } else if e.ce_count > 0 {
                    add(Severity::Warn, format!("memory {}: {} corrected ECC errors", e.name, e.ce_count));
                }
            }
        }
        if let Some(k) = &self.kmsg {
            let mut tags: Vec<(String, usize)> = Vec::new();
            for l in &k.lines {
                for t in &l.tags {
                    match tags.iter_mut().find(|(n, _)| n == t) {
                        Some(e) => e.1 += 1,
                        None => tags.push((t.clone(), 1)),
                    }
                }
            }
            for (t, n) in tags {
                add(Severity::Warn, format!("kernel log: {} x {}", n, t));
            }
        }
        for e in &self.extra_attention {
            add(Severity::Warn, e.clone());
        }
        v.sort_by_key(|a| a.severity);
        v
    }

    /// F34: the host has PCI NICs but no Ethernet works as the control path (bound driver, link up). Unbound Wi-Fi
    /// alone never raises this when Ethernet is usable; it is a warning line in `attention()`.
    pub fn no_control_path(&self) -> Option<String> {
        let pci = self.pci.as_ref()?;
        if !pci.devices.iter().any(|d| matches!(d.nic_kind(), Some(NicKind::Ethernet) | Some(NicKind::Wifi))) {
            return None;
        }
        let empty = labprobe::net::NetReport::default();
        if pci.control_path_available(self.net.as_ref().unwrap_or(&empty)) {
            return None;
        }
        let unbound = pci.unbound_ethernet();
        if unbound.is_empty() {
            return Some("NO CONTROL PATH: no Ethernet with a bound driver and link up".into());
        }
        let names: Vec<String> = unbound.iter().map(|d| format!("{} {}", d.bdf, d.device_name.as_deref().unwrap_or("?"))).collect();
        Some(format!("NO CONTROL PATH: no NIC driver for {}", names.join(", ")))
    }

    /// Banners for the red strip under the tab bar: host supplied ones plus the computed no-control-path one.
    pub fn banners(&self) -> Vec<String> {
        let mut b = self.identity.banners.clone();
        b.extend(self.no_control_path());
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use labprobe::net::{NetIface, NetReport};
    use labprobe::pci::{AerCounters, NicKind, PciDevice, PcieLink};

    #[test]
    fn attention_collects_and_sorts() {
        let mut d = ViewData::default();
        d.pci = Some(PciReport {
            iommu_enabled: true,
            devices: vec![
                PciDevice {
                    bdf: "0000:01:00.0".into(),
                    link: Some(PcieLink { cur_gen: Some(1), cur_width: Some(1), max_gen: Some(3), max_width: Some(4), degraded: true }),
                    ..Default::default()
                },
                PciDevice { bdf: "0000:02:00.0".into(), aer: Some(AerCounters { correctable: 0, nonfatal: 0, fatal: 2 }), ..Default::default() },
                PciDevice { bdf: "0000:03:00.0".into(), class: 0x020000, device_name: Some("RTL8126".into()), ..Default::default() },
            ],
        });
        d.extra_attention.push("watchdog off".into());
        let a = d.attention();
        assert_eq!(a.len(), 4);
        assert_eq!(a[0].severity, Severity::Bad);
        assert!(a.iter().any(|x| x.text.contains("degraded")));
        assert_eq!(a.last().unwrap().text, "watchdog off");
        assert!(d.no_control_path().unwrap().contains("RTL8126"));
        assert_eq!(d.banners().len(), 1);
    }
    fn darter(eth_up: bool, eth_driver: bool) -> ViewData {
        let mut d = ViewData::default();
        d.pci = Some(PciReport {
            iommu_enabled: true,
            devices: vec![
                PciDevice { bdf: "0000:00:14.3".into(), vendor: 0x8086, device: 0x51f0, class: 0x028000, device_name: Some("Alder Lake PCH CNVi WiFi".into()), ..Default::default() },
                PciDevice {
                    bdf: "0000:2e:00.0".into(),
                    vendor: 0x10ec,
                    device: 0x8168,
                    class: 0x020000,
                    device_name: Some("RTL8111/8168".into()),
                    driver: eth_driver.then(|| "r8169".to_string()),
                    ..Default::default()
                },
            ],
        });
        d.net = Some(NetReport {
            ifaces: vec![NetIface {
                name: "enp46s0".into(),
                driver: Some("r8169".into()),
                bus_info: Some("0000:2e:00.0".into()),
                operstate: if eth_up { "up".into() } else { "down".into() },
                carrier: Some(eth_up),
                ..Default::default()
            }],
            ..Default::default()
        });
        d
    }

    #[test]
    fn unbound_wifi_is_a_warning_and_no_banner_with_working_ethernet() {
        let d = darter(true, true);
        assert_eq!(d.pci.as_ref().unwrap().devices[0].nic_kind(), Some(NicKind::Wifi));
        let a = d.attention();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].severity, Severity::Warn);
        assert!(a[0].text.contains("Wi-Fi adapter Alder Lake PCH CNVi WiFi (8086:51f0) has no Linux driver bound in this image"), "{}", a[0].text);
        assert!(!a[0].text.contains("control traffic"));
        assert!(d.no_control_path().is_none());
        assert!(d.banners().is_empty());
    }

    #[test]
    fn ethernet_without_link_raises_banner_and_unbound_ethernet_is_bad() {
        let d = darter(false, true);
        assert!(d.no_control_path().unwrap().contains("no Ethernet"));
        let d = darter(true, false);
        assert!(d.attention().iter().any(|a| a.severity == Severity::Bad && a.text.contains("0000:2e:00.0 has no driver")));
        assert!(d.no_control_path().unwrap().contains("0000:2e:00.0"));
    }

    #[test]
    fn hostname_fallback() {
        let mut d = ViewData::default();
        assert_eq!(d.hostname(), "?");
        d.system = Some(SystemInfo { hostname: "a".into(), ..Default::default() });
        assert_eq!(d.hostname(), "a");
        d.identity.hostname = "b".into();
        assert_eq!(d.hostname(), "b");
    }
}
