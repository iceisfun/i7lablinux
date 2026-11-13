//! The System76 Darter Pro lab host (Core i5-1240P, coreboot) as a sysfs fixture: real PCI/USB ids and names, the
//! r8169 Ethernet, the unbound CNVi Wi-Fi, the kernel's dummy0/sit0. Values are those the live host reported
//! (subsystem ids only where known). Fixture generator is not kept: the tree is plain files.

use std::path::PathBuf;

use labprobe::pci::{self, NicKind};
use labprobe::{net, system, usb, ProbeCtx};
use labproto::json::to_json;

fn ctx() -> ProbeCtx {
    ProbeCtx::fixture(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/system76-darter-pro"))
}

fn dev<'a>(r: &'a pci::PciReport, bdf: &str) -> &'a pci::PciDevice {
    r.devices.iter().find(|d| d.bdf == bdf).unwrap_or_else(|| panic!("{} missing", bdf))
}

#[test]
fn pci_ids_are_read_from_the_0x_prefixed_sysfs_files() {
    let r = pci::probe(&ctx(), &pci::PciOpts::default()).unwrap();
    assert_eq!(r.devices.len(), 12);
    let id = |b: &str| {
        let d = dev(&r, b);
        (d.vendor, d.device)
    };
    assert_eq!(id("0000:00:14.3"), (0x8086, 0x51f0));
    assert_eq!(id("0000:2e:00.0"), (0x10ec, 0x8168));
    assert_eq!(id("0000:01:00.0"), (0x15b7, 0x5036));
    assert_eq!(id("0000:2d:00.0"), (0x1217, 0x8621));
    assert_eq!(id("0000:00:02.0"), (0x8086, 0x46a6));
    assert_eq!(id("0000:00:0d.0"), (0x8086, 0x461e));
    assert_eq!(id("0000:00:14.0"), (0x8086, 0x51ed));
    assert_eq!(id("0000:00:1f.3"), (0x8086, 0x51c8));
    assert_eq!(id("0000:00:00.0"), (0x8086, 0x4621));
    let wifi = dev(&r, "0000:00:14.3");
    assert_eq!((wifi.subsys_vendor, wifi.subsys_device, wifi.class), (0x8086, 0x0074, 0x028000));
    assert_eq!(dev(&r, "0000:00:00.0").subsys_vendor, 0x1558);
}

#[test]
fn pci_names_resolve_from_the_embedded_table() {
    let r = pci::probe(&ctx(), &pci::PciOpts::default()).unwrap();
    let names = |b: &str| (dev(&r, b).vendor_name.clone().unwrap(), dev(&r, b).device_name.clone());
    assert_eq!(names("0000:00:14.3"), ("Intel Corporation".to_string(), Some("Alder Lake PCH CNVi WiFi".to_string())));
    assert_eq!(names("0000:2e:00.0").1.as_deref(), Some("RTL8111/8168/8211/8411 PCI Express Gigabit Ethernet Controller"));
    assert_eq!(names("0000:01:00.0").0, "Sandisk Corp");
    assert!(names("0000:01:00.0").1.unwrap().contains("SN3000"));
    assert_eq!(names("0000:2d:00.0"), ("O2 Micro, Inc.".to_string(), Some("SD/MMC Card Reader Controller".to_string())));
    assert!(names("0000:00:02.0").1.unwrap().contains("Iris Xe"));
    assert!(names("0000:00:0d.0").1.unwrap().contains("Thunderbolt 4 USB"));
    assert!(names("0000:00:14.0").1.unwrap().contains("xHCI"));
    assert!(names("0000:00:1f.3").1.unwrap().contains("High Definition Audio"));
    assert!(names("0000:00:00.0").1.unwrap().contains("Host Bridge"));
    // an id the table does not know keeps its hex id and no device name
    let (v, d) = labprobe::pciids::lookup(0x8086, 0x464d);
    assert_eq!((v, d), (Some("Intel Corporation"), None));
}

#[test]
fn json_carries_hex_ids_and_the_nic_kind() {
    let r = pci::probe(&ctx(), &pci::PciOpts::default()).unwrap();
    let j = to_json(&r);
    assert!(j.contains("\"vendor\":\"8086\",\"device\":\"51f0\",\"subsys_vendor\":\"8086\",\"subsys_device\":\"0074\""), "{}", j);
    assert!(j.contains("\"nic_kind\":\"wifi\"") && j.contains("\"nic_kind\":\"ethernet\"") && j.contains("\"nic_kind\":null"), "{}", j);
}

#[test]
fn wifi_is_not_an_ethernet_problem() {
    let r = pci::probe(&ctx(), &pci::PciOpts::default()).unwrap();
    assert_eq!(dev(&r, "0000:00:14.3").nic_kind(), Some(NicKind::Wifi));
    assert_eq!(dev(&r, "0000:2e:00.0").nic_kind(), Some(NicKind::Ethernet));
    assert_eq!(dev(&r, "0000:01:00.0").nic_kind(), None);
    // the old function still lists every unbound network function (compatible), the new ones split them
    assert_eq!(r.unbound_nics().iter().map(|d| d.bdf.as_str()).collect::<Vec<_>>(), ["0000:00:14.3"]);
    assert!(r.unbound_ethernet().is_empty());
    assert_eq!(r.unbound_wifi().len(), 1);
    assert_eq!(dev(&r, "0000:2e:00.0").driver.as_deref(), Some("r8169"));
    assert_eq!(dev(&r, "0000:2e:00.0").parent.as_deref(), Some("0000:00:1c.7"));
}

#[test]
fn control_path_needs_a_bound_ethernet_with_link() {
    let c = ctx();
    let r = pci::probe(&c, &pci::PciOpts::default()).unwrap();
    let n = net::probe(&c).unwrap();
    assert!(r.control_path_available(&n));
    // link down: no control path
    let mut down = net::probe(&c).unwrap();
    for i in down.ifaces.iter_mut().filter(|i| i.name == "eth0") {
        i.operstate = "down".into();
        i.carrier = Some(false);
    }
    assert!(!r.control_path_available(&down));
    // driver unbound: no control path even though the interface list still says up
    let mut r2 = pci::probe(&c, &pci::PciOpts::default()).unwrap();
    r2.devices.iter_mut().find(|d| d.bdf == "0000:2e:00.0").unwrap().driver = None;
    assert!(!r2.control_path_available(&n));
    assert_eq!(r2.unbound_ethernet().len(), 1);
    // a working Wi-Fi alone does not count
    let mut r3 = pci::probe(&c, &pci::PciOpts::default()).unwrap();
    r3.devices.retain(|d| d.bdf != "0000:2e:00.0");
    assert!(!r3.control_path_available(&n));
}

#[test]
fn usb_ids_and_names() {
    let u = usb::probe(&ctx()).unwrap();
    let by = |p: &str| u.devices.iter().find(|d| d.path == p).unwrap();
    assert_eq!((by("usb3").vid, by("usb3").pid), (0x1d6b, 0x0002));
    assert_eq!(by("usb3").product_name.as_deref(), Some("2.0 root hub"));
    assert_eq!((by("usb4").vid, by("usb4").pid), (0x1d6b, 0x0003));
    assert_eq!((by("3-7").vid, by("3-7").pid), (0x04f2, 0xb6fb));
    assert_eq!(by("3-7").vendor_name.as_deref(), Some("Chicony Electronics Co., Ltd"));
    assert_eq!(by("3-10").vendor_name.as_deref(), Some("Intel Corp."));
    assert_eq!(by("3-10").product_name.as_deref(), Some("AX201 Bluetooth"));
    assert_eq!(by("3-10").manufacturer, None);
    let j = to_json(&u);
    assert!(j.contains("\"vid\":\"8087\",\"pid\":\"0026\""), "{}", j);
}

#[test]
fn uptime_is_present_in_the_system_report() {
    let s = system::probe(&ctx()).unwrap();
    assert!((s.uptime_s - 4321.98).abs() < 1e-6);
    assert!(to_json(&s).contains("\"uptime_s\":4321.98"));
}

#[test]
fn net_kinds_mark_the_kernel_devices() {
    let n = net::probe(&ctx()).unwrap();
    let kind = |name: &str| n.ifaces.iter().find(|i| i.name == name).unwrap().kind.clone();
    assert_eq!(kind("eth0"), "ethernet");
    assert_eq!(kind("dummy0"), "virtual/kernel");
    assert_eq!(kind("sit0"), "virtual/kernel");
    assert_eq!(n.ifaces.iter().find(|i| i.name == "eth0").unwrap().driver.as_deref(), Some("r8169"));
    assert!(to_json(&n).contains("\"kind\":\"virtual/kernel\""));
    for k in ["dummy0", "sit0", "tunl0", "ip6tnl0", "ip6gre0", "gre0", "gretap0", "erspan0", "ip_vti0", "ip6_vti0", "ifb1"] {
        assert!(net::is_kernel_default(k), "{}", k);
    }
    for k in ["eth0", "wlan0", "docker0", "br0", "veth1a2b", "wg0", "dummy", "dummy100", "tun0", "bond0"] {
        assert!(!net::is_kernel_default(k), "{}", k);
    }
}
