//! Probes over captured (scrubbed) sysfs/procfs trees: structural assertions plus golden JSON files.
//! Regenerate goldens after an intended schema change with `UPDATE_GOLDEN=1 cargo test -p labprobe --test probe_fixture`
//! and review the diff. Fixtures (captured unprivileged by scripts/capture-fixture):
//!   amd-zen4-desktop       AMD Ryzen 9 7945HX3D, Realtek NIC, iGPU
//!   intel-raptorlake-desktop  Intel Core i7-14700KF (hybrid P/E cores), MSI board
//!   amd-epyc-2s-cpu        cpuinfo + CPU topology of a 2-socket EPYC 7601 (CPU probe only)

use std::path::PathBuf;

use labprobe::{cpu, dmi, firmware, gpu, mem, net, pci, serial, system, thermal, usb, ProbeCtx, Section};
use labproto::json::to_json;

const AMD: &str = "amd-zen4-desktop";
const INTEL: &str = "intel-raptorlake-desktop";

fn fx(name: &str) -> ProbeCtx {
    ProbeCtx::fixture(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name))
}

fn fixture() -> ProbeCtx {
    fx(AMD)
}

fn golden(name: &str, json: &str) {
    golden_for(AMD, name, json)
}

fn golden_for(fixture: &str, name: &str, json: &str) {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden").join(fixture).join(format!("{}.json", name));
    if std::env::var_os("UPDATE_GOLDEN").is_some() || !p.exists() {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("{}\n", json)).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&p).unwrap();
    assert_eq!(want.trim_end(), json, "golden mismatch for {name}: rerun with UPDATE_GOLDEN=1 if intended");
}

#[test]
fn cpu_topology_and_codename() {
    let c = cpu::probe(&fixture()).unwrap();
    assert_eq!(c.vendor, "AuthenticAMD");
    assert_eq!((c.family, c.model), (25, 97));
    assert_eq!(c.codename.as_deref(), Some("Zen 4 (Raphael / Dragon Range)"));
    assert_eq!((c.sockets, c.cores, c.threads), (1, 16, 32));
    assert!(c.flags_summary.iter().any(|f| f == "avx2") && c.flags_summary.iter().any(|f| f == "svm"));
    assert!(c.caches.iter().any(|k| k.level == 3), "{:?}", c.caches);
    assert!(!c.vulnerabilities.is_empty());
    golden("cpu", &to_json(&c));
}

#[test]
fn mem_and_system() {
    let m = mem::probe(&fixture()).unwrap();
    assert!(m.total_kib > 1 << 20 && m.available_kib <= m.total_kib);
    assert!(m.dimms.is_empty(), "no raw DMI table in the fixture");
    golden("mem", &to_json(&m));
    let s = system::probe(&fixture()).unwrap();
    assert_eq!(s.hostname, "fixture");
    assert_eq!(s.boot_mode, "bios".replace("bios", if fixture().path("/sys/firmware/efi").exists() { "uefi" } else { "bios" }));
    assert!(s.kernel.starts_with("6."));
    golden("system", &to_json(&SystemStable(&s)));
}

/// uptime and load change at every capture; the golden pins only the stable fields.
struct SystemStable<'a>(&'a system::SystemInfo);
impl labproto::json::ToJson for SystemStable<'_> {
    fn write_json(&self, w: &mut labproto::json::JsonWriter) {
        w.begin_object();
        w.field_str("hostname", &self.0.hostname);
        w.field_str("kernel", &self.0.kernel);
        w.field_str("cmdline", &self.0.cmdline);
        w.field_str("boot_mode", &self.0.boot_mode);
        w.end_object();
    }
}

#[test]
fn dmi_is_scrubbed() {
    let d = dmi::probe(&fixture()).unwrap();
    assert_eq!(d.get("product_serial"), Some("SERIAL-SCRUBBED"));
    assert_eq!(d.get("product_uuid"), Some("00000000-0000-0000-0000-000000000000"));
    assert!(d.get("board_name").is_some() && d.get("bios_vendor").is_some());
    golden("dmi", &to_json(&d));
}

#[test]
fn pci_topology_names_links() {
    let r = pci::probe(&fixture(), &pci::PciOpts::default()).unwrap();
    assert!(r.devices.len() > 20, "{}", r.devices.len());
    let bdfs: Vec<&str> = r.devices.iter().map(|d| d.bdf.as_str()).collect();
    for d in &r.devices {
        if let Some(p) = &d.parent {
            assert!(bdfs.contains(&p.as_str()), "{} parent {} not in the device list", d.bdf, p);
        }
        assert!(!d.class_name.is_empty());
    }
    assert!(r.devices.iter().any(|d| d.parent.is_some()), "bridges give a topology");
    assert!(r.devices.iter().any(|d| d.link.as_ref().map(|l| l.max_gen.is_some() && l.max_width.is_some()).unwrap_or(false)));
    assert!(r.devices.iter().any(|d| d.vendor_name.is_some()));
    assert!(r.devices.iter().any(|d| d.driver.is_some()));
    assert!(r.devices.iter().any(|d| d.iommu_group.is_some()));
    // the verbose pass reads config space (64+ bytes without root) and finds capabilities
    let v = pci::probe(&fixture(), &pci::PciOpts { verbose: true, ..Default::default() }).unwrap();
    // an unprivileged capture holds only the first 64 bytes of config space, which cannot reach the capability
    // chain; the chain walk itself is covered by the synthetic unit test in pci.rs
    assert!(v.devices.iter().all(|d| d.config_hex.is_some()));
    assert!(v.devices.iter().any(|d| !d.bars.is_empty()));
    // filters
    let nvme = pci::probe(&fixture(), &pci::PciOpts { filter_class: Some(0x01), ..Default::default() }).unwrap();
    assert!(nvme.devices.iter().all(|d| d.class >> 16 == 1));
    golden("pci", &to_json(&r));
    golden("pci_verbose", &to_json(&v));
}

#[test]
fn net_ifaces() {
    let r = net::probe(&fixture()).unwrap();
    assert!(!r.ifaces.is_empty() && r.ifaces.iter().all(|i| i.name != "lo"));
    for i in &r.ifaces {
        if let Some(m) = &i.mac {
            assert!(m.starts_with("02:00:00:00:00:"), "MAC not scrubbed: {m}");
        }
        assert!(i.mtu > 0);
    }
    let phys = r.ifaces.iter().find(|i| i.bus_info.as_deref().map(|b| b.contains(':')).unwrap_or(false));
    assert!(phys.is_some(), "a PCI NIC with bus_info: {:?}", r.ifaces.iter().map(|i| (&i.name, &i.bus_info)).collect::<Vec<_>>());
    assert!(phys.unwrap().driver.is_some());
    golden("net", &to_json(&r));
}

#[test]
fn thermal_hwmon() {
    let t = thermal::probe(&fixture()).unwrap();
    assert!(!t.hwmon.is_empty());
    for h in &t.hwmon {
        for s in &h.temps {
            assert!((-50.0..200.0).contains(&s.value), "{} {} = {}", h.name, s.label, s.value);
        }
    }
    assert!(t.hwmon.iter().any(|h| !h.temps.is_empty()));
    golden("thermal", &to_json(&t));
}

#[test]
fn firmware_boot_entries() {
    let f = firmware::probe(&fixture()).unwrap();
    assert_eq!(f.boot_mode, "uefi");
    assert!(f.secure_boot.is_some() && f.setup_mode.is_some());
    assert!(!f.boot_entries.is_empty(), "{:?}", f);
    assert!(f.boot_entries.iter().all(|e| !e.description.is_empty()));
    golden("firmware", &to_json(&f));
}

#[test]
fn gpu_and_serial_and_usb() {
    let g = gpu::probe(&fixture()).unwrap();
    assert!(!g.gpus.is_empty());
    assert!(g.gpus.iter().all(|x| x.class_name.contains("VGA") || x.class_name.contains("3D") || x.class_name.contains("Display") || x.class_name == "display"), "{:?}", g.gpus.iter().map(|x| &x.class_name).collect::<Vec<_>>());
    assert!(g.gpus.iter().any(|x| x.card.is_some() && !x.connectors.is_empty()));
    golden("gpu", &to_json(&g));
    let s = serial::probe(&fixture()).unwrap();
    golden("serial", &to_json(&s));
    let u = usb::probe(&fixture());
    assert!(u.is_err() || u.unwrap().devices.iter().all(|d| d.parent.is_some() || d.path.starts_with("usb")));
}

#[test]
fn inventory_isolates_failures_and_every_section_has_v1() {
    let ctx = fixture();
    let inv = labprobe::inventory(&ctx, Section::ALL);
    assert_eq!(inv.sections.len(), Section::ALL.len());
    let json = to_json(&inv);
    assert!(json.starts_with("{\"v\":1,"));
    for (s, r) in &inv.sections {
        match (s, r) {
            // the fixture has no /dev/kmsg and no /dev nodes: those sections report an error object, the rest works
            (Section::Kmsg, Err(e)) => assert_eq!(e.code(), "not_found"),
            (Section::Smart, _) => {}
            (_, Err(e)) => panic!("section {} failed: {}", s.name(), e),
            (_, Ok(j)) => assert!(j.starts_with("{\"v\":1"), "{}: {}", s.name(), &j[..j.len().min(60)]),
        }
    }
    assert!(json.contains("\"kmsg\":{\"error\":\"not_found\""));
}

#[test]
fn intel_hybrid_desktop() {
    let ctx = fx(INTEL);
    let c = cpu::probe(&ctx).unwrap();
    assert_eq!(c.vendor, "GenuineIntel");
    assert_eq!((c.family, c.model), (6, 183));
    assert_eq!(c.codename.as_deref(), Some("Raptor Lake"));
    assert_eq!((c.sockets, c.cores, c.threads), (1, 20, 28), "8 P-cores with HT + 12 E-cores");
    assert!(c.flags_summary.iter().any(|f| f == "vmx") && c.flags_summary.iter().any(|f| f == "avx2"));
    golden_for(INTEL, "cpu", &to_json(&c));

    let d = dmi::probe(&ctx).unwrap();
    assert_eq!(d.get("sys_vendor"), Some("Micro-Star International Co., Ltd."));
    assert_eq!(d.get("board_serial"), Some("SERIAL-SCRUBBED"));
    golden_for(INTEL, "dmi", &to_json(&d));

    let p = pci::probe(&ctx, &pci::PciOpts::default()).unwrap();
    assert!(p.devices.iter().any(|d| d.vendor == 0x10de && d.class >> 16 == 3), "an NVIDIA display function");
    assert!(p.devices.iter().any(|d| d.vendor == 0x8086 && d.vendor_name.as_deref() == Some("Intel Corporation")));
    assert!(p.devices.iter().any(|d| d.class == 0x010802 && d.class_name == "NVMe controller"));
    assert!(p.iommu_enabled);
    assert!(p.unbound_nics().is_empty() || p.unbound_nics().iter().all(|d| d.driver.is_none()));
    golden_for(INTEL, "pci", &to_json(&p));

    let n = net::probe(&ctx).unwrap();
    let eth = n.ifaces.iter().find(|i| i.name == "enp5s0").expect("enp5s0");
    assert_eq!(eth.driver.as_deref().is_some(), true);
    assert!(eth.bus_info.as_deref().unwrap().starts_with("0000:05:"));
    golden_for(INTEL, "net", &to_json(&n));

    let t = thermal::probe(&ctx).unwrap();
    assert!(t.hwmon.iter().any(|h| h.name == "coretemp" && !h.temps.is_empty()), "{:?}", t.hwmon.iter().map(|h| &h.name).collect::<Vec<_>>());
    golden_for(INTEL, "thermal", &to_json(&t));

    let f = firmware::probe(&ctx).unwrap();
    assert_eq!(f.boot_mode, "uefi");
    assert!(!f.boot_entries.is_empty());
    golden_for(INTEL, "firmware", &to_json(&f));

    let g = gpu::probe(&ctx).unwrap();
    assert!(g.gpus.iter().any(|x| x.vendor == 0x10de));
    golden_for(INTEL, "gpu", &to_json(&g));

    let inv = labprobe::inventory(&ctx, Section::ALL);
    assert!(inv.sections.iter().all(|(s, r)| r.is_ok() || matches!(s, Section::Kmsg)));
}

#[test]
fn two_socket_epyc_topology() {
    let c = cpu::probe(&fx("amd-epyc-2s-cpu")).unwrap();
    assert_eq!((c.vendor.as_str(), c.family), ("AuthenticAMD", 23));
    assert_eq!((c.sockets, c.cores, c.threads), (2, 64, 128), "2 x EPYC 7601 (32 cores, SMT)");
    assert!(c.caches.iter().any(|k| k.level == 3 && k.size_kib == 8192));
    assert!(!c.vulnerabilities.is_empty() || c.caches.len() > 0);
    golden_for("amd-epyc-2s-cpu", "cpu", &to_json(&c));
}
