//! pci: /sys/bus/pci/devices walk, link speed/width, IOMMU groups, AER, BARs, capabilities. Owner: P3.

use labproto::json::{JsonWriter, ToJson};

use crate::ctx::{ProbeCtx, ProbeError};

#[derive(Clone, Debug, Default)]
pub struct PciOpts {
    /// adds BARs, capability list and config-space hex
    pub verbose: bool,
    pub filter_id: Option<(u16, u16)>,
    pub filter_class: Option<u8>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PcieLink {
    pub cur_gen: Option<u8>,
    pub cur_width: Option<u8>,
    pub max_gen: Option<u8>,
    pub max_width: Option<u8>,
    pub degraded: bool,
}

#[derive(Clone, Debug, Default)]
pub struct AerCounters {
    pub correctable: u64,
    pub nonfatal: u64,
    pub fatal: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Bar {
    pub index: u8,
    pub base: u64,
    pub size: u64,
    /// "mem32" | "mem64" | "io"
    pub kind: String,
    pub prefetch: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PciDevice {
    pub bdf: String,
    pub parent: Option<String>,
    pub vendor: u16,
    pub device: u16,
    pub subsys_vendor: u16,
    pub subsys_device: u16,
    pub class: u32,
    pub revision: u8,
    pub class_name: String,
    pub vendor_name: Option<String>,
    pub device_name: Option<String>,
    pub driver: Option<String>,
    pub link: Option<PcieLink>,
    pub iommu_group: Option<u32>,
    pub numa_node: Option<i32>,
    pub aer: Option<AerCounters>,
    pub bars: Vec<Bar>,
    pub caps: Vec<String>,
    pub config_hex: Option<String>,
}

/// What kind of network function a PCI device is (class 0x02xxxx only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NicKind {
    /// class 0x0200
    Ethernet,
    /// class 0x0280 (Network controller: Wi-Fi cards report this)
    Wifi,
    /// any other 0x02xxxx class (InfiniBand, token ring, ...)
    OtherNetwork,
}

impl NicKind {
    /// Stable JSON value of the `nic_kind` field.
    pub fn name(self) -> &'static str {
        match self {
            NicKind::Ethernet => "ethernet",
            NicKind::Wifi => "wifi",
            NicKind::OtherNetwork => "other-network",
        }
    }
}

impl PciDevice {
    /// `None` for anything that is not a network-class function.
    pub fn nic_kind(&self) -> Option<NicKind> {
        if self.class >> 16 != 0x02 {
            return None;
        }
        Some(match (self.class >> 8) & 0xff {
            0x00 => NicKind::Ethernet,
            0x80 => NicKind::Wifi,
            _ => NicKind::OtherNetwork,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct PciReport {
    pub iommu_enabled: bool,
    pub devices: Vec<PciDevice>,
}

impl PciReport {
    /// Network-class (0x02xxxx) functions with no bound driver: the "NO CONTROL PATH" banner in the TUI and the
    /// `attention` list (review feasibility F34).
    pub fn unbound_nics(&self) -> Vec<&PciDevice> {
        self.devices.iter().filter(|d| d.class >> 16 == 0x02 && d.driver.is_none()).collect()
    }

    /// Ethernet (class 0x0200) functions with no bound driver: these are the ones that matter for the control path.
    pub fn unbound_ethernet(&self) -> Vec<&PciDevice> {
        self.devices.iter().filter(|d| d.nic_kind() == Some(NicKind::Ethernet) && d.driver.is_none()).collect()
    }

    /// Wi-Fi (class 0x0280) functions with no bound driver. Expected on the lab image (no Wi-Fi drivers or
    /// firmware): informational, never a reason to say "this host cannot be reached".
    pub fn unbound_wifi(&self) -> Vec<&PciDevice> {
        self.devices.iter().filter(|d| d.nic_kind() == Some(NicKind::Wifi) && d.driver.is_none()).collect()
    }

    /// At least one Ethernet function has a bound driver and its interface (matched through the PCI address in
    /// `bus_info`) is up with carrier.
    pub fn control_path_available(&self, net: &crate::net::NetReport) -> bool {
        self.devices.iter().filter(|d| d.nic_kind() == Some(NicKind::Ethernet) && d.driver.is_some()).any(|d| {
            net.ifaces.iter().any(|i| {
                i.bus_info.as_deref() == Some(d.bdf.as_str()) && i.driver.is_some() && (i.carrier == Some(true) || i.operstate == "up")
            })
        })
    }
}

/// "8.0 GT/s PCIe" -> 3
pub fn parse_link_gen(s: &str) -> Option<u8> {
    let gts: f64 = s.split_whitespace().next()?.parse().ok()?;
    Some(match gts {
        x if x < 3.0 => 1,
        x if x < 6.0 => 2,
        x if x < 10.0 => 3,
        x if x < 20.0 => 4,
        x if x < 40.0 => 5,
        _ => 6,
    })
}

fn hex_u(s: Option<String>) -> u32 {
    s.and_then(|v| crate::ctx::parse_hex(&v)).unwrap_or(0) as u32
}

/// True for "0000:00:1c.0".
fn is_bdf(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 12
        && b[4] == b':'
        && b[7] == b':'
        && b[10] == b'.'
        && s.chars().enumerate().all(|(i, c)| matches!(i, 4 | 7 | 10) || c.is_ascii_hexdigit())
}

/// Upstream bridge from the canonical sysfs path: the BDF component before the device's own.
/// `/sys/devices/pci0000:00/0000:00:1c.0/0000:03:00.0` -> `0000:00:1c.0`; a root-complex device has none.
pub fn parent_from_path(real: &str) -> Option<String> {
    let segs: Vec<&str> = real.split('/').filter(|s| is_bdf(s)).collect();
    if segs.len() >= 2 {
        Some(segs[segs.len() - 2].to_string())
    } else {
        None
    }
}

/// Count line `TOTAL_ERR_*` of an `aer_dev_*` file.
pub fn parse_aer_total(text: &str) -> Option<u64> {
    text.lines().find(|l| l.starts_with("TOTAL_ERR_")).and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
}

/// The six BARs (the sysfs `resource` file: "start end flags" per line; the first six lines are BAR0..5).
pub fn parse_resource(text: &str) -> Vec<Bar> {
    let mut v = Vec::new();
    for (i, line) in text.lines().take(6).enumerate() {
        let f: Vec<u64> = line.split_whitespace().filter_map(|x| crate::ctx::parse_hex(x)).collect();
        if f.len() != 3 || (f[0] == 0 && f[1] == 0) {
            continue;
        }
        let (start, end, flags) = (f[0], f[1], f[2]);
        let kind = if flags & 0x100 != 0 {
            "io"
        } else if flags & 0x0010_0000 != 0 {
            "mem64"
        } else {
            "mem32"
        };
        v.push(Bar { index: i as u8, base: start, size: end.saturating_sub(start) + 1, kind: kind.into(), prefetch: flags & 0x2000 != 0 });
    }
    v
}

fn cap_name(id: u8) -> Option<&'static str> {
    Some(match id {
        0x01 => "PM",
        0x03 => "VPD",
        0x04 => "SlotID",
        0x05 => "MSI",
        0x07 => "PCI-X",
        0x09 => "Vendor",
        0x0c => "HotPlug",
        0x0d => "SubsysID",
        0x10 => "PCIe",
        0x11 => "MSI-X",
        0x12 => "SATA",
        0x13 => "AF",
        _ => return None,
    })
}

fn ecap_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x0001 => "AER",
        0x0002 => "VC",
        0x0003 => "DSN",
        0x0004 => "PowerBudget",
        0x0005 => "RCLink",
        0x000b => "VendorExt",
        0x000d => "ACS",
        0x000e => "ARI",
        0x000f => "ATS",
        0x0010 => "SR-IOV",
        0x0013 => "PRI",
        0x0015 => "ResizableBAR",
        0x0017 => "TPH",
        0x0018 => "LTR",
        0x0019 => "SecondaryPCIe",
        0x001d => "DPC",
        0x001e => "L1PM",
        0x001f => "PTM",
        0x0025 => "DataLinkFeature",
        0x0026 => "PhysLayer16GT",
        _ => return None,
    })
}

/// Names of the capabilities found by walking the capability lists of a config space dump (64 bytes give the
/// standard list; 256+ bytes reach the extended list at 0x100). Loops and out-of-range pointers end the walk.
pub fn parse_caps(cfg: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if cfg.len() >= 0x40 && cfg[6] & 0x10 != 0 {
        let mut p = cfg[0x34] as usize & !3;
        let mut guard = 0;
        while p >= 0x40 && p + 2 <= cfg.len() && guard < 48 {
            let id = cfg[p];
            out.push(cap_name(id).map(str::to_string).unwrap_or_else(|| format!("cap{:02x}", id)));
            p = cfg[p + 1] as usize & !3;
            guard += 1;
        }
    }
    if cfg.len() >= 0x104 {
        let mut p = 0x100usize;
        let mut guard = 0;
        while p >= 0x100 && p + 4 <= cfg.len() && guard < 96 {
            let h = u32::from_le_bytes([cfg[p], cfg[p + 1], cfg[p + 2], cfg[p + 3]]);
            if h == 0 || h == 0xffff_ffff {
                break;
            }
            let id = (h & 0xffff) as u16;
            out.push(ecap_name(id).map(str::to_string).unwrap_or_else(|| format!("ecap{:04x}", id)));
            p = ((h >> 20) & 0xffc) as usize;
            guard += 1;
        }
    }
    out
}

fn hex_string(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub fn probe(ctx: &ProbeCtx, opts: &PciOpts) -> Result<PciReport, ProbeError> {
    let mut rep = PciReport { iommu_enabled: ctx.list_dir("/sys/class/iommu").map(|v| !v.is_empty()).unwrap_or(false), devices: vec![] };
    for bdf in ctx.list_dir("/sys/bus/pci/devices")? {
        let base = format!("/sys/bus/pci/devices/{}", bdf);
        let r = |f: &str| ctx.read_opt(&format!("{}/{}", base, f));
        let mut d = PciDevice {
            vendor: hex_u(r("vendor")) as u16,
            device: hex_u(r("device")) as u16,
            subsys_vendor: hex_u(r("subsystem_vendor")) as u16,
            subsys_device: hex_u(r("subsystem_device")) as u16,
            class: hex_u(r("class")),
            revision: hex_u(r("revision")) as u8,
            bdf: bdf.clone(),
            ..Default::default()
        };
        d.class_name = crate::pciids::class_name(d.class).to_string();
        let (vn, dn) = crate::pciids::lookup(d.vendor, d.device);
        d.vendor_name = vn.map(str::to_string);
        d.device_name = dn.map(str::to_string);
        d.driver = ctx.link_name(&format!("{}/driver", base));
        d.parent = crate::block::enumerate::real_sys_path(ctx, &base).and_then(|p| parent_from_path(&p));
        d.iommu_group = ctx.link_name(&format!("{}/iommu_group", base)).and_then(|n| n.parse().ok());
        d.numa_node = r("numa_node").and_then(|n| n.parse::<i32>().ok()).filter(|n| *n >= 0);
        if let (Some(cs), Some(ms)) = (r("current_link_speed"), r("max_link_speed")) {
            // width 0 / 255 and "Unknown speed" come from functions that merely sit behind a link (RCiEP)
            let width = |f: &str| r(f).and_then(|x| x.parse::<u8>().ok()).filter(|w| *w != 0 && *w != 255);
            let (cg, mg) = (parse_link_gen(&cs), parse_link_gen(&ms));
            if cg.is_some() || mg.is_some() {
                d.link = Some(PcieLink { cur_gen: cg, cur_width: width("current_link_width"), max_gen: mg, max_width: width("max_link_width"), degraded: false });
            }
        }
        let aer = |f: &str| r(f).and_then(|t| parse_aer_total(&t));
        if let (Some(c), Some(n), Some(f)) = (aer("aer_dev_correctable"), aer("aer_dev_nonfatal"), aer("aer_dev_fatal")) {
            d.aer = Some(AerCounters { correctable: c, nonfatal: n, fatal: f });
        }
        if opts.verbose {
            d.bars = r("resource").map(|t| parse_resource(&t)).unwrap_or_default();
            let cfg_len = if ctx.privileged { 4096 } else { 256 };
            if let Ok(cfg) = ctx.read_bytes(&format!("{}/config", base), cfg_len) {
                d.caps = parse_caps(&cfg);
                d.config_hex = Some(hex_string(&cfg[..cfg.len().min(256)]));
            }
        }
        rep.devices.push(d);
    }
    mark_degraded(&mut rep.devices);
    rep.devices.retain(|d| {
        opts.filter_id.map(|(v, dv)| d.vendor == v && d.device == dv).unwrap_or(true) && opts.filter_class.map(|c| (d.class >> 16) as u8 == c).unwrap_or(true)
    });
    Ok(rep)
}

/// Set `PcieLink::degraded`: the link runs below what both ends support. A link is between a device and its
/// parent; a root port (no parent in the list) is judged against its downstream devices. Down-clocking of the
/// generation is normal for idle display adapters (and their root ports and audio functions), so only the width
/// counts there. A port with nothing attached reports no width and is never degraded.
fn mark_degraded(devs: &mut [PciDevice]) {
    let maxes: Vec<(String, Option<u8>, Option<u8>)> =
        devs.iter().map(|d| (d.bdf.clone(), d.link.as_ref().and_then(|l| l.max_gen), d.link.as_ref().and_then(|l| l.max_width))).collect();
    let find = |bdf: &str| maxes.iter().find(|m| m.0 == bdf).cloned();
    let slot = |bdf: &str| bdf.rsplit_once('.').map(|x| x.0.to_string()).unwrap_or_default();
    let display_slots: Vec<String> = devs.iter().filter(|d| d.class >> 16 == 0x03).map(|d| slot(&d.bdf)).collect();
    let display_bdfs: Vec<String> = devs.iter().filter(|d| d.class >> 16 == 0x03).map(|d| d.bdf.clone()).collect();
    let verdicts: Vec<bool> = devs
        .iter()
        .map(|d| {
            let Some(l) = &d.link else { return false };
            let (Some(cw), Some(mw)) = (l.cur_width, l.max_width) else { return false };
            let (mut eg, mut ew) = (l.max_gen, mw);
            let peers: Vec<(Option<u8>, Option<u8>)> = match &d.parent {
                Some(p) => find(p).map(|m| vec![(m.1, m.2)]).unwrap_or_default(),
                None => maxes.iter().zip(devs.iter()).filter(|(_, c)| c.parent.as_deref() == Some(d.bdf.as_str())).map(|(m, _)| (m.1, m.2)).collect(),
            };
            if d.parent.is_none() && peers.is_empty() {
                return false; // nothing below this port
            }
            if let Some(best_g) = peers.iter().filter_map(|p| p.0).max() {
                eg = eg.map(|g| g.min(best_g));
            }
            if let Some(best_w) = peers.iter().filter_map(|p| p.1).max() {
                ew = ew.min(best_w);
            }
            let gpu_related = d.class >> 16 == 0x03
                || display_slots.contains(&slot(&d.bdf))
                || devs.iter().any(|c| c.parent.as_deref() == Some(d.bdf.as_str()) && display_bdfs.contains(&c.bdf));
            let gen_down = !gpu_related && matches!((l.cur_gen, eg), (Some(c), Some(e)) if c < e);
            cw < ew || gen_down
        })
        .collect();
    for (d, v) in devs.iter_mut().zip(verdicts) {
        if let Some(l) = d.link.as_mut() {
            l.degraded = v;
        }
    }
}

impl ToJson for PciReport {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_u64("v", crate::SCHEMA_V);
        w.field_bool("iommu_enabled", self.iommu_enabled);
        w.key("devices");
        w.begin_array();
        for d in &self.devices {
            w.begin_object();
            w.field_str("bdf", &d.bdf);
            w.field_opt_str("parent", d.parent.as_deref());
            w.field_str("vendor", &format!("{:04x}", d.vendor));
            w.field_str("device", &format!("{:04x}", d.device));
            w.field_str("subsys_vendor", &format!("{:04x}", d.subsys_vendor));
            w.field_str("subsys_device", &format!("{:04x}", d.subsys_device));
            w.field_str("class", &format!("{:06x}", d.class));
            w.field_u64("revision", d.revision as u64);
            w.field_str("class_name", &d.class_name);
            w.field_opt_str("nic_kind", d.nic_kind().map(NicKind::name));
            w.field_opt_str("vendor_name", d.vendor_name.as_deref());
            w.field_opt_str("device_name", d.device_name.as_deref());
            w.field_opt_str("driver", d.driver.as_deref());
            w.key("link");
            match &d.link {
                None => w.null(),
                Some(l) => {
                    w.begin_object();
                    w.field_opt_u64("cur_gen", l.cur_gen.map(u64::from));
                    w.field_opt_u64("cur_width", l.cur_width.map(u64::from));
                    w.field_opt_u64("max_gen", l.max_gen.map(u64::from));
                    w.field_opt_u64("max_width", l.max_width.map(u64::from));
                    w.field_bool("degraded", l.degraded);
                    w.end_object();
                }
            }
            w.field_opt_u64("iommu_group", d.iommu_group.map(u64::from));
            w.key("numa_node");
            match d.numa_node {
                Some(n) => w.i64(n as i64),
                None => w.null(),
            }
            w.key("aer");
            match &d.aer {
                None => w.null(),
                Some(a) => {
                    w.begin_object();
                    w.field_u64("correctable", a.correctable);
                    w.field_u64("nonfatal", a.nonfatal);
                    w.field_u64("fatal", a.fatal);
                    w.end_object();
                }
            }
            w.key("bars");
            w.begin_array();
            for b in &d.bars {
                w.begin_object();
                w.field_u64("index", b.index as u64);
                w.field_u64("base", b.base);
                w.field_u64("size", b.size);
                w.field_str("kind", &b.kind);
                w.field_bool("prefetch", b.prefetch);
                w.end_object();
            }
            w.end_array();
            w.key("caps");
            w.value(&d.caps);
            w.field_opt_str("config_hex", d.config_hex.as_deref());
            w.end_object();
        }
        w.end_array();
        w.end_object();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parents() {
        assert_eq!(parent_from_path("/devices/pci0000:00/0000:00:1c.0/0000:03:00.0").as_deref(), Some("0000:00:1c.0"));
        assert_eq!(parent_from_path("/devices/pci0000:00/0000:00:1c.0"), None);
        assert_eq!(parent_from_path("/devices/pci0000:00/0000:00:01.1/0000:01:00.0/0000:02:03.0/0000:05:00.0").as_deref(), Some("0000:02:03.0"));
    }

    #[test]
    fn aer_and_bars() {
        assert_eq!(parse_aer_total("RxErr 0\nBadTLP 3\nTOTAL_ERR_COR 3\n"), Some(3));
        assert_eq!(parse_aer_total("nothing"), None);
        let bars = parse_resource(
            "0x00000000f6000000 0x00000000f6ffffff 0x0000000000040200\n\
             0x0000000000000000 0x0000000000000000 0x0000000000000000\n\
             0x00000000e0000000 0x00000000efffffff 0x000000000014220c\n\
             0x000000000000e000 0x000000000000e07f 0x0000000000040101\n",
        );
        assert_eq!(bars.len(), 3);
        assert_eq!((bars[0].index, bars[0].size, bars[0].kind.as_str(), bars[0].prefetch), (0, 16 << 20, "mem32", false));
        assert_eq!((bars[1].index, bars[1].size, bars[1].kind.as_str(), bars[1].prefetch), (2, 256 << 20, "mem64", true));
        assert_eq!((bars[2].index, bars[2].size, bars[2].kind.as_str()), (3, 128, "io"));
    }

    #[test]
    fn capability_walk() {
        let mut cfg = vec![0u8; 4096];
        cfg[6] = 0x10; // status: capabilities list
        cfg[0x34] = 0x40;
        cfg[0x40] = 0x01; // PM
        cfg[0x41] = 0x50;
        cfg[0x50] = 0x05; // MSI
        cfg[0x51] = 0x70;
        cfg[0x70] = 0x10; // PCIe
        cfg[0x71] = 0x00;
        // extended: AER at 0x100 -> next 0x150 (SR-IOV 0x10)
        cfg[0x100..0x104].copy_from_slice(&(0x0001u32 | 1 << 16 | 0x150 << 20).to_le_bytes());
        cfg[0x150..0x154].copy_from_slice(&(0x0010u32 | 1 << 16).to_le_bytes());
        assert_eq!(parse_caps(&cfg), ["PM", "MSI", "PCIe", "AER", "SR-IOV"]);
        // a pointer loop terminates
        cfg[0x71] = 0x40;
        assert!(parse_caps(&cfg).len() < 200);
        // 64-byte config (unprivileged read) still gives the standard list
        assert_eq!(parse_caps(&cfg[..64]), Vec::<String>::new());
        assert!(parse_caps(&[0u8; 10]).is_empty());
    }

    fn dev(bdf: &str, parent: Option<&str>, class: u32, cur: (u8, u8), max: (u8, u8)) -> PciDevice {
        PciDevice {
            bdf: bdf.into(),
            parent: parent.map(str::to_string),
            class,
            link: Some(PcieLink { cur_gen: Some(cur.0), cur_width: Some(cur.1), max_gen: Some(max.0), max_width: Some(max.1), degraded: false }),
            ..Default::default()
        }
    }

    #[test]
    fn degraded_compares_against_both_link_ends() {
        let mut v = vec![
            // root port gen4 x4 to a gen5 NVMe running at gen4 x4: optimal, not degraded
            dev("0000:00:06.0", None, 0x060400, (4, 4), (4, 4)),
            dev("0000:02:00.0", Some("0000:00:06.0"), 0x010802, (4, 4), (5, 4)),
            // root port gen3 to a gen2-only NIC at gen2: optimal
            dev("0000:00:1c.3", None, 0x060400, (2, 1), (3, 1)),
            dev("0000:05:00.0", Some("0000:00:1c.3"), 0x020000, (2, 1), (2, 1)),
            // gen3 x4 slot with a x4 gen3 device at x1: width loss is degraded
            dev("0000:00:1c.4", None, 0x060400, (3, 1), (3, 4)),
            dev("0000:06:00.0", Some("0000:00:1c.4"), 0x020000, (3, 1), (3, 4)),
            // GPU idling at gen1 plus its root port and audio function: not degraded
            dev("0000:00:01.0", None, 0x060400, (1, 16), (5, 16)),
            dev("0000:01:00.0", Some("0000:00:01.0"), 0x030000, (1, 16), (4, 16)),
            dev("0000:01:00.1", Some("0000:00:01.0"), 0x040300, (1, 16), (4, 16)),
            // empty root port: link down
            dev("0000:00:1c.0", None, 0x060400, (1, 1), (3, 1)),
        ];
        v[9].link.as_mut().unwrap().cur_width = Some(1);
        mark_degraded(&mut v);
        let flags: Vec<bool> = v.iter().map(|d| d.link.as_ref().unwrap().degraded).collect();
        assert_eq!(flags, [false, false, false, false, true, true, false, false, false, false], "{:?}", v.iter().map(|d| &d.bdf).collect::<Vec<_>>());
    }

    #[test]
    fn link_gen() {
        assert_eq!(super::parse_link_gen("8.0 GT/s PCIe"), Some(3));
        assert_eq!(super::parse_link_gen("2.5 GT/s"), Some(1));
        assert_eq!(super::parse_link_gen("Unknown"), None);
    }
}
