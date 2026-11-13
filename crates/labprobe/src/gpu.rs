//! gpu: display-class PCI functions joined with /sys/class/drm (connectors, boot VGA, amdgpu VRAM). Owner: P3.

use labproto::json::{JsonWriter, ToJson};

use crate::ctx::{ProbeCtx, ProbeError};
use crate::pci::{self, PciOpts};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Connector {
    /// "HDMI-A-1"
    pub name: String,
    /// "connected" | "disconnected" | "unknown"
    pub status: String,
    /// first (preferred) mode, e.g. "3840x1600"
    pub mode: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Gpu {
    pub bdf: String,
    pub vendor: u16,
    pub device: u16,
    pub vendor_name: Option<String>,
    pub device_name: Option<String>,
    pub class_name: String,
    pub driver: Option<String>,
    /// DRM card node ("card0") when a driver bound
    pub card: Option<String>,
    pub boot_vga: bool,
    /// amdgpu `mem_info_vram_total`
    pub vram_bytes: Option<u64>,
    pub connectors: Vec<Connector>,
}

#[derive(Clone, Debug, Default)]
pub struct GpuReport {
    pub gpus: Vec<Gpu>,
}

pub fn probe(ctx: &ProbeCtx) -> Result<GpuReport, ProbeError> {
    let pci = pci::probe(ctx, &PciOpts { filter_class: Some(0x03), ..Default::default() })?;
    let drm = ctx.list_dir("/sys/class/drm").unwrap_or_default();
    let mut rep = GpuReport::default();
    for d in pci.devices {
        let card = drm
            .iter()
            .find(|c| c.starts_with("card") && c[4..].bytes().all(|b| b.is_ascii_digit()) && ctx.link_name(&format!("/sys/class/drm/{}/device", c)).as_deref() == Some(d.bdf.as_str()))
            .cloned();
        let mut connectors = Vec::new();
        if let Some(c) = &card {
            let prefix = format!("{}-", c);
            for e in drm.iter().filter(|e| e.starts_with(&prefix)) {
                let base = format!("/sys/class/drm/{}", e);
                connectors.push(Connector {
                    name: e[prefix.len()..].to_string(),
                    status: ctx.read_opt(&format!("{}/status", base)).unwrap_or_else(|| "unknown".into()),
                    mode: ctx.read_trim(&format!("{}/modes", base)).ok().and_then(|m| m.lines().next().map(str::to_string)).filter(|m| !m.is_empty()),
                });
            }
        }
        let dev = format!("/sys/bus/pci/devices/{}", d.bdf);
        rep.gpus.push(Gpu {
            boot_vga: ctx.read_opt(&format!("{}/boot_vga", dev)).as_deref() == Some("1"),
            vram_bytes: ctx.read_opt(&format!("{}/mem_info_vram_total", dev)).and_then(|v| v.parse().ok()),
            bdf: d.bdf,
            vendor: d.vendor,
            device: d.device,
            vendor_name: d.vendor_name,
            device_name: d.device_name,
            class_name: d.class_name,
            driver: d.driver,
            card,
            connectors,
        });
    }
    Ok(rep)
}

impl ToJson for GpuReport {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_u64("v", crate::SCHEMA_V);
        w.key("gpus");
        w.begin_array();
        for g in &self.gpus {
            w.begin_object();
            w.field_str("bdf", &g.bdf);
            w.field_str("vendor", &format!("{:04x}", g.vendor));
            w.field_str("device", &format!("{:04x}", g.device));
            w.field_opt_str("vendor_name", g.vendor_name.as_deref());
            w.field_opt_str("device_name", g.device_name.as_deref());
            w.field_str("class_name", &g.class_name);
            w.field_opt_str("driver", g.driver.as_deref());
            w.field_opt_str("card", g.card.as_deref());
            w.field_bool("boot_vga", g.boot_vga);
            w.field_opt_u64("vram_bytes", g.vram_bytes);
            w.key("connectors");
            w.begin_array();
            for c in &g.connectors {
                w.begin_object();
                w.field_str("name", &c.name);
                w.field_str("status", &c.status);
                w.field_opt_str("mode", c.mode.as_deref());
                w.end_object();
            }
            w.end_array();
            w.end_object();
        }
        w.end_array();
        w.end_object();
    }
}
