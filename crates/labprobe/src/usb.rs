//! usb: /sys/bus/usb/devices walk. Owner: P3.

use labproto::json::{JsonWriter, ToJson};

use crate::ctx::{ProbeCtx, ProbeError};

#[derive(Clone, Debug, Default)]
pub struct UsbDevice {
    /// sysfs name, e.g. "1-2.3"; root hubs "usb1"
    pub path: String,
    pub parent: Option<String>,
    pub busnum: u32,
    pub devnum: u32,
    pub vid: u16,
    pub pid: u16,
    /// names from the embedded id table (`usbids`); `None` for ids it does not know
    pub vendor_name: Option<String>,
    pub product_name: Option<String>,
    pub class: u8,
    pub speed_mbps: Option<u32>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    /// interface drivers (e.g. "usb-storage", "xhci_hcd" for a root hub)
    pub drivers: Vec<String>,
    /// USB spec version of the device ("2.00", "3.10")
    pub version: Option<String>,
    /// name of the device class, or of the first interface's class when the device class is 0
    pub class_name: String,
}

#[derive(Clone, Debug, Default)]
pub struct UsbReport {
    pub devices: Vec<UsbDevice>,
}

/// Parent in the USB tree from the sysfs name: "1-2.3" -> "1-2", "1-2" -> "usb1", "usb1" -> none.
pub fn parent_of(name: &str) -> Option<String> {
    if name.starts_with("usb") {
        return None;
    }
    let (bus, rest) = name.split_once('-')?;
    match rest.rsplit_once('.') {
        Some((head, _)) => Some(format!("{}-{}", bus, head)),
        None => Some(format!("usb{}", bus)),
    }
}

/// USB class code -> name (base class table of usb.org).
pub fn class_name(c: u8) -> &'static str {
    match c {
        0x00 => "per-interface",
        0x01 => "audio",
        0x02 => "communications",
        0x03 => "hid",
        0x05 => "physical",
        0x06 => "image",
        0x07 => "printer",
        0x08 => "mass-storage",
        0x09 => "hub",
        0x0a => "cdc-data",
        0x0b => "smart-card",
        0x0d => "content-security",
        0x0e => "video",
        0x0f => "personal-healthcare",
        0x10 => "audio-video",
        0xdc => "diagnostic",
        0xe0 => "wireless-controller",
        0xef => "miscellaneous",
        0xfe => "application-specific",
        0xff => "vendor-specific",
        _ => "other",
    }
}

pub fn probe(ctx: &ProbeCtx) -> Result<UsbReport, ProbeError> {
    let mut rep = UsbReport::default();
    let all = ctx.list_dir("/sys/bus/usb/devices")?;
    for name in &all {
        if name.contains(':') {
            continue; // interfaces
        }
        let base = format!("/sys/bus/usb/devices/{}", name);
        let r = |f: &str| ctx.read_opt(&format!("{}/{}", base, f));
        let hx = |f: &str| r(f).and_then(|v| crate::ctx::parse_hex(&v)).unwrap_or(0);
        // interface directories are "<name>:<config>.<n>"
        let prefix = format!("{}:", name);
        let mut drivers: Vec<String> = Vec::new();
        let mut first_iface_class = None;
        for i in all.iter().filter(|i| i.starts_with(&prefix)) {
            if let Some(d) = ctx.link_name(&format!("/sys/bus/usb/devices/{}/driver", i)) {
                if !drivers.contains(&d) {
                    drivers.push(d);
                }
            }
            if first_iface_class.is_none() {
                first_iface_class = ctx.read_opt(&format!("/sys/bus/usb/devices/{}/bInterfaceClass", i)).and_then(|v| crate::ctx::parse_hex(&v)).map(|v| v as u8);
            }
        }
        let class = hx("bDeviceClass") as u8;
        let shown_class = if class == 0 { first_iface_class.unwrap_or(0) } else { class };
        let (vid, pid) = (hx("idVendor") as u16, hx("idProduct") as u16);
        let (vn, pn) = crate::usbids::lookup(vid, pid);
        rep.devices.push(UsbDevice {
            vendor_name: vn.map(str::to_string),
            product_name: pn.map(str::to_string),
            busnum: r("busnum").and_then(|v| v.parse().ok()).unwrap_or(0),
            devnum: r("devnum").and_then(|v| v.parse().ok()).unwrap_or(0),
            vid,
            pid,
            class,
            speed_mbps: r("speed").and_then(|v| v.parse::<f64>().ok()).map(|v| v as u32),
            manufacturer: r("manufacturer"),
            product: r("product"),
            serial: r("serial"),
            parent: parent_of(name),
            drivers,
            version: r("version"),
            class_name: class_name(shown_class).to_string(),
            path: name.clone(),
        });
    }
    // a stable order: bus, then device number
    rep.devices.sort_by_key(|d| (d.busnum, d.devnum, d.path.clone()));
    Ok(rep)
}

impl ToJson for UsbReport {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_u64("v", crate::SCHEMA_V);
        w.key("devices");
        w.begin_array();
        for d in &self.devices {
            w.begin_object();
            w.field_str("path", &d.path);
            w.field_opt_str("parent", d.parent.as_deref());
            w.field_u64("busnum", d.busnum as u64);
            w.field_u64("devnum", d.devnum as u64);
            w.field_str("vid", &format!("{:04x}", d.vid));
            w.field_str("pid", &format!("{:04x}", d.pid));
            w.field_opt_str("vendor_name", d.vendor_name.as_deref());
            w.field_opt_str("product_name", d.product_name.as_deref());
            w.field_u64("class", d.class as u64);
            w.field_opt_u64("speed_mbps", d.speed_mbps.map(u64::from));
            w.field_opt_str("manufacturer", d.manufacturer.as_deref());
            w.field_opt_str("product", d.product.as_deref());
            w.field_opt_str("serial", d.serial.as_deref());
            w.key("drivers");
            w.value(&d.drivers);
            w.field_opt_str("version", d.version.as_deref());
            w.field_str("class_name", &d.class_name);
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
        assert_eq!(parent_of("usb1"), None);
        assert_eq!(parent_of("1-2").as_deref(), Some("usb1"));
        assert_eq!(parent_of("1-2.3").as_deref(), Some("1-2"));
        assert_eq!(parent_of("3-1.4.2").as_deref(), Some("3-1.4"));
    }

    #[test]
    fn class_names() {
        assert_eq!(class_name(8), "mass-storage");
        assert_eq!(class_name(9), "hub");
        assert_eq!(class_name(0x42), "other");
    }
}
