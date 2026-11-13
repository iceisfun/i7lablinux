//! PCI class names and the vendor/device name table (`data/pci-ids.tsv`, a curated subset embedded with
//! `include_str!`). Owner: P3. Unknown ids return `None`; names are never guessed.

use std::sync::OnceLock;

/// Name of a class code: the sub-class level when known ("NVMe controller"), else the base class.
pub fn class_name(class: u32) -> &'static str {
    match (class >> 8) & 0xffff {
        0x0100 => "SCSI storage controller",
        0x0101 => "IDE interface",
        0x0106 => "SATA controller",
        0x0107 => "Serial Attached SCSI controller",
        0x0108 => "NVMe controller",
        0x0200 => "Ethernet controller",
        0x0207 => "InfiniBand controller",
        0x0280 => "Network controller",
        0x0300 => "VGA compatible controller",
        0x0301 => "XGA compatible controller",
        0x0302 => "3D controller",
        0x0380 => "Display controller",
        0x0401 => "Multimedia audio controller",
        0x0403 => "Audio device",
        0x0600 => "Host bridge",
        0x0601 => "ISA bridge",
        0x0604 => "PCI bridge",
        0x0680 => "Bridge",
        0x0c03 => "USB controller",
        0x0c05 => "SMBus",
        0x0d11 => "Bluetooth",
        0x0d80 => "Wireless controller",
        _ => match class >> 16 {
            0x00 => "unclassified",
            0x01 => "storage",
            0x02 => "network",
            0x03 => "display",
            0x04 => "multimedia",
            0x05 => "memory",
            0x06 => "bridge",
            0x07 => "communication",
            0x08 => "system",
            0x09 => "input",
            0x0b => "processor",
            0x0c => "serial-bus",
            0x0d => "wireless",
            0x10 => "encryption",
            0x11 => "signal-processing",
            0x12 => "accelerator",
            _ => "other",
        },
    }
}

struct Table {
    vendors: Vec<(u16, &'static str)>,
    devices: Vec<(u32, &'static str)>,
}

const DATA: &str = include_str!("../data/pci-ids.tsv");

/// Parse the embedded file. Pure and sorted on load so the data file need not be ordered.
fn parse(data: &'static str) -> Table {
    let mut t = Table { vendors: vec![], devices: vec![] };
    let mut section = "";
    for line in data.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            section = line;
            continue;
        }
        let Some((key, name)) = line.split_once('\t') else { continue };
        match section {
            "[vendors]" => {
                if let Ok(v) = u16::from_str_radix(key, 16) {
                    t.vendors.push((v, name));
                }
            }
            "[devices]" => {
                if let Some((v, d)) = key.split_once(':') {
                    if let (Ok(v), Ok(d)) = (u16::from_str_radix(v, 16), u16::from_str_radix(d, 16)) {
                        t.devices.push(((v as u32) << 16 | d as u32, name));
                    }
                }
            }
            _ => {}
        }
    }
    t.vendors.sort_by_key(|x| x.0);
    t.devices.sort_by_key(|x| x.0);
    t
}

fn table() -> &'static Table {
    static T: OnceLock<Table> = OnceLock::new();
    T.get_or_init(|| parse(DATA))
}

/// (vendor name, device name) from the embedded subset.
pub fn lookup(vendor: u16, device: u16) -> (Option<&'static str>, Option<&'static str>) {
    let t = table();
    let v = t.vendors.binary_search_by_key(&vendor, |x| x.0).ok().map(|i| t.vendors[i].1);
    let key = (vendor as u32) << 16 | device as u32;
    let d = t.devices.binary_search_by_key(&key, |x| x.0).ok().map(|i| t.devices[i].1);
    (v, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookups() {
        assert_eq!(lookup(0x10de, 0x1b02), (Some("NVIDIA Corporation"), Some("GP102 [TITAN Xp]")));
        assert_eq!(lookup(0x8086, 0xffff), (Some("Intel Corporation"), None));
        assert_eq!(lookup(0x1234, 0x0001).1, None);
        assert_eq!(lookup(0xdead, 0xbeef), (None, None));
    }

    #[test]
    fn data_file_is_well_formed() {
        let t = parse(DATA);
        assert!(t.vendors.len() > 30 && t.devices.len() > 100, "{} {}", t.vendors.len(), t.devices.len());
        // no duplicate keys (a duplicate would silently shadow)
        for w in t.vendors.windows(2) {
            assert!(w[0].0 != w[1].0, "duplicate vendor {:04x}", w[0].0);
        }
        for w in t.devices.windows(2) {
            assert!(w[0].0 != w[1].0, "duplicate device {:08x}", w[0].0);
        }
        // every device id has a vendor entry
        for (k, _) in &t.devices {
            assert!(t.vendors.binary_search_by_key(&((k >> 16) as u16), |x| x.0).is_ok(), "vendor of {:08x} missing", k);
        }
        assert!(DATA.is_ascii());
    }

    #[test]
    fn class_names() {
        assert_eq!(class_name(0x010802), "NVMe controller");
        assert_eq!(class_name(0x020000), "Ethernet controller");
        assert_eq!(class_name(0x0c0330), "USB controller");
        assert_eq!(class_name(0x028000), "Network controller");
        assert_eq!(class_name(0x0b4000), "processor");
        assert_eq!(class_name(0xff0000), "other");
    }
}
