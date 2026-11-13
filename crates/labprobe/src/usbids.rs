//! USB vendor/product names from the embedded subset (`data/usb-ids.tsv`, same format as `pci-ids.tsv`).
//! Unknown ids return `None`; names are never guessed.

use std::sync::OnceLock;

struct Table {
    vendors: Vec<(u16, &'static str)>,
    devices: Vec<(u32, &'static str)>,
}

const DATA: &str = include_str!("../data/usb-ids.tsv");

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

/// (vendor name, product name) from the embedded subset.
pub fn lookup(vid: u16, pid: u16) -> (Option<&'static str>, Option<&'static str>) {
    let t = table();
    let v = t.vendors.binary_search_by_key(&vid, |x| x.0).ok().map(|i| t.vendors[i].1);
    let key = (vid as u32) << 16 | pid as u32;
    let d = t.devices.binary_search_by_key(&key, |x| x.0).ok().map(|i| t.devices[i].1);
    (v, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookups() {
        assert_eq!(lookup(0x1d6b, 0x0002), (Some("Linux Foundation"), Some("2.0 root hub")));
        assert_eq!(lookup(0x8087, 0x0026), (Some("Intel Corp."), Some("AX201 Bluetooth")));
        assert_eq!(lookup(0x04f2, 0xb6fb), (Some("Chicony Electronics Co., Ltd"), None));
        assert_eq!(lookup(0xdead, 0xbeef), (None, None));
    }

    #[test]
    fn data_file_is_well_formed() {
        let t = parse(DATA);
        assert!(t.vendors.len() > 20 && t.devices.len() > 30);
        for w in t.vendors.windows(2) {
            assert!(w[0].0 != w[1].0, "duplicate vendor {:04x}", w[0].0);
        }
        for w in t.devices.windows(2) {
            assert!(w[0].0 != w[1].0, "duplicate device {:08x}", w[0].0);
        }
        for (k, _) in &t.devices {
            assert!(t.vendors.binary_search_by_key(&((k >> 16) as u16), |x| x.0).is_ok(), "vendor of {:08x} missing", k);
        }
        assert!(DATA.is_ascii());
    }
}
