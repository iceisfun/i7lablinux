//! firmware: boot mode, Secure Boot state, BootOrder/BootNext/Boot#### from efivarfs (read-only). Owner: P3.

use labproto::json::{JsonWriter, ToJson};

use crate::ctx::{ProbeCtx, ProbeError};

pub const EFI_GLOBAL_GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";

#[derive(Clone, Debug, Default)]
pub struct BootEntry {
    pub num: u16,
    pub description: String,
    pub active: bool,
    /// compact text of the device path, e.g. "PciRoot(0x0)/Pci(0x1d,0x0)/NVMe/HD(1,GPT)/\\EFI\\BOOT\\BOOTX64.EFI"
    pub device_path: Option<String>,
    /// the device path runs through a USB node
    pub usb: bool,
    /// the device path is a network boot (MAC / IPv4 / IPv6 / URI node)
    pub network: bool,
}

#[derive(Clone, Debug, Default)]
pub struct FirmwareInfo {
    /// "uefi" | "bios"
    pub boot_mode: String,
    pub platform_bits: Option<u8>,
    pub secure_boot: Option<bool>,
    pub setup_mode: Option<bool>,
    pub boot_current: Option<u16>,
    pub boot_next: Option<u16>,
    pub boot_order: Vec<u16>,
    pub boot_entries: Vec<BootEntry>,
}

/// The "internal OS" entry for `reboot --to-os`: the first BootOrder entry that is active, not USB, not network
/// and not BootCurrent (review feasibility F17). Entries missing from `boot_entries` are skipped.
pub fn internal_os_entry(info: &FirmwareInfo) -> Option<u16> {
    info.boot_order.iter().copied().find(|n| {
        Some(*n) != info.boot_current
            && info.boot_entries.iter().any(|e| e.num == *n && e.active && !e.usb && !e.network)
    })
}

fn efivar_path(name: &str) -> String {
    format!("/sys/firmware/efi/efivars/{}-{}", name, EFI_GLOBAL_GUID)
}

/// Contents of an EFI variable without the 4 attribute bytes; `None` when absent or shorter than the attributes.
fn efivar(ctx: &ProbeCtx, name: &str) -> Option<Vec<u8>> {
    let b = ctx.read_bytes(&efivar_path(name), 64 * 1024).ok()?;
    if b.len() < 4 {
        None
    } else {
        Some(b[4..].to_vec())
    }
}

fn u16_of(b: &[u8]) -> Option<u16> {
    (b.len() >= 2).then(|| u16::from_le_bytes([b[0], b[1]]))
}

/// Write a global EFI variable with attributes NV|BS|RT in ONE write (efivarfs requires attributes + data
/// together). The caller (i7labd power handler) remounts efivarfs rw around the call only (MS_REMOUNT), then back
/// to ro. Refuses without the privilege check: efivarfs itself enforces it.
fn write_efivar(ctx: &ProbeCtx, name: &str, data: &[u8]) -> Result<(), ProbeError> {
    use std::io::Write;
    let mut buf = 0x07u32.to_le_bytes().to_vec();
    buf.extend_from_slice(data);
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(ctx.path(&efivar_path(name)))?;
    f.write_all(&buf)?;
    Ok(())
}

/// Write BootNext (u16 LE, attributes NV|BS|RT = 0x07). Only entries that exist in BootOrder-visible `Boot####`
/// variables are accepted, so a typo cannot make the next boot fail.
pub fn set_boot_next(ctx: &ProbeCtx, entry: u16) -> Result<(), ProbeError> {
    if !ctx.exists(&efivar_path(&format!("Boot{:04X}", entry))) {
        return Err(ProbeError::NotFound(format!("Boot{:04X}", entry)));
    }
    write_efivar(ctx, "BootNext", &entry.to_le_bytes())
}

/// Set bits in OsIndications (bit 0 = EFI_OS_INDICATIONS_BOOT_TO_FW_UI) for `reboot --uefi`; keeps the bits
/// already set and fails `Unsupported` when OsIndicationsSupported does not offer the bits. Same remount rule.
pub fn set_os_indications(ctx: &ProbeCtx, bits: u64) -> Result<(), ProbeError> {
    let supported = efivar(ctx, "OsIndicationsSupported").and_then(|b| b.get(..8).map(|x| u64::from_le_bytes(x.try_into().unwrap())));
    match supported {
        Some(s) if s & bits == bits => {}
        _ => return Err(ProbeError::Unsupported),
    }
    let cur = efivar(ctx, "OsIndications").and_then(|b| b.get(..8).map(|x| u64::from_le_bytes(x.try_into().unwrap()))).unwrap_or(0);
    write_efivar(ctx, "OsIndications", &(cur | bits).to_le_bytes())
}

/// Decode a `Boot####` load option (data after the 4 attribute bytes of the variable): attributes u32,
/// FilePathListLength u16, NUL-terminated UTF-16 description, device path nodes.
pub fn parse_load_option(num: u16, b: &[u8]) -> Option<BootEntry> {
    if b.len() < 6 {
        return None;
    }
    let attrs = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let fp_len = u16::from_le_bytes([b[4], b[5]]) as usize;
    let mut units = Vec::new();
    let mut p = 6;
    while p + 2 <= b.len() {
        let u = u16::from_le_bytes([b[p], b[p + 1]]);
        p += 2;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    let dp = b.get(p..(p + fp_len).min(b.len())).unwrap_or(&[]);
    let (text, usb, network) = describe_device_path(dp);
    Some(BootEntry {
        num,
        description: String::from_utf16_lossy(&units),
        active: attrs & 1 != 0,
        device_path: if text.is_empty() { None } else { Some(text) },
        usb,
        network,
    })
}

/// Compact text of a UEFI device path plus (has a USB node, has a network node). Unknown nodes print as
/// `Type(0xTT,0xSS)`.
pub fn describe_device_path(b: &[u8]) -> (String, bool, bool) {
    let mut parts: Vec<String> = Vec::new();
    let (mut usb, mut net) = (false, false);
    let mut p = 0;
    while p + 4 <= b.len() {
        let (ty, sub, len) = (b[p], b[p + 1], u16::from_le_bytes([b[p + 2], b[p + 3]]) as usize);
        if len < 4 || p + len > b.len() {
            break;
        }
        let d = &b[p + 4..p + len];
        if ty == 0x7f {
            break;
        }
        let node = match (ty, sub) {
            (1, 1) if d.len() >= 2 => format!("Pci({:#x},{:#x})", d[1], d[0]),
            (2, 1) if d.len() >= 8 => {
                let hid = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
                let uid = u32::from_le_bytes([d[4], d[5], d[6], d[7]]);
                if hid == 0x0a03_41d0 {
                    format!("PciRoot({:#x})", uid)
                } else {
                    format!("Acpi({:#x},{:#x})", hid, uid)
                }
            }
            (3, 5) if d.len() >= 2 => {
                usb = true;
                format!("USB({:#x},{:#x})", d[0], d[1])
            }
            (3, 0x0f) => {
                usb = true;
                "UsbClass".to_string()
            }
            (3, 0x12) => "Sata".to_string(),
            (3, 0x17) => "NVMe".to_string(),
            (3, 0x0b) => {
                net = true;
                "MAC".to_string()
            }
            (3, 0x0c) => {
                net = true;
                "IPv4".to_string()
            }
            (3, 0x0d) => {
                net = true;
                "IPv6".to_string()
            }
            (3, 0x18) => {
                net = true;
                "Uri".to_string()
            }
            (4, 1) if d.len() >= 38 => {
                let n = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
                format!("HD({},{})", n, if d[36] == 2 { "GPT" } else { "MBR" })
            }
            (4, 4) => {
                let units: Vec<u16> = d.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|u| *u != 0).collect();
                String::from_utf16_lossy(&units)
            }
            (_, _) => format!("Type({:#x},{:#x})", ty, sub),
        };
        parts.push(node);
        p += len;
    }
    (parts.join("/"), usb, net)
}

pub fn probe(ctx: &ProbeCtx) -> Result<FirmwareInfo, ProbeError> {
    let uefi = ctx.path("/sys/firmware/efi").exists();
    let mut f = FirmwareInfo { boot_mode: if uefi { "uefi" } else { "bios" }.into(), ..Default::default() };
    if uefi {
        f.platform_bits = ctx.read_opt("/sys/firmware/efi/fw_platform_size").and_then(|s| s.parse().ok());
        f.secure_boot = efivar(ctx, "SecureBoot").and_then(|b| b.first().map(|v| *v == 1));
        f.setup_mode = efivar(ctx, "SetupMode").and_then(|b| b.first().map(|v| *v == 1));
        f.boot_current = efivar(ctx, "BootCurrent").and_then(|b| u16_of(&b));
        f.boot_next = efivar(ctx, "BootNext").and_then(|b| u16_of(&b));
        f.boot_order = efivar(ctx, "BootOrder").map(|b| b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()).unwrap_or_default();
        let mut nums: Vec<u16> = f.boot_order.clone();
        // entries that exist but are not in BootOrder (e.g. a one-shot) are still listed
        for name in ctx.list_dir("/sys/firmware/efi/efivars").unwrap_or_default() {
            if let Some(hex) = name.strip_prefix("Boot").and_then(|r| r.strip_suffix(&format!("-{}", EFI_GLOBAL_GUID))) {
                if hex.len() == 4 {
                    if let Ok(n) = u16::from_str_radix(hex, 16) {
                        if !nums.contains(&n) {
                            nums.push(n);
                        }
                    }
                }
            }
        }
        for n in nums {
            if let Some(e) = efivar(ctx, &format!("Boot{:04X}", n)).and_then(|b| parse_load_option(n, &b)) {
                f.boot_entries.push(e);
            }
        }
    }
    Ok(f)
}

impl ToJson for FirmwareInfo {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_u64("v", crate::SCHEMA_V);
        w.field_str("boot_mode", &self.boot_mode);
        w.field_opt_u64("platform_bits", self.platform_bits.map(u64::from));
        for (k, v) in [("secure_boot", self.secure_boot), ("setup_mode", self.setup_mode)] {
            w.key(k);
            match v {
                Some(b) => w.bool(b),
                None => w.null(),
            }
        }
        w.field_opt_u64("boot_current", self.boot_current.map(u64::from));
        w.field_opt_u64("boot_next", self.boot_next.map(u64::from));
        w.key("boot_order");
        w.begin_array();
        for n in &self.boot_order {
            w.u64(*n as u64);
        }
        w.end_array();
        w.key("boot_entries");
        w.begin_array();
        for e in &self.boot_entries {
            w.begin_object();
            w.field_u64("num", e.num as u64);
            w.field_str("description", &e.description);
            w.field_bool("active", e.active);
            w.field_opt_str("device_path", e.device_path.as_deref());
            w.field_bool("usb", e.usb);
            w.field_bool("network", e.network);
            w.end_object();
        }
        w.end_array();
        w.end_object();
    }
}
