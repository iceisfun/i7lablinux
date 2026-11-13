//! dmi: /sys/class/dmi/id plus a decoder of the raw SMBIOS structure table (/sys/firmware/dmi/tables/DMI) for
//! types 0, 1, 2, 3, 4, 16 and 17 (and `mem.rs` DIMMs). Owner: P3.
//!
//! sysfs gives the common identity fields to unprivileged readers except the serial numbers and the UUID (0400);
//! the raw table needs root too, so an unprivileged probe reports `null` for those. When a sysfs field is
//! missing the table value fills it. Strings are raw (sanitised at display time).

use labproto::json::{JsonWriter, ToJson};

use crate::ctx::{ProbeCtx, ProbeError};

pub const FIELDS: [&str; 13] = [
    "sys_vendor", "product_name", "product_serial", "product_uuid", "board_vendor", "board_name", "board_serial",
    "bios_vendor", "bios_version", "bios_date", "chassis_type", "chassis_serial", "product_version",
];

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DmiProcessor {
    pub socket: Option<String>,
    pub manufacturer: Option<String>,
    pub version: Option<String>,
    pub max_speed_mhz: Option<u32>,
    pub current_speed_mhz: Option<u32>,
    pub cores: Option<u32>,
    pub threads: Option<u32>,
    /// socket status bit 6: a CPU is installed
    pub populated: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DmiMemArray {
    pub location: String,
    pub usage: String,
    /// "none" | "parity" | "single-bit-ecc" | "multi-bit-ecc" | "crc" | "unknown" ...
    pub ecc: String,
    pub max_capacity_mib: Option<u64>,
    pub slots: u32,
}

/// Values in FIELDS order; `None` when unreadable or empty.
#[derive(Clone, Debug, Default)]
pub struct DmiInfo {
    pub fields: Vec<(&'static str, Option<String>)>,
    pub processors: Vec<DmiProcessor>,
    pub memory_arrays: Vec<DmiMemArray>,
}

impl DmiInfo {
    pub fn get(&self, k: &str) -> Option<&str> {
        self.fields.iter().find(|(n, _)| *n == k).and_then(|(_, v)| v.as_deref())
    }
}

/// One SMBIOS structure: `data` is the formatted area including the 4-byte header.
#[derive(Clone, Debug, PartialEq)]
pub struct Structure {
    pub ty: u8,
    pub handle: u16,
    pub data: Vec<u8>,
    pub strings: Vec<String>,
}

impl Structure {
    pub fn u8_at(&self, off: usize) -> Option<u8> {
        self.data.get(off).copied()
    }
    pub fn u16_at(&self, off: usize) -> Option<u16> {
        self.data.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    pub fn u32_at(&self, off: usize) -> Option<u32> {
        self.data.get(off..off + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn u64_at(&self, off: usize) -> Option<u64> {
        self.data.get(off..off + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    }
    /// String referenced by the index byte at `off` (index 0 = none, 1 = first string). Blank strings are `None`.
    pub fn str_at(&self, off: usize) -> Option<String> {
        let idx = self.u8_at(off)? as usize;
        if idx == 0 {
            return None;
        }
        let s = self.strings.get(idx - 1)?.trim();
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    }
}

/// Walk an SMBIOS structure table. Stops at the end-of-table structure (type 127) or at truncated data.
pub fn parse_structures(b: &[u8]) -> Vec<Structure> {
    let mut out = Vec::new();
    let mut p = 0;
    while p + 4 <= b.len() {
        let (ty, len, handle) = (b[p], b[p + 1] as usize, u16::from_le_bytes([b[p + 2], b[p + 3]]));
        if len < 4 || p + len > b.len() {
            break;
        }
        let data = b[p..p + len].to_vec();
        let mut q = p + len;
        let mut strings = Vec::new();
        loop {
            if q >= b.len() {
                break;
            }
            let end = b[q..].iter().position(|c| *c == 0).map(|e| q + e).unwrap_or(b.len());
            if end == q {
                q += 1; // the terminating empty string (or the second NUL of an empty string set)
                if strings.is_empty() && q < b.len() && b[q] == 0 {
                    q += 1;
                }
                break;
            }
            strings.push(String::from_utf8_lossy(&b[q..end]).into_owned());
            q = end + 1;
        }
        out.push(Structure { ty, handle, data, strings });
        if ty == 127 {
            break;
        }
        p = q;
    }
    out
}

/// SMBIOS 2.6 UUID text (first three fields little endian); `None` for all-zero / all-FF.
pub fn format_uuid(b: &[u8]) -> Option<String> {
    if b.len() < 16 || b[..16].iter().all(|x| *x == 0) || b[..16].iter().all(|x| *x == 0xff) {
        return None;
    }
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    ))
}

fn ecc_name(v: u8) -> &'static str {
    match v {
        1 => "other",
        3 => "none",
        4 => "parity",
        5 => "single-bit-ecc",
        6 => "multi-bit-ecc",
        7 => "crc",
        _ => "unknown",
    }
}

fn array_location(v: u8) -> &'static str {
    match v {
        3 => "system-board",
        4 | 5 | 6 | 7 => "add-on-card",
        _ => "other",
    }
}

fn array_use(v: u8) -> &'static str {
    match v {
        3 => "system-memory",
        4 => "video-memory",
        5 => "flash-memory",
        6 => "non-volatile-ram",
        7 => "cache-memory",
        _ => "other",
    }
}

/// Fields of types 0-3 keyed by the FIELDS names.
pub fn table_fields(s: &[Structure]) -> Vec<(&'static str, Option<String>)> {
    let first = |ty: u8| s.iter().find(|x| x.ty == ty);
    let mut v: Vec<(&'static str, Option<String>)> = Vec::new();
    let sys = first(1);
    let board = first(2);
    let bios = first(0);
    let chassis = first(3);
    v.push(("sys_vendor", sys.and_then(|x| x.str_at(4))));
    v.push(("product_name", sys.and_then(|x| x.str_at(5))));
    v.push(("product_version", sys.and_then(|x| x.str_at(6))));
    v.push(("product_serial", sys.and_then(|x| x.str_at(7))));
    v.push(("product_uuid", sys.and_then(|x| x.data.get(8..24).and_then(format_uuid))));
    v.push(("board_vendor", board.and_then(|x| x.str_at(4))));
    v.push(("board_name", board.and_then(|x| x.str_at(5))));
    v.push(("board_serial", board.and_then(|x| x.str_at(7))));
    v.push(("bios_vendor", bios.and_then(|x| x.str_at(4))));
    v.push(("bios_version", bios.and_then(|x| x.str_at(5))));
    v.push(("bios_date", bios.and_then(|x| x.str_at(8))));
    v.push(("chassis_type", chassis.and_then(|x| x.u8_at(5)).map(|t| (t & 0x7f).to_string())));
    v.push(("chassis_serial", chassis.and_then(|x| x.str_at(7))));
    v
}

pub fn decode_processors(s: &[Structure]) -> Vec<DmiProcessor> {
    s.iter()
        .filter(|x| x.ty == 4)
        .map(|x| {
            let nz = |v: Option<u16>| v.filter(|n| *n != 0).map(u32::from);
            let cores8 = x.u8_at(0x23).filter(|c| *c != 0 && *c != 0xff).map(u32::from);
            let threads8 = x.u8_at(0x25).filter(|c| *c != 0 && *c != 0xff).map(u32::from);
            DmiProcessor {
                socket: x.str_at(4),
                manufacturer: x.str_at(7),
                version: x.str_at(0x10),
                max_speed_mhz: nz(x.u16_at(0x14)),
                current_speed_mhz: nz(x.u16_at(0x16)),
                // 0xff means "see the 16-bit field" (SMBIOS 3.0)
                cores: if x.u8_at(0x23) == Some(0xff) { nz(x.u16_at(0x2a)) } else { cores8 },
                threads: if x.u8_at(0x25) == Some(0xff) { nz(x.u16_at(0x2e)) } else { threads8 },
                populated: x.u8_at(0x18).map(|st| st & 0x40 != 0).unwrap_or(false),
            }
        })
        .collect()
}

pub fn decode_mem_arrays(s: &[Structure]) -> Vec<DmiMemArray> {
    s.iter()
        .filter(|x| x.ty == 16)
        .map(|x| {
            let cap_kb = x.u32_at(7);
            let max_capacity_mib = match cap_kb {
                Some(0x8000_0000) => x.u64_at(0x0f).map(|b| b >> 20), // bytes in the extended field
                Some(k) => Some(k as u64 / 1024),
                None => None,
            };
            DmiMemArray {
                location: array_location(x.u8_at(4).unwrap_or(0)).into(),
                usage: array_use(x.u8_at(5).unwrap_or(0)).into(),
                ecc: ecc_name(x.u8_at(6).unwrap_or(0)).into(),
                max_capacity_mib,
                slots: x.u16_at(0x0d).map(u32::from).unwrap_or(0),
            }
        })
        .collect()
}

/// Read and walk the raw table; empty when the file is absent or unreadable (unprivileged).
pub fn read_table(ctx: &ProbeCtx) -> Vec<Structure> {
    ctx.read_bytes("/sys/firmware/dmi/tables/DMI", 4 << 20).map(|b| parse_structures(&b)).unwrap_or_default()
}

pub fn probe(ctx: &ProbeCtx) -> Result<DmiInfo, ProbeError> {
    let table = read_table(ctx);
    let from_table = table_fields(&table);
    let fields = FIELDS
        .iter()
        .map(|f| {
            let sysfs = ctx.read_opt(&format!("/sys/class/dmi/id/{}", f));
            let t = from_table.iter().find(|(n, _)| n == f).and_then(|(_, v)| v.clone());
            (*f, sysfs.or(t))
        })
        .collect();
    Ok(DmiInfo { fields, processors: decode_processors(&table), memory_arrays: decode_mem_arrays(&table) })
}

impl ToJson for DmiInfo {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_u64("v", crate::SCHEMA_V);
        for (k, v) in &self.fields {
            w.field_opt_str(k, v.as_deref());
        }
        w.key("processors");
        w.begin_array();
        for p in &self.processors {
            w.begin_object();
            w.field_opt_str("socket", p.socket.as_deref());
            w.field_opt_str("manufacturer", p.manufacturer.as_deref());
            w.field_opt_str("version", p.version.as_deref());
            w.field_opt_u64("max_speed_mhz", p.max_speed_mhz.map(u64::from));
            w.field_opt_u64("current_speed_mhz", p.current_speed_mhz.map(u64::from));
            w.field_opt_u64("cores", p.cores.map(u64::from));
            w.field_opt_u64("threads", p.threads.map(u64::from));
            w.field_bool("populated", p.populated);
            w.end_object();
        }
        w.end_array();
        w.key("memory_arrays");
        w.begin_array();
        for a in &self.memory_arrays {
            w.begin_object();
            w.field_str("location", &a.location);
            w.field_str("usage", &a.usage);
            w.field_str("ecc", &a.ecc);
            w.field_opt_u64("max_capacity_mib", a.max_capacity_mib);
            w.field_u64("slots", a.slots as u64);
            w.end_object();
        }
        w.end_array();
        w.end_object();
    }
}

/// Build a structure (header + formatted bytes + strings) for tests and fixtures.
#[cfg(test)]
pub(crate) fn build_structure(ty: u8, handle: u16, body: &[u8], strings: &[&str]) -> Vec<u8> {
    let mut v = vec![ty, (4 + body.len()) as u8];
    v.extend_from_slice(&handle.to_le_bytes());
    v.extend_from_slice(body);
    for s in strings {
        v.extend_from_slice(s.as_bytes());
        v.push(0);
    }
    if strings.is_empty() {
        v.push(0);
    }
    v.push(0);
    v
}

#[cfg(test)]
pub(crate) fn sample_table() -> Vec<u8> {
    let mut t = Vec::new();
    // type 0 BIOS: vendor=1 version=2, start seg, release date=3
    let mut b0 = vec![1, 2, 0, 0, 3];
    b0.extend_from_slice(&[0u8; 10]);
    t.extend(build_structure(0, 0, &b0, &["ACME BIOS", "1.2.3", "01/02/2024"]));
    // type 1: manufacturer 1, product 2, version 3, serial 4, uuid, wakeup
    let mut b1 = vec![1, 2, 3, 4];
    b1.extend_from_slice(&[0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    b1.push(6);
    t.extend(build_structure(1, 1, &b1, &["ACME", "Rack 1U", "rev B", "SN123"]));
    // type 2 baseboard: manufacturer 1, product 2, version 3, serial 4
    t.extend(build_structure(2, 2, &[1, 2, 3, 4, 0, 0], &["ACME Boards", "B-100", "r1", "BSN9"]));
    // type 3 chassis: manufacturer 1, type 0x81 (locked rack mount=23?) use 23|0x80, version 2, serial 3
    t.extend(build_structure(3, 3, &[1, 23 | 0x80, 2, 3, 0], &["ACME", "v1", "CSN7"]));
    // type 4 processor: socket 1, type 3, family 0xb3, manufacturer 2, id 8 bytes, version 3 ...
    let mut b4 = vec![1, 3, 0xb3, 2];
    b4.extend_from_slice(&[0u8; 8]); // id (0x08..0x10)
    b4.push(3); // version string idx at 0x10 -> offset index in body is 0x10-4=12
    b4.extend_from_slice(&[0, 0, 0]); // voltage, ext clock (u16) -> pad: voltage(0x11) extclk(0x12,0x13)
    b4.extend_from_slice(&4000u16.to_le_bytes()); // max speed 0x14
    b4.extend_from_slice(&2900u16.to_le_bytes()); // current 0x16
    b4.push(0x41); // status 0x18: bit6 populated
    while b4.len() < 0x23 - 4 {
        b4.push(0);
    }
    b4.push(8); // core count 0x23
    b4.push(8); // core enabled 0x24
    b4.push(16); // thread count 0x25
    t.extend(build_structure(4, 4, &b4, &["CPU0", "ACME", "ACME Xeon 9000"]));
    // type 16: location 3, use 3, ecc 6, max cap 0x8000_0000 -> extended, error handle 0xfffe, devices 4, ext cap 128 GiB
    let mut b16 = vec![3, 3, 6];
    b16.extend_from_slice(&0x8000_0000u32.to_le_bytes());
    b16.extend_from_slice(&0xfffeu16.to_le_bytes());
    b16.extend_from_slice(&4u16.to_le_bytes());
    b16.extend_from_slice(&(128u64 << 30).to_le_bytes());
    t.extend(build_structure(16, 0x10, &b16, &[]));
    t.extend(build_structure(17, 0x20, &dimm_body(16384, 1, 0x1a, 4, 3200, 3200), &["DIMM_A1", "BANK 0", "Samsung", "SER-A1", "M393A4K40CB2"]));
    t.extend(build_structure(17, 0x21, &dimm_body(0, 0, 0, 0, 0, 0), &["DIMM_B1", "BANK 1"]));
    t.extend(build_structure(127, 0x7f, &[], &[]));
    t
}

/// Body (after the 4-byte header) of a type 17 structure, SMBIOS 2.7+ layout (length 0x22).
#[cfg(test)]
pub(crate) fn dimm_body(size_mb: u16, ecc: u8, mem_type: u8, rank: u8, speed: u16, conf: u16) -> Vec<u8> {
    let mut b = vec![0u8; 0x22 - 4];
    let put16 = |b: &mut Vec<u8>, off: usize, v: u16| b[off - 4..off - 2].copy_from_slice(&v.to_le_bytes());
    put16(&mut b, 4, 0x10); // array handle
    put16(&mut b, 6, 0xfffe);
    let (total, data) = if ecc == 1 { (72, 64) } else { (64, 64) };
    put16(&mut b, 8, if size_mb == 0 { 0 } else { total });
    put16(&mut b, 0xA, if size_mb == 0 { 0 } else { data });
    put16(&mut b, 0xC, size_mb);
    b[0xE - 4] = 9; // DIMM
    b[0x10 - 4] = 1; // locator
    b[0x11 - 4] = 2; // bank
    b[0x12 - 4] = mem_type;
    put16(&mut b, 0x15, speed);
    if size_mb != 0 {
        b[0x17 - 4] = 3; // manufacturer
        b[0x18 - 4] = 4; // serial
        b[0x1A - 4] = 5; // part number
        b[0x1B - 4] = rank;
    }
    put16(&mut b, 0x20, conf);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structure_walk_and_strings() {
        let t = sample_table();
        let s = parse_structures(&t);
        assert_eq!(s.iter().map(|x| x.ty).collect::<Vec<_>>(), [0, 1, 2, 3, 4, 16, 17, 17, 127]);
        assert_eq!(s[1].strings, ["ACME", "Rack 1U", "rev B", "SN123"]);
        assert_eq!(s[5].strings.len(), 0);
        // truncated table ends cleanly
        assert!(parse_structures(&t[..t.len() - 40]).len() < s.len());
        assert!(parse_structures(&[]).is_empty());
        assert!(parse_structures(&[1, 2, 3]).is_empty());
    }

    #[test]
    fn fields_processors_arrays() {
        let s = parse_structures(&sample_table());
        let f = table_fields(&s);
        let get = |k: &str| f.iter().find(|(n, _)| *n == k).unwrap().1.clone();
        assert_eq!(get("sys_vendor").as_deref(), Some("ACME"));
        assert_eq!(get("product_serial").as_deref(), Some("SN123"));
        assert_eq!(get("product_uuid").as_deref(), Some("00112233-4455-6677-8899-aabbccddeeff"));
        assert_eq!(get("bios_date").as_deref(), Some("01/02/2024"));
        assert_eq!(get("board_name").as_deref(), Some("B-100"));
        assert_eq!(get("chassis_type").as_deref(), Some("23"));
        let p = decode_processors(&s);
        assert_eq!(p.len(), 1);
        assert_eq!((p[0].max_speed_mhz, p[0].current_speed_mhz, p[0].cores, p[0].threads, p[0].populated), (Some(4000), Some(2900), Some(8), Some(16), true));
        assert_eq!(p[0].version.as_deref(), Some("ACME Xeon 9000"));
        let a = decode_mem_arrays(&s);
        assert_eq!(a, vec![DmiMemArray { location: "system-board".into(), usage: "system-memory".into(), ecc: "multi-bit-ecc".into(), max_capacity_mib: Some(131072), slots: 4 }]);
    }

    #[test]
    fn uuid_edge_cases() {
        assert_eq!(format_uuid(&[0; 16]), None);
        assert_eq!(format_uuid(&[0xff; 16]), None);
        assert_eq!(format_uuid(&[1; 3]), None);
    }
}
