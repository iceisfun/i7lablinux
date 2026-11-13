//! mem: /proc/meminfo, DMI type 16/17 DIMMs, EDAC counters. Owner: P3.

use labproto::json::{JsonWriter, ToJson};

use crate::ctx::{ProbeCtx, ProbeError};

#[derive(Clone, Debug, Default)]
pub struct Dimm {
    pub locator: String,
    pub bank: Option<String>,
    /// 0 = empty slot
    pub size_mib: u64,
    pub kind: Option<String>,
    pub speed_mts: Option<u32>,
    pub configured_speed_mts: Option<u32>,
    pub manufacturer: Option<String>,
    pub part_number: Option<String>,
    pub serial: Option<String>,
    pub rank: Option<u8>,
    pub ecc: bool,
}

#[derive(Clone, Debug, Default)]
pub struct EdacMc {
    pub name: String,
    pub ce_count: u64,
    pub ue_count: u64,
}

#[derive(Clone, Debug, Default)]
pub struct MemInfo {
    pub total_kib: u64,
    pub available_kib: u64,
    pub swap_kib: u64,
    pub dimms: Vec<Dimm>,
    pub ecc: Option<String>,
    pub edac: Vec<EdacMc>,
}

fn mem_type_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0x03 => "DRAM",
        0x0f => "SDRAM",
        0x12 => "DDR",
        0x13 => "DDR2",
        0x14 => "DDR2 FB-DIMM",
        0x18 => "DDR3",
        0x1a => "DDR4",
        0x1b => "LPDDR",
        0x1c => "LPDDR2",
        0x1d => "LPDDR3",
        0x1e => "LPDDR4",
        0x20 => "HBM",
        0x21 => "HBM2",
        0x22 => "DDR5",
        0x23 => "LPDDR5",
        0x24 => "HBM3",
        _ => return None,
    })
}

/// Decode the type 17 (Memory Device) structures. Empty slots are kept with `size_mib == 0`.
pub fn decode_dimms(structs: &[crate::dmi::Structure]) -> Vec<Dimm> {
    structs
        .iter()
        .filter(|s| s.ty == 17)
        .map(|s| {
            let raw = s.u16_at(0xC).unwrap_or(0);
            let size_mib = match raw {
                0 | 0xFFFF => 0,
                0x7FFF => s.u32_at(0x1C).map(|v| (v & 0x7FFF_FFFF) as u64).unwrap_or(0),
                v if v & 0x8000 != 0 => (v & 0x7FFF) as u64 / 1024, // kilobytes
                v => v as u64,
            };
            let (total, data) = (s.u16_at(8).unwrap_or(0), s.u16_at(0xA).unwrap_or(0));
            let nz16 = |off: usize| s.u16_at(off).filter(|v| *v != 0 && *v != 0xFFFF).map(u32::from);
            Dimm {
                locator: s.str_at(0x10).unwrap_or_default(),
                bank: s.str_at(0x11),
                size_mib,
                kind: s.u8_at(0x12).and_then(mem_type_name).map(str::to_string),
                speed_mts: nz16(0x15),
                configured_speed_mts: nz16(0x20),
                manufacturer: s.str_at(0x17),
                part_number: s.str_at(0x1A),
                serial: s.str_at(0x18),
                rank: s.u8_at(0x1B).map(|r| r & 0x0F).filter(|r| *r != 0),
                ecc: total != 0 && total != 0xFFFF && data != 0 && total > data,
            }
        })
        .collect()
}

pub fn parse_meminfo(t: &str) -> (u64, u64, u64) {
    let (mut total, mut avail, mut swap) = (0, 0, 0);
    for l in t.lines() {
        let mut it = l.split_whitespace();
        let (k, v) = (it.next().unwrap_or(""), it.next().and_then(|x| x.parse().ok()).unwrap_or(0));
        match k {
            "MemTotal:" => total = v,
            "MemAvailable:" => avail = v,
            "SwapTotal:" => swap = v,
            _ => {}
        }
    }
    (total, avail, swap)
}

pub fn probe(ctx: &ProbeCtx) -> Result<MemInfo, ProbeError> {
    let t = ctx.read_trim("/proc/meminfo")?;
    let (total_kib, available_kib, swap_kib) = parse_meminfo(&t);
    let mut m = MemInfo { total_kib, available_kib, swap_kib, ..Default::default() };
    let table = crate::dmi::read_table(ctx);
    m.dimms = decode_dimms(&table);
    m.ecc = crate::dmi::decode_mem_arrays(&table).into_iter().find(|a| a.usage == "system-memory").map(|a| a.ecc);
    let base = "/sys/devices/system/edac/mc";
    for mc in ctx.list_dir(base).unwrap_or_default() {
        if !mc.starts_with("mc") || mc.len() < 3 || !mc[2..].bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let n = |f: &str| ctx.read_opt(&format!("{}/{}/{}", base, mc, f)).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        m.edac.push(EdacMc { name: ctx.read_opt(&format!("{}/{}/mc_name", base, mc)).unwrap_or_else(|| mc.clone()), ce_count: n("ce_count"), ue_count: n("ue_count") });
    }
    Ok(m)
}

impl ToJson for MemInfo {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_u64("v", crate::SCHEMA_V);
        w.field_u64("total_kib", self.total_kib);
        w.field_u64("available_kib", self.available_kib);
        w.field_u64("swap_kib", self.swap_kib);
        w.key("dimms");
        w.begin_array();
        for d in &self.dimms {
            w.begin_object();
            w.field_str("locator", &d.locator);
            w.field_opt_str("bank", d.bank.as_deref());
            w.field_u64("size_mib", d.size_mib);
            w.field_opt_str("kind", d.kind.as_deref());
            w.field_opt_u64("speed_mts", d.speed_mts.map(u64::from));
            w.field_opt_u64("configured_speed_mts", d.configured_speed_mts.map(u64::from));
            w.field_opt_str("manufacturer", d.manufacturer.as_deref());
            w.field_opt_str("part_number", d.part_number.as_deref());
            w.field_opt_str("serial", d.serial.as_deref());
            w.field_opt_u64("rank", d.rank.map(u64::from));
            w.field_bool("ecc", d.ecc);
            w.end_object();
        }
        w.end_array();
        w.field_opt_str("ecc", self.ecc.as_deref());
        w.key("edac");
        w.begin_array();
        for e in &self.edac {
            w.begin_object();
            w.field_str("name", &e.name);
            w.field_u64("ce_count", e.ce_count);
            w.field_u64("ue_count", e.ue_count);
            w.end_object();
        }
        w.end_array();
        w.end_object();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dmi::{build_structure, dimm_body, parse_structures, sample_table};

    #[test]
    fn dimms_from_table() {
        let d = decode_dimms(&parse_structures(&sample_table()));
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].locator, "DIMM_A1");
        assert_eq!((d[0].size_mib, d[0].kind.as_deref(), d[0].speed_mts, d[0].configured_speed_mts, d[0].rank, d[0].ecc), (16384, Some("DDR4"), Some(3200), Some(3200), Some(4), true));
        assert_eq!((d[0].manufacturer.as_deref(), d[0].serial.as_deref(), d[0].part_number.as_deref(), d[0].bank.as_deref()), (Some("Samsung"), Some("SER-A1"), Some("M393A4K40CB2"), Some("BANK 0")));
        assert_eq!((d[1].locator.as_str(), d[1].size_mib, d[1].speed_mts, d[1].manufacturer.clone()), ("DIMM_B1", 0, None, None));
    }

    #[test]
    fn size_encodings() {
        let mk = |raw: u16, ext: Option<u32>| {
            let mut b = dimm_body(raw, 0, 0x1a, 1, 2400, 2400);
            if let Some(e) = ext {
                b[0x1C - 4..0x20 - 4].copy_from_slice(&e.to_le_bytes());
            }
            decode_dimms(&parse_structures(&build_structure(17, 1, &b, &["A", "B", "C", "D", "E"])))[0].size_mib
        };
        assert_eq!(mk(8192, None), 8192);
        assert_eq!(mk(0x7FFF, Some(65536)), 65536);
        assert_eq!(mk(0x8000 | 2048, None), 2); // 2048 KB
        assert_eq!(mk(0xFFFF, None), 0);
    }

    #[test]
    fn meminfo() {
        assert_eq!(parse_meminfo("MemTotal:       16384 kB\nMemFree: 1 kB\nMemAvailable:    8192 kB\nSwapTotal:       512 kB\n"), (16384, 8192, 512));
    }
}
