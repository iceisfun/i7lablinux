//! Protective MBR / GPT (with CRC checks) / legacy MBR parsing from raw sectors. Pure. Owner: P4.

use labproto::json::{JsonWriter, ToJson};

#[derive(Clone, Debug, PartialEq)]
pub struct Partition {
    pub index: u32,
    pub first_lba: u64,
    pub last_lba: u64,
    pub type_guid: Option<String>,
    pub mbr_type: Option<u8>,
    pub name: Option<String>,
    pub part_uuid: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PartTable {
    /// "gpt" | "mbr"
    pub kind: String,
    pub disk_guid: Option<String>,
    /// GPT header CRC32 matches (always true for mbr)
    pub header_crc_ok: bool,
    /// GPT entry array CRC32 matches; true for mbr, and true for a GPT whose entry array is not fully inside the
    /// buffer handed to `parse` (cannot be checked)
    pub entries_crc_ok: bool,
    /// GPT backup header at the last LBA is valid and points back at the primary (filled by the caller that read
    /// the last sector, see `check_backup`); `None` when not checked
    pub backup_ok: Option<bool>,
}

/// CRC-32 (IEEE 802.3, reflected, as used by GPT).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn le64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// GUID in the usual text form (first three fields little endian), lower case.
pub fn guid_string(b: &[u8]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        le32(b, 0),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Fields of a GPT header that matter here.
#[derive(Clone, Debug, PartialEq)]
pub struct GptHeader {
    pub crc_ok: bool,
    pub my_lba: u64,
    pub alt_lba: u64,
    pub disk_guid: String,
    pub entries_lba: u64,
    pub num_entries: u32,
    pub entry_size: u32,
    pub entries_crc: u32,
}

/// Parse a GPT header sector ("EFI PART"). `None` when the signature or header size is wrong.
pub fn parse_gpt_header(sector: &[u8]) -> Option<GptHeader> {
    if sector.len() < 92 || &sector[0..8] != b"EFI PART" {
        return None;
    }
    let hsize = le32(sector, 12) as usize;
    if !(92..=sector.len()).contains(&hsize) {
        return None;
    }
    let stored = le32(sector, 16);
    let mut copy = sector[..hsize].to_vec();
    copy[16..20].fill(0);
    Some(GptHeader {
        crc_ok: crc32(&copy) == stored,
        my_lba: le64(sector, 24),
        alt_lba: le64(sector, 32),
        disk_guid: guid_string(&sector[56..72]),
        entries_lba: le64(sector, 72),
        num_entries: le32(sector, 80),
        entry_size: le32(sector, 84),
        entries_crc: le32(sector, 88),
    })
}

/// Check the backup header read from the last LBA: valid CRC, `my_lba == last_lba`, `alt_lba` = primary (1).
pub fn check_backup(last_sector: &[u8], last_lba: u64) -> bool {
    parse_gpt_header(last_sector).map(|h| h.crc_ok && h.my_lba == last_lba && h.alt_lba == 1).unwrap_or(false)
}

fn utf16_name(b: &[u8]) -> Option<String> {
    let units: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|u| *u != 0).collect();
    if units.is_empty() {
        None
    } else {
        Some(String::from_utf16_lossy(&units))
    }
}

/// Parse a partition table from the first sectors (`head` covers LBA 0..=33 at `block` bytes per sector).
/// GPT wins over the protective MBR. A boot sector that merely ends in 0x55AA (FAT, NTFS) is not an MBR table:
/// at least one entry must be plausible (status 0x00/0x80, non-zero type, non-zero start and size) and no entry
/// may have another status byte.
pub fn parse(head: &[u8], block: u32) -> Option<(PartTable, Vec<Partition>)> {
    let block = block as usize;
    if block < 512 {
        return None;
    }
    if head.len() >= block * 2 {
        if let Some(h) = parse_gpt_header(&head[block..block * 2]) {
            let mut parts = Vec::new();
            let mut entries_crc_ok = true;
            let esize = h.entry_size as usize;
            if (128..=4096).contains(&esize) && esize % 8 == 0 && h.num_entries <= 4096 && h.entries_lba >= 2 {
                let start = h.entries_lba as usize * block;
                let total = esize * h.num_entries as usize;
                if start + total <= head.len() {
                    let arr = &head[start..start + total];
                    entries_crc_ok = crc32(arr) == h.entries_crc;
                    for i in 0..h.num_entries as usize {
                        let e = &arr[i * esize..(i + 1) * esize];
                        if e[..16].iter().all(|b| *b == 0) {
                            continue;
                        }
                        parts.push(Partition {
                            index: i as u32 + 1,
                            first_lba: le64(e, 32),
                            last_lba: le64(e, 40),
                            type_guid: Some(guid_string(&e[0..16])),
                            mbr_type: None,
                            name: utf16_name(&e[56..esize.min(128)]),
                            part_uuid: Some(guid_string(&e[16..32])),
                        });
                    }
                }
            }
            return Some((
                PartTable { kind: "gpt".into(), disk_guid: Some(h.disk_guid), header_crc_ok: h.crc_ok, entries_crc_ok, backup_ok: None },
                parts,
            ));
        }
    }
    if head.len() >= 512 && head[510] == 0x55 && head[511] == 0xAA {
        let mut parts = Vec::new();
        let disk_sig = le32(head, 0x1B8);
        for i in 0..4 {
            let e = &head[446 + i * 16..446 + (i + 1) * 16];
            if e[0] != 0x00 && e[0] != 0x80 {
                return None;
            }
            let (ty, lba, n) = (e[4], le32(e, 8) as u64, le32(e, 12) as u64);
            if ty != 0 && lba != 0 && n != 0 {
                parts.push(Partition {
                    index: i as u32 + 1,
                    first_lba: lba,
                    last_lba: lba + n - 1,
                    type_guid: None,
                    mbr_type: Some(ty),
                    name: None,
                    // Linux PARTUUID for MBR disks: <disk signature>-<partition number>
                    part_uuid: Some(format!("{:08x}-{:02x}", disk_sig, i + 1)),
                });
            }
        }
        if parts.is_empty() {
            return None;
        }
        return Some((PartTable { kind: "mbr".into(), disk_guid: None, header_crc_ok: true, entries_crc_ok: true, backup_ok: None }, parts));
    }
    None
}

impl ToJson for PartTable {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_str("kind", &self.kind);
        w.field_opt_str("disk_guid", self.disk_guid.as_deref());
        w.field_bool("header_crc_ok", self.header_crc_ok);
        w.field_bool("entries_crc_ok", self.entries_crc_ok);
        w.key("backup_ok");
        match self.backup_ok {
            Some(b) => w.bool(b),
            None => w.null(),
        }
        w.end_object();
    }
}

impl ToJson for Partition {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_u64("index", self.index as u64);
        w.field_u64("first_lba", self.first_lba);
        w.field_u64("last_lba", self.last_lba);
        w.field_opt_str("type_guid", self.type_guid.as_deref());
        w.field_opt_u64("mbr_type", self.mbr_type.map(u64::from));
        w.field_opt_str("name", self.name.as_deref());
        w.field_opt_str("part_uuid", self.part_uuid.as_deref());
        w.end_object();
    }
}

/// Build a GPT image prefix (LBA 0..=33 at `block` bytes, protective MBR, 128 entries of type "Linux filesystem",
/// entry i has PARTUUID `0101..` repeated with byte i+1): helper for tests and fixture generation.
pub fn build_gpt(block: usize, disk_sectors: u64, parts: &[(u64, u64, &str)]) -> Vec<u8> {
    let mut img = vec![0u8; block * 34];
    // protective MBR
    img[446 + 4] = 0xEE;
    img[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    img[446 + 12..446 + 16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;
    let arr_off = block * 2;
    for (i, (first, last, name)) in parts.iter().enumerate() {
        let e = &mut img[arr_off + i * 128..arr_off + (i + 1) * 128];
        e[0..16].copy_from_slice(&[0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4]);
        e[16..32].copy_from_slice(&[i as u8 + 1; 16]);
        e[32..40].copy_from_slice(&first.to_le_bytes());
        e[40..48].copy_from_slice(&last.to_le_bytes());
        for (j, u) in name.encode_utf16().enumerate() {
            e[56 + j * 2..58 + j * 2].copy_from_slice(&u.to_le_bytes());
        }
    }
    let ecrc = crc32(&img[arr_off..arr_off + 128 * 128]);
    let h = &mut img[block..block + 92];
    h[0..8].copy_from_slice(b"EFI PART");
    h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    h[12..16].copy_from_slice(&92u32.to_le_bytes());
    h[24..32].copy_from_slice(&1u64.to_le_bytes());
    h[32..40].copy_from_slice(&(disk_sectors - 1).to_le_bytes());
    h[56..72].copy_from_slice(&[0x11; 16]);
    h[72..80].copy_from_slice(&2u64.to_le_bytes());
    h[80..84].copy_from_slice(&128u32.to_le_bytes());
    h[84..88].copy_from_slice(&128u32.to_le_bytes());
    h[88..92].copy_from_slice(&ecrc.to_le_bytes());
    let hcrc = crc32(&h[..92].to_vec());
    h[16..20].copy_from_slice(&hcrc.to_le_bytes());
    img
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_known() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn gpt_512_and_4096() {
        for block in [512usize, 4096] {
            let img = build_gpt(block, 20000, &[(2048, 4095, "ESP"), (4096, 9999, "data")]);
            let (t, p) = parse(&img, block as u32).unwrap();
            assert_eq!(t.kind, "gpt");
            assert!(t.header_crc_ok && t.entries_crc_ok);
            assert_eq!(p.len(), 2);
            assert_eq!(p[0].name.as_deref(), Some("ESP"));
            assert_eq!((p[1].first_lba, p[1].last_lba), (4096, 9999));
            assert_eq!(p[0].type_guid.as_deref(), Some("0fc63daf-8483-4772-8e79-3d69d8477de4"));
            assert_eq!(p[0].part_uuid.as_deref(), Some("01010101-0101-0101-0101-010101010101"));
        }
    }

    #[test]
    fn gpt_corruption_is_reported_but_still_a_table() {
        let mut img = build_gpt(512, 20000, &[(2048, 4095, "ESP")]);
        img[512 + 40] ^= 1; // header byte
        let (t, _) = parse(&img, 512).unwrap();
        assert!(!t.header_crc_ok);
        let mut img = build_gpt(512, 20000, &[(2048, 4095, "ESP")]);
        img[1024 + 56] ^= 1; // entry byte
        let (t, _) = parse(&img, 512).unwrap();
        assert!(t.header_crc_ok && !t.entries_crc_ok);
    }

    #[test]
    fn backup_header_check() {
        let img = build_gpt(512, 20000, &[]);
        let mut backup = img[512..1024].to_vec();
        backup[24..32].copy_from_slice(&19999u64.to_le_bytes());
        backup[32..40].copy_from_slice(&1u64.to_le_bytes());
        backup[16..20].fill(0);
        let c = crc32(&backup[..92]);
        backup[16..20].copy_from_slice(&c.to_le_bytes());
        assert!(check_backup(&backup, 19999));
        assert!(!check_backup(&backup, 19998));
        assert!(!check_backup(&[0u8; 512], 19999));
    }

    #[test]
    fn legacy_mbr_and_fat_boot_sector() {
        let mut m = vec![0u8; 512];
        m[446] = 0x80;
        m[446 + 4] = 0x83;
        m[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
        m[446 + 12..446 + 16].copy_from_slice(&1000u32.to_le_bytes());
        m[510] = 0x55;
        m[511] = 0xAA;
        let (t, p) = parse(&m, 512).unwrap();
        assert_eq!((t.kind.as_str(), p.len(), p[0].mbr_type), ("mbr", 1, Some(0x83)));
        // FAT boot sector: signature but entries are boot code garbage / empty
        let mut f = vec![0u8; 512];
        f[510] = 0x55;
        f[511] = 0xAA;
        assert!(parse(&f, 512).is_none());
        f[446] = 0xE8; // invalid status byte
        assert!(parse(&f, 512).is_none());
        assert!(parse(&[0u8; 4096], 512).is_none());
    }
}
