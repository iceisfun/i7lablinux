//! Streaming image writer core and GPT backup relocation for `blk.image`. The writer never buffers more than one
//! record; every function takes the already-gated `&File` of a `WriteGuard` (the only way to get a writable block
//! handle), so nothing here can bypass the safety gate. Everything also works on a regular file (host tests).
//!
//! Zero ranges: `ImageWriter::write_zeros` uses BLKZEROOUT (the kernel zero-fills with WRITE ZEROES or
//! unmap-with-zeroes where the device guarantees that, else it writes zero pages), and falls back to ordinary
//! zero writes when the ioctl is unavailable. BLKDISCARD is deliberately NOT used: its read-back content is
//! unspecified, which would make the verification inexact.

use std::fs::File;
use std::io;

use labproto::crypto::Sha256;

use super::ioctl::{self, AlignedBuf};
use super::parttable::{check_backup, crc32, parse_gpt_header};

const ZERO_PIECE: u64 = 1 << 30;
const IO_CHUNK: usize = 1 << 20;

pub struct ImageWriter<'a> {
    file: &'a File,
    block: u64,
    base: u64,
    size: u64,
    buf: AlignedBuf,
    zeros: Option<AlignedBuf>,
    ioctl_zero: bool,
    /// bytes zeroed by BLKZEROOUT / written as zero pages (statistics)
    pub zero_ioctl_bytes: u64,
    pub zero_written_bytes: u64,
}

fn bad(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

impl<'a> ImageWriter<'a> {
    /// `block`: logical block size; `base`: byte offset of the image on the device; `size`: image bytes.
    pub fn new(file: &'a File, block: u64, dev_size: u64, base: u64, size: u64) -> io::Result<ImageWriter<'a>> {
        if block < 512 || !block.is_power_of_two() {
            return Err(bad(format!("bad logical block size {}", block)));
        }
        if base % block != 0 {
            return Err(bad(format!("destination offset {} is not a multiple of the logical block size {}", base, block)));
        }
        if size == 0 || base.checked_add(size).map_or(true, |e| e > dev_size) {
            return Err(bad(format!("image of {} bytes at offset {} does not fit a device of {} bytes", size, base, dev_size)));
        }
        Ok(ImageWriter { file, block, base, size, buf: AlignedBuf::new(IO_CHUNK), zeros: None, ioctl_zero: true, zero_ioctl_bytes: 0, zero_written_bytes: 0 })
    }

    fn round_up(&self, n: u64) -> u64 {
        n.div_ceil(self.block) * self.block
    }

    fn check_range(&self, off: u64, len: u64) -> io::Result<()> {
        let end = off.checked_add(len).filter(|e| *e <= self.size).ok_or_else(|| bad(format!("range {}+{} is outside the image ({} bytes)", off, len, self.size)))?;
        if off % self.block != 0 {
            return Err(bad(format!("offset {} is not a multiple of the logical block size {}", off, self.block)));
        }
        if len % self.block != 0 && end != self.size {
            return Err(bad(format!("a range of {} bytes that is not a multiple of {} may only end the image", len, self.block)));
        }
        Ok(())
    }

    /// pwrite `data` at image offset `off`. A final partial block is zero-padded to the block size.
    pub fn write_data(&mut self, off: u64, data: &[u8]) -> io::Result<()> {
        self.check_range(off, data.len() as u64)?;
        let padded = self.round_up(data.len() as u64) as usize;
        if self.buf.len() < padded {
            self.buf = AlignedBuf::new(padded);
        }
        let b = self.buf.as_mut_slice();
        b[..data.len()].copy_from_slice(data);
        b[data.len()..padded].fill(0);
        ioctl::write_all_at(self.file, &self.buf.as_slice()[..padded], self.base + off)
    }

    /// Make `[off, off+len)` of the image read back as zeros.
    pub fn write_zeros(&mut self, off: u64, len: u64) -> io::Result<()> {
        self.check_range(off, len)?;
        let total = self.round_up(len);
        let mut done = 0u64;
        while done < total {
            let n = (total - done).min(ZERO_PIECE);
            let at = self.base + off + done;
            if self.ioctl_zero {
                match ioctl::zero_out(self.file, at, n) {
                    Ok(()) => {
                        self.zero_ioctl_bytes += n;
                        done += n;
                        continue;
                    }
                    // not a block device / not supported: ordinary writes from now on
                    Err(e) if matches!(e.raw_os_error(), Some(25) | Some(95) | Some(22) | Some(38)) => self.ioctl_zero = false,
                    Err(e) => return Err(e),
                }
            }
            let z = self.zeros.get_or_insert_with(|| AlignedBuf::new(IO_CHUNK));
            let mut w = 0u64;
            while w < n {
                let k = (n - w).min(z.len() as u64) as usize;
                ioctl::write_all_at(self.file, &z.as_slice()[..k], at + w)?;
                w += k as u64;
            }
            self.zero_written_bytes += n;
            done += n;
        }
        Ok(())
    }

    /// Feed `h` with the `len` image bytes at `off`, read back from the device in 1 MiB steps.
    pub fn hash_range(&mut self, off: u64, len: u64, h: &mut Sha256) -> io::Result<()> {
        self.check_range(off, len)?;
        let mut done = 0u64;
        while done < len {
            let n = (len - done).min(IO_CHUNK as u64);
            let padded = self.round_up(n) as usize;
            let got = ioctl::read_full_at(self.file, &mut self.buf.as_mut_slice()[..padded], self.base + off + done)?;
            if (got as u64) < n {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!("short read at {} (got {} of {})", off + done, got, n)));
            }
            h.update(&self.buf.as_slice()[..n as usize]);
            done += n;
        }
        Ok(())
    }

    /// fsync and drop the device's page cache (so a following read comes from the device).
    pub fn sync(&self) -> io::Result<()> {
        ioctl::flush(self.file)
    }

    pub fn durable_sync(&self) -> io::Result<()> {
        self.file.sync_data()
    }
}

// ------------------------------------------------------------------------------------------------ GPT

/// What `relocate_backup_gpt` did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GptMove {
    /// "none" (no GPT on the disk), "already_at_end" (valid backup at the last LBA), "moved"
    pub action: &'static str,
    pub backup_lba: u64,
    pub last_usable: u64,
    /// `--grow-last`: (partition index 1-based, old last LBA, new last LBA)
    pub grown: Option<(u32, u64, u64)>,
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

fn read_lbas(f: &File, block: u64, lba: u64, n: u64) -> Result<AlignedBuf, String> {
    let mut b = AlignedBuf::new((n * block) as usize);
    let got = ioctl::read_full_at(f, &mut b.as_mut_slice()[..(n * block) as usize], lba * block).map_err(|e| format!("read LBA {}: {}", lba, e))?;
    if (got as u64) < n * block {
        return Err(format!("short read at LBA {}", lba));
    }
    Ok(b)
}

fn write_lbas(f: &File, block: u64, lba: u64, data: &[u8]) -> Result<(), String> {
    let n = (data.len() as u64).div_ceil(block) * block;
    let mut b = AlignedBuf::new(n as usize);
    b.as_mut_slice()[..data.len()].copy_from_slice(data);
    ioctl::write_all_at(f, &b.as_slice()[..n as usize], lba * block).map_err(|e| format!("write LBA {}: {}", lba, e))
}

/// The equivalent of `sgdisk -e`: when the disk is larger than the GPT in its first sectors describes, write
/// the backup header and entry array at the end of the disk and fix the primary header (alternate LBA, last
/// usable LBA, CRCs). The primary entry array is left unchanged unless `grow_last` extends the last partition.
/// The protective MBR's size field is brought up to date (like gdisk). Refuses (Err, nothing written) a GPT whose
/// header or entry CRC is bad, whose backup lies beyond the disk, or whose partitions would not fit.
pub fn relocate_backup_gpt(f: &File, dev_size: u64, block: u64, grow_last: bool) -> Result<GptMove, String> {
    let total = dev_size / block;
    if total < 68 {
        return Err("disk too small for a GPT".into());
    }
    let last_lba = total - 1;
    let sec1 = read_lbas(f, block, 1, 1)?;
    let h = &sec1.as_slice()[..block as usize];
    let Some(hd) = parse_gpt_header(h) else {
        return Ok(GptMove { action: "none", backup_lba: 0, last_usable: 0, grown: None });
    };
    if !hd.crc_ok {
        return Err("primary GPT header CRC is bad; not touching the disk".into());
    }
    if hd.my_lba != 1 {
        return Err(format!("GPT header says it lives at LBA {}, but it is at LBA 1 (image made for another sector size?)", hd.my_lba));
    }
    let hsize = le32(h, 12) as usize;
    let (num, esize) = (hd.num_entries as u64, hd.entry_size as u64);
    if !(128..=1024).contains(&esize) || esize % 8 != 0 || num == 0 || num > 4096 {
        return Err(format!("unsupported GPT entry array ({} entries of {} bytes)", num, esize));
    }
    let arr_bytes = (num * esize) as usize;
    let arr_sectors = (arr_bytes as u64).div_ceil(block);
    if hd.entries_lba < 2 || hd.entries_lba + arr_sectors > last_lba {
        return Err(format!("GPT entry array at LBA {} does not fit the disk", hd.entries_lba));
    }
    if hd.alt_lba > last_lba {
        return Err(format!("the image's GPT backup (LBA {}) lies beyond the end of this disk (last LBA {})", hd.alt_lba, last_lba));
    }
    let arr = read_lbas(f, block, hd.entries_lba, arr_sectors)?;
    let mut entries = arr.as_slice()[..arr_bytes].to_vec();
    if crc32(&entries) != hd.entries_crc {
        return Err("primary GPT entry array CRC is bad; not touching the disk".into());
    }
    let backup_entries_lba = last_lba - arr_sectors;
    let new_last_usable = backup_entries_lba - 1;
    let old_last_usable = le64(h, 48);

    // partitions: highest end must fit; optional growth of the one that ends last
    let mut grown = None;
    let mut last_part: Option<(usize, u64)> = None;
    for i in 0..num as usize {
        let e = &entries[i * esize as usize..(i + 1) * esize as usize];
        if e[..16].iter().all(|b| *b == 0) {
            continue;
        }
        let end = le64(e, 40);
        if end > new_last_usable {
            return Err(format!("partition {} ends at LBA {}, beyond the usable area of this disk ({})", i + 1, end, new_last_usable));
        }
        if last_part.map_or(true, |(_, l)| end > l) {
            last_part = Some((i, end));
        }
    }
    let mut entries_changed = false;
    if grow_last {
        if let Some((i, end)) = last_part {
            if end < new_last_usable {
                let o = i * esize as usize + 40;
                entries[o..o + 8].copy_from_slice(&new_last_usable.to_le_bytes());
                grown = Some((i as u32 + 1, end, new_last_usable));
                entries_changed = true;
            }
        }
    }

    // already in the final state? (valid backup at the last LBA, same usable area, nothing to grow)
    if !entries_changed && hd.alt_lba == last_lba && old_last_usable == new_last_usable {
        let last = read_lbas(f, block, last_lba, 1)?;
        if check_backup(&last.as_slice()[..block as usize], last_lba) {
            return Ok(GptMove { action: "already_at_end", backup_lba: last_lba, last_usable: new_last_usable, grown: None });
        }
    }

    let new_ecrc = crc32(&entries);
    let mut header = h.to_vec();
    let mk = |mut hdr: Vec<u8>, my: u64, alt: u64, elba: u64| -> Vec<u8> {
        hdr[24..32].copy_from_slice(&my.to_le_bytes());
        hdr[32..40].copy_from_slice(&alt.to_le_bytes());
        hdr[48..56].copy_from_slice(&new_last_usable.to_le_bytes());
        hdr[72..80].copy_from_slice(&elba.to_le_bytes());
        hdr[88..92].copy_from_slice(&new_ecrc.to_le_bytes());
        hdr[16..20].fill(0);
        let c = crc32(&hdr[..hsize]);
        hdr[16..20].copy_from_slice(&c.to_le_bytes());
        hdr
    };
    let primary = mk(std::mem::take(&mut header), 1, last_lba, hd.entries_lba);
    // backup header: same fields, zero tail of the sector
    let mut backup = vec![0u8; block as usize];
    backup[..hsize].copy_from_slice(&primary[..hsize]);
    let backup = mk(backup, last_lba, 1, backup_entries_lba);

    // order: backup entries, backup header, (primary entries), primary header, protective MBR
    write_lbas(f, block, backup_entries_lba, &entries)?;
    write_lbas(f, block, last_lba, &backup)?;
    if entries_changed {
        write_lbas(f, block, hd.entries_lba, &entries)?;
    }
    write_lbas(f, block, 1, &primary)?;
    fix_protective_mbr(f, block, last_lba)?;
    f.sync_data().map_err(|e| format!("fsync: {}", e))?;
    Ok(GptMove { action: "moved", backup_lba: last_lba, last_usable: new_last_usable, grown })
}

/// Set the sector count of the 0xEE entry of the protective MBR to `min(last_lba, 0xFFFFFFFF)`.
fn fix_protective_mbr(f: &File, block: u64, last_lba: u64) -> Result<(), String> {
    let s0 = read_lbas(f, block, 0, 1)?;
    let mut m = s0.as_slice()[..block as usize].to_vec();
    if m[510] != 0x55 || m[511] != 0xAA {
        return Ok(());
    }
    let want = last_lba.min(0xFFFF_FFFF) as u32;
    let mut changed = false;
    for i in 0..4 {
        let o = 446 + i * 16;
        if m[o + 4] == 0xEE {
            let cur = u32::from_le_bytes(m[o + 12..o + 16].try_into().unwrap());
            if cur != want {
                m[o + 12..o + 16].copy_from_slice(&want.to_le_bytes());
                changed = true;
            }
            break;
        }
    }
    if changed {
        write_lbas(f, block, 0, &m)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::parttable::{build_gpt, parse};
    use super::*;
    use std::fs::OpenOptions;
    use std::os::unix::fs::FileExt;

    fn tmp(label: &str, size: u64) -> (std::path::PathBuf, File) {
        let p = std::env::temp_dir().join(format!("i7img-{}-{}-{}", label, std::process::id(), size));
        let f = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&p).unwrap();
        f.set_len(size).unwrap();
        (p, f)
    }

    /// `build_gpt` plus first/last usable LBAs and a header CRC that covers them, for an image of `sectors`.
    fn synthetic(block: usize, sectors: u64, parts: &[(u64, u64, &str)]) -> Vec<u8> {
        let mut img = build_gpt(block, sectors, parts);
        let arr_sectors = (128u64 * 128).div_ceil(block as u64);
        let h = &mut img[block..block + 92];
        h[40..48].copy_from_slice(&(2 + arr_sectors).to_le_bytes());
        h[48..56].copy_from_slice(&(sectors - 2 - arr_sectors).to_le_bytes());
        h[16..20].fill(0);
        let c = crc32(&h[..92].to_vec());
        h[16..20].copy_from_slice(&c.to_le_bytes());
        img
    }

    fn put(f: &File, off: u64, d: &[u8]) {
        f.write_all_at(d, off).unwrap();
    }
    fn get(f: &File, off: u64, n: usize) -> Vec<u8> {
        let mut b = vec![0u8; n];
        f.read_exact_at(&mut b, off).unwrap();
        b
    }

    #[test]
    fn gpt_relocation_512_and_4096() {
        for block in [512u64, 4096] {
            let img_sectors = 20000u64;
            let disk_sectors = 50000u64;
            let (p, f) = tmp(&format!("gpt{}", block), disk_sectors * block);
            let img = synthetic(block as usize, img_sectors, &[(2048, 4095, "ESP"), (4096, 9999, "data")]);
            put(&f, 0, &img);
            let before_entries = get(&f, 2 * block, 128 * 128);
            let r = relocate_backup_gpt(&f, disk_sectors * block, block, false).unwrap();
            let arr_sectors = (128 * 128u64).div_ceil(block);
            assert_eq!(r.action, "moved");
            assert_eq!(r.backup_lba, disk_sectors - 1);
            assert_eq!(r.last_usable, disk_sectors - 2 - arr_sectors);
            // primary: header updated, entries untouched
            let prim = get(&f, block, block as usize);
            let hd = parse_gpt_header(&prim).unwrap();
            assert!(hd.crc_ok);
            assert_eq!((hd.my_lba, hd.alt_lba, hd.entries_lba), (1, disk_sectors - 1, 2));
            assert_eq!(le64(&prim, 48), disk_sectors - 2 - arr_sectors);
            assert_eq!(get(&f, 2 * block, 128 * 128), before_entries);
            // backup: valid, points back, entries equal and CRC-correct
            let back = get(&f, (disk_sectors - 1) * block, block as usize);
            assert!(check_backup(&back, disk_sectors - 1));
            let bh = parse_gpt_header(&back).unwrap();
            assert_eq!(bh.entries_lba, disk_sectors - 1 - arr_sectors);
            let be = get(&f, bh.entries_lba * block, 128 * 128);
            assert_eq!(be, before_entries);
            assert_eq!(crc32(&be), bh.entries_crc);
            assert_eq!(bh.disk_guid, hd.disk_guid);
            // the whole table still parses and sees both partitions
            let head = get(&f, 0, 34 * block as usize);
            let (t, parts) = parse(&head, block as u32).unwrap();
            assert!(t.header_crc_ok && t.entries_crc_ok);
            assert_eq!(parts.len(), 2);
            // protective MBR size field
            let mbr = get(&f, 0, 512);
            assert_eq!(le32(&mbr, 446 + 12), (disk_sectors - 1) as u32);
            // idempotent
            let again = relocate_backup_gpt(&f, disk_sectors * block, block, false).unwrap();
            assert_eq!(again.action, "already_at_end");
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn grow_last_extends_only_the_last_partition_and_both_copies() {
        let (p, f) = tmp("grow", 60000 * 512);
        put(&f, 0, &synthetic(512, 20000, &[(2048, 4095, "ESP"), (4096, 9999, "data")]));
        let r = relocate_backup_gpt(&f, 60000 * 512, 512, true).unwrap();
        let new_last = 60000 - 2 - 32;
        assert_eq!(r.grown, Some((2, 9999, new_last)));
        let head = get(&f, 0, 34 * 512);
        let (t, parts) = parse(&head, 512).unwrap();
        assert!(t.header_crc_ok && t.entries_crc_ok);
        assert_eq!((parts[0].first_lba, parts[0].last_lba), (2048, 4095));
        assert_eq!((parts[1].first_lba, parts[1].last_lba), (4096, new_last));
        // the backup copy has the same grown entries with a matching CRC
        let back = get(&f, 59999 * 512, 512);
        let bh = parse_gpt_header(&back).unwrap();
        let be = get(&f, bh.entries_lba * 512, 128 * 128);
        assert_eq!(crc32(&be), bh.entries_crc);
        assert_eq!(le64(&be, 128 + 40), new_last);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn refusals_leave_the_disk_untouched() {
        // no GPT at all
        let (p, f) = tmp("nogpt", 1 << 20);
        assert_eq!(relocate_backup_gpt(&f, 1 << 20, 512, false).unwrap().action, "none");
        // bad header CRC
        let (p2, f2) = tmp("badcrc", 50000 * 512);
        let mut img = synthetic(512, 20000, &[(2048, 4095, "ESP")]);
        img[512 + 40] ^= 1;
        put(&f2, 0, &img);
        let snapshot = get(&f2, 0, 40 * 512);
        assert!(relocate_backup_gpt(&f2, 50000 * 512, 512, false).unwrap_err().contains("CRC"));
        assert_eq!(get(&f2, 0, 40 * 512), snapshot);
        // bad entry CRC
        let (p3, f3) = tmp("badecrc", 50000 * 512);
        let mut img = synthetic(512, 20000, &[(2048, 4095, "ESP")]);
        img[1024 + 56] ^= 1;
        put(&f3, 0, &img);
        assert!(relocate_backup_gpt(&f3, 50000 * 512, 512, false).unwrap_err().contains("entry array CRC"));
        // image GPT describes a bigger disk than this one
        let (p4, f4) = tmp("toobig", 10000 * 512);
        put(&f4, 0, &synthetic(512, 20000, &[(2048, 4095, "ESP")]));
        assert!(relocate_backup_gpt(&f4, 10000 * 512, 512, false).unwrap_err().contains("beyond the end"));
        for x in [p, p2, p3, p4] {
            let _ = std::fs::remove_file(x);
        }
    }

    #[test]
    fn writer_pads_the_tail_zeroes_and_hashes() {
        let (p, f) = tmp("wr", 8 << 20);
        let size = (3 << 20) + 100;
        let mut w = ImageWriter::new(&f, 512, 8 << 20, 4096, size).unwrap();
        let data: Vec<u8> = (0..(1 << 20)).map(|i| (i % 251) as u8).collect();
        put(&f, 0, &vec![0xEE; 8 << 20]); // pre-existing garbage
        w.write_data(0, &data).unwrap();
        w.write_zeros(1 << 20, 1 << 20).unwrap();
        w.write_data(2 << 20, &data).unwrap();
        let tail = vec![9u8; (1 << 20) + 100];
        w.write_data(2 << 20, &vec![0u8; (1 << 20) + 101]).unwrap_err(); // runs past the end of the image
        w.write_data(3 << 20, &tail[..100]).unwrap();
        assert_eq!(get(&f, 4096, 16), data[..16]);
        assert!(get(&f, 4096 + (1 << 20), 1 << 20).iter().all(|b| *b == 0));
        // the 100-byte tail is padded with zeros to the next 512 boundary, nothing beyond is touched
        assert_eq!(get(&f, 4096 + (3 << 20), 100), vec![9u8; 100]);
        assert!(get(&f, 4096 + (3 << 20) + 100, 412).iter().all(|b| *b == 0));
        assert_eq!(get(&f, 4096 + (3 << 20) + 512, 4), vec![0xEE; 4]);
        assert_eq!(get(&f, 0, 4), vec![0xEE; 4]);
        // re-read hash equals the hash of what the image should contain
        let mut want = Vec::new();
        want.extend(&data);
        want.extend(vec![0u8; 1 << 20]);
        want.extend(&data);
        want.extend(&tail[..100]);
        let mut h = Sha256::new();
        w.hash_range(0, size, &mut h).unwrap();
        assert_eq!(h.finish(), labproto::crypto::sha256(&want));
        assert!(w.zero_written_bytes >= 1 << 20, "regular file: ioctl unavailable, fell back to writes");
        // misaligned or out-of-range use is an error, not a write
        assert!(w.write_data(100, b"x").is_err());
        assert!(w.write_zeros(0, size + 512).is_err());
        assert!(ImageWriter::new(&f, 512, 8 << 20, 100, 10).is_err());
        assert!(ImageWriter::new(&f, 512, 1 << 20, 0, (1 << 20) + 1).is_err());
        let _ = std::fs::remove_file(p);
    }
}
