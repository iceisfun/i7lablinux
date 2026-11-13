//! The only `unsafe` in labprobe: block-device ioctls over `labproto::sys::ioctl_ptr` and an aligned I/O buffer
//! (O_DIRECT needs buffer, offset and length aligned to the logical block size). Owner: P4.
//! Every function degrades on regular files (test fixtures): the ioctl wrappers return `Err(ENOTTY)`.

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;

pub const O_EXCL: i32 = 0o200;
pub const O_NOFOLLOW: i32 = 0o400000;
pub const O_DIRECT: i32 = 0o40000;
const BLKROGET: u64 = 0x125E;
const BLKRRPART: u64 = 0x125F;
const BLKFLSBUF: u64 = 0x1261;
const BLKSSZGET: u64 = 0x1268;
const BLKGETSIZE64: u64 = 0x8008_1272;

/// Buffer aligned to 4096 (enough for any logical block size we meet).
pub struct AlignedBuf {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: the buffer is uniquely owned heap memory.
unsafe impl Send for AlignedBuf {}

impl AlignedBuf {
    pub fn new(len: usize) -> AlignedBuf {
        let len = len.max(4096).div_ceil(4096) * 4096;
        let layout = Layout::from_size_align(len, 4096).expect("valid layout");
        // SAFETY: layout has non-zero size.
        let ptr = unsafe { alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "out of memory");
        AlignedBuf { ptr, len }
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr is valid for len bytes and initialised (zeroed at allocation).
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as above, and `&mut self` is unique.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        let layout = Layout::from_size_align(self.len, 4096).expect("valid layout");
        // SAFETY: allocated in `new` with this exact layout.
        unsafe { dealloc(self.ptr, layout) }
    }
}

/// Open options. `direct` retries without O_DIRECT only when the file is not a block device (tmpfs rejects it
/// with EINVAL); on a real block device an EINVAL stays an error.
pub fn open(path: &Path, write: bool, excl: bool, direct: bool) -> io::Result<File> {
    let mut flags = 0;
    if excl {
        // exclusive claim, and never through a symlink planted at /dev/<name>
        flags |= O_EXCL | O_NOFOLLOW;
    }
    let try_open = |extra: i32| {
        let mut o = OpenOptions::new();
        o.read(true).write(write).custom_flags(flags | extra | 0o2000000 /* O_CLOEXEC */);
        o.open(path)
    };
    if !direct {
        return try_open(0);
    }
    match try_open(O_DIRECT) {
        Err(e) if e.raw_os_error() == Some(22) && !is_block_device(path) => try_open(0),
        r => r,
    }
}

pub fn is_block_device(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(path).map(|m| m.file_type().is_block_device()).unwrap_or(false)
}

fn ioctl(f: &File, req: u64, arg: *mut u8) -> io::Result<()> {
    // SAFETY: every caller passes either null or a pointer to a live local of the size `req` encodes.
    unsafe { labproto::sys::ioctl_ptr(f.as_raw_fd(), req, arg) }.map(|_| ())
}

/// Size in bytes: BLKGETSIZE64 for block devices, file length otherwise.
pub fn size_bytes(f: &File) -> io::Result<u64> {
    let md = f.metadata()?;
    if md.is_file() {
        return Ok(md.len());
    }
    let mut v: u64 = 0;
    ioctl(f, BLKGETSIZE64, &mut v as *mut u64 as *mut u8)?;
    Ok(v)
}

pub fn logical_block(f: &File) -> Option<u32> {
    let mut v: i32 = 0;
    ioctl(f, BLKSSZGET, &mut v as *mut i32 as *mut u8).ok()?;
    u32::try_from(v).ok().filter(|b| *b >= 512)
}

/// BLKROGET; `false` on regular files.
pub fn read_only(f: &File) -> bool {
    let mut v: i32 = 0;
    ioctl(f, BLKROGET, &mut v as *mut i32 as *mut u8).map(|_| v != 0).unwrap_or(false)
}

/// fsync + BLKFLSBUF (drop the page cache of the device). BLKFLSBUF is skipped on regular files.
pub fn flush(f: &File) -> io::Result<()> {
    f.sync_all()?;
    match ioctl(f, BLKFLSBUF, std::ptr::null_mut()) {
        Err(e) if e.raw_os_error() == Some(25) => Ok(()), // ENOTTY: regular file
        r => r,
    }
}

pub fn reread_partitions(f: &File) -> io::Result<()> {
    ioctl(f, BLKRRPART, std::ptr::null_mut())
}

/// pread until `buf` is full or EOF; returns bytes read. Retries EINTR.
pub fn read_full_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        match f.read_at(&mut buf[done..], off + done as u64) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(done)
}

/// pwrite the whole buffer. Retries EINTR.
pub fn write_all_at(f: &File, buf: &[u8], off: u64) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        match f.write_at(&buf[done..], off + done as u64) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Result of one SG_IO request.
#[derive(Clone, Debug, Default)]
pub struct SgResult {
    /// SCSI status byte (0 good, 2 check condition)
    pub status: u8,
    pub host_status: u16,
    pub driver_status: u16,
    pub sense: Vec<u8>,
}

/// `struct sg_io_hdr` of <scsi/sg.h> (x86_64 layout, 88 bytes).
#[repr(C)]
struct SgIoHdr {
    interface_id: i32,
    dxfer_direction: i32,
    cmd_len: u8,
    mx_sb_len: u8,
    iovec_count: u16,
    dxfer_len: u32,
    dxferp: *mut u8,
    cmdp: *mut u8,
    sbp: *mut u8,
    timeout: u32,
    flags: u32,
    pack_id: i32,
    usr_ptr: *mut u8,
    status: u8,
    masked_status: u8,
    msg_status: u8,
    sb_len_wr: u8,
    host_status: u16,
    driver_status: u16,
    resid: i32,
    duration: u32,
    info: u32,
}

const SG_IO: u64 = 0x2285;
const SG_DXFER_NONE: i32 = -1;
const SG_DXFER_FROM_DEV: i32 = -3;

/// One SCSI CDB through SG_IO (read-only commands only: no data goes to the device). `data` is the buffer the
/// device fills (`None` = no data phase). Errors are the ioctl's own (not a SCSI check condition: that is in the result).
pub fn sg_io(f: &File, cdb: &[u8], data: Option<&mut [u8]>, timeout_ms: u32) -> io::Result<SgResult> {
    let mut cdb = cdb.to_vec();
    let mut sense = [0u8; 64];
    let (dir, ptr, len) = match data {
        Some(d) => (SG_DXFER_FROM_DEV, d.as_mut_ptr(), d.len() as u32),
        None => (SG_DXFER_NONE, std::ptr::null_mut(), 0),
    };
    let mut h = SgIoHdr {
        interface_id: b'S' as i32,
        dxfer_direction: dir,
        cmd_len: cdb.len() as u8,
        mx_sb_len: sense.len() as u8,
        iovec_count: 0,
        dxfer_len: len,
        dxferp: ptr,
        cmdp: cdb.as_mut_ptr(),
        sbp: sense.as_mut_ptr(),
        timeout: timeout_ms,
        flags: 0,
        pack_id: 0,
        usr_ptr: std::ptr::null_mut(),
        status: 0,
        masked_status: 0,
        msg_status: 0,
        sb_len_wr: 0,
        host_status: 0,
        driver_status: 0,
        resid: 0,
        duration: 0,
        info: 0,
    };
    ioctl(f, SG_IO, &mut h as *mut SgIoHdr as *mut u8)?;
    let n = (h.sb_len_wr as usize).min(sense.len());
    Ok(SgResult { status: h.status, host_status: h.host_status, driver_status: h.driver_status, sense: sense[..n].to_vec() })
}

/// `struct nvme_admin_cmd` of <linux/nvme_ioctl.h> (72 bytes).
#[repr(C)]
#[derive(Default)]
struct NvmeAdminCmd {
    opcode: u8,
    flags: u8,
    rsvd1: u16,
    nsid: u32,
    cdw2: u32,
    cdw3: u32,
    metadata: u64,
    addr: u64,
    metadata_len: u32,
    data_len: u32,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
    timeout_ms: u32,
    result: u32,
}

/// NVME_IOCTL_ADMIN_CMD = _IOWR('N', 0x41, struct nvme_admin_cmd)
const NVME_IOCTL_ADMIN_CMD: u64 = 0xC048_4E41;

/// One admin command that reads `buf.len()` bytes into `buf` (Identify, Get Log Page: never a write or format
/// opcode; callers pass only 0x02 and 0x06). Returns the NVMe status field (0 = success).
pub fn nvme_admin_read(f: &File, opcode: u8, nsid: u32, cdw10: u32, buf: &mut AlignedBuf, len: usize) -> io::Result<u32> {
    assert!(matches!(opcode, 0x02 | 0x06), "only Get Log Page and Identify");
    assert!(len <= buf.len());
    let mut c = NvmeAdminCmd { opcode, nsid, addr: buf.as_mut_slice().as_mut_ptr() as u64, data_len: len as u32, cdw10, timeout_ms: 5000, ..Default::default() };
    let r = ioctl_ret(f, NVME_IOCTL_ADMIN_CMD, &mut c as *mut NvmeAdminCmd as *mut u8)?;
    Ok(r as u32)
}

fn ioctl_ret(f: &File, req: u64, arg: *mut u8) -> io::Result<i32> {
    // SAFETY: as `ioctl`: `arg` points at a live local of the size `req` encodes (the buffer it references outlives the call).
    unsafe { labproto::sys::ioctl_ptr(f.as_raw_fd(), req, arg) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_layouts_match_the_kernel_headers() {
        assert_eq!(std::mem::size_of::<NvmeAdminCmd>(), 72);
        assert_eq!(std::mem::size_of::<SgIoHdr>(), 88);
    }

    #[test]
    fn aligned() {
        let mut b = AlignedBuf::new(10);
        assert_eq!(b.len(), 4096);
        assert_eq!(b.as_slice().as_ptr() as usize % 4096, 0);
        b.as_mut_slice()[5] = 7;
        assert_eq!(b.as_slice()[5], 7);
    }

    #[test]
    fn regular_file_degrades() {
        let p = std::env::temp_dir().join(format!("i7ll-ioctl-{}", std::process::id()));
        std::fs::write(&p, vec![1u8; 8192]).unwrap();
        let f = open(&p, false, false, true).unwrap();
        assert_eq!(size_bytes(&f).unwrap(), 8192);
        assert!(!read_only(&f));
        assert!(logical_block(&f).is_none());
        let mut b = vec![0u8; 100];
        assert_eq!(read_full_at(&f, &mut b, 8150).unwrap(), 42);
        let _ = std::fs::remove_file(&p);
    }
}
