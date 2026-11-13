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

#[cfg(test)]
mod tests {
    use super::*;

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
