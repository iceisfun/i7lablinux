//! Randomness for the labproto crypto module (it calls `crate::sys::getrandom_blocking`).

use std::io;

#[cfg(windows)]
pub fn getrandom_blocking(buf: &mut [u8]) -> io::Result<()> {
    // RtlGenRandom (advapi32 exports it as SystemFunction036); no import library name for it, so declare it.
    #[link(name = "advapi32")]
    extern "system" {
        #[link_name = "SystemFunction036"]
        fn RtlGenRandom(buf: *mut u8, len: u32) -> u8;
    }
    for chunk in buf.chunks_mut(1 << 16) {
        // SAFETY: chunk is a valid writable slice.
        if unsafe { RtlGenRandom(chunk.as_mut_ptr(), chunk.len() as u32) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn getrandom_blocking(buf: &mut [u8]) -> io::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)
}
