//! Wire records of `blk.image` (PROTOCOL.md section 7.1): the framing both i7labctl (sender) and i7labd (receiver)
//! use for the byte stream of a disk image. The records travel on the upload channel of the request (ether:
//! `Chan::File` DATA frames; HTTP: the body of `PUT /api/v1/blk-image`), so the transport's own reliability and
//! authentication carry them; this layer adds offsets, a SHA-256 per data chunk and a whole-image trailer.
//!
//! Record = `[type u8][body_len u32 BE][body]`:
//!   DATA (1): `offset u64 BE | sha256(payload) [32] | payload`   (1 .. MAX_PAYLOAD bytes)
//!   ZERO (2): `offset u64 BE | len u64 BE`                         (the range reads back as zeros)
//!   END  (3): `total u64 BE | sha256(whole image) [32]`
//! Offsets are image offsets (the host adds `--dest-offset`). Records must arrive in order: the host accepts a
//! record only at its current `next` offset.

use crate::crypto::sha256;

pub const T_DATA: u8 = 1;
pub const T_ZERO: u8 = 2;
pub const T_END: u8 = 3;

/// Largest DATA payload the host accepts (bounds the host's per-record memory).
pub const MAX_PAYLOAD: usize = 2 << 20;
/// Largest record body the reader accepts.
pub const MAX_BODY: usize = MAX_PAYLOAD + 40;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Data { off: u64, sha: [u8; 32], payload: Vec<u8> },
    Zero { off: u64, len: u64 },
    End { total: u64, sha: [u8; 32] },
}

fn head(t: u8, body_len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + body_len);
    v.push(t);
    v.extend_from_slice(&(body_len as u32).to_be_bytes());
    v
}

pub fn encode_data(off: u64, payload: &[u8]) -> Vec<u8> {
    let mut v = head(T_DATA, 40 + payload.len());
    v.extend_from_slice(&off.to_be_bytes());
    v.extend_from_slice(&sha256(payload));
    v.extend_from_slice(payload);
    v
}

pub fn encode_zero(off: u64, len: u64) -> Vec<u8> {
    let mut v = head(T_ZERO, 16);
    v.extend_from_slice(&off.to_be_bytes());
    v.extend_from_slice(&len.to_be_bytes());
    v
}

pub fn encode_end(total: u64, sha: &[u8; 32]) -> Vec<u8> {
    let mut v = head(T_END, 40);
    v.extend_from_slice(&total.to_be_bytes());
    v.extend_from_slice(sha);
    v
}

fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b[..8].try_into().unwrap())
}

/// Incremental parser: `push` bytes as they arrive, `next` yields whole records. Memory is bounded by one record
/// (`MAX_BODY + 5`) plus the last pushed slice.
#[derive(Default)]
pub struct RecordReader {
    buf: Vec<u8>,
    pos: usize,
}

impl RecordReader {
    pub fn new() -> RecordReader {
        RecordReader::default()
    }

    pub fn push(&mut self, b: &[u8]) {
        if self.pos > 0 && (self.pos >= 1 << 20 || self.pos * 2 >= self.buf.len()) {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(b);
    }

    /// Bytes buffered and not yet parsed.
    pub fn pending(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// `Ok(None)` = need more bytes; `Err` = the stream is not valid (unknown type, oversize, bad lengths).
    pub fn next(&mut self) -> Result<Option<Record>, String> {
        let b = &self.buf[self.pos..];
        if b.len() < 5 {
            return Ok(None);
        }
        let t = b[0];
        let len = u32::from_be_bytes([b[1], b[2], b[3], b[4]]) as usize;
        if !matches!(t, T_DATA | T_ZERO | T_END) {
            return Err(format!("unknown record type {}", t));
        }
        if len > MAX_BODY {
            return Err(format!("record body of {} bytes exceeds the {} byte limit", len, MAX_BODY));
        }
        if b.len() < 5 + len {
            return Ok(None);
        }
        let body = &b[5..5 + len];
        let rec = match t {
            T_DATA => {
                if len <= 40 {
                    return Err("DATA record without payload".into());
                }
                Record::Data { off: be64(body), sha: body[8..40].try_into().unwrap(), payload: body[40..].to_vec() }
            }
            T_ZERO => {
                if len != 16 {
                    return Err("bad ZERO record length".into());
                }
                Record::Zero { off: be64(body), len: be64(&body[8..]) }
            }
            _ => {
                if len != 40 {
                    return Err("bad END record length".into());
                }
                Record::End { total: be64(body), sha: body[8..40].try_into().unwrap() }
            }
        };
        self.pos += 5 + len;
        Ok(Some(rec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_in_odd_slices() {
        let data = vec![7u8; 1000];
        let mut wire = encode_data(4096, &data);
        wire.extend(encode_zero(5096, 1 << 20));
        wire.extend(encode_end(1 << 21, &[9; 32]));
        let mut r = RecordReader::new();
        let mut got = Vec::new();
        for c in wire.chunks(13) {
            r.push(c);
            while let Some(x) = r.next().unwrap() {
                got.push(x);
            }
        }
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], Record::Data { off: 4096, sha: sha256(&data), payload: data });
        assert_eq!(got[1], Record::Zero { off: 5096, len: 1 << 20 });
        assert_eq!(got[2], Record::End { total: 1 << 21, sha: [9; 32] });
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn rejects_garbage() {
        let mut r = RecordReader::new();
        r.push(&[9, 0, 0, 0, 1, 0]);
        assert!(r.next().is_err());
        let mut r = RecordReader::new();
        r.push(&[T_DATA, 0xff, 0xff, 0xff, 0xff]);
        assert!(r.next().unwrap_err().contains("limit"));
        let mut r = RecordReader::new();
        r.push(&[T_ZERO, 0, 0, 0, 3, 1, 2, 3]);
        assert!(r.next().is_err());
        let mut r = RecordReader::new();
        r.push(&encode_data(0, b"x")[..20]);
        assert_eq!(r.next().unwrap(), None);
    }
}
