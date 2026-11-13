//! Command frame codec, ethertype 0x88B6 (PROTOCOL.md section 3, byte exact). Owner: P1.
//! The section 12 test vector is checked in the tests below.

use crate::crypto::{ct_eq, hmac_sha256};
use crate::mac::Mac;

pub const ETHERTYPE_BEACON: u16 = 0x88B5;
pub const ETHERTYPE_CTL: u16 = 0x88B6;
pub const TPID_8021Q: u16 = 0x8100;
pub const TPID_8021AD: u16 = 0x88A8;
pub const MAGIC: [u8; 2] = [0x49, 0x37];
pub const VERSION: u8 = 1;
pub const HDR_LEN: usize = 40;
pub const TAG_LEN: usize = 16;
pub const DEFAULT_FRAG: u16 = 1400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Hello = 1,
    Challenge = 2,
    Open = 3,
    OpenOk = 4,
    Req = 5,
    Resp = 6,
    Data = 7,
    Ack = 8,
    Cancel = 9,
    Close = 10,
    Keepalive = 11,
    NoSession = 12,
    Err = 13,
    Probe = 16,
    ProbeReply = 17,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Option<FrameType> {
        use FrameType::*;
        Some(match v {
            1 => Hello,
            2 => Challenge,
            3 => Open,
            4 => OpenOk,
            5 => Req,
            6 => Resp,
            7 => Data,
            8 => Ack,
            9 => Cancel,
            10 => Close,
            11 => Keepalive,
            12 => NoSession,
            13 => Err,
            16 => Probe,
            17 => ProbeReply,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Chan {
    Msg = 0,
    Stdout = 1,
    Stderr = 2,
    Stdin = 3,
    File = 4,
    Ctl = 5,
}

pub mod flags {
    pub const FIN: u8 = 1;
    pub const ACK_REQ: u8 = 2;
    pub const REPLY: u8 = 4;
    pub const ENC: u8 = 0x80;
}

#[derive(Debug, PartialEq)]
pub enum FrameError {
    Short,
    BadMagic,
    BadVersion,
    BadLength,
    TooBig,
    Misaligned,
    BadPayload(&'static str),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub ver: u8,
    pub ftype: u8,
    pub flags: u8,
    pub chan: u8,
    pub cmd: u16,
    pub session: u32,
    pub req_id: u32,
    pub ctr: u64,
    pub msg_len: u32,
    pub off: u32,
    pub plen: u16,
    pub win: u16,
    pub status: u16,
}

impl Header {
    pub fn encode(&self) -> [u8; HDR_LEN] {
        let mut b = [0u8; HDR_LEN];
        b[0..2].copy_from_slice(&MAGIC);
        b[2] = self.ver;
        b[3] = self.ftype;
        b[4] = self.flags;
        b[5] = self.chan;
        b[6..8].copy_from_slice(&self.cmd.to_be_bytes());
        b[8..12].copy_from_slice(&self.session.to_be_bytes());
        b[12..16].copy_from_slice(&self.req_id.to_be_bytes());
        b[16..24].copy_from_slice(&self.ctr.to_be_bytes());
        b[24..28].copy_from_slice(&self.msg_len.to_be_bytes());
        b[28..32].copy_from_slice(&self.off.to_be_bytes());
        b[32..34].copy_from_slice(&self.plen.to_be_bytes());
        b[34..36].copy_from_slice(&self.win.to_be_bytes());
        b[36..38].copy_from_slice(&self.status.to_be_bytes());
        // 38..40 rsv = 0
        b
    }

    pub fn decode(b: &[u8]) -> Result<Header, FrameError> {
        if b.len() < HDR_LEN {
            return Err(FrameError::Short);
        }
        if b[0..2] != MAGIC {
            return Err(FrameError::BadMagic);
        }
        let u16_at = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
        let u32_at = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        Ok(Header {
            ver: b[2],
            ftype: b[3],
            flags: b[4],
            chan: b[5],
            cmd: u16_at(6),
            session: u32_at(8),
            req_id: u32_at(12),
            ctr: u64::from_be_bytes(b[16..24].try_into().unwrap()),
            msg_len: u32_at(24),
            off: u32_at(28),
            plen: u16_at(32),
            win: u16_at(34),
            status: u16_at(36),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Dir {
    ClientToServer = 1,
    ServerToClient = 2,
}

/// Which key and domain string authenticate a frame (PROTOCOL.md 4.2, 4.3).
pub enum TagKey<'a> {
    Hello(&'a [u8; 32]),
    Challenge { k: &'a [u8; 32], cn: &'a [u8; 16] },
    Session { sk: &'a [u8; 32], dir: Dir },
    NoSession(&'a [u8; 32]),
    /// PROBE / PROBE_REPLY: unauthenticated, tag field is zero
    None,
}

fn tag(hdr: &[u8], payload: &[u8], key: &TagKey) -> [u8; TAG_LEN] {
    let full = match key {
        TagKey::Hello(k) => hmac_sha256(*k, &[b"i7c-hello\0", hdr, payload]),
        TagKey::Challenge { k, cn } => hmac_sha256(*k, &[b"i7c-chal\0", hdr, payload, &cn[..]]),
        TagKey::Session { sk, dir } => hmac_sha256(*sk, &[&[*dir as u8], hdr, payload]),
        // PROTOCOL 4.3: HMAC(K, "i7c-nosess\0" | session | boot_id). The session id is header bytes 8..12; the 8-byte
        // boot id rides in header bytes 24..32 (msg_len | off) so a NO_SESSION frame has plen 0 and is exactly as
        // small as the smallest authenticated request (an ACK or KEEPALIVE): no amplification.
        TagKey::NoSession(k) => hmac_sha256(*k, &[b"i7c-nosess\0", &hdr[8..12], &hdr[24..32]]),
        TagKey::None => [0u8; 32],
    };
    let mut t = [0u8; TAG_LEN];
    t.copy_from_slice(&full[..TAG_LEN]);
    t
}

/// Header + payload + tag (the Ethernet payload after the ethertype). `hdr.plen` must equal `payload.len()`.
pub fn seal(hdr: &Header, payload: &[u8], key: TagKey) -> Vec<u8> {
    let h = hdr.encode();
    let mut out = Vec::with_capacity(HDR_LEN + payload.len() + TAG_LEN);
    out.extend_from_slice(&h);
    out.extend_from_slice(payload);
    out.extend_from_slice(&tag(&h, payload, &key));
    out
}

pub struct Frame<'a> {
    pub hdr: Header,
    /// the 40 header bytes as received (they are what the tag covers)
    pub raw_hdr: &'a [u8],
    pub payload: &'a [u8],
    pub tag: &'a [u8],
}

/// Parse without any crypto: magic, version, `plen` against the buffer (trailing padding ignored).
pub fn open(buf: &[u8]) -> Result<Frame<'_>, FrameError> {
    let hdr = Header::decode(buf)?;
    if hdr.ver != VERSION {
        return Err(FrameError::BadVersion);
    }
    let end = HDR_LEN + hdr.plen as usize;
    if buf.len() < end + TAG_LEN {
        return Err(FrameError::BadLength);
    }
    Ok(Frame { hdr, raw_hdr: &buf[..HDR_LEN], payload: &buf[HDR_LEN..end], tag: &buf[end..end + TAG_LEN] })
}

/// Constant-time tag check.
pub fn verify(frame: &Frame, key: TagKey) -> bool {
    ct_eq(&tag(frame.raw_hdr, frame.payload, &key), frame.tag)
}

/// Build the NO_SESSION header: `session` and `boot_id` (in `msg_len`/`off`), no payload.
pub fn nosession_header(session: u32, boot_id: &[u8; 8]) -> Header {
    Header {
        ver: VERSION,
        ftype: FrameType::NoSession as u8,
        session,
        msg_len: u32::from_be_bytes([boot_id[0], boot_id[1], boot_id[2], boot_id[3]]),
        off: u32::from_be_bytes([boot_id[4], boot_id[5], boot_id[6], boot_id[7]]),
        ..Default::default()
    }
}

/// The boot id carried by a NO_SESSION header.
pub fn nosession_boot_id(h: &Header) -> [u8; 8] {
    let a = h.msg_len.to_be_bytes();
    let b = h.off.to_be_bytes();
    [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthHeader {
    pub dst: Mac,
    pub src: Mac,
    /// (TPID, TCI) outermost first
    pub tags: Vec<(u16, u16)>,
    pub ethertype: u16,
}

/// Canonical VLAN tag stack of a received frame (review security F12): the auxdata tag (kernel-stripped outer
/// tag) if valid, then the in-band tags in wire order. More than 2 tags in total => `None` (frame dropped).
/// The session key, the reply tag stack and the BPF filter all use exactly this shape set:
/// untagged, 1 tag (in-band or auxdata), 2 tags (auxdata+in-band or 2 in-band).
pub fn canonical_tags(aux: Option<(u16, u16)>, inband: &[(u16, u16)]) -> Option<Vec<(u16, u16)>> {
    let v: Vec<(u16, u16)> = aux.into_iter().chain(inband.iter().copied()).collect();
    if v.len() > 2 {
        None
    } else {
        Some(v)
    }
}

/// Split an Ethernet frame (no FCS) into header and payload, walking up to two VLAN tags. A third tag leaves
/// `ethertype` = that TPID, so the frame never matches 0x88B5/0x88B6 and is dropped.
pub fn eth_parse(buf: &[u8]) -> Option<(EthHeader, &[u8])> {
    if buf.len() < 14 {
        return None;
    }
    let dst = Mac(buf[0..6].try_into().ok()?);
    let src = Mac(buf[6..12].try_into().ok()?);
    let mut pos = 12;
    let mut tags = Vec::new();
    loop {
        let et = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]);
        if (et == TPID_8021Q || et == TPID_8021AD) && tags.len() < 2 {
            let tci = u16::from_be_bytes([*buf.get(pos + 2)?, *buf.get(pos + 3)?]);
            tags.push((et, tci));
            pos += 4;
            continue;
        }
        return Some((EthHeader { dst, src, tags, ethertype: et }, &buf[pos + 2..]));
    }
}

/// Build an Ethernet frame, padded to the 60-byte minimum.
pub fn eth_build(h: &EthHeader, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(18 + h.tags.len() * 4 + payload.len());
    out.extend_from_slice(&h.dst.0);
    out.extend_from_slice(&h.src.0);
    for (tpid, tci) in &h.tags {
        out.extend_from_slice(&tpid.to_be_bytes());
        out.extend_from_slice(&tci.to_be_bytes());
    }
    out.extend_from_slice(&h.ethertype.to_be_bytes());
    out.extend_from_slice(payload);
    if out.len() < 60 {
        out.resize(60, 0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn header_vector_bytes() {
        // PROTOCOL.md section 12 header (tag checked by P1 once HMAC is real)
        let h = Header { ver: 1, ftype: 5, cmd: 1, session: 0x2222_2222, req_id: 1, ctr: 2, msg_len: 4, plen: 4, ..Default::default() };
        let want = "49370105000000012222222200000001000000000000000200000004000000000004000000000000";
        assert_eq!(crate::crypto::hex(&h.encode()), want);
        assert_eq!(Header::decode(&h.encode()).unwrap(), h);
    }
    #[test]
    fn protocol_section_12_vector() {
        use crate::crypto::hex;
        let k: Vec<u8> = (0u8..32).collect();
        let k: [u8; 32] = k.try_into().unwrap();
        let (cm, sm) = (Mac([2, 0, 0, 0, 0, 1]), Mac([2, 0, 0, 0, 0, 2]));
        let sk = crate::handshake::session_key(&k, &[0x11; 16], &[0x22; 16], &cm, &sm, 1);
        assert_eq!(hex(&sk), "3e2246060b62e669bcbbe0ab430f8bc9a42f16e84c77a0eaae64ec744a36e2c1");
        let h = Header { ver: 1, ftype: 5, cmd: 1, session: 0x2222_2222, req_id: 1, ctr: 2, msg_len: 4, plen: 4, ..Default::default() };
        let sealed = seal(&h, b"abcd", TagKey::Session { sk: &sk, dir: Dir::ClientToServer });
        let want = "49370105000000012222222200000001000000000000000200000004000000000004000000000000\
                    6162636459d90ce842120b5d6685d8246bcc4499";
        assert_eq!(hex(&sealed), want);
        let eth = eth_build(&EthHeader { dst: sm, src: cm, tags: vec![], ethertype: ETHERTYPE_CTL }, &sealed);
        assert_eq!(eth.len(), 74);
        assert_eq!(hex(&eth), format!("020000000002020000000001{}{}", "88b6", want));
        let f = open(&sealed).unwrap();
        assert!(verify(&f, TagKey::Session { sk: &sk, dir: Dir::ClientToServer }));
        assert!(!verify(&f, TagKey::Session { sk: &sk, dir: Dir::ServerToClient }));
        assert_eq!(hex(&crate::keys::Key { role: crate::keys::Role::Admin, bytes: k }.key_id()), "14b746da");
    }

    #[test]
    fn nosession_roundtrip() {
        let k = [3u8; 32];
        let boot = [1, 2, 3, 4, 5, 6, 7, 8];
        let h = nosession_header(0xdead_beef, &boot);
        let sealed = seal(&h, &[], TagKey::NoSession(&k));
        assert_eq!(sealed.len(), HDR_LEN + TAG_LEN);
        let f = open(&sealed).unwrap();
        assert!(verify(&f, TagKey::NoSession(&k)));
        assert_eq!(nosession_boot_id(&f.hdr), boot);
        assert!(!verify(&f, TagKey::NoSession(&[4u8; 32])));
        // another boot id or session id breaks the tag
        let mut bad = sealed.clone();
        bad[31] ^= 1;
        assert!(!verify(&open(&bad).unwrap(), TagKey::NoSession(&k)));
        let mut bad = sealed.clone();
        bad[11] ^= 1;
        assert!(!verify(&open(&bad).unwrap(), TagKey::NoSession(&k)));
    }

    #[test]
    fn open_rejects_bad_input() {
        let h = Header { ver: 1, ftype: 5, plen: 10, ..Default::default() };
        let sealed = seal(&Header { plen: 4, ..h.clone() }, b"abcd", TagKey::None);
        // plen claims 10 but only 4 bytes follow
        let mut lie = sealed.clone();
        lie[32..34].copy_from_slice(&10u16.to_be_bytes());
        assert_eq!(open(&lie).err(), Some(FrameError::BadLength));
        assert_eq!(open(&sealed[..HDR_LEN - 1]).err(), Some(FrameError::Short));
        let mut m = sealed.clone();
        m[0] = 0;
        assert_eq!(open(&m).err(), Some(FrameError::BadMagic));
        let mut v = sealed.clone();
        v[2] = 2;
        assert_eq!(open(&v).err(), Some(FrameError::BadVersion));
        // trailing Ethernet padding is ignored
        let mut padded = sealed.clone();
        padded.extend_from_slice(&[0; 30]);
        assert_eq!(open(&padded).unwrap().payload, b"abcd");
    }

    #[test]
    fn eth_parse_tag_stacks() {
        let (d, s) = (Mac([2, 0, 0, 0, 0, 2]), Mac([2, 0, 0, 0, 0, 1]));
        for tags in [vec![], vec![(0x8100, 13)], vec![(0x88a8, 100), (0x8100, 13)]] {
            let f = eth_build(&EthHeader { dst: d, src: s, tags: tags.clone(), ethertype: ETHERTYPE_CTL }, b"xyz");
            let (h, p) = eth_parse(&f).unwrap();
            assert_eq!(h.tags, tags);
            assert_eq!(h.ethertype, ETHERTYPE_CTL);
            assert_eq!(&p[..3], b"xyz");
        }
        // a third tag is not walked: ethertype stays a TPID, so the frame never matches 0x88B6
        let mut f = eth_build(&EthHeader { dst: d, src: s, tags: vec![(0x8100, 1), (0x8100, 2)], ethertype: 0x8100 }, &[0, 3, 0x88, 0xb6, 1, 2, 3]);
        f.truncate(60);
        let (h, _) = eth_parse(&f).unwrap();
        assert_eq!(h.tags.len(), 2);
        assert_eq!(h.ethertype, 0x8100);
        assert!(eth_parse(&f[..13]).is_none());
    }

    #[test]
    fn eth_roundtrip_with_tag() {
        let h = EthHeader { dst: Mac([2, 0, 0, 0, 0, 2]), src: Mac([2, 0, 0, 0, 0, 1]), tags: vec![(0x8100, 13)], ethertype: ETHERTYPE_CTL };
        let f = eth_build(&h, b"abc");
        assert_eq!(f.len(), 60);
        let (h2, p) = eth_parse(&f).unwrap();
        assert_eq!(h2, h);
        assert_eq!(&p[..3], b"abc");
    }

    #[test]
    fn canonical_tag_stack() {
        let q = |v: u16| (TPID_8021Q, v);
        assert_eq!(canonical_tags(None, &[]), Some(vec![]));
        assert_eq!(canonical_tags(Some(q(13)), &[]), Some(vec![q(13)]));
        assert_eq!(canonical_tags(None, &[q(13)]), Some(vec![q(13)]));
        assert_eq!(canonical_tags(Some((TPID_8021AD, 100)), &[q(13)]), Some(vec![(TPID_8021AD, 100), q(13)]));
        assert_eq!(canonical_tags(None, &[q(100), q(13)]), Some(vec![q(100), q(13)]));
        assert_eq!(canonical_tags(Some(q(1)), &[q(2), q(3)]), None);
        // the outer tag is never lost: aux+inband differs from inband alone
        assert_ne!(canonical_tags(Some(q(100)), &[q(13)]), canonical_tags(None, &[q(13)]));
    }
}
