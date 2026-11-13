//! HELLO / CHALLENGE / OPEN / OPEN_OK payloads, session key derivation, stateless cookie (PROTOCOL.md 4.2). Owner: P1.

use std::io;

use crate::crypto::{hmac_sha256, random_bytes};
use crate::frame::FrameError;
use crate::keys::Role;
use crate::mac::Mac;

#[derive(Clone, Debug, PartialEq)]
pub struct Hello {
    pub cn: [u8; 16],
    pub key_id: [u8; 4],
    pub ver_min: u8,
    pub ver_max: u8,
    pub max_frag: u16,
    pub caps: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Challenge {
    pub sn: [u8; 16],
    pub boot_id: [u8; 8],
    pub uptime_ms: u32,
    pub ver: u8,
    pub max_frag: u16,
    pub caps: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OpenOk {
    pub role: Role,
    pub idle_s: u16,
    pub frag: u16,
    pub window: u16,
    pub caps: u32,
    pub hostname: String,
}

pub const HELLO_LEN: usize = 48;
pub const CHALLENGE_LEN: usize = 36;

impl Hello {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; HELLO_LEN];
        b[0..16].copy_from_slice(&self.cn);
        b[16..20].copy_from_slice(&self.key_id);
        b[20] = self.ver_min;
        b[21] = self.ver_max;
        b[22..24].copy_from_slice(&self.max_frag.to_be_bytes());
        b[24..28].copy_from_slice(&self.caps.to_be_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Hello, FrameError> {
        if b.len() < HELLO_LEN {
            return Err(FrameError::BadPayload("hello too short"));
        }
        Ok(Hello {
            cn: b[0..16].try_into().unwrap(),
            key_id: b[16..20].try_into().unwrap(),
            ver_min: b[20],
            ver_max: b[21],
            max_frag: u16::from_be_bytes([b[22], b[23]]),
            caps: u32::from_be_bytes(b[24..28].try_into().unwrap()),
        })
    }
}

impl Challenge {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; CHALLENGE_LEN];
        b[0..16].copy_from_slice(&self.sn);
        b[16..24].copy_from_slice(&self.boot_id);
        b[24..28].copy_from_slice(&self.uptime_ms.to_be_bytes());
        b[28] = self.ver;
        b[30..32].copy_from_slice(&self.max_frag.to_be_bytes());
        b[32..36].copy_from_slice(&self.caps.to_be_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Challenge, FrameError> {
        if b.len() < CHALLENGE_LEN {
            return Err(FrameError::BadPayload("challenge too short"));
        }
        Ok(Challenge {
            sn: b[0..16].try_into().unwrap(),
            boot_id: b[16..24].try_into().unwrap(),
            uptime_ms: u32::from_be_bytes(b[24..28].try_into().unwrap()),
            ver: b[28],
            max_frag: u16::from_be_bytes([b[30], b[31]]),
            caps: u32::from_be_bytes(b[32..36].try_into().unwrap()),
        })
    }
}

impl OpenOk {
    pub fn encode(&self) -> Vec<u8> {
        let host = self.hostname.as_bytes();
        let hl = host.len().min(255);
        let mut b = vec![0u8; 14];
        b[0] = self.role as u8;
        b[2..4].copy_from_slice(&self.idle_s.to_be_bytes());
        b[4..6].copy_from_slice(&self.frag.to_be_bytes());
        b[6..8].copy_from_slice(&self.window.to_be_bytes());
        b[8..12].copy_from_slice(&self.caps.to_be_bytes());
        b[12..14].copy_from_slice(&(hl as u16).to_be_bytes());
        b.extend_from_slice(&host[..hl]);
        b
    }
    pub fn decode(b: &[u8]) -> Result<OpenOk, FrameError> {
        if b.len() < 14 {
            return Err(FrameError::BadPayload("open_ok too short"));
        }
        let hl = u16::from_be_bytes([b[12], b[13]]) as usize;
        let host = b.get(14..14 + hl).ok_or(FrameError::BadPayload("hostname truncated"))?;
        Ok(OpenOk {
            role: if b[0] == 0 { Role::Admin } else { Role::Ro },
            idle_s: u16::from_be_bytes([b[2], b[3]]),
            frag: u16::from_be_bytes([b[4], b[5]]),
            window: u16::from_be_bytes([b[6], b[7]]),
            caps: u32::from_be_bytes(b[8..12].try_into().unwrap()),
            hostname: String::from_utf8_lossy(host).into_owned(),
        })
    }
}

/// SK = HMAC(K, "i7c-sess\0" | cn | sn | client_mac | server_mac | ver)
pub fn session_key(k: &[u8; 32], cn: &[u8; 16], sn: &[u8; 16], client: &Mac, server: &Mac, ver: u8) -> [u8; 32] {
    hmac_sha256(k, &[b"i7c-sess\0", cn, sn, &client.0, &server.0, &[ver]])
}

/// session id = big-endian u32 of sn[0..4]
pub fn session_id(sn: &[u8; 16]) -> u32 {
    u32::from_be_bytes([sn[0], sn[1], sn[2], sn[3]])
}

/// Stateless cookie: sn = first16(HMAC(secret, cli | srv | cn | tags | bucket)), bucket = now_ms / 15000.
pub struct CookieJar {
    secret: [u8; 32],
}

pub const COOKIE_BUCKET_MS: u64 = 15_000;

impl CookieJar {
    pub fn new() -> io::Result<CookieJar> {
        let mut secret = [0u8; 32];
        random_bytes(&mut secret)?;
        Ok(CookieJar { secret })
    }

    pub fn with_secret(secret: [u8; 32]) -> CookieJar {
        CookieJar { secret }
    }

    fn at(&self, bucket: u64, cli: &Mac, srv: &Mac, cn: &[u8; 16], tags: &[(u16, u16)]) -> [u8; 16] {
        let mut t = Vec::with_capacity(tags.len() * 4);
        for (a, b) in tags {
            t.extend_from_slice(&a.to_be_bytes());
            t.extend_from_slice(&b.to_be_bytes());
        }
        let h = hmac_sha256(&self.secret, &[&cli.0, &srv.0, cn, &t, &bucket.to_be_bytes()]);
        h[..16].try_into().unwrap()
    }

    pub fn make(&self, now_ms: u64, cli: &Mac, srv: &Mac, cn: &[u8; 16], tags: &[(u16, u16)]) -> [u8; 16] {
        self.at(now_ms / COOKIE_BUCKET_MS, cli, srv, cn, tags)
    }

    /// Accepts the current and the previous bucket (15 to 30 s validity).
    pub fn check(&self, now_ms: u64, cli: &Mac, srv: &Mac, cn: &[u8; 16], tags: &[(u16, u16)], sn: &[u8; 16]) -> bool {
        let b = now_ms / COOKIE_BUCKET_MS;
        let cur = self.at(b, cli, srv, cn, tags);
        let ok_cur = crate::crypto::ct_eq(&cur, sn);
        let ok_prev = b > 0 && crate::crypto::ct_eq(&self.at(b - 1, cli, srv, cn, tags), sn);
        ok_cur | ok_prev
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn payload_roundtrips() {
        let h = Hello { cn: [0x11; 16], key_id: [1, 2, 3, 4], ver_min: 1, ver_max: 1, max_frag: 1400, caps: 0 };
        assert_eq!(Hello::decode(&h.encode()).unwrap(), h);
        let c = Challenge { sn: [0x22; 16], boot_id: [9; 8], uptime_ms: 5, ver: 1, max_frag: 1400, caps: 0x3ff };
        assert_eq!(Challenge::decode(&c.encode()).unwrap(), c);
        let o = OpenOk { role: Role::Ro, idle_s: 120, frag: 1400, window: 16, caps: 7, hostname: "h".into() };
        assert_eq!(OpenOk::decode(&o.encode()).unwrap(), o);
        assert_eq!(session_id(&[0x22; 16]), 0x2222_2222);
    }
    #[test]
    fn cookie_window() {
        let j = CookieJar::with_secret([5; 32]);
        let (a, b) = (Mac([2, 0, 0, 0, 0, 1]), Mac([2, 0, 0, 0, 0, 2]));
        let sn = j.make(100_000, &a, &b, &[1; 16], &[]);
        assert!(j.check(100_000 + 15_000, &a, &b, &[1; 16], &[], &sn));
        assert!(!j.check(100_000 + 31_000, &a, &b, &[1; 16], &[], &sn));
    }
}
