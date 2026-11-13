//! HTTP request signing (lab-proxy scheme, PLAN.md C3). Owner: P1.
//! Request:  X-Lab-Key: <key id hex>, X-Lab-Nonce: <from GET /api/v1/nonce>,
//!           X-Lab-Auth = hex(HMAC(K, "lp-req\n" nonce "\n" method "\n" target "\n" hex(sha256(body))))
//! Response: X-Lab-Proof = hex(HMAC(K, "lp-resp\n" nonce "\n" status "\n" hex(sha256(body))))
//! Streams (NDJSON `?stream=1`, SSE): every event object carries `"seq":N` (0,1,2.. per response) and
//!   `"mac":hex(first16(HMAC(K, "lp-evt\n" nonce "\n" seq "\n" event_without_mac)))`; the client rejects a bad
//!   mac or a seq gap, and the final `{"event":"result"}` is just another event (review security F9).
//!   SSE uses the nonce of the `GET /api/v1/events` request.
//! Raw file bodies (`PUT/GET /api/v1/file`, PLAN.md C17) hash the streamed body: use the `_hashed` forms.

use std::collections::VecDeque;
use std::io;
use std::time::{Duration, Instant};

use crate::crypto::{ct_eq, hex, hmac_sha256, random_bytes, sha256};

pub const H_NONCE: &str = "X-Lab-Nonce";
pub const H_AUTH: &str = "X-Lab-Auth";
pub const H_PROOF: &str = "X-Lab-Proof";
pub const H_KEYID: &str = "X-Lab-Key";

pub fn request_mac(key: &[u8], nonce: &str, method: &str, target: &str, body: &[u8]) -> [u8; 32] {
    request_mac_hashed(key, nonce, method, target, &sha256(body))
}

/// Same as `request_mac` with the body hash computed by the caller (streaming `crypto::Sha256`).
pub fn request_mac_hashed(key: &[u8], nonce: &str, method: &str, target: &str, body_sha256: &[u8; 32]) -> [u8; 32] {
    let msg = format!("lp-req\n{}\n{}\n{}\n{}", nonce, method, target, hex(body_sha256));
    hmac_sha256(key, &[msg.as_bytes()])
}

pub fn response_mac(key: &[u8], nonce: &str, status: u16, body: &[u8]) -> [u8; 32] {
    response_mac_hashed(key, nonce, status, &sha256(body))
}

/// For raw streamed bodies the proof is sent as an HTTP trailer `X-Lab-Proof` after the last chunk.
pub fn response_mac_hashed(key: &[u8], nonce: &str, status: u16, body_sha256: &[u8; 32]) -> [u8; 32] {
    let msg = format!("lp-resp\n{}\n{}\n{}", nonce, status, hex(body_sha256));
    hmac_sha256(key, &[msg.as_bytes()])
}

/// Per-event tag of a stream: `event` is the canonical JSON of the event object WITHOUT the "mac" field.
pub fn event_mac(key: &[u8], nonce: &str, seq: u64, event: &str) -> [u8; 16] {
    let msg = format!("lp-evt\n{}\n{}\n{}", nonce, seq, event);
    let full = hmac_sha256(key, &[msg.as_bytes()]);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

pub fn check_hex_mac(expected: &[u8; 32], got_hex: &str) -> bool {
    ct_eq(hex(expected).as_bytes(), got_hex.trim().as_bytes())
}

/// Single-use nonces with a TTL and a cap on outstanding ones (oldest evicted).
pub struct NonceStore {
    cap: usize,
    ttl: Duration,
    items: VecDeque<(String, Instant)>,
}

impl NonceStore {
    pub fn new(cap: usize, ttl: Duration) -> NonceStore {
        NonceStore { cap, ttl, items: VecDeque::new() }
    }

    pub fn issue(&mut self, now: Instant) -> io::Result<String> {
        let mut b = [0u8; 16];
        random_bytes(&mut b)?;
        let n = hex(&b);
        self.items.retain(|(_, t)| now.duration_since(*t) < self.ttl);
        if self.items.len() >= self.cap {
            self.items.pop_front();
        }
        self.items.push_back((n.clone(), now));
        Ok(n)
    }

    pub fn take(&mut self, nonce: &str, now: Instant) -> bool {
        if let Some(i) = self.items.iter().position(|(n, t)| n == nonce && now.duration_since(*t) < self.ttl) {
            self.items.remove(i);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nonce_single_use() {
        let mut s = NonceStore::new(2, Duration::from_secs(30));
        let t = Instant::now();
        let n = s.issue(t).unwrap();
        assert!(s.take(&n, t));
        assert!(!s.take(&n, t));
    }

    #[test]
    fn hashed_forms_match() {
        let k = [3u8; 32];
        assert_eq!(request_mac(&k, "n", "PUT", "/x", b"body"), request_mac_hashed(&k, "n", "PUT", "/x", &sha256(b"body")));
        assert_ne!(event_mac(&k, "n", 0, "{}"), event_mac(&k, "n", 1, "{}"));
    }
}
