//! Request authentication: the i7labd HTTP scheme (labproto::httpauth), identical bytes on the wire.
//!   X-Lab-Key:   hex key id (first 4 bytes of SHA256("i7c-keyid"|K))
//!   X-Lab-Nonce: from GET /nonce (single use, 30 s)
//!   X-Lab-Auth:  hex(HMAC(K, "lp-req\n" nonce "\n" method "\n" target "\n" hex(sha256(body))))
//! Responses to authenticated requests carry X-Lab-Proof = hex(HMAC(K, "lp-resp\n" nonce "\n" status "\n" hex(sha256(body)))).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::crypto;
use crate::httpauth::{self, NonceStore};
use crate::keys::{KeySet, Role};

pub const NONCE_TTL: Duration = Duration::from_secs(30);
pub const NONCE_CAP: usize = 256;
const LOCK_AFTER: u32 = 10;
const LOCK_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    Missing,
    BadKey,
    BadNonce,
    BadMac,
    Locked,
}

pub struct Authed {
    pub role: Role,
    pub key: [u8; 32],
    pub nonce: String,
    pub fp: String,
}

/// After `LOCK_AFTER` failures from one address inside a minute the address gets 429 for the rest of that minute.
#[derive(Default)]
pub struct AuthGuard {
    fails: HashMap<IpAddr, (u32, Instant)>,
}

impl AuthGuard {
    pub fn locked(&mut self, ip: IpAddr, now: Instant) -> bool {
        match self.fails.get(&ip) {
            Some((n, t)) if now.duration_since(*t) < LOCK_WINDOW => *n >= LOCK_AFTER,
            Some(_) => {
                self.fails.remove(&ip);
                false
            }
            None => false,
        }
    }
    pub fn fail(&mut self, ip: IpAddr, now: Instant) {
        if self.fails.len() > 1024 {
            self.fails.retain(|_, (_, t)| now.duration_since(*t) < LOCK_WINDOW);
        }
        let e = self.fails.entry(ip).or_insert((0, now));
        if now.duration_since(e.1) >= LOCK_WINDOW {
            *e = (0, now);
        }
        e.0 += 1;
    }
}

pub fn new_nonces() -> NonceStore {
    NonceStore::new(NONCE_CAP, NONCE_TTL)
}

/// `hdr(name)` returns the value of a lower-case header name.
#[allow(clippy::too_many_arguments)]
pub fn authenticate(
    keys: &KeySet,
    nonces: &mut NonceStore,
    guard: &mut AuthGuard,
    peer: IpAddr,
    method: &str,
    target: &str,
    body: &[u8],
    hdr: &dyn Fn(&str) -> Option<String>,
    now: Instant,
) -> Result<Authed, AuthError> {
    if guard.locked(peer, now) {
        return Err(AuthError::Locked);
    }
    let fail = |g: &mut AuthGuard, e: AuthError| {
        g.fail(peer, now);
        Err(e)
    };
    let (Some(kid), Some(nonce), Some(auth)) = (hdr("x-lab-key"), hdr("x-lab-nonce"), hdr("x-lab-auth")) else {
        return fail(guard, AuthError::Missing);
    };
    let id = crypto::unhex(kid.trim()).and_then(|v| <[u8; 4]>::try_from(v).ok());
    let Some(key) = id.and_then(|id| keys.by_id(&id)) else {
        return fail(guard, AuthError::BadKey);
    };
    // consumed whether or not the MAC is right
    if !nonces.take(nonce.trim(), now) {
        return fail(guard, AuthError::BadNonce);
    }
    let want = httpauth::request_mac(&key.bytes, nonce.trim(), method, target, body);
    if !httpauth::check_hex_mac(&want, &auth) {
        return fail(guard, AuthError::BadMac);
    }
    Ok(Authed { role: key.role, key: key.bytes, nonce: nonce.trim().to_string(), fp: key.fingerprint() })
}

pub fn proof(a: &Authed, status: u16, body: &[u8]) -> String {
    crypto::hex(&httpauth::response_mac(&a.key, &a.nonce, status, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Key;

    fn ks() -> KeySet {
        KeySet { admin: Some(Key { role: Role::Admin, bytes: [1; 32] }), ro: Some(Key { role: Role::Ro, bytes: [2; 32] }) }
    }
    const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 9));

    // Vectors computed independently with python3 hmac/hashlib (tools/oracled-curl.py uses the same code path):
    //   key=0x01*32 nonce="abcd" method=POST target="/run?x=1" body={"name":"a.exe"}
    #[test]
    fn request_mac_vector() {
        let body = br#"{"name":"a.exe"}"#;
        let mac = httpauth::request_mac(&[1; 32], "abcd", "POST", "/run?x=1", body);
        assert_eq!(crypto::hex(&mac), "514ec892c0b84d20bd525d2af9f240616dc3dc789eb27ee212b6610e26ddeea4");
        let p = httpauth::response_mac(&[1; 32], "abcd", 200, b"{}");
        assert_eq!(crypto::hex(&p), "0a23e438de74cb06f669fcf5a7adffa11aaf5bcf15f58138b94830c8189d86cf");
    }

    fn call(ks: &KeySet, n: &mut NonceStore, g: &mut AuthGuard, kid: &str, nonce: &str, auth: &str) -> Result<Authed, AuthError> {
        let (kid, nonce, auth) = (kid.to_string(), nonce.to_string(), auth.to_string());
        let h = move |k: &str| match k {
            "x-lab-key" => Some(kid.clone()),
            "x-lab-nonce" => Some(nonce.clone()),
            "x-lab-auth" => Some(auth.clone()),
            _ => None,
        };
        authenticate(ks, n, g, IP, "GET", "/info", b"", &h, Instant::now())
    }

    #[test]
    fn accept_replay_and_roles() {
        let ks = ks();
        let mut n = new_nonces();
        let mut g = AuthGuard::default();
        let kid = ks.ro.as_ref().unwrap().fingerprint();
        let nonce = n.issue(Instant::now()).unwrap();
        let mac = crypto::hex(&httpauth::request_mac(&[2; 32], &nonce, "GET", "/info", b""));
        let a = call(&ks, &mut n, &mut g, &kid, &nonce, &mac).unwrap();
        assert_eq!(a.role, Role::Ro);
        // replay of the same nonce
        assert_eq!(call(&ks, &mut n, &mut g, &kid, &nonce, &mac).err(), Some(AuthError::BadNonce));
        // wrong key bytes
        let nonce = n.issue(Instant::now()).unwrap();
        let bad = crypto::hex(&httpauth::request_mac(&[9; 32], &nonce, "GET", "/info", b""));
        assert_eq!(call(&ks, &mut n, &mut g, &kid, &nonce, &bad).err(), Some(AuthError::BadMac));
        assert_eq!(call(&ks, &mut n, &mut g, "deadbeef", "x", "y").err(), Some(AuthError::BadKey));
    }

    #[test]
    fn lockout() {
        let ks = ks();
        let mut n = new_nonces();
        let mut g = AuthGuard::default();
        for _ in 0..LOCK_AFTER {
            assert_eq!(call(&ks, &mut n, &mut g, "deadbeef", "x", "y").err(), Some(AuthError::BadKey));
        }
        assert_eq!(call(&ks, &mut n, &mut g, "deadbeef", "x", "y").err(), Some(AuthError::Locked));
    }
}
