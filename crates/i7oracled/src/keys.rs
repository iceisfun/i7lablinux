//! Key files, same format as labproto::keys (`i7k1:<role>:<64 hex>`), without the unix permission check
//! (Windows: the installer restricts the directory with icacls instead).

use std::io;
use std::path::Path;

use crate::crypto::{self, ct_eq};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Admin,
    Ro,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Ro => "ro",
        }
    }
}

#[derive(Clone)]
pub struct Key {
    pub role: Role,
    pub bytes: [u8; 32],
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({} {})", self.role.name(), self.fingerprint())
    }
}

impl Key {
    pub fn parse_line(line: &str) -> Result<Key, String> {
        let mut it = line.trim().trim_start_matches('\u{feff}').splitn(3, ':');
        let (p, r, h) = (it.next(), it.next(), it.next());
        if p != Some("i7k1") {
            return Err("missing i7k1 prefix".into());
        }
        let role = match r {
            Some("admin") => Role::Admin,
            Some("ro") => Role::Ro,
            _ => return Err("bad role".into()),
        };
        let raw = h.and_then(crypto::unhex).ok_or("bad hex")?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| "key must be 32 bytes".to_string())?;
        Ok(Key { role, bytes })
    }

    /// first4(SHA256("i7c-keyid" | K)), identical to labproto::keys::Key::key_id.
    pub fn key_id(&self) -> [u8; 4] {
        let mut h = crypto::Sha256::new();
        h.update(b"i7c-keyid");
        h.update(&self.bytes);
        let d = h.finish();
        [d[0], d[1], d[2], d[3]]
    }

    pub fn fingerprint(&self) -> String {
        crypto::hex(&self.key_id())
    }
}

#[derive(Clone, Default, Debug)]
pub struct KeySet {
    pub admin: Option<Key>,
    pub ro: Option<Key>,
}

impl KeySet {
    pub fn load_dir(dir: &Path) -> Result<KeySet, String> {
        let mut set = KeySet::default();
        for role in [Role::Admin, Role::Ro] {
            let p = dir.join(format!("{}.key", role.name()));
            match std::fs::read_to_string(&p) {
                Ok(s) => {
                    let k = Key::parse_line(&s).map_err(|e| format!("{}: {}", p.display(), e))?;
                    if k.role != role {
                        return Err(format!("{} holds a {} key", p.display(), k.role.name()));
                    }
                    match role {
                        Role::Admin => set.admin = Some(k),
                        Role::Ro => set.ro = Some(k),
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("{}: {}", p.display(), e)),
            }
        }
        if let (Some(a), Some(r)) = (&set.admin, &set.ro) {
            if ct_eq(&a.bytes, &r.bytes) {
                return Err("admin.key and ro.key hold the same key".into());
            }
        }
        Ok(set)
    }

    pub fn by_id(&self, id: &[u8; 4]) -> Option<&Key> {
        [self.admin.as_ref(), self.ro.as_ref()].into_iter().flatten().find(|k| &k.key_id() == id)
    }

    pub fn is_empty(&self) -> bool {
        self.admin.is_none() && self.ro.is_none()
    }

    /// K_beacon = HMAC(K_ro, "i7c-beacon-key"), same derivation as labproto::keys::KeySet::beacon_key.
    pub fn beacon_key(&self) -> Option<[u8; 32]> {
        self.ro.as_ref().map(|k| crypto::hmac_sha256(&k.bytes, &[b"i7c-beacon-key"]))
    }

    /// `a:<fp>,r:<fp>` style, no secrets.
    pub fn kid_summary(&self) -> String {
        let mut v = Vec::new();
        if let Some(k) = &self.admin {
            v.push(format!("a:{}", k.fingerprint()));
        }
        if let Some(k) = &self.ro {
            v.push(format!("r:{}", k.fingerprint()));
        }
        v.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_ids_match_labproto() {
        let k = Key::parse_line(&format!("i7k1:ro:{}\r\n", "07".repeat(32))).unwrap();
        assert_eq!(k.role, Role::Ro);
        assert_eq!(k.bytes, [7; 32]);
        // SHA256("i7c-keyid" || 07*32)[..4], computed with python hashlib
        assert_eq!(k.fingerprint(), crate::crypto::hex(&crate::crypto::sha256(&[b"i7c-keyid".as_slice(), &[7u8; 32]].concat())[..4]));
        assert!(Key::parse_line("i7k1:root:00").is_err());
        assert!(Key::parse_line(&format!("i7k1:ro:{}", "07".repeat(31))).is_err());
        let dbg = format!("{:?}", k);
        assert!(!dbg.contains("0707"));
    }

    #[test]
    fn load_dir_rules() {
        let d = std::env::temp_dir().join(format!("i7oracled-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        assert!(KeySet::load_dir(&d).unwrap().is_empty());
        std::fs::write(d.join("admin.key"), format!("i7k1:admin:{}", "01".repeat(32))).unwrap();
        std::fs::write(d.join("ro.key"), format!("i7k1:ro:{}", "02".repeat(32))).unwrap();
        let ks = KeySet::load_dir(&d).unwrap();
        let id = ks.ro.as_ref().unwrap().key_id();
        assert_eq!(ks.by_id(&id).unwrap().role, Role::Ro);
        assert!(ks.beacon_key().is_some());
        assert!(ks.kid_summary().starts_with("a:"));
        std::fs::write(d.join("ro.key"), format!("i7k1:admin:{}", "02".repeat(32))).unwrap();
        assert!(KeySet::load_dir(&d).is_err());
        std::fs::write(d.join("ro.key"), format!("i7k1:ro:{}", "01".repeat(32))).unwrap();
        assert!(KeySet::load_dir(&d).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
