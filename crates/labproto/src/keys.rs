//! Key files and key sets. Owner: P1. Scheme: docs/PLAN.md section 5, PROTOCOL.md 4.1.

use std::io;
use std::path::{Path, PathBuf};

use crate::crypto;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Admin = 0,
    Ro = 1,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Ro => "ro",
        }
    }
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "admin" => Some(Role::Admin),
            "ro" => Some(Role::Ro),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct Key {
    pub role: Role,
    pub bytes: [u8; 32],
}

/// Redacted: prints role + fingerprint only, never key bytes (review security F17). `to_line` is the only way
/// to get the secret as text and is called only by `key show --secret` / `key export` and the key writers.
impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({} {})", self.role.name(), self.fingerprint())
    }
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug)]
pub enum KeyError {
    Io(io::Error),
    Format(String),
    Permissions(PathBuf),
}

impl From<io::Error> for KeyError {
    fn from(e: io::Error) -> Self {
        KeyError::Io(e)
    }
}

pub const KEY_LINE_PREFIX: &str = "i7k1";

impl Key {
    pub fn generate(role: Role) -> io::Result<Key> {
        let mut bytes = [0u8; 32];
        crypto::random_bytes(&mut bytes)?;
        Ok(Key { role, bytes })
    }

    /// Parse `i7k1:<role>:<64 lowercase hex>` (surrounding whitespace ignored).
    pub fn parse_line(line: &str) -> Result<Key, KeyError> {
        let mut it = line.trim().splitn(3, ':');
        let (p, r, h) = (it.next(), it.next(), it.next());
        if p != Some(KEY_LINE_PREFIX) {
            return Err(KeyError::Format("missing i7k1 prefix".into()));
        }
        let role = r.and_then(Role::parse).ok_or_else(|| KeyError::Format("bad role".into()))?;
        let raw = h.and_then(crypto::unhex).ok_or_else(|| KeyError::Format("bad hex".into()))?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| KeyError::Format("key must be 32 bytes".into()))?;
        Ok(Key { role, bytes })
    }

    pub fn to_line(&self) -> String {
        format!("{}:{}:{}", KEY_LINE_PREFIX, self.role.name(), crypto::hex(&self.bytes))
    }

    /// first4(SHA256("i7c-keyid" | K))
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

    /// The documented, public demo key: K = SHA256("i7lablinux-demo-<role>") (PLAN.md section 5).
    pub fn demo(role: Role) -> Key {
        Key { role, bytes: crypto::sha256(format!("i7lablinux-demo-{}", role.name()).as_bytes()) }
    }

    /// Either public demo key, whatever role the file claims (a real admin file holding the demo ro bytes is
    /// just as public).
    pub fn is_demo(&self) -> bool {
        [Role::Admin, Role::Ro].iter().any(|r| crypto::ct_eq(&self.bytes, &Key::demo(*r).bytes))
    }
}

#[derive(Clone, Default, Debug)]
pub struct KeySet {
    pub admin: Option<Key>,
    pub ro: Option<Key>,
}

impl KeySet {
    /// Load `admin.key` and `ro.key` from `dir`. Missing files are `None`; a file readable by group/other is an error.
    pub fn load_dir(dir: &Path) -> Result<KeySet, KeyError> {
        let mut set = KeySet::default();
        for role in [Role::Admin, Role::Ro] {
            let p = dir.join(format!("{}.key", role.name()));
            match std::fs::read_to_string(&p) {
                Ok(s) => {
                    {
                        use std::os::unix::fs::PermissionsExt;
                        // a key readable by group/other is refused (it may already have leaked)
                        if std::fs::metadata(&p)?.permissions().mode() & 0o077 != 0 {
                            return Err(KeyError::Permissions(p));
                        }
                    }
                    let k = Key::parse_line(&s)?;
                    if k.role != role {
                        return Err(KeyError::Format(format!("{} holds a {} key", p.display(), k.role.name())));
                    }
                    match role {
                        Role::Admin => set.admin = Some(k),
                        Role::Ro => set.ro = Some(k),
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        // the same bytes in both files would make every ro holder admin (by_id finds admin first)
        if let (Some(a), Some(r)) = (&set.admin, &set.ro) {
            if crypto::ct_eq(&a.bytes, &r.bytes) {
                return Err(KeyError::Format("admin.key and ro.key hold the same key".into()));
            }
        }
        Ok(set)
    }

    pub fn by_id(&self, id: &[u8; 4]) -> Option<&Key> {
        [self.admin.as_ref(), self.ro.as_ref()].into_iter().flatten().find(|k| &k.key_id() == id)
    }

    /// true if any loaded key is a demo key. i7labd then runs in demo policy (PLAN.md C20): admin requests are
    /// downgraded to ro unless the host is a QEMU/KVM guest.
    pub fn is_demo(&self) -> bool {
        [self.admin.as_ref(), self.ro.as_ref()].into_iter().flatten().any(Key::is_demo)
    }

    /// K_beacon = HMAC(K_ro, "i7c-beacon-key")
    pub fn beacon_key(&self) -> Option<[u8; 32]> {
        self.ro.as_ref().map(|k| crypto::hmac_sha256(&k.bytes, &[b"i7c-beacon-key"]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn line_roundtrip() {
        let k = Key { role: Role::Ro, bytes: [7; 32] };
        let k2 = Key::parse_line(&k.to_line()).unwrap();
        assert_eq!(k2.role, Role::Ro);
        assert_eq!(k2.bytes, [7; 32]);
        assert!(Key::parse_line("i7k1:root:00").is_err());
    }

    #[test]
    fn group_readable_key_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("i7ll-keyperm-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("ro.key");
        std::fs::write(&f, Key { role: Role::Ro, bytes: [3; 32] }.to_line()).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(KeySet::load_dir(&d).unwrap().ro.is_some());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(KeySet::load_dir(&d), Err(KeyError::Permissions(_))));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn identical_admin_and_ro_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("i7ll-keysame-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        for role in [Role::Admin, Role::Ro] {
            let f = d.join(format!("{}.key", role.name()));
            std::fs::write(&f, Key { role, bytes: [9; 32] }.to_line()).unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(KeySet::load_dir(&d), Err(KeyError::Format(_))));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn debug_is_redacted() {
        let k = Key { role: Role::Admin, bytes: [0xab; 32] };
        let d = format!("{:?} {}", k, k);
        assert!(!d.contains("abababab"), "{}", d);
        assert!(format!("{:?}", KeySet { admin: Some(k), ro: None }).len() < 200);
    }

    #[test]
    fn demo_detection() {
        assert!(Key::demo(Role::Ro).is_demo());
        assert!(!Key { role: Role::Ro, bytes: [1; 32] }.is_demo());
        assert!(KeySet { admin: Some(Key::demo(Role::Admin)), ro: None }.is_demo());
        assert!(Key { role: Role::Admin, bytes: Key::demo(Role::Ro).bytes }.is_demo(), "role-swapped demo bytes");
    }
}
