//! Registry ~/.cache/i7labctl/hosts.json (version 2, lab-proxy compatible: a map keyed by MAC plus the v2
//! fields), aliases (~/.config/i7labctl/aliases) and host selector resolution. Owner: P9.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use labproto::beacon::Beacon;
use labproto::json::{JsonWriter, Value};
use labproto::Mac;

use crate::{jv, ClientError};

/// No beacon for this long: shown as stale.
pub const STALE_SECS: u64 = 15;
/// No beacon for this long: hidden from `ls` unless --all.
pub const AGE_OUT_SECS: u64 = 600;
/// No beacon for this long: dropped from the file.
pub const PURGE_SECS: u64 = 7 * 24 * 3600;
pub const MAX_HOSTS: usize = 1024;
pub const MAX_FIELD: usize = 128;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct HostEntry {
    pub mac: String,
    pub iface: String,
    pub stick_iface: String,
    pub src_mac: String,
    pub mac_mismatch: bool,
    pub vlan: Option<u16>,
    /// `a.b.c.d` or `a.b.c.d/N`, empty when the host has no address
    pub ip: String,
    pub host: String,
    pub product: String,
    pub vendor: String,
    pub board: String,
    pub board_serial: String,
    pub serial: String,
    pub kernel: String,
    pub link: String,
    // v2
    /// beacon version seen last: 1 or 2
    pub proto_ver: u8,
    pub proto: String,
    pub boot: String,
    pub state: String,
    pub build: String,
    pub kid: String,
    pub ctl: String,
    pub http: String,
    pub caps: String,
    pub tag_ok: Option<bool>,
    pub up: Option<u64>,
    pub first_seen: u64,
    pub last_seen: u64,
}

impl HostEntry {
    pub fn addr(&self) -> Option<&str> {
        let a = self.ip.split('/').next().unwrap_or("");
        if a.is_empty() {
            None
        } else {
            Some(a)
        }
    }
    pub fn age(&self, now: u64) -> u64 {
        now.saturating_sub(self.last_seen)
    }
    pub fn live(&self, now: u64) -> bool {
        self.age(now) <= STALE_SECS
    }
    pub fn state_word(&self, now: u64) -> &'static str {
        if self.live(now) {
            "live"
        } else {
            "stale"
        }
    }
    pub fn http_port(&self) -> Option<u16> {
        self.http.parse().ok().filter(|p| *p != 0)
    }
    /// (admin fingerprint, ro fingerprint) from `kid=a:<8hex>,r:<8hex>`
    pub fn kid_pair(&self) -> (Option<String>, Option<String>) {
        let mut a = None;
        let mut r = None;
        for part in self.kid.split(',') {
            match part.split_once(':') {
                Some(("a", v)) if !v.is_empty() => a = Some(v.to_ascii_lowercase()),
                Some(("r", v)) if !v.is_empty() => r = Some(v.to_ascii_lowercase()),
                _ => {}
            }
        }
        (a, r)
    }
    /// Notes shown by `ls` (I7LABCTL.md 3.1): `src-mac-mismatch`, `v1`, `unverified-tag`, `other-keyset`.
    pub fn flags(&self, local_fps: &[String]) -> Vec<&'static str> {
        let mut f = Vec::new();
        if self.mac_mismatch {
            f.push("src-mac-mismatch");
        }
        if self.proto_ver == 1 {
            f.push("v1");
        } else if self.tag_ok != Some(true) {
            f.push("unverified-tag");
        }
        if !self.kid.is_empty() && !self.kid_matches(local_fps) {
            f.push("other-keyset");
        }
        f
    }
    /// true when `kid` is empty/unknown or one of the local key fingerprints appears in it
    pub fn kid_matches(&self, local_fps: &[String]) -> bool {
        let (a, r) = self.kid_pair();
        if a.is_none() && r.is_none() {
            return true;
        }
        local_fps.iter().any(|fp| Some(fp) == a.as_ref() || Some(fp) == r.as_ref())
    }
}

#[derive(Clone, Debug, Default)]
pub struct Registry {
    pub hosts: BTreeMap<String, HostEntry>,
}

pub fn default_path(home: &Path) -> PathBuf {
    home.join(".cache/i7labctl/hosts.json")
}

pub fn aliases_path(home: &Path) -> PathBuf {
    home.join(".config/i7labctl/aliases")
}

#[derive(Clone, Debug, Default)]
pub struct ObserveMeta {
    pub iface: String,
    pub src_mac: Option<Mac>,
    pub vlan: Option<u16>,
    pub tag_ok: Option<bool>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Change {
    New,
    Changed,
    Same,
    Rejected,
}

fn cap(s: &str) -> String {
    let s = s.trim();
    let mut e = s.len().min(MAX_FIELD);
    while !s.is_char_boundary(e) {
        e -= 1;
    }
    s[..e].to_string()
}

/// Empty, or a dotted quad with an optional /prefix.
pub fn valid_ip_field(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    let (a, pre) = s.split_once('/').map(|(a, p)| (a, Some(p))).unwrap_or((s, None));
    a.split('.').count() == 4
        && a.split('.').all(|o| !o.is_empty() && o.len() <= 3 && o.parse::<u8>().is_ok())
        && pre.map(|p| p.parse::<u8>().map(|n| n <= 32).unwrap_or(false)).unwrap_or(true)
}

pub fn is_ipv4(s: &str) -> bool {
    !s.is_empty() && !s.contains('/') && valid_ip_field(s)
}

impl Registry {
    /// Apply one beacon. Rejects frames whose `mac=` is not a well formed unicast address or whose `ip=` is not
    /// IPv4 (PROTOCOL 10.2 reader rules). A `mac=` that differs from the Ethernet source is kept but flagged.
    pub fn observe(&mut self, b: &Beacon, m: &ObserveMeta, now: u64) -> Change {
        let Some(mac) = b.get("mac").and_then(Mac::parse).filter(|m| m.is_unicast()) else { return Change::Rejected };
        let ip = b.get("ip").unwrap_or("");
        if !valid_ip_field(ip) {
            return Change::Rejected;
        }
        let g = |k: &str| cap(b.get(k).unwrap_or(""));
        let mut e = HostEntry {
            mac: mac.to_string(),
            iface: m.iface.clone(),
            stick_iface: g("iface"),
            src_mac: m.src_mac.map(|s| s.to_string()).unwrap_or_default(),
            mac_mismatch: m.src_mac.is_some_and(|s| s != mac),
            vlan: m.vlan.or_else(|| b.get("vlan").and_then(|v| v.parse().ok()).filter(|v| *v != 0)),
            ip: ip.to_string(),
            host: g("host"),
            product: g("product"),
            vendor: g("vendor"),
            board: g("board"),
            board_serial: g("board_serial"),
            serial: g("serial"),
            kernel: g("kernel"),
            link: g("link"),
            proto_ver: b.version,
            proto: g("proto"),
            boot: g("boot"),
            state: g("state"),
            build: g("build"),
            kid: g("kid"),
            ctl: g("ctl"),
            http: g("http"),
            caps: g("caps"),
            tag_ok: if b.version == 2 { m.tag_ok } else { None },
            up: b.get("up").and_then(|v| v.parse().ok()),
            first_seen: now,
            last_seen: now,
        };
        match self.hosts.get_mut(&e.mac) {
            None => {
                while self.hosts.len() >= MAX_HOSTS {
                    self.evict_oldest();
                }
                self.hosts.insert(e.mac.clone(), e);
                Change::New
            }
            Some(old) => {
                // a v2 entry is not downgraded by a v1 frame (PROTOCOL 10.3): the v1 frame only refreshes last_seen
                if old.proto_ver == 2 && e.proto_ver == 1 {
                    old.last_seen = now;
                    return Change::Same;
                }
                e.first_seen = old.first_seen;
                let was_stale = !old.live(now);
                let mut same = e.clone();
                same.last_seen = old.last_seen;
                same.up = old.up;
                let unchanged = same == *old;
                *old = e;
                if unchanged && !was_stale {
                    Change::Same
                } else {
                    Change::Changed
                }
            }
        }
    }

    fn evict_oldest(&mut self) {
        if let Some(k) = self.hosts.values().min_by_key(|h| (h.last_seen, h.mac.clone())).map(|h| h.mac.clone()) {
            self.hosts.remove(&k);
        }
    }

    pub fn purge(&mut self, now: u64) -> usize {
        let n = self.hosts.len();
        self.hosts.retain(|_, h| h.age(now) <= PURGE_SECS);
        n - self.hosts.len()
    }

    /// Exact (case-insensitive) matches: MAC, IPv4, board serial, hostname, board name, in that order.
    pub fn find(&self, key: &str) -> Vec<&HostEntry> {
        let k = key.trim().to_ascii_lowercase();
        let preds: [&dyn Fn(&HostEntry) -> bool; 5] = [
            &|h| h.mac == k,
            &|h| h.addr() == Some(k.as_str()),
            &|h| !h.board_serial.is_empty() && h.board_serial.to_ascii_lowercase() == k,
            &|h| !h.host.is_empty() && h.host.to_ascii_lowercase() == k,
            &|h| !h.board.is_empty() && h.board.to_ascii_lowercase() == k,
        ];
        for p in preds {
            let v: Vec<&HostEntry> = self.hosts.values().filter(|h| p(h)).collect();
            if !v.is_empty() {
                return v;
            }
        }
        Vec::new()
    }

    /// Unique prefix of a MAC (at least 4 characters).
    pub fn find_prefix(&self, prefix: &str) -> Vec<&HostEntry> {
        let p = prefix.trim().to_ascii_lowercase();
        if p.len() < 4 || !p.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            return Vec::new();
        }
        self.hosts.values().filter(|h| h.mac.starts_with(&p)).collect()
    }

    pub fn to_json(&self) -> String {
        let mut w = JsonWriter::new();
        w.begin_object();
        w.field_u64("version", 2);
        w.key("hosts");
        w.begin_object();
        for h in self.hosts.values() {
            w.key(&h.mac);
            w.begin_object();
            w.field_u64("first_seen", h.first_seen);
            w.field_u64("last_seen", h.last_seen);
            w.field_str("iface", &h.iface);
            w.field_str("stick_iface", &h.stick_iface);
            w.field_str("src_mac", &h.src_mac);
            w.field_bool("mac_mismatch", h.mac_mismatch);
            w.field_opt_u64("vlan", h.vlan.map(u64::from));
            w.field_str("ip", &h.ip);
            w.field_str("board", &h.board);
            w.field_str("board_serial", &h.board_serial);
            w.field_str("host", &h.host);
            w.field_str("product", &h.product);
            w.field_str("vendor", &h.vendor);
            w.field_str("serial", &h.serial);
            w.field_str("kernel", &h.kernel);
            w.field_str("link", &h.link);
            w.field_u64("proto_ver", u64::from(h.proto_ver));
            w.field_str("proto", &h.proto);
            w.field_str("boot", &h.boot);
            w.field_str("state", &h.state);
            w.field_str("build", &h.build);
            w.field_str("kid", &h.kid);
            w.field_str("ctl", &h.ctl);
            w.field_str("http", &h.http);
            w.field_str("caps", &h.caps);
            w.key("tag_ok");
            match h.tag_ok {
                Some(b) => w.bool(b),
                None => w.null(),
            }
            w.field_opt_u64("up", h.up);
            w.end_object();
        }
        w.end_object();
        w.end_object();
        let mut s = w.finish();
        s.push('\n');
        s
    }

    pub fn from_json(s: &str) -> Option<Registry> {
        let j = jv::parse(s)?;
        let Value::Obj(hosts) = j.get("hosts")? else { return None };
        let mut r = Registry::default();
        for (mac, v) in hosts {
            let st = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            let nu = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
            let mac = match Mac::parse(mac) {
                Some(m) => m.to_string(),
                None => continue,
            };
            let proto_ver = match nu("proto_ver") {
                0 => {
                    // a v1 (lab-proxy) file has none of the v2 fields
                    if st("boot").is_empty() && st("kid").is_empty() && st("state").is_empty() {
                        1
                    } else {
                        2
                    }
                }
                n => n as u8,
            };
            r.hosts.insert(
                mac.clone(),
                HostEntry {
                    mac,
                    iface: st("iface"),
                    stick_iface: st("stick_iface"),
                    src_mac: st("src_mac"),
                    mac_mismatch: jv::b(v, "mac_mismatch").unwrap_or(false),
                    vlan: v.get("vlan").and_then(Value::as_u64).map(|n| n as u16),
                    ip: st("ip"),
                    host: st("host"),
                    product: st("product"),
                    vendor: st("vendor"),
                    board: st("board"),
                    board_serial: st("board_serial"),
                    serial: st("serial"),
                    kernel: st("kernel"),
                    link: st("link"),
                    proto_ver,
                    proto: st("proto"),
                    boot: st("boot"),
                    state: st("state"),
                    build: st("build"),
                    kid: st("kid"),
                    ctl: st("ctl"),
                    http: st("http"),
                    caps: st("caps"),
                    tag_ok: jv::b(v, "tag_ok"),
                    up: v.get("up").and_then(Value::as_u64),
                    first_seen: nu("first_seen"),
                    last_seen: nu("last_seen"),
                },
            );
        }
        while r.hosts.len() > MAX_HOSTS {
            r.evict_oldest();
        }
        Some(r)
    }

    pub fn load(path: &Path) -> Registry {
        std::fs::read_to_string(path).ok().and_then(|s| Registry::from_json(&s)).unwrap_or_default()
    }

    /// Atomic and private: write a sibling temp file (mode 0600, exclusive), fsync, rename.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let tmp = path.with_extension(format!("json.tmp{}", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        f.write_all(self.to_json().as_bytes())?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
    }
}

/// `name = value` lines; `#` comments; names are case-insensitive.
pub fn parse_aliases(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let l = l.split('#').next().unwrap_or("").trim();
            let (k, v) = l.split_once('=')?;
            let (k, v) = (k.trim(), v.trim());
            if k.is_empty() || v.is_empty() {
                None
            } else {
                Some((k.to_ascii_lowercase(), v.to_string()))
            }
        })
        .collect()
}

pub fn load_aliases(path: &Path) -> Vec<(String, String)> {
    std::fs::read_to_string(path).map(|t| parse_aliases(&t)).unwrap_or_default()
}

#[derive(Clone, Debug)]
pub enum Resolution {
    Entry(HostEntry),
    /// a bare MAC not in the registry
    Mac(Mac),
    /// a bare IPv4 not in the registry
    Ip(String),
}

/// Resolve a host selector (I7LABCTL.md 2.1): alias, then registry (MAC, IPv4, board serial, hostname, board
/// name; exact), then a bare MAC or IPv4, then a unique MAC prefix.
pub fn resolve(sel: &str, reg: &Registry, aliases: &[(String, String)]) -> Result<Resolution, ClientError> {
    let sel = sel.trim();
    if sel.is_empty() {
        return Err(ClientError::Usage("empty host selector".into()));
    }
    let lower = sel.to_ascii_lowercase();
    let sel = aliases.iter().find(|(k, _)| *k == lower).map(|(_, v)| v.as_str()).unwrap_or(sel);

    let found = reg.find(sel);
    if !found.is_empty() {
        return pick(sel, found);
    }
    if let Some(m) = Mac::parse(sel) {
        return Ok(Resolution::Mac(m));
    }
    if is_ipv4(sel) {
        return Ok(Resolution::Ip(sel.to_string()));
    }
    let found = reg.find_prefix(sel);
    if !found.is_empty() {
        return pick(sel, found);
    }
    Err(ClientError::NoHost(format!("'{}' is not in the registry (run: i7labctl discover)", sel)))
}

fn pick(sel: &str, found: Vec<&HostEntry>) -> Result<Resolution, ClientError> {
    if found.len() == 1 {
        return Ok(Resolution::Entry(found[0].clone()));
    }
    // several NICs of the same machine (same non-empty board serial) are one host: take the most recent one
    let s0 = &found[0].board_serial;
    if !s0.is_empty() && found.iter().all(|h| &h.board_serial == s0) {
        let best = found.iter().max_by_key(|h| h.last_seen).unwrap();
        return Ok(Resolution::Entry((*best).clone()));
    }
    let _ = sel;
    let mut c: Vec<String> = found.iter().map(|h| format!("{} ({})", h.mac, if h.host.is_empty() { &h.board } else { &h.host })).collect();
    c.sort();
    Err(ClientError::Ambiguous(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn beacon(extra: &[(&str, &str)]) -> Beacon {
        let mut b = Beacon { version: 2, fields: vec![] };
        b.set("mac", "52:54:00:17:00:01");
        b.set("host", "lab-1");
        b.set("board", "Q35");
        b.set("board_serial", "SER1");
        b.set("ip", "10.0.0.5/24");
        b.set("boot", "9f3c");
        b.set("kid", "a:14b746da,r:7c01de33");
        for (k, v) in extra {
            b.set(k, v);
        }
        b
    }

    fn meta() -> ObserveMeta {
        ObserveMeta { iface: "eth0".into(), src_mac: Mac::parse("52:54:00:17:00:01"), vlan: None, tag_ok: Some(true) }
    }

    #[test]
    fn observe_and_resolve() {
        let mut r = Registry::default();
        assert_eq!(r.observe(&beacon(&[]), &meta(), 100), Change::New);
        assert_eq!(r.observe(&beacon(&[]), &meta(), 101), Change::Same);
        assert_eq!(r.observe(&beacon(&[("state", "busy")]), &meta(), 102), Change::Changed);
        for sel in ["52:54:00:17:00:01", "10.0.0.5", "ser1", "LAB-1", "q35", "52:54:00:17"] {
            match resolve(sel, &r, &[]) {
                Ok(Resolution::Entry(e)) => assert_eq!(e.mac, "52:54:00:17:00:01", "{}", sel),
                other => panic!("{} -> {:?}", sel, other),
            }
        }
        assert!(matches!(resolve("nope", &r, &[]), Err(ClientError::NoHost(_))));
        assert!(matches!(resolve("aa:bb:cc:dd:ee:01", &r, &[]), Ok(Resolution::Mac(_))));
        assert!(matches!(resolve("192.168.1.9", &r, &[]), Ok(Resolution::Ip(_))));
        let al = parse_aliases("# c\nM900 = lab-1 # trailing\nbad line\n");
        assert!(matches!(resolve("m900", &r, &al), Ok(Resolution::Entry(_))));
    }

    #[test]
    fn rejects_bad_beacons_and_flags_mismatch() {
        let mut r = Registry::default();
        let mut b = beacon(&[]);
        b.set("mac", "ff:ff:ff:ff:ff:ff");
        assert_eq!(r.observe(&b, &meta(), 1), Change::Rejected);
        let b = beacon(&[("ip", "javascript:alert(1)")]);
        assert_eq!(r.observe(&b, &meta(), 1), Change::Rejected);
        let mut m = meta();
        m.src_mac = Mac::parse("02:00:00:00:00:99");
        assert_eq!(r.observe(&beacon(&[]), &m, 1), Change::New);
        assert!(r.hosts.values().next().unwrap().flags(&[]).contains(&"src-mac-mismatch"));
    }

    #[test]
    fn v1_frame_does_not_downgrade() {
        let mut r = Registry::default();
        r.observe(&beacon(&[]), &meta(), 1);
        let mut v1 = Beacon { version: 1, fields: vec![] };
        v1.set("mac", "52:54:00:17:00:01");
        r.observe(&v1, &meta(), 5);
        let e = r.hosts.values().next().unwrap();
        assert_eq!(e.proto_ver, 2);
        assert_eq!(e.last_seen, 5);
        assert_eq!(e.kid, "a:14b746da,r:7c01de33");
    }

    #[test]
    fn kid_matching() {
        let mut r = Registry::default();
        r.observe(&beacon(&[]), &meta(), 1);
        let e = r.hosts.values().next().unwrap();
        assert!(e.kid_matches(&["14b746da".into()]));
        assert!(e.kid_matches(&["7c01de33".into()]));
        assert!(!e.kid_matches(&["deadbeef".into()]));
        assert!(e.flags(&["deadbeef".into()]).contains(&"other-keyset"));
        assert!(e.flags(&["14b746da".into()]).iter().all(|f| *f != "other-keyset"));
    }

    #[test]
    fn json_roundtrip_and_perms() {
        if jv::parse("{\"a\":1}").is_none() {
            eprintln!("SKIPPED: labproto::json::parse is still a stub (P1)");
            return;
        }
        let mut r = Registry::default();
        r.observe(&beacon(&[]), &meta(), 77);
        let j = r.to_json();
        let r2 = Registry::from_json(&j).expect("parse");
        assert_eq!(r.hosts, r2.hosts);
        let dir = std::env::temp_dir().join(format!("i7ctl-reg-{}", std::process::id()));
        let p = dir.join("hosts.json");
        r.save(&p).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(Registry::load(&p).hosts, r.hosts);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_board_serial_is_one_host() {
        let mut r = Registry::default();
        r.observe(&beacon(&[]), &meta(), 10);
        let mut b2 = beacon(&[]);
        b2.set("mac", "52:54:00:17:00:02");
        b2.set("host", "lab-1");
        r.observe(&b2, &ObserveMeta { src_mac: Mac::parse("52:54:00:17:00:02"), ..meta() }, 20);
        match resolve("ser1", &r, &[]) {
            Ok(Resolution::Entry(e)) => assert_eq!(e.mac, "52:54:00:17:00:02"),
            o => panic!("{:?}", o),
        }
        r.hosts.get_mut("52:54:00:17:00:02").unwrap().board_serial = "OTHER".into();
        assert!(matches!(resolve("lab-1", &r, &[]), Err(ClientError::Ambiguous(_))));
    }
}
