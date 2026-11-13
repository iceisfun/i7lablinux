//! L2 beacon v1/v2 and address hints I7LR1/I7LR2, ethertype 0x88B5 (PROTOCOL.md section 10). Owner: P1.

use crate::crypto::{ct_eq, hex, hmac_sha256};
use crate::frame::FrameError;
use crate::mac::Mac;

pub const MAGIC_V1: &str = "I7LP1";
pub const MAGIC_V2: &str = "I7LP2";
pub const HINT_V1: &str = "I7LR1";
pub const HINT_V2: &str = "I7LR2";
pub const MAX_VALUE: usize = 128;
/// Keys of a v1 beacon in send order (also sent first, same order, in v2).
pub const V1_KEYS: [&str; 11] = ["mac", "iface", "host", "product", "vendor", "serial", "board", "board_serial", "kernel", "link", "ip"];

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Beacon {
    pub version: u8,
    /// ordered key=value pairs, excluding `tag`
    pub fields: Vec<(String, String)>,
}

fn clean(v: &str, max: usize) -> String {
    let s: String = v.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

impl Beacon {
    pub fn get(&self, k: &str) -> Option<&str> {
        self.fields.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str())
    }

    pub fn set(&mut self, k: &str, v: &str) {
        let v = clean(v, 64);
        match self.fields.iter_mut().find(|(key, _)| key == k) {
            Some(e) => e.1 = v,
            None => self.fields.push((k.to_string(), v)),
        }
    }

    fn body(&self, magic: &str, keys: Option<&[&str]>) -> String {
        let mut s = format!("{}\n", magic);
        for (k, v) in &self.fields {
            if k == "tag" || keys.is_some_and(|ks| !ks.contains(&k.as_str())) {
                continue;
            }
            s.push_str(&format!("{}={}\n", k, v));
        }
        s
    }

    /// I7LP2 text; with a beacon key the last line is `tag=<32 hex>` over src MAC and all lines before it.
    pub fn encode_v2(&self, beacon_key: Option<&[u8; 32]>, src: &Mac) -> Vec<u8> {
        let mut s = self.body(MAGIC_V2, None);
        if let Some(k) = beacon_key {
            let t = hmac_sha256(k, &[b"i7c-beacon\0", &src.0, s.as_bytes()]);
            s.push_str(&format!("tag={}\n", hex(&t[..16])));
        }
        s.into_bytes()
    }

    /// I7LP1 text with exactly the v1 keys (beacon_compat).
    pub fn encode_v1(&self) -> Vec<u8> {
        self.body(MAGIC_V1, Some(&V1_KEYS)).into_bytes()
    }

    /// Parse I7LP1 or I7LP2. First occurrence of a key wins; values cut to 128 bytes; NUL padding ignored.
    pub fn parse(payload: &[u8]) -> Result<Beacon, FrameError> {
        let end = payload.iter().position(|b| *b == 0).unwrap_or(payload.len());
        let text = std::str::from_utf8(&payload[..end]).map_err(|_| FrameError::BadPayload("not utf-8"))?;
        let mut lines = text.split('\n');
        let version = match lines.next() {
            Some(MAGIC_V1) => 1,
            Some(MAGIC_V2) => 2,
            _ => return Err(FrameError::BadMagic),
        };
        let mut b = Beacon { version, fields: Vec::new() };
        for l in lines {
            if let Some((k, v)) = l.split_once('=') {
                if b.get(k).is_none() {
                    b.fields.push((k.to_string(), clean(v, MAX_VALUE)));
                }
            }
        }
        Ok(b)
    }

    /// Verify the v2 tag against the raw payload as received.
    pub fn tag_ok(raw: &[u8], beacon_key: &[u8; 32], src: &Mac) -> bool {
        let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        let raw = &raw[..end];
        let Some(pos) = find_tag_line(raw) else { return false };
        let body = &raw[..pos];
        let tag_hex = std::str::from_utf8(&raw[pos + 4..]).unwrap_or("").trim_end_matches('\n');
        let t = hmac_sha256(beacon_key, &[b"i7c-beacon\0", &src.0, body]);
        ct_eq(hex(&t[..16]).as_bytes(), tag_hex.as_bytes())
    }
}

fn find_tag_line(raw: &[u8]) -> Option<usize> {
    let mut start = 0;
    for (i, b) in raw.iter().enumerate() {
        if *b == b'\n' {
            if raw[start..].starts_with(b"tag=") {
                return Some(start);
            }
            start = i + 1;
        }
    }
    if raw[start..].starts_with(b"tag=") {
        Some(start)
    } else {
        None
    }
}

/// Address hint (lab -> host).
#[derive(Clone, Debug, PartialEq)]
pub struct Hint {
    pub target: Mac,
    pub ip: [u8; 4],
    pub prefix: u8,
    pub gw: Option<[u8; 4]>,
    pub vlan: Option<u16>,
    pub boot: Option<String>,
    pub seq: u32,
}

fn fmt_ip(ip: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn parse_ip(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut n = 0;
    for part in s.split('.') {
        if n == 4 || part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        out[n] = part.parse::<u8>().ok()?;
        n += 1;
    }
    (n == 4).then_some(out)
}

fn unicast_ok(ip: &[u8; 4]) -> bool {
    ip[0] != 0 && ip[0] != 127 && ip[0] < 224
}

fn in_subnet(a: &[u8; 4], b: &[u8; 4], prefix: u8) -> bool {
    let (a, b) = (u32::from_be_bytes(*a), u32::from_be_bytes(*b));
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
    a & mask == b & mask
}

impl Hint {
    fn lines(&self, magic: &str, v2: bool) -> String {
        let mut s = format!("{}\nmac={}\nip={}/{}\n", magic, self.target, fmt_ip(&self.ip), self.prefix);
        if let Some(gw) = &self.gw {
            s.push_str(&format!("gw={}\n", fmt_ip(gw)));
        }
        if v2 {
            match self.vlan {
                Some(v) => s.push_str(&format!("vlan={}\n", v)),
                None => s.push_str("vlan=\n"),
            }
            s.push_str(&format!("boot={}\nseq={}\n", self.boot.as_deref().unwrap_or(""), self.seq));
        }
        s
    }

    /// I7LR2 with tag = trunc16(HMAC(K_admin, "i7c-hint\0" | dst_mac | lines before tag)); `dst_mac` is the
    /// target (the hint is unicast to it).
    pub fn encode_v2(&self, admin: &[u8; 32]) -> Vec<u8> {
        let mut s = self.lines(HINT_V2, true);
        let t = hmac_sha256(admin, &[b"i7c-hint\0", &self.target.0, s.as_bytes()]);
        s.push_str(&format!("tag={}\n", hex(&t[..16])));
        s.into_bytes()
    }

    pub fn encode_v1(&self) -> Vec<u8> {
        self.lines(HINT_V1, false).into_bytes()
    }

    /// v2 hints need `admin` to verify; v1 hints are accepted without (option accept_v1_hint, decided by the
    /// caller). Sanity rules for both: unicast address, prefix 8..=30, gateway inside the subnet.
    pub fn parse(payload: &[u8], admin: Option<&[u8; 32]>) -> Result<Hint, FrameError> {
        let end = payload.iter().position(|b| *b == 0).unwrap_or(payload.len());
        let text = std::str::from_utf8(&payload[..end]).map_err(|_| FrameError::BadPayload("not utf-8"))?;
        let v2 = if text.starts_with("I7LR2\n") {
            true
        } else if text.starts_with("I7LR1\n") {
            false
        } else {
            return Err(FrameError::BadMagic);
        };
        let bad = |m: &'static str| FrameError::BadPayload(m);
        let (mut target, mut ip, mut gw, mut vlan, mut boot, mut seq) = (None, None, None, None, None, None);
        let mut tag_hex: Option<&str> = None;
        let mut before_tag = 0usize;
        let mut next = text.find('\n').map_or(text.len(), |i| i + 1);
        while next < text.len() {
            let start = next;
            let rest = &text[start..];
            let nl = rest.find('\n');
            let l = &rest[..nl.unwrap_or(rest.len())];
            next += nl.map_or(rest.len(), |i| i + 1);
            let Some((k, v)) = l.split_once('=') else { continue };
            match k {
                "mac" if target.is_none() => target = Some(Mac::parse(v).ok_or(bad("bad mac"))?),
                "ip" if ip.is_none() => {
                    let (a, p) = v.split_once('/').ok_or(bad("ip needs /prefix"))?;
                    ip = Some((parse_ip(a).ok_or(bad("bad ip"))?, p.parse::<u8>().map_err(|_| bad("bad prefix"))?));
                }
                "gw" if gw.is_none() && !v.is_empty() => gw = Some(parse_ip(v).ok_or(bad("bad gw"))?),
                "vlan" if vlan.is_none() => {
                    if !v.is_empty() {
                        let id: u16 = v.parse().map_err(|_| bad("bad vlan"))?;
                        if id == 0 || id > 4094 {
                            return Err(bad("bad vlan"));
                        }
                        vlan = Some(id);
                    }
                }
                "boot" if boot.is_none() && !v.is_empty() => boot = Some(clean(v, 32)),
                "seq" if seq.is_none() => seq = Some(v.parse::<u32>().map_err(|_| bad("bad seq"))?),
                "tag" if tag_hex.is_none() => {
                    tag_hex = Some(v);
                    before_tag = start;
                }
                _ => {}
            }
        }
        let target = target.ok_or(bad("no mac"))?;
        let (ipa, prefix) = ip.ok_or(bad("no ip"))?;
        if !target.is_unicast() || !unicast_ok(&ipa) || !(8..=30).contains(&prefix) {
            return Err(bad("address not acceptable"));
        }
        if let Some(g) = &gw {
            if !unicast_ok(g) || !in_subnet(g, &ipa, prefix) || g == &ipa {
                return Err(bad("gateway not in subnet"));
            }
        }
        if v2 {
            let admin = admin.ok_or(bad("no admin key to verify I7LR2"))?;
            let tag_hex = tag_hex.ok_or(bad("no tag"))?;
            let t = hmac_sha256(admin, &[b"i7c-hint\0", &target.0, &text.as_bytes()[..before_tag]]);
            if !ct_eq(hex(&t[..16]).as_bytes(), tag_hex.as_bytes()) {
                return Err(bad("bad tag"));
            }
            if seq.is_none() {
                return Err(bad("no seq"));
            }
        }
        Ok(Hint { target, ip: ipa, prefix, gw, vlan, boot, seq: seq.unwrap_or(0) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn v2_roundtrip_and_tag() {
        let mut b = Beacon { version: 2, fields: vec![] };
        b.set("mac", "02:00:00:00:00:01");
        b.set("host", "lab\x1bx");
        let src = Mac([2, 0, 0, 0, 0, 1]);
        let raw = b.encode_v2(Some(&[9; 32]), &src);
        let p = Beacon::parse(&raw).unwrap();
        assert_eq!(p.version, 2);
        assert_eq!(p.get("host"), Some("lab x"));
        assert!(Beacon::tag_ok(&raw, &[9; 32], &src));
        assert!(!Beacon::tag_ok(&raw, &[8; 32], &src));
        assert!(Beacon::parse(&b.encode_v1()).unwrap().version == 1);
    }

    #[test]
    fn beacon_v1_keys_only_and_first_key_wins() {
        let mut b = Beacon { version: 2, fields: vec![] };
        for (k, v) in [("mac", "02:00:00:00:00:01"), ("host", "h"), ("proto", "1"), ("boot", "00ff")] {
            b.set(k, v);
        }
        let v1 = Beacon::parse(&b.encode_v1()).unwrap();
        assert_eq!(v1.get("host"), Some("h"));
        assert_eq!(v1.get("proto"), None);
        let p = Beacon::parse(b"I7LP2\nhost=a\nhost=b\nunknown=1\n\0\0\0").unwrap();
        assert_eq!(p.get("host"), Some("a"));
        assert_eq!(p.get("unknown"), Some("1"));
        assert!(Beacon::parse(b"I7LP3\n").is_err());
        let long = format!("I7LP2\nhost={}\n", "x".repeat(500));
        assert_eq!(Beacon::parse(long.as_bytes()).unwrap().get("host").unwrap().len(), MAX_VALUE);
    }

    #[test]
    fn beacon_tag_detects_modification_and_wrong_source() {
        let mut b = Beacon { version: 2, fields: vec![] };
        b.set("mac", "02:00:00:00:00:01");
        b.set("up", "5");
        let src = Mac([2, 0, 0, 0, 0, 1]);
        let raw = b.encode_v2(Some(&[9; 32]), &src);
        assert!(Beacon::tag_ok(&raw, &[9; 32], &src));
        assert!(!Beacon::tag_ok(&raw, &[9; 32], &Mac([2, 0, 0, 0, 0, 9])));
        let mut text = String::from_utf8(raw.clone()).unwrap();
        text = text.replace("up=5", "up=6");
        assert!(!Beacon::tag_ok(text.as_bytes(), &[9; 32], &src));
        // no tag at all
        assert!(!Beacon::tag_ok(&b.encode_v2(None, &src), &[9; 32], &src));
        // NUL padding after the frame is fine
        let mut padded = raw;
        padded.extend_from_slice(&[0; 20]);
        assert!(Beacon::tag_ok(&padded, &[9; 32], &src));
    }

    fn sample_hint() -> Hint {
        Hint { target: Mac([2, 0, 0, 0, 0, 7]), ip: [192, 0, 2, 195], prefix: 24, gw: Some([192, 0, 2, 1]), vlan: Some(13), boot: Some("9f3c".into()), seq: 4 }
    }

    #[test]
    fn hint_v2_roundtrip_and_forgery() {
        let h = sample_hint();
        let k = [7u8; 32];
        let raw = h.encode_v2(&k);
        assert_eq!(Hint::parse(&raw, Some(&k)).unwrap(), h);
        assert!(Hint::parse(&raw, Some(&[8u8; 32])).is_err());
        assert!(Hint::parse(&raw, None).is_err());
        let text = String::from_utf8(raw).unwrap();
        for (from, to) in [("ip=192.0.2.195", "ip=192.0.2.196"), ("seq=4", "seq=5"), ("vlan=13", "vlan=14"), ("boot=9f3c", "boot=9f3d")] {
            assert!(Hint::parse(text.replace(from, to).as_bytes(), Some(&k)).is_err(), "{}", from);
        }
        // a hint for another target MAC does not verify
        let other = text.replace("mac=02:00:00:00:00:07", "mac=02:00:00:00:00:08");
        assert!(Hint::parse(other.as_bytes(), Some(&k)).is_err());
    }

    #[test]
    fn hint_v1_roundtrip_and_sanity() {
        let mut h = sample_hint();
        h.vlan = None;
        h.boot = None;
        h.seq = 0;
        assert_eq!(Hint::parse(&h.encode_v1(), None).unwrap(), h);
        let bad = |t: &str| Hint::parse(t.as_bytes(), None).is_err();
        assert!(bad("I7LR1\nmac=02:00:00:00:00:07\nip=192.0.2.195/31\n"));
        assert!(bad("I7LR1\nmac=02:00:00:00:00:07\nip=192.0.2.195/7\n"));
        assert!(bad("I7LR1\nmac=02:00:00:00:00:07\nip=224.0.0.1/24\n"));
        assert!(bad("I7LR1\nmac=02:00:00:00:00:07\nip=127.0.0.1/24\n"));
        assert!(bad("I7LR1\nmac=02:00:00:00:00:07\nip=192.0.2.195/24\ngw=10.4.0.1\n"));
        assert!(bad("I7LR1\nmac=ff:ff:ff:ff:ff:ff\nip=192.0.2.195/24\n"));
        assert!(bad("I7LR1\nip=192.0.2.195/24\n"));
        assert!(bad("garbage"));
        assert!(!bad("I7LR1\nmac=02:00:00:00:00:07\nip=192.0.2.195/24\n"));
    }
}
