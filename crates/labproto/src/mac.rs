//! MAC address type. Owner: P1.

use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    pub const BROADCAST: Mac = Mac([0xff; 6]);

    /// Accepts `aa:bb:cc:dd:ee:ff` or `aa-bb-...`, any case.
    pub fn parse(s: &str) -> Option<Mac> {
        let parts: Vec<&str> = s.split([':', '-']).collect();
        if parts.len() != 6 {
            return None;
        }
        let mut m = [0u8; 6];
        for (i, p) in parts.iter().enumerate() {
            if p.len() != 2 {
                return None;
            }
            m[i] = u8::from_str_radix(p, 16).ok()?;
        }
        Some(Mac(m))
    }

    pub fn is_unicast(&self) -> bool {
        self.0[0] & 1 == 0 && self.0 != [0; 6]
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
    }
}

impl fmt::Debug for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_display() {
        let m = Mac::parse("02:00:00:00:00:0A").unwrap();
        assert_eq!(m.to_string(), "02:00:00:00:00:0a");
        assert!(m.is_unicast());
        assert!(!Mac::BROADCAST.is_unicast());
        assert!(Mac::parse("02:00:00:00:00").is_none());
    }
}
