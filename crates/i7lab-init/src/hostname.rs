//! Hostname from DMI: `i7lab-<last 6 alphanumerics of the board serial>`.

/// Values firmware vendors leave in unset DMI fields.
fn is_placeholder(norm: &str) -> bool {
    const CONTAINS: &[&str] = &["tobefilled", "defaultstring", "notspecified", "notapplicable", "serialnumber", "notavailable"];
    const EQUALS: &[&str] = &["none", "unknown", "na", "oem", "empty"];
    norm.len() < 3 || CONTAINS.iter().any(|b| norm.contains(b)) || EQUALS.contains(&norm) || norm.bytes().all(|b| b == norm.as_bytes()[0])
}

/// First usable serial wins; none -> plain "i7lab".
pub fn from_serials(serials: &[Option<String>]) -> String {
    for s in serials.iter().flatten() {
        let norm: String = s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase();
        if is_placeholder(&norm) {
            continue;
        }
        let tail = &norm[norm.len().saturating_sub(6)..];
        return format!("i7lab-{}", tail);
    }
    "i7lab".to_string()
}

/// RFC 952-ish: letters, digits, '-', 1..=63, no leading/trailing '-'. Anything else -> None.
pub fn valid(h: &str) -> bool {
    !h.is_empty() && h.len() <= 63 && !h.starts_with('-') && !h.ends_with('-') && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

pub fn dmi_serials() -> Vec<Option<String>> {
    ["board_serial", "product_serial", "chassis_serial", "product_uuid"]
        .iter()
        .map(|f| std::fs::read_to_string(format!("/sys/class/dmi/id/{}", f)).ok().map(|s| s.trim().to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn s(x: &str) -> Option<String> {
        Some(x.to_string())
    }
    #[test]
    fn tail_of_the_board_serial() {
        assert_eq!(from_serials(&[s("PF2ABC-1234")]), "i7lab-bc1234");
        assert_eq!(from_serials(&[s("AB")]), "i7lab"); // too short to be a serial
    }
    #[test]
    fn placeholders_fall_through() {
        assert_eq!(from_serials(&[s("To be filled by O.E.M."), s("Default string"), s("00000000"), s("XYZ99887766")]), "i7lab-887766");
        assert_eq!(from_serials(&[None, s("None")]), "i7lab");
    }
    #[test]
    fn hostname_validation() {
        assert!(valid("i7lab-a1b2c3") && !valid("-x") && !valid("a b") && !valid("") && !valid(&"a".repeat(64)));
    }
}
