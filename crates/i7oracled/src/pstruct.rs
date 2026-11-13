//! Byte-level decoders for the Windows power structures (pure, so they are unit-tested on Linux).
//! Layouts: SYSTEM_POWER_STATUS (12 bytes), SYSTEM_BATTERY_STATE (32), SYSTEM_POWER_CAPABILITIES (76),
//! SYSTEM_POWER_INFORMATION (16).

use crate::crypto::hex;
use crate::evlog::json_str;

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn bl(b: &[u8], o: usize) -> &'static str {
    match b.get(o) {
        Some(0) => "false",
        Some(_) => "true",
        None => "null",
    }
}

fn opt_u32(v: Option<u32>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "null".into())
}

/// GetSystemPowerStatus. 255 / 0xFFFFFFFF mean "unknown" in the API; we report the raw numbers plus names.
pub fn power_status(b: &[u8]) -> String {
    let ac = match b.first() {
        Some(0) => "offline",
        Some(1) => "online",
        _ => "unknown",
    };
    let flag = b.get(1).copied().unwrap_or(255);
    let mut names = Vec::new();
    for (bit, n) in [(1u8, "high"), (2, "low"), (4, "critical"), (8, "charging"), (128, "no-battery")] {
        if flag != 255 && flag & bit != 0 {
            names.push(json_str(n));
        }
    }
    format!(
        "{{\"ac_line\":{},\"ac_line_raw\":{},\"battery_flag\":{},\"battery_flags\":[{}],\"battery_percent\":{},\"battery_saver\":{},\"life_s\":{},\"full_life_s\":{}}}",
        json_str(ac),
        b.first().copied().unwrap_or(255),
        flag,
        names.join(","),
        b.get(2).copied().unwrap_or(255),
        b.get(3).map(|x| *x & 1 == 1).unwrap_or(false),
        opt_u32(u32_at(b, 4)),
        opt_u32(u32_at(b, 8))
    )
}

pub fn battery_present(b: &[u8]) -> bool {
    let f = b.get(1).copied().unwrap_or(255);
    f != 255 && f & 128 == 0
}

/// SYSTEM_BATTERY_STATE.
pub fn battery_state(b: &[u8]) -> String {
    format!(
        "{{\"ac_online\":{},\"battery_present\":{},\"charging\":{},\"discharging\":{},\"max_capacity_mwh\":{},\"remaining_capacity_mwh\":{},\"rate_mw\":{},\"estimated_time_s\":{},\"default_alert1\":{},\"default_alert2\":{}}}",
        bl(b, 0),
        bl(b, 1),
        bl(b, 2),
        bl(b, 3),
        opt_u32(u32_at(b, 8)),
        opt_u32(u32_at(b, 12)),
        u32_at(b, 16).map(|x| (x as i32).to_string()).unwrap_or_else(|| "null".into()),
        opt_u32(u32_at(b, 20)),
        opt_u32(u32_at(b, 24)),
        opt_u32(u32_at(b, 28))
    )
}

/// SYSTEM_POWER_INFORMATION.
pub fn power_information(b: &[u8]) -> String {
    format!(
        "{{\"max_idleness_allowed\":{},\"idleness\":{},\"time_remaining\":{},\"cooling_mode\":{}}}",
        opt_u32(u32_at(b, 0)),
        opt_u32(u32_at(b, 4)),
        opt_u32(u32_at(b, 8)),
        b.get(12).map(|x| x.to_string()).unwrap_or_else(|| "null".into())
    )
}

fn sys_state(v: Option<u32>) -> String {
    match v {
        Some(0) => "Unspecified".into(),
        Some(1) => "Working(S0)".into(),
        Some(2) => "Sleeping1(S1)".into(),
        Some(3) => "Sleeping2(S2)".into(),
        Some(4) => "Sleeping3(S3)".into(),
        Some(5) => "Hibernate(S4)".into(),
        Some(6) => "Shutdown(S5)".into(),
        Some(x) => format!("state{}", x),
        None => "null".into(),
    }
}

/// SYSTEM_POWER_CAPABILITIES. Includes the raw bytes so a field we mislabel can be re-read from the log.
pub fn capabilities(b: &[u8]) -> String {
    let mut o = String::from("{");
    for (i, n) in [
        "power_button", "sleep_button", "lid", "s1", "s2", "s3", "s4", "s5", "hiber_file_present", "full_wake", "video_dim", "apm", "ups", "thermal_control", "processor_throttle",
    ]
    .iter()
    .enumerate()
    {
        o.push_str(&format!("\"{}\":{},", n, bl(b, i)));
    }
    o.push_str(&format!("\"processor_min_throttle\":{},\"processor_max_throttle\":{},", b.get(15).copied().unwrap_or(0), b.get(16).copied().unwrap_or(0)));
    for (i, n) in [(17usize, "fast_system_s4"), (18, "hiberboot"), (19, "wake_alarm_present"), (20, "aoac_modern_standby"), (21, "disk_spin_down")] {
        o.push_str(&format!("\"{}\":{},", n, bl(b, i)));
    }
    o.push_str(&format!("\"hiber_file_type\":{},\"aoac_connectivity_supported\":{},\"batteries_present\":{},\"batteries_short_term\":{},", b.get(22).copied().unwrap_or(0), bl(b, 23), bl(b, 30), bl(b, 31)));
    for (off, n) in [(56usize, "ac_online_wake"), (60, "soft_lid_wake"), (64, "rtc_wake"), (68, "min_device_wake_state"), (72, "default_low_latency_wake")] {
        o.push_str(&format!("\"{}\":{},", n, json_str(&sys_state(u32_at(b, off)))));
    }
    o.push_str(&format!("\"len\":{},\"raw\":{}}}", b.len(), json_str(&hex(b))));
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::{parse, Limits};

    fn ok(s: &str) {
        assert!(parse(s, &Limits::default()).is_ok(), "{}", s);
    }

    #[test]
    fn status_decoding() {
        let mut b = [0u8; 12];
        b[0] = 1;
        b[1] = 9; // high + charging
        b[2] = 87;
        b[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        b[8..12].copy_from_slice(&36_000u32.to_le_bytes());
        let j = power_status(&b);
        ok(&j);
        assert!(j.contains("\"ac_line\":\"online\"") && j.contains("\"high\",\"charging\"") && j.contains("\"battery_percent\":87") && j.contains("\"full_life_s\":36000"), "{}", j);
        assert!(battery_present(&b));
        b[1] = 128;
        assert!(!battery_present(&b));
        ok(&power_status(&[]));
    }

    #[test]
    fn battery_and_info() {
        let mut b = [0u8; 32];
        b[1] = 1;
        b[3] = 1;
        b[8..12].copy_from_slice(&50_000u32.to_le_bytes());
        b[12..16].copy_from_slice(&25_000u32.to_le_bytes());
        b[16..20].copy_from_slice(&(-8000i32).to_le_bytes());
        let j = battery_state(&b);
        ok(&j);
        assert!(j.contains("\"discharging\":true") && j.contains("\"rate_mw\":-8000") && j.contains("\"remaining_capacity_mwh\":25000"), "{}", j);
        ok(&battery_state(&[]));
        ok(&power_information(&[0u8; 16]));
    }

    #[test]
    fn capability_table() {
        let mut b = [0u8; 76];
        b[2] = 1; // lid
        b[5] = 1; // S3
        b[6] = 1; // S4
        b[20] = 1; // AoAc
        b[56..60].copy_from_slice(&4u32.to_le_bytes());
        let j = capabilities(&b);
        ok(&j);
        assert!(j.contains("\"lid\":true") && j.contains("\"s3\":true") && j.contains("\"aoac_modern_standby\":true") && j.contains("\"ac_online_wake\":\"Sleeping3(S3)\"") && j.contains("\"len\":76"), "{}", j);
        ok(&capabilities(&[]));
    }
}
