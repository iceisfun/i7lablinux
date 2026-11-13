//! Pure power-event vocabulary: PBT_* names, power-setting GUIDs and their payloads, and the /power request.

use crate::crypto::hex;
use crate::evlog::json_str;
use crate::json::{self, Limits, Value};

pub const WM_POWERBROADCAST: u32 = 0x0218;
pub const PBT_POWERSETTINGCHANGE: u32 = 0x8013;
pub const PBT_APMSUSPEND: u32 = 0x4;
pub const PBT_APMRESUMESUSPEND: u32 = 0x7;
pub const PBT_APMRESUMEAUTOMATIC: u32 = 0x12;

pub fn pbt_name(t: u32) -> &'static str {
    match t {
        0x0 => "PBT_APMQUERYSUSPEND",
        0x1 => "PBT_APMQUERYSTANDBY",
        0x2 => "PBT_APMQUERYSUSPENDFAILED",
        0x3 => "PBT_APMQUERYSTANDBYFAILED",
        0x4 => "PBT_APMSUSPEND",
        0x5 => "PBT_APMSTANDBY",
        0x6 => "PBT_APMRESUMECRITICAL",
        0x7 => "PBT_APMRESUMESUSPEND",
        0x8 => "PBT_APMRESUMESTANDBY",
        0x9 => "PBT_APMBATTERYLOW",
        0xA => "PBT_APMPOWERSTATUSCHANGE",
        0xB => "PBT_APMOEMEVENT",
        0x12 => "PBT_APMRESUMEAUTOMATIC",
        0x8013 => "PBT_POWERSETTINGCHANGE",
        _ => "PBT_UNKNOWN",
    }
}

/// Windows GUID in memory layout (Data1/2/3 little endian).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    pub fn parse(s: &str) -> Option<Guid> {
        let h: String = s.trim_matches(|c| c == '{' || c == '}').chars().filter(|c| *c != '-').collect();
        let raw = crate::crypto::unhex(&h)?;
        if raw.len() != 16 {
            return None;
        }
        let mut g = [0u8; 16];
        g[0..4].copy_from_slice(&[raw[3], raw[2], raw[1], raw[0]]);
        g[4..6].copy_from_slice(&[raw[5], raw[4]]);
        g[6..8].copy_from_slice(&[raw[7], raw[6]]);
        g[8..16].copy_from_slice(&raw[8..16]);
        Some(Guid(g))
    }

    pub fn from_bytes(b: &[u8]) -> Option<Guid> {
        <[u8; 16]>::try_from(b.get(..16)?).ok().map(Guid)
    }

    pub fn to_string(&self) -> String {
        let g = &self.0;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{}",
            g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], hex(&g[10..16])
        )
    }
}

/// Power settings we register for. Names are the SDK constants. A GUID that a given Windows build does not know
/// registers fine and simply never fires; the per-GUID registration result is logged in the `monitor_ready` event.
pub const SETTINGS: &[(&str, &str)] = &[
    ("GUID_ACDC_POWER_SOURCE", "5d3e9a59-e9d5-4b00-a6bd-ff34ff516548"),
    ("GUID_BATTERY_PERCENTAGE_REMAINING", "a7ad8041-b45a-4cae-87a3-eecbb468a9e1"),
    ("GUID_CONSOLE_DISPLAY_STATE", "6fe69556-704a-47a0-8f24-c28d936fda47"),
    ("GUID_GLOBAL_USER_PRESENCE", "786e8a1d-b427-4344-9207-09e70bdcbea9"),
    ("GUID_IDLE_BACKGROUND_TASK", "515c31d8-f734-163d-a0fd-11a08c91e8f1"),
    ("GUID_LIDSWITCH_STATE_CHANGE", "ba3e0f4d-b817-4094-a2d1-d56379e6a0f3"),
    ("GUID_MONITOR_POWER_ON", "02731015-4510-4526-99e6-e5a17ebd1aea"),
    ("GUID_POWERSCHEME_PERSONALITY", "245d8541-3943-4422-b025-13a784f679b7"),
    ("GUID_SESSION_DISPLAY_STATUS", "2b84c20e-ad23-4ddf-93db-05ffbd7efca5"),
    ("GUID_SESSION_USER_PRESENCE", "3c0f4548-c03f-4c4d-b9f2-237ede686376"),
    ("GUID_SYSTEM_AWAYMODE", "98a7f580-01f7-48aa-9c0f-44352c29e5c0"),
    ("GUID_ENERGY_SAVER_STATUS", "550e8400-e29b-41d4-a716-446655440000"),
    ("GUID_POWER_SAVING_STATUS", "e00958c0-c213-4ace-ac77-fecced2eeea5"),
    ("GUID_LIDOPEN_POWERSTATE", "99ff10e7-23b1-4c07-a9d1-5c3206d741b4"),
];

const PERSONALITIES: &[(&str, &str)] = &[
    ("8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", "high-performance (GUID_MIN_POWER_SAVINGS)"),
    ("381b4222-f694-41f0-9685-ff5bb260df2e", "balanced (GUID_TYPICAL_POWER_SAVINGS)"),
    ("a1841308-3541-4fab-bc81-f71556f20b4a", "power-saver (GUID_MAX_POWER_SAVINGS)"),
];

pub fn setting_name(g: &Guid) -> Option<&'static str> {
    SETTINGS.iter().find(|(_, s)| Guid::parse(s).as_ref() == Some(g)).map(|(n, _)| *n)
}

fn meaning(name: &str, v: u32) -> Option<&'static str> {
    Some(match (name, v) {
        ("GUID_ACDC_POWER_SOURCE", 0) => "AC",
        ("GUID_ACDC_POWER_SOURCE", 1) => "DC (battery)",
        ("GUID_ACDC_POWER_SOURCE", 2) => "short-term DC (UPS)",
        ("GUID_LIDSWITCH_STATE_CHANGE", 0) => "lid closed",
        ("GUID_LIDSWITCH_STATE_CHANGE", 1) => "lid open",
        ("GUID_CONSOLE_DISPLAY_STATE" | "GUID_SESSION_DISPLAY_STATUS", 0) => "display off",
        ("GUID_CONSOLE_DISPLAY_STATE" | "GUID_SESSION_DISPLAY_STATUS", 1) => "display on",
        ("GUID_CONSOLE_DISPLAY_STATE" | "GUID_SESSION_DISPLAY_STATUS", 2) => "display dimmed",
        ("GUID_MONITOR_POWER_ON", 0) => "monitor off",
        ("GUID_MONITOR_POWER_ON", 1) => "monitor on",
        ("GUID_SYSTEM_AWAYMODE", 0) => "exiting away mode",
        ("GUID_SYSTEM_AWAYMODE", 1) => "entering away mode",
        ("GUID_GLOBAL_USER_PRESENCE" | "GUID_SESSION_USER_PRESENCE", 0) => "user present",
        ("GUID_GLOBAL_USER_PRESENCE" | "GUID_SESSION_USER_PRESENCE", 2) => "user inactive",
        ("GUID_ENERGY_SAVER_STATUS", 0) => "energy saver off",
        ("GUID_ENERGY_SAVER_STATUS", 1) => "energy saver standard",
        ("GUID_ENERGY_SAVER_STATUS", 2) => "energy saver high savings",
        ("GUID_POWER_SAVING_STATUS", 0) => "battery saver off",
        ("GUID_POWER_SAVING_STATUS", 1) => "battery saver on",
        _ => return None,
    })
}

/// JSON object for one PBT_POWERSETTINGCHANGE payload. Always carries the raw bytes in hex.
pub fn decode_setting(guid: &Guid, data: &[u8]) -> String {
    let name = setting_name(guid);
    let mut o = format!("{{\"guid\":{},\"setting\":{},\"len\":{},\"raw\":{}", json_str(&guid.to_string()), name.map(json_str).unwrap_or_else(|| "null".into()), data.len(), json_str(&hex(data)));
    if name == Some("GUID_POWERSCHEME_PERSONALITY") {
        if let Some(g) = Guid::from_bytes(data) {
            let gs = g.to_string();
            let nm = PERSONALITIES.iter().find(|(x, _)| *x == gs).map(|(_, n)| *n).unwrap_or("custom");
            o.push_str(&format!(",\"scheme_guid\":{},\"meaning\":{}", json_str(&gs), json_str(nm)));
        }
    } else if data.len() >= 4 {
        let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        o.push_str(&format!(",\"value\":{}", v));
        if let Some(m) = name.and_then(|n| meaning(n, v)) {
            o.push_str(&format!(",\"meaning\":{}", json_str(m)));
        }
    }
    o.push('}');
    o
}

// ------------------------------------------------------------------------------------------------ /power request

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Sleep,
    Hibernate,
    Shutdown,
    Reboot,
    ModernStandbyHint,
}

impl Action {
    pub fn name(self) -> &'static str {
        match self {
            Action::Sleep => "sleep",
            Action::Hibernate => "hibernate",
            Action::Shutdown => "shutdown",
            Action::Reboot => "reboot",
            Action::ModernStandbyHint => "modern-standby-hint",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeMethod {
    Timer,
    Task,
    Both,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PowerReq {
    pub action: Action,
    pub wake_after_s: Option<u64>,
    pub wake_method: WakeMethod,
    /// Seconds between the HTTP reply and the transition, so the caller sees the 202 first.
    pub delay_s: u64,
}

pub fn parse_power_req(body: &[u8]) -> Result<PowerReq, String> {
    let text = std::str::from_utf8(body).map_err(|_| "body is not utf-8")?;
    let v = json::parse(text, &Limits::default()).map_err(|e| format!("bad json: {}", e.msg))?;
    let action = match v.get("action").and_then(Value::as_str) {
        Some("sleep") => Action::Sleep,
        Some("hibernate") => Action::Hibernate,
        Some("shutdown") => Action::Shutdown,
        Some("reboot") => Action::Reboot,
        Some("modern-standby-hint") => Action::ModernStandbyHint,
        _ => return Err("action must be sleep|hibernate|shutdown|reboot|modern-standby-hint".into()),
    };
    let wake_after_s = match v.get("wake_after_s") {
        None | Some(Value::Null) => None,
        Some(x) => {
            let n = x.as_u64().ok_or("wake_after_s must be a non-negative integer")?;
            if n == 0 {
                None
            } else if !(5..=7 * 86_400).contains(&n) {
                return Err("wake_after_s must be 5..604800".into());
            } else {
                Some(n)
            }
        }
    };
    if wake_after_s.is_some() && matches!(action, Action::Shutdown | Action::Reboot) {
        return Err("wake_after_s only makes sense for sleep, hibernate and modern-standby-hint".into());
    }
    let wake_method = match v.get("wake_method").and_then(Value::as_str) {
        None | Some("timer") => WakeMethod::Timer,
        Some("task") => WakeMethod::Task,
        Some("both") => WakeMethod::Both,
        Some(_) => return Err("wake_method must be timer|task|both".into()),
    };
    let delay_s = match v.get("delay_s") {
        None | Some(Value::Null) => 2,
        Some(x) => x.as_u64().filter(|n| *n <= 3600).ok_or("delay_s must be 0..3600")?,
    };
    Ok(PowerReq { action, wake_after_s, wake_method, delay_s })
}

/// Task Scheduler XML for a one-shot task that wakes the machine (WakeToRun) at `start_local`
/// (`YYYY-MM-DDTHH:MM:SS`, local time, no zone) and runs `cmd.exe /c exit 0`.
pub fn wake_task_xml(start_local: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n  <RegistrationInfo><Description>i7oracled one-shot wake</Description></RegistrationInfo>\n  <Triggers><TimeTrigger><StartBoundary>{}</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers>\n  <Principals><Principal id=\"Author\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>\n  <Settings>\n    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n    <StartWhenAvailable>true</StartWhenAvailable>\n    <WakeToRun>true</WakeToRun>\n    <ExecutionTimeLimit>PT1M</ExecutionTimeLimit>\n  </Settings>\n  <Actions Context=\"Author\"><Exec><Command>cmd.exe</Command><Arguments>/c exit 0</Arguments></Exec></Actions>\n</Task>\n",
        start_local
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_roundtrip_and_layout() {
        let g = Guid::parse("{5d3e9a59-e9d5-4b00-a6bd-ff34ff516548}").unwrap();
        assert_eq!(g.0[0..4], [0x59, 0x9a, 0x3e, 0x5d]); // Data1 little endian
        assert_eq!(g.0[4..6], [0xd5, 0xe9]);
        assert_eq!(g.to_string(), "5d3e9a59-e9d5-4b00-a6bd-ff34ff516548");
        assert_eq!(setting_name(&g), Some("GUID_ACDC_POWER_SOURCE"));
        assert!(Guid::parse("nope").is_none());
        for (n, s) in SETTINGS {
            assert!(Guid::parse(s).is_some(), "{}", n);
        }
    }

    #[test]
    fn settings_decode() {
        let g = Guid::parse(SETTINGS[0].1).unwrap();
        let j = decode_setting(&g, &1u32.to_le_bytes());
        assert!(j.contains("\"value\":1") && j.contains("DC (battery)") && j.contains("\"raw\":\"01000000\""), "{}", j);
        let lid = Guid::parse("ba3e0f4d-b817-4094-a2d1-d56379e6a0f3").unwrap();
        assert!(decode_setting(&lid, &0u32.to_le_bytes()).contains("lid closed"));
        let pers = Guid::parse("245d8541-3943-4422-b025-13a784f679b7").unwrap();
        let bal = Guid::parse("381b4222-f694-41f0-9685-ff5bb260df2e").unwrap();
        assert!(decode_setting(&pers, &bal.0).contains("balanced"));
        let unk = Guid::parse("00000000-0000-0000-0000-000000000001").unwrap();
        let j = decode_setting(&unk, &[1, 2]);
        assert!(j.contains("\"setting\":null") && !j.contains("value"));
        for s in [j, decode_setting(&g, &[])] {
            assert!(json::parse(&s, &Limits::default()).is_ok());
        }
    }

    #[test]
    fn pbt_names() {
        assert_eq!(pbt_name(PBT_APMRESUMEAUTOMATIC), "PBT_APMRESUMEAUTOMATIC");
        assert_eq!(pbt_name(0x8013), "PBT_POWERSETTINGCHANGE");
        assert_eq!(pbt_name(77), "PBT_UNKNOWN");
    }

    #[test]
    fn power_request_parsing() {
        let r = parse_power_req(br#"{"action":"sleep","wake_after_s":20}"#).unwrap();
        assert_eq!(r, PowerReq { action: Action::Sleep, wake_after_s: Some(20), wake_method: WakeMethod::Timer, delay_s: 2 });
        let r = parse_power_req(br#"{"action":"hibernate","wake_after_s":60,"wake_method":"both","delay_s":0}"#).unwrap();
        assert_eq!((r.wake_method, r.delay_s), (WakeMethod::Both, 0));
        assert_eq!(parse_power_req(br#"{"action":"reboot"}"#).unwrap().wake_after_s, None);
        for bad in [&br#"{"action":"explode"}"#[..], br#"{}"#, br#"{"action":"sleep","wake_after_s":1}"#, br#"{"action":"sleep","wake_after_s":-3}"#, br#"{"action":"shutdown","wake_after_s":30}"#, br#"{"action":"sleep","wake_method":"x"}"#, br#"{"action":"sleep","delay_s":99999}"#, b"nonsense"] {
            assert!(parse_power_req(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn task_xml_mentions_wake() {
        let x = wake_task_xml("2026-11-12T10:20:30");
        assert!(x.contains("<WakeToRun>true</WakeToRun>") && x.contains("2026-11-12T10:20:30"));
    }
}
