//! Whitelisted powercfg / registry commands behind POST /powercfg. Nothing from the request reaches a command line
//! except values that were parsed to integers or matched against fixed words.

use std::path::Path;

use crate::json::{self, Limits, Value};

#[derive(Debug, PartialEq, Eq)]
pub struct Cmd {
    pub program: &'static str,
    pub args: Vec<String>,
    /// File this command writes into the results directory (for the reply), if any.
    pub output_file: Option<String>,
}

fn pc(args: &[&str]) -> Cmd {
    Cmd { program: "powercfg.exe", args: args.iter().map(|s| s.to_string()).collect(), output_file: None }
}

fn pc_s(args: Vec<String>, out: Option<String>) -> Cmd {
    Cmd { program: "powercfg.exe", args, output_file: out }
}

fn minutes(v: &Value, key: &str) -> Result<Option<u64>, String> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(x) => x.as_u64().filter(|n| *n <= 10_080).map(Some).ok_or_else(|| format!("{} must be 0..10080 minutes", key)),
    }
}

fn lid_value(w: &str) -> Result<&'static str, String> {
    Ok(match w {
        "nothing" => "0",
        "sleep" => "1",
        "hibernate" => "2",
        "shutdown" => "3",
        _ => return Err("lid action must be nothing|sleep|hibernate|shutdown".into()),
    })
}

/// Turn a request body into the exact commands to run. `results` is where reports are written; `stamp` a file-name-safe UTC stamp.
pub fn plan(body: &[u8], results: &Path, stamp: &str) -> Result<Vec<Cmd>, String> {
    let text = std::str::from_utf8(body).map_err(|_| "body is not utf-8")?;
    let v = json::parse(text, &Limits::default()).map_err(|e| format!("bad json: {}", e.msg))?;
    let action = v.get("action").and_then(Value::as_str).ok_or("action required")?;
    let flag = |k: &str| match v.get(k) {
        Some(Value::Bool(b)) => Ok(*b),
        _ => Err(format!("{} (true|false) required", k)),
    };
    let rpath = |name: &str| results.join(format!("{}-{}", stamp, name)).to_string_lossy().into_owned();
    let mut out = Vec::new();
    match action {
        "hibernate" => {
            out.push(pc(&["/hibernate", if flag("on")? { "on" } else { "off" }]));
            if let Some(t) = v.get("type").and_then(Value::as_str) {
                if !matches!(t, "full" | "reduced") {
                    return Err("type must be full|reduced".into());
                }
                out.push(pc(&["/hibernate", "/type", t]));
            }
        }
        "timeouts" => {
            // minutes; 0 = never. Keys: standby_ac standby_dc hibernate_ac hibernate_dc monitor_ac monitor_dc disk_ac disk_dc
            let mut any = false;
            for (key, sw) in [("standby_ac", "standby-timeout-ac"), ("standby_dc", "standby-timeout-dc"), ("hibernate_ac", "hibernate-timeout-ac"), ("hibernate_dc", "hibernate-timeout-dc"), ("monitor_ac", "monitor-timeout-ac"), ("monitor_dc", "monitor-timeout-dc"), ("disk_ac", "disk-timeout-ac"), ("disk_dc", "disk-timeout-dc")] {
                if let Some(m) = minutes(&v, key)? {
                    out.push(pc_s(vec!["/change".into(), sw.into(), m.to_string()], None));
                    any = true;
                }
            }
            if !any {
                return Err("timeouts: give at least one of standby_ac standby_dc hibernate_ac hibernate_dc monitor_ac monitor_dc disk_ac disk_dc".into());
            }
        }
        "lid-action" => {
            let mut any = false;
            for (key, verb) in [("ac", "/setacvalueindex"), ("dc", "/setdcvalueindex")] {
                if let Some(w) = v.get(key).and_then(Value::as_str) {
                    out.push(pc_s(vec![verb.into(), "SCHEME_CURRENT".into(), "SUB_BUTTONS".into(), "LIDACTION".into(), lid_value(w)?.into()], None));
                    any = true;
                }
            }
            if !any {
                return Err("lid-action: give ac and/or dc".into());
            }
            out.push(pc(&["/setactive", "SCHEME_CURRENT"]));
        }
        "wake-timers" => {
            let val = if flag("on")? { "1" } else { "0" };
            for verb in ["/setacvalueindex", "/setdcvalueindex"] {
                out.push(pc(&[verb, "SCHEME_CURRENT", "SUB_SLEEP", "RTCWAKE", val]));
            }
            out.push(pc(&["/setactive", "SCHEME_CURRENT"]));
        }
        // reboot needed: Modern Standby (S0ix/AoAc) off exposes S3 where the firmware offers it. UNVERIFIED on the target laptop.
        "modern-standby" => {
            let key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power";
            if flag("enable")? {
                out.push(Cmd { program: "reg.exe", args: ["delete", key, "/v", "PlatformAoAcOverride", "/f"].iter().map(|s| s.to_string()).collect(), output_file: None });
            } else {
                out.push(Cmd { program: "reg.exe", args: ["add", key, "/v", "PlatformAoAcOverride", "/t", "REG_DWORD", "/d", "0", "/f"].iter().map(|s| s.to_string()).collect(), output_file: None });
            }
        }
        "available-states" => out.push(pc(&["/a"])),
        "requests" => out.push(pc(&["/requests"])),
        "lastwake" => out.push(pc(&["/lastwake"])),
        "wake-armed" => out.push(pc(&["/devicequery", "wake_armed"])),
        "list" => out.push(pc(&["/list"])),
        "sleepstudy" | "batteryreport" | "energy" => {
            let dur = match v.get("duration") {
                None | Some(Value::Null) => None,
                Some(x) => Some(x.as_u64().filter(|n| (1..=365).contains(n)).ok_or("duration must be 1..365")?),
            };
            let (flagname, file, durflag) = match action {
                "sleepstudy" => ("/sleepstudy", "sleepstudy.html", "/duration"),
                "batteryreport" => ("/batteryreport", "batteryreport.html", "/duration"),
                _ => ("/energy", "energy.html", "/duration"),
            };
            let f = rpath(file);
            let mut a = vec![flagname.to_string(), "/output".into(), f.clone()];
            if let Some(d) = dur {
                a.push(durflag.into());
                a.push(d.to_string());
            }
            out.push(pc_s(a, Some(format!("{}-{}", stamp, file))));
        }
        _ => return Err("unknown action (hibernate|timeouts|lid-action|wake-timers|modern-standby|available-states|requests|lastwake|wake-armed|list|sleepstudy|batteryreport|energy)".into()),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(b: &str) -> Result<Vec<Cmd>, String> {
        plan(b.as_bytes(), Path::new("C:\\oracle\\results"), "20261112T000000Z")
    }

    #[test]
    fn hibernate_and_timeouts() {
        let c = p(r#"{"action":"hibernate","on":true,"type":"full"}"#).unwrap();
        assert_eq!(c[0].args, ["/hibernate", "on"]);
        assert_eq!(c[1].args, ["/hibernate", "/type", "full"]);
        let c = p(r#"{"action":"timeouts","standby_ac":0,"monitor_dc":5}"#).unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].args, ["/change", "standby-timeout-ac", "0"]);
        assert!(p(r#"{"action":"timeouts"}"#).is_err());
        assert!(p(r#"{"action":"timeouts","standby_ac":"1; calc"}"#).is_err());
        assert!(p(r#"{"action":"hibernate","on":true,"type":"x y"}"#).is_err());
    }

    #[test]
    fn lid_wake_and_reports() {
        let c = p(r#"{"action":"lid-action","ac":"nothing","dc":"sleep"}"#).unwrap();
        assert_eq!(c[0].args, ["/setacvalueindex", "SCHEME_CURRENT", "SUB_BUTTONS", "LIDACTION", "0"]);
        assert_eq!(c[1].args[4], "1");
        assert_eq!(c.last().unwrap().args, ["/setactive", "SCHEME_CURRENT"]);
        assert!(p(r#"{"action":"lid-action","ac":"explode"}"#).is_err());
        let c = p(r#"{"action":"wake-timers","on":true}"#).unwrap();
        assert_eq!(c[0].args[4], "1");
        let c = p(r#"{"action":"sleepstudy","duration":3}"#).unwrap();
        assert_eq!(c[0].args[0], "/sleepstudy");
        assert!(c[0].args[2].contains("20261112T000000Z-sleepstudy.html"));
        assert_eq!(c[0].args[4], "3");
        assert_eq!(c[0].output_file.as_deref(), Some("20261112T000000Z-sleepstudy.html"));
        assert_eq!(p(r#"{"action":"available-states"}"#).unwrap()[0].args, ["/a"]);
        assert!(p(r#"{"action":"batteryreport","duration":0}"#).is_err());
    }

    #[test]
    fn modern_standby_registry() {
        let c = p(r#"{"action":"modern-standby","enable":false}"#).unwrap();
        assert_eq!(c[0].program, "reg.exe");
        assert!(c[0].args.contains(&"PlatformAoAcOverride".to_string()) && c[0].args.contains(&"0".to_string()));
        assert_eq!(p(r#"{"action":"modern-standby","enable":true}"#).unwrap()[0].args[0], "delete");
    }

    #[test]
    fn unknown_refused() {
        for b in [r#"{"action":"format-c"}"#, r#"{}"#, "xx", r#"{"action":"hibernate"}"#] {
            assert!(p(b).is_err(), "{}", b);
        }
    }
}
