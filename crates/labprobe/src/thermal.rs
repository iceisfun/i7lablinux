//! thermal: thermal zones, hwmon (temps, fans, voltages, power), alarms. Owner: P3.

use labproto::json::{JsonWriter, ToJson};

use crate::ctx::{ProbeCtx, ProbeError};

#[derive(Clone, Debug, Default)]
pub struct Zone {
    pub name: String,
    pub kind: String,
    pub temp_c: Option<f64>,
    pub crit_c: Option<f64>,
}

#[derive(Clone, Debug, Default)]
pub struct Sensor {
    /// attribute number (temp3_input -> 3)
    pub index: u32,
    pub label: String,
    pub value: f64,
    pub max: Option<f64>,
    pub crit: Option<f64>,
}

#[derive(Clone, Debug, Default)]
pub struct Hwmon {
    pub name: String,
    /// value in degrees C
    pub temps: Vec<Sensor>,
    /// value in rpm
    pub fans: Vec<Sensor>,
    /// value in mV
    pub volts: Vec<Sensor>,
    /// value in mW
    pub power: Vec<Sensor>,
}

#[derive(Clone, Debug, Default)]
pub struct ThermalReport {
    pub zones: Vec<Zone>,
    pub hwmon: Vec<Hwmon>,
    pub alarms: Vec<String>,
}

fn milli(s: Option<String>) -> Option<f64> {
    s.and_then(|v| v.parse::<f64>().ok())
}

/// hwmon chip: `temp*`, `fan*`, `in*`, `power*` attribute groups. Units: millidegrees C -> C, rpm, millivolts,
/// microwatts -> milliwatts. A group with no `_input` is skipped; label defaults to the group name.
fn read_hwmon(ctx: &ProbeCtx, dir: &str, alarms: &mut Vec<String>) -> Hwmon {
    let files = ctx.list_dir(dir).unwrap_or_default();
    let r = |f: &str| ctx.read_opt(&format!("{}/{}", dir, f));
    let name = r("name").unwrap_or_else(|| dir.rsplit('/').next().unwrap_or("hwmon").to_string());
    let mut h = Hwmon { name: name.clone(), ..Default::default() };
    for f in &files {
        let Some(group) = f.strip_suffix("_input") else { continue };
        let kind = ["temp", "fan", "in", "power"].into_iter().find(|k| group.strip_prefix(*k).map(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())).unwrap_or(false));
        let Some(kind) = kind else { continue };
        let Some(raw) = milli(r(f)) else { continue };
        let label = r(&format!("{}_label", group)).unwrap_or_else(|| group.to_string());
        let scale = |v: f64| match kind {
            "temp" => v / 1000.0,
            "power" => v / 1000.0,
            _ => v,
        };
        let index = group.trim_start_matches(|c: char| c.is_ascii_alphabetic()).parse().unwrap_or(0);
        let mut s = Sensor {
            index,
            label: label.clone(),
            value: scale(raw),
            max: milli(r(&format!("{}_max", group))).map(scale),
            crit: milli(r(&format!("{}_crit", group))).map(scale),
        };
        match kind {
            "temp" => {
                if let Some(c) = s.crit.filter(|c| *c > 0.0) {
                    if s.value >= c {
                        alarms.push(format!("{} {}: {:.1} C at or over critical {:.1} C", name, label, s.value, c));
                    }
                }
                h.temps.push(s)
            }
            "fan" => {
                let min = milli(r(&format!("{}_min", group))).unwrap_or(0.0);
                if raw == 0.0 && (min > 0.0 || r(&format!("{}_label", group)).is_some()) {
                    alarms.push(format!("{} {}: fan stopped (0 rpm)", name, label));
                }
                s.max = None;
                s.crit = None;
                h.fans.push(s)
            }
            "in" => {
                // in*_max / in*_min are millivolts as well
                h.volts.push(s)
            }
            _ => h.power.push(s),
        }
        if r(&format!("{}_alarm", group)).as_deref() == Some("1") {
            alarms.push(format!("{} {}: hardware alarm", name, label));
        }
    }
    sort_sensors(&mut h.temps);
    sort_sensors(&mut h.fans);
    sort_sensors(&mut h.volts);
    sort_sensors(&mut h.power);
    h
}

fn sort_sensors(v: &mut [Sensor]) {
    v.sort_by_key(|s| s.index);
}

pub fn probe(ctx: &ProbeCtx) -> Result<ThermalReport, ProbeError> {
    let mut rep = ThermalReport::default();
    for z in ctx.list_dir("/sys/class/thermal").unwrap_or_default() {
        if !z.starts_with("thermal_zone") {
            continue;
        }
        let base = format!("/sys/class/thermal/{}", z);
        let r = |f: &str| ctx.read_opt(&format!("{}/{}", base, f));
        let temp_c = milli(r("temp")).map(|m| m / 1000.0);
        let mut crit_c = None;
        for i in 0..16 {
            if r(&format!("trip_point_{}_type", i)).as_deref() == Some("critical") {
                crit_c = milli(r(&format!("trip_point_{}_temp", i))).map(|m| m / 1000.0);
                break;
            }
        }
        let kind = r("type").unwrap_or_default();
        if let (Some(t), Some(c)) = (temp_c, crit_c) {
            if c > 0.0 && t >= c {
                rep.alarms.push(format!("{} ({}): {:.1} C at or over critical {:.1} C", z, kind, t, c));
            }
        }
        rep.zones.push(Zone { name: z, kind, temp_c, crit_c });
    }
    let mut dirs: Vec<String> = ctx.list_dir("/sys/class/hwmon").unwrap_or_default().into_iter().filter(|d| d.starts_with("hwmon")).collect();
    dirs.sort_by_key(|d| d[5..].parse::<u32>().unwrap_or(u32::MAX));
    for d in dirs {
        let mut al = Vec::new();
        let h = read_hwmon(ctx, &format!("/sys/class/hwmon/{}", d), &mut al);
        rep.alarms.extend(al);
        if !(h.temps.is_empty() && h.fans.is_empty() && h.volts.is_empty() && h.power.is_empty()) {
            rep.hwmon.push(h);
        }
    }
    Ok(rep)
}

fn sensors(w: &mut JsonWriter, k: &str, v: &[Sensor]) {
    w.key(k);
    w.begin_array();
    for s in v {
        w.begin_object();
        w.field_str("label", &s.label);
        w.field_f64("value", s.value);
        w.field_opt_f64("max", s.max);
        w.field_opt_f64("crit", s.crit);
        w.end_object();
    }
    w.end_array();
}

impl ToJson for ThermalReport {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_u64("v", crate::SCHEMA_V);
        w.key("zones");
        w.begin_array();
        for z in &self.zones {
            w.begin_object();
            w.field_str("name", &z.name);
            w.field_str("kind", &z.kind);
            w.field_opt_f64("temp_c", z.temp_c);
            w.field_opt_f64("crit_c", z.crit_c);
            w.end_object();
        }
        w.end_array();
        w.key("hwmon");
        w.begin_array();
        for h in &self.hwmon {
            w.begin_object();
            w.field_str("name", &h.name);
            sensors(w, "temps_c", &h.temps);
            sensors(w, "fans_rpm", &h.fans);
            sensors(w, "volts_mv", &h.volts);
            sensors(w, "power_mw", &h.power);
            w.end_object();
        }
        w.end_array();
        w.key("alarms");
        w.value(&self.alarms);
        w.end_object();
    }
}
