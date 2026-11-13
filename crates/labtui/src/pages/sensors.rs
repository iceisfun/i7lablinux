//! Sensors: temperatures, fans, voltages and power with sparkline history; thresholds colour the value. Owner: P5.

use crate::buffer::{Rect, Style};
use crate::input::Key;
use crate::model::ViewData;
use crate::page::{missing, DrawCx, KeyCx, Left, Md, MdView, Page, PageAction};
use crate::theme::Theme;
use crate::widgets::{kv, line, span, spark_string, Col, Line, Span};

use super::{blank, heading};

#[derive(Default)]
pub struct SensorsPage {
    md: Md,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Temp,
    Fan,
    Volt,
    Power,
}

struct Row {
    name: String,
    kind: Kind,
    value: f64,
    max: Option<f64>,
    crit: Option<f64>,
    series: Option<String>,
}

const COLS: [Col; 4] = [Col::new("Sensor", 0, 0), Col::new("Kind", 5, 2), Col::new("Value", 10, 0).right(), Col::new("Limit", 10, 1).right()];

fn rows(data: &ViewData) -> Vec<Row> {
    let mut v = Vec::new();
    let Some(t) = &data.thermal else { return v };
    for z in &t.zones {
        if let Some(c) = z.temp_c {
            v.push(Row { name: format!("zone {} ({})", z.name, z.kind), kind: Kind::Temp, value: c, max: None, crit: z.crit_c, series: Some(format!("temp:zone/{}", z.name)) });
        }
    }
    for h in &t.hwmon {
        for s in &h.temps {
            v.push(Row { name: format!("{}/{}", h.name, s.label), kind: Kind::Temp, value: s.value, max: s.max, crit: s.crit, series: Some(format!("temp:{}/{}", h.name, s.label)) });
        }
        for s in &h.fans {
            v.push(Row { name: format!("{}/{}", h.name, s.label), kind: Kind::Fan, value: s.value, max: s.max, crit: s.crit, series: None });
        }
        for s in &h.volts {
            v.push(Row { name: format!("{}/{}", h.name, s.label), kind: Kind::Volt, value: s.value, max: s.max, crit: s.crit, series: None });
        }
        for s in &h.power {
            v.push(Row { name: format!("{}/{}", h.name, s.label), kind: Kind::Power, value: s.value, max: s.max, crit: s.crit, series: None });
        }
    }
    v
}

fn fmt_value(kind: Kind, v: f64) -> String {
    match kind {
        Kind::Temp => format!("{:.1} C", v),
        Kind::Fan => format!("{:.0} rpm", v),
        Kind::Volt => format!("{:.3} V", v / 1000.0),
        Kind::Power => format!("{:.1} W", v / 1000.0),
    }
}

fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::Temp => "temp",
        Kind::Fan => "fan",
        Kind::Volt => "volt",
        Kind::Power => "power",
    }
}

/// Status colour: red at or above the critical limit, yellow at the max or within 10 degrees of critical.
fn status(r: &Row, t: &Theme) -> Style {
    if r.crit.map(|c| r.value >= c).unwrap_or(false) {
        t.bad
    } else if r.max.map(|m| r.value >= m).unwrap_or(false) || (r.kind == Kind::Temp && r.crit.map(|c| r.value >= c - 10.0).unwrap_or(false)) {
        t.warn
    } else {
        t.ok
    }
}

fn limit_text(r: &Row) -> String {
    match (r.max, r.crit) {
        (Some(m), Some(c)) => format!("{}/{}", short(r.kind, m), short(r.kind, c)),
        (Some(m), None) => short(r.kind, m),
        (None, Some(c)) => format!("crit {}", short(r.kind, c)),
        _ => "-".into(),
    }
}

fn short(kind: Kind, v: f64) -> String {
    match kind {
        Kind::Temp => format!("{:.0}", v),
        Kind::Fan => format!("{:.0}", v),
        Kind::Volt => format!("{:.2}", v / 1000.0),
        Kind::Power => format!("{:.0}", v / 1000.0),
    }
}

fn detail(r: &Row, data: &ViewData, t: &Theme, unicode: bool) -> Vec<Line> {
    let mut v = vec![
        kv("Sensor", r.name.clone(), t),
        kv("Kind", kind_name(r.kind), t),
        vec![span(format!("{:<15}", "Value:"), t.dim), span(fmt_value(r.kind, r.value), status(r, t))],
        kv("Max", r.max.map(|m| fmt_value(r.kind, m)).unwrap_or_else(|| "-".into()), t),
        kv("Critical", r.crit.map(|m| fmt_value(r.kind, m)).unwrap_or_else(|| "-".into()), t),
    ];
    if let Some(s) = r.series.as_ref().and_then(|k| data.series.get(k)).filter(|s| !s.is_empty()) {
        let lo = s.iter().cloned().fold(f32::MAX, f32::min);
        let hi = s.iter().cloned().fold(f32::MIN, f32::max);
        v.push(blank());
        v.push(heading(t, "History"));
        v.push(line(spark_string(s, 40, unicode), t.accent));
        v.push(line(format!("min {:.1}  max {:.1}  ({} samples)", lo, hi, s.len()), t.dim));
    }
    if let Some(th) = &data.thermal {
        if !th.alarms.is_empty() {
            v.push(blank());
            v.push(heading(t, "Alarms"));
            for a in &th.alarms {
                v.push(line(a.clone(), t.warn));
            }
        }
    }
    v
}

impl Page for SensorsPage {
    fn title(&self) -> &'static str {
        "Sensors"
    }
    fn short(&self) -> &'static str {
        "Sen"
    }
    fn draw(&mut self, cx: &mut DrawCx, area: Rect) {
        let t = cx.theme;
        if cx.data.thermal.is_none() {
            let l = missing(t, "sensors");
            self.md.draw(cx, area, MdView { left_title: "Sensors", left: Left::Lines(&l), detail_title: "Detail", detail: &[], live: None });
            return;
        }
        let rs = rows(cx.data);
        let table: Vec<Vec<Span>> = rs
            .iter()
            .map(|r| vec![span(r.name.clone(), t.text), span(kind_name(r.kind), t.dim), span(fmt_value(r.kind, r.value), status(r, t)), span(limit_text(r), t.dim)])
            .collect();
        let sel = self.md.list.selected.min(rs.len().saturating_sub(1));
        let unicode = cx.unicode();
        let det = rs.get(sel).map(|r| detail(r, cx.data, t, unicode)).unwrap_or_else(|| vec![line("no sensors found", t.dim)]);
        // wide: every temperature with its graph
        let mut live: Vec<Line> = Vec::new();
        for r in rs.iter().filter(|r| r.kind == Kind::Temp) {
            let s = r.series.as_ref().and_then(|k| cx.data.series.get(k));
            live.push(vec![span(format!("{:<24.24}", r.name), t.dim), span(spark_string(s.map(|v| v.as_slice()).unwrap_or(&[]), 20, unicode), t.accent), span(format!(" {:.0}", r.value), status(r, t))]);
        }
        self.md.draw(cx, area, MdView { left_title: "Sensors", left: Left::Table(&COLS, &table), detail_title: "Sensor", detail: &det, live: Some(("Temperatures", &live)) });
    }
    fn key(&mut self, key: Key, cx: &KeyCx) -> PageAction {
        self.md.key(key, cx.focus)
    }
    fn help(&self) -> &'static [(&'static str, &'static str)] {
        &[("Up/Down", "select sensor"), ("Enter", "history and limits")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn r(kind: Kind, value: f64, max: Option<f64>, crit: Option<f64>) -> Row {
        Row { name: "x".into(), kind, value, max, crit, series: None }
    }
    #[test]
    fn thresholds_colour() {
        let t = Theme::dark();
        assert_eq!(status(&r(Kind::Temp, 50.0, Some(80.0), Some(100.0)), &t), t.ok);
        assert_eq!(status(&r(Kind::Temp, 80.0, Some(80.0), Some(100.0)), &t), t.warn);
        assert_eq!(status(&r(Kind::Temp, 91.0, None, Some(100.0)), &t), t.warn);
        assert_eq!(status(&r(Kind::Temp, 100.0, Some(80.0), Some(100.0)), &t), t.bad);
        assert_eq!(status(&r(Kind::Fan, 0.0, None, None), &t), t.ok);
    }
    #[test]
    fn units() {
        assert_eq!(fmt_value(Kind::Volt, 12100.0), "12.100 V");
        assert_eq!(fmt_value(Kind::Power, 45500.0), "45.5 W");
        assert_eq!(limit_text(&r(Kind::Temp, 1.0, Some(80.0), Some(100.0))), "80/100");
    }
}
