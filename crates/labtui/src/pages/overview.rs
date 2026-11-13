//! Overview: identity, CPU, memory, NICs, disks, attention list, recent activity. Owner: P5.

use crate::buffer::Rect;
use crate::fmt;
use crate::input::Key;
use crate::model::{Severity, ViewData};
use crate::page::{DrawCx, KeyCx, Page, PageAction};
use crate::theme::Theme;
use crate::widgets::{self, kv, line, span, spark_string, Line};
use crate::LayoutClass;

use super::storage::bar_string;
use super::or_dash;

#[derive(Default)]
pub struct OverviewPage {
    /// scroll of the single column used in the compact layout
    scroll: usize,
}

struct Section {
    title: &'static str,
    lines: Vec<Line>,
}

fn status_bar(ratio: f64, label: String, unicode: bool, t: &Theme) -> Line {
    let st = if ratio >= 0.9 {
        t.bad
    } else if ratio >= 0.7 {
        t.warn
    } else {
        t.ok
    };
    vec![span(bar_string(ratio, 20, unicode), st), span(format!(" {}", label), t.text)]
}

fn identity(d: &ViewData, t: &Theme) -> Section {
    let dmi = d.dmi.as_ref();
    let g = |k: &str| or_dash(dmi.and_then(|x| x.get(k)));
    let mut l = vec![
        kv("Product", format!("{} {}", g("sys_vendor"), g("product_name")), t),
        kv("Serial", g("product_serial"), t),
        kv("Board", format!("{} {}", g("board_vendor"), g("board_name")), t),
        kv("BIOS", format!("{} {} {}", g("bios_vendor"), g("bios_version"), g("bios_date")), t),
    ];
    if let Some(fw) = &d.firmware {
        let sb = match fw.secure_boot {
            Some(true) => "secure boot on",
            Some(false) => "secure boot off",
            None => "secure boot n/a",
        };
        l.push(kv("Boot", format!("{} ({})", fw.boot_mode, sb), t));
    } else if let Some(s) = &d.system {
        l.push(kv("Boot", s.boot_mode.clone(), t));
    }
    if let Some(s) = &d.system {
        l.push(kv("Kernel", s.kernel.clone(), t));
        l.push(kv("Uptime", fmt::uptime(s.uptime_s), t));
        l.push(kv("Load", format!("{:.2} {:.2} {:.2}", s.load[0], s.load[1], s.load[2]), t));
        if let Some(b) = &s.image_build {
            l.push(kv("Image", b.clone(), t));
        }
    }
    Section { title: "System", lines: l }
}

fn hottest(d: &ViewData) -> Option<(f64, String)> {
    let th = d.thermal.as_ref()?;
    th.hwmon.iter().flat_map(|h| h.temps.iter().map(move |s| (s.value, format!("{}/{}", h.name, s.label)))).max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
}

fn cpu(d: &ViewData, t: &Theme) -> Section {
    let mut l = Vec::new();
    match &d.cpu {
        Some(c) => {
            l.push(line(c.model_name.clone(), t.text));
            l.push(kv("Cores", format!("{} sockets, {} cores, {} threads", c.sockets, c.cores, c.threads), t));
            if let Some(f) = c.freq_mhz {
                l.push(kv("Frequency", format!("{:.0} MHz", f), t));
            }
            if let Some(mc) = &c.microcode {
                l.push(kv("Microcode", mc.clone(), t));
            }
        }
        None => l.push(line("CPU not probed yet", t.dim)),
    }
    if let Some((v, name)) = hottest(d) {
        l.push(kv("Hottest", format!("{:.0} C  {}", v, name), t));
    }
    Section { title: "CPU", lines: l }
}

fn memory(d: &ViewData, t: &Theme, unicode: bool) -> Section {
    let mut l = Vec::new();
    match &d.mem {
        Some(m) if m.total_kib > 0 => {
            let used = m.total_kib.saturating_sub(m.available_kib);
            let ratio = used as f64 / m.total_kib as f64;
            l.push(status_bar(ratio, format!("{} / {}", fmt::kib_bin(used), fmt::kib_bin(m.total_kib)), unicode, t));
            // DIMM summary: group identical modules
            let mut groups: Vec<(String, usize)> = Vec::new();
            for dimm in m.dimms.iter().filter(|x| x.size_mib > 0) {
                let key = format!("{} {} {}", fmt::kib_bin(dimm.size_mib * 1024), dimm.kind.as_deref().unwrap_or(""), dimm.speed_mts.map(|s| format!("@{}", s)).unwrap_or_default()).trim().to_string();
                match groups.iter_mut().find(|(k, _)| *k == key) {
                    Some(g) => g.1 += 1,
                    None => groups.push((key, 1)),
                }
            }
            if !groups.is_empty() {
                let txt: Vec<String> = groups.iter().map(|(k, n)| format!("{}x {}", n, k)).collect();
                l.push(kv("DIMMs", txt.join(", "), t));
            }
            l.push(kv("ECC", m.ecc.clone().unwrap_or_else(|| "-".into()), t));
        }
        _ => l.push(line("memory not probed yet", t.dim)),
    }
    Section { title: "Memory", lines: l }
}

fn network(d: &ViewData, t: &Theme) -> Section {
    let mut l = Vec::new();
    match &d.net {
        Some(n) => {
            for i in n.ifaces.iter().filter(|i| i.name != "lo") {
                let up = i.operstate == "up" || i.carrier == Some(true);
                l.push(vec![
                    span(format!("{:<9}", i.name), t.text),
                    span(format!("{:<5}", if up { "up" } else { "down" }), if up { t.ok } else { t.warn }),
                    span(i.speed_mbps.map(|s| format!("{:>5} Mb/s ", s)).unwrap_or_else(|| "     -      ".into()), t.dim),
                    span(i.ipv4.first().cloned().unwrap_or_else(|| "no address".into()), t.text),
                ]);
            }
            if l.is_empty() {
                l.push(line("no network interfaces", t.warn));
            }
        }
        None => l.push(line("network not probed yet", t.dim)),
    }
    Section { title: "Network", lines: l }
}

fn storage(d: &ViewData, t: &Theme) -> Section {
    let mut l = Vec::new();
    match &d.block {
        Some(b) => {
            l.push(kv("Disks", b.devices.len().to_string(), t));
            for dev in &b.devices {
                let verdict = d.smart.as_ref().and_then(|s| s.devices.iter().find(|r| r.dev == dev.name)).map(|r| r.verdict.as_str());
                let (sm, st) = match verdict {
                    Some("pass") => ("smart ok", t.ok),
                    Some("warn") => ("SMART WARN", t.warn),
                    Some("fail") => ("SMART FAIL", t.bad),
                    _ => ("smart -", t.dim),
                };
                l.push(vec![
                    span(format!("{:<9}", dev.name), t.text),
                    span(format!("{:>9} ", fmt::bytes_dec(dev.size_bytes)), t.text),
                    span(format!("{:<11}", st_label(dev)), t.dim),
                    span(sm, st),
                ]);
            }
        }
        None => l.push(line("disks not probed yet", t.dim)),
    }
    Section { title: "Storage", lines: l }
}

fn st_label(d: &labprobe::block::BlockDevice) -> &'static str {
    if d.boot_media {
        "boot media"
    } else if !d.mounts.is_empty() {
        "mounted"
    } else {
        "idle"
    }
}

fn attention(d: &ViewData, t: &Theme) -> Section {
    let a = d.attention();
    let mut l: Vec<Line> = Vec::new();
    if a.is_empty() {
        l.push(line("nothing needs attention", t.ok));
    }
    for x in &a {
        let (mark, st) = match x.severity {
            Severity::Bad => ("!! ", t.bad),
            Severity::Warn => ("!  ", t.warn),
        };
        l.push(vec![span(mark, st), span(x.text.clone(), st)]);
    }
    Section { title: "Attention", lines: l }
}

fn activity(d: &ViewData, t: &Theme) -> Section {
    let mut l: Vec<Line> = d.audit.iter().rev().take(5).map(|a| line(a.clone(), t.text)).collect();
    if l.is_empty() {
        l.push(line("no activity yet", t.dim));
    }
    Section { title: "Recent activity", lines: l }
}

fn temperatures(d: &ViewData, t: &Theme, unicode: bool) -> Section {
    let mut l = Vec::new();
    if let Some(th) = &d.thermal {
        for h in &th.hwmon {
            for s in h.temps.iter().take(6) {
                let key = format!("temp:{}/{}", h.name, s.label);
                let hist = d.series.get(&key).map(|v| v.as_slice()).unwrap_or(&[]);
                l.push(vec![span(format!("{:<16.16}", format!("{}/{}", h.name, s.label)), t.dim), span(spark_string(hist, 20, unicode), t.accent), span(format!(" {:.0} C", s.value), t.text)]);
            }
        }
    }
    if l.is_empty() {
        l.push(line("no temperature sensors", t.dim));
    }
    Section { title: "Temperatures", lines: l }
}

/// Draw sections into a column of panes.
fn column(cx: &mut DrawCx, area: Rect, secs: &[Section]) {
    let mut y = area.y;
    let mut remaining = area.h;
    let n = secs.len();
    for (i, s) in secs.iter().enumerate() {
        let left = (n - i - 1) as u16;
        let need = s.lines.len() as u16 + 2;
        let reserve = 3 * left;
        let give = if i + 1 == n { need.min(remaining) } else { need.min(remaining.saturating_sub(reserve)).max(3.min(remaining)) };
        if give < 3 {
            break;
        }
        let r = Rect::new(area.x, y, area.w, give);
        let inner = widgets::pane(cx.buf, r, s.title, false, cx.theme, cx.set);
        widgets::text(cx.buf, inner, &s.lines, 0, cx.theme);
        y += give;
        remaining -= give;
    }
}

impl Page for OverviewPage {
    fn title(&self) -> &'static str {
        "Overview"
    }
    fn short(&self) -> &'static str {
        "Ovw"
    }
    fn draw(&mut self, cx: &mut DrawCx, area: Rect) {
        let t = cx.theme;
        let u = cx.unicode();
        let d = cx.data;
        match cx.class {
            LayoutClass::Compact | LayoutClass::TooSmall => {
                // one scrolling column: attention first, it is what the operator came to see
                let mut lines: Vec<Line> = Vec::new();
                for s in [attention(d, t), identity(d, t), cpu(d, t), memory(d, t, u), network(d, t), storage(d, t), activity(d, t)] {
                    lines.push(line(s.title.to_string(), t.title));
                    lines.extend(s.lines);
                    lines.push(super::blank());
                }
                let inner = widgets::pane(cx.buf, area, "Overview", true, t, cx.set);
                self.scroll = self.scroll.min(lines.len().saturating_sub(inner.h as usize));
                widgets::text(cx.buf, inner, &lines, self.scroll, t);
            }
            LayoutClass::Standard => {
                let (l, r) = area.split_h(area.w / 2);
                column(cx, l, &[identity(d, t), cpu(d, t), memory(d, t, u), activity(d, t)]);
                column(cx, r, &[attention(d, t), network(d, t), storage(d, t)]);
            }
            LayoutClass::Wide => {
                let w3 = area.w / 3;
                let (a, rest) = area.split_h(w3);
                let (b, c) = rest.split_h(w3);
                column(cx, a, &[identity(d, t), cpu(d, t), memory(d, t, u)]);
                column(cx, b, &[network(d, t), storage(d, t), activity(d, t)]);
                column(cx, c, &[attention(d, t), temperatures(d, t, u)]);
            }
        }
    }
    fn key(&mut self, key: Key, _cx: &KeyCx) -> PageAction {
        match key {
            Key::Up | Key::Char('k') => self.scroll = self.scroll.saturating_sub(1),
            Key::Down | Key::Char('j') => self.scroll += 1,
            Key::PgUp => self.scroll = self.scroll.saturating_sub(10),
            Key::PgDn => self.scroll += 10,
            Key::Home => self.scroll = 0,
            Key::End => self.scroll = usize::MAX / 2,
            _ => return PageAction::Unhandled,
        }
        PageAction::Handled
    }
    fn help(&self) -> &'static [(&'static str, &'static str)] {
        &[("Up/Down", "scroll (compact layout)"), ("1..8", "jump to a page")]
    }
}
