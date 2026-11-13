//! Storage: block devices with SMART and the write-safety verdict; read test on `t`. Owner: P5.

use labprobe::block::{BlockDevice, Reason, Verdict};

use crate::buffer::Rect;
use crate::fmt;
use crate::input::Key;
use crate::model::ViewData;
use crate::page::{missing, DrawCx, KeyCx, Left, Md, MdView, Page, PageAction, Request, Then};
use crate::theme::Theme;
use crate::widgets::{kv, line, span, Col, Dialog, DialogKind, Line, Span};

use super::{blank, heading, or_dash};

#[derive(Default)]
pub struct StoragePage {
    md: Md,
    /// device names of the rows at the last draw
    names: Vec<String>,
}

const COLS: [Col; 7] = [
    Col::new("Dev", 9, 0),
    Col::new("Type", 6, 4),
    Col::new("Size", 9, 0).right(),
    Col::new("Model", 0, 0),
    Col::new("Serial", 20, 3),
    Col::new("SMART", 5, 2),
    Col::new("State", 10, 1),
];

/// Human text for one write-gate reason.
#[allow(unreachable_patterns)]
pub fn reason_text(r: &Reason) -> String {
    match r {
        Reason::NotDestructive => "the destructive flag was not given".into(),
        Reason::SerialMissing => "no serial was given".into(),
        Reason::SerialMismatch => "the given serial does not match".into(),
        Reason::NoSerial => "the device has no serial or WWID to confirm against".into(),
        Reason::BootMedia => "this is the boot media".into(),
        Reason::BacksRunningSystem => "backs the running system".into(),
        Reason::Mounted(m) => format!("mounted at {}", m),
        Reason::Held(h) => format!("held by {}", h),
        Reason::Swap => "in use as swap".into(),
        Reason::Busy => "busy (claimed by another opener)".into(),
        Reason::ReadOnly => "read-only device".into(),
        Reason::UnderTest => "another test is running on it".into(),
        Reason::PartitionTable(k) => format!("has a {} partition table", k),
        Reason::Signature(k) => format!("carries a {} signature", k),
        Reason::NotFound => "device not found".into(),
        Reason::NotADisk => "not a whole disk".into(),
        other => format!("{:?}", other),
    }
}

fn state(d: &BlockDevice) -> &'static str {
    if d.boot_media {
        "boot media"
    } else if !d.mounts.is_empty() {
        "mounted"
    } else if !d.holders.is_empty() {
        "in use"
    } else {
        "idle"
    }
}

fn smart_of<'a>(data: &'a ViewData, dev: &str) -> Option<&'a labprobe::block::smart::SmartReport> {
    data.smart.as_ref()?.devices.iter().find(|r| r.dev == dev)
}

/// `[#####.....]` progress bar as text.
pub fn bar_string(ratio: f64, width: usize, unicode: bool) -> String {
    let ratio = if ratio.is_finite() { ratio.clamp(0.0, 1.0) } else { 0.0 };
    let filled = (ratio * width as f64).round() as usize;
    let (on, off) = if unicode { ('█', '░') } else { ('#', '.') };
    let mut s = String::from("[");
    s.extend(std::iter::repeat(on).take(filled));
    s.extend(std::iter::repeat(off).take(width.saturating_sub(filled)));
    s.push(']');
    s
}

fn detail(d: &BlockDevice, data: &ViewData, t: &Theme, unicode: bool) -> Vec<Line> {
    let mut v = vec![
        kv("Device", format!("/dev/{}", d.name), t),
        kv("Model", format!("{} {}", d.vendor.as_deref().unwrap_or(""), d.model.as_deref().unwrap_or("")).trim().to_string(), t),
        kv("Serial", format!("{}{}", or_dash(d.serial.as_deref()), d.serial_source.map(|s| format!("  ({})", s.name())).unwrap_or_default()), t),
        kv("WWID", or_dash(d.wwid.as_deref()), t),
        kv("Firmware", or_dash(d.firmware_rev.as_deref()), t),
        kv("Size", format!("{} ({} bytes)", fmt::bytes_dec(d.size_bytes), d.size_bytes), t),
        kv("Sector", format!("{} logical / {} physical", d.logical_block, d.physical_block), t),
        kv("Type", format!("{}{}{}", d.kind.name(), if d.rotational { ", rotational" } else { ", solid state" }, if d.removable { ", removable" } else { "" }), t),
    ];
    if d.read_only {
        v.push(vec![span(format!("{:<15}", "Read-only:"), t.dim), span("yes", t.warn)]);
    }
    // write safety, in colour
    let (word, st) = match d.write_safety.verdict {
        Verdict::Safe => ("blank: writable with the destructive flag + serial", t.ok),
        Verdict::NeedsOverride => ("has data structures: writable only with the destructive flag + serial", t.warn),
        Verdict::Refused => ("REFUSED", t.bad),
    };
    v.push(vec![span(format!("{:<15}", "Write gate:"), t.dim), span(word, st)]);
    for r in &d.write_safety.absolute {
        v.push(line(format!("  - {}", reason_text(r)), t.bad));
    }
    for r in &d.write_safety.overridable {
        v.push(line(format!("  - {}", reason_text(r)), t.warn));
    }
    v.push(blank());
    v.push(heading(t, "Partitions"));
    match &d.partition_table {
        Some(pt) => {
            let crc = if pt.header_crc_ok { "crc ok" } else { "HEADER CRC BAD" };
            v.push(line(format!("{}  {}  {}", pt.kind, pt.disk_guid.as_deref().unwrap_or(""), crc), if pt.header_crc_ok { t.text } else { t.bad }));
        }
        None => v.push(line("no partition table", t.dim)),
    }
    for p in &d.partitions {
        let sectors = p.last_lba.saturating_sub(p.first_lba) + 1;
        let kind = p.type_guid.clone().or_else(|| p.mbr_type.map(|b| format!("type 0x{:02x}", b))).unwrap_or_default();
        v.push(line(format!("p{:<2} {:>10} {:>10}  {} {}", p.index, p.first_lba, fmt::bytes_dec(sectors * d.logical_block.max(1) as u64), p.name.as_deref().unwrap_or(""), kind), t.text));
    }
    v.push(blank());
    v.push(heading(t, "Signatures"));
    if d.signatures.is_empty() {
        v.push(line("none detected", t.dim));
    }
    for s in &d.signatures {
        v.push(line(format!("{} @{}  {}  {}", s.kind, s.offset, s.label.as_deref().unwrap_or(""), s.uuid.as_deref().unwrap_or("")), t.text));
    }
    if !d.mounts.is_empty() {
        v.push(blank());
        v.push(heading(t, "Mounted"));
        for m in &d.mounts {
            v.push(line(m.clone(), t.warn));
        }
    }
    if !d.holders.is_empty() {
        v.push(kv("Held by", d.holders.join(", "), t));
    }
    // SMART
    v.push(blank());
    v.push(heading(t, "SMART"));
    match smart_of(data, &d.name) {
        None => v.push(line("not probed", t.dim)),
        Some(s) => {
            let st = match s.verdict.as_str() {
                "pass" => t.ok,
                "warn" => t.warn,
                "fail" => t.bad,
                _ => t.dim,
            };
            v.push(vec![span(format!("{:<15}", "Verdict:"), t.dim), span(s.verdict.clone(), st), span(format!("  ({})", s.kind), t.dim)]);
            for r in &s.reasons {
                v.push(line(format!("  - {}", r), st));
            }
            if let Some(c) = s.temperature_c {
                v.push(kv("Temperature", format!("{:.0} C", c), t));
            }
            if let Some(h) = s.power_on_hours {
                v.push(kv("Power on", format!("{} h", h), t));
            }
            if let Some(n) = &s.nvme {
                v.push(kv("Critical warn", format!("0x{:02x}", n.critical_warning), t));
                v.push(kv("Spare / used", format!("{}% spare, {}% used", n.available_spare, n.percentage_used), t));
                v.push(kv("Media errors", n.media_errors.to_string(), t));
                v.push(kv("Unsafe stops", n.unsafe_shutdowns.to_string(), t));
            }
            for a in &s.attrs {
                v.push(line(format!("{:>3} {:<24} {:>3}/{:>3}/{:>3} raw {}", a.id, a.name, a.value, a.worst, a.thresh, a.raw), if a.failing_now { t.bad } else { t.text }));
            }
        }
    }
    // running test
    if let Some(tv) = data.test.as_ref().filter(|x| x.dev == d.name) {
        v.push(blank());
        v.push(heading(t, &format!("Test: {} ({})", tv.mode, tv.progress.region)));
        let ratio = if tv.progress.total_bytes > 0 { tv.progress.done_bytes as f64 / tv.progress.total_bytes as f64 } else { 0.0 };
        v.push(line(format!("{} {:>3.0}%", bar_string(ratio, 24, unicode), ratio * 100.0), t.accent));
        v.push(line(
            format!("{} of {}  {:.0} MiB/s  errors {}", fmt::bytes_bin(tv.progress.done_bytes), fmt::bytes_bin(tv.progress.total_bytes), tv.progress.mib_s, tv.errors),
            if tv.errors > 0 { t.bad } else { t.text },
        ));
        let max = tv.latency.iter().map(|(_, n)| *n).max().unwrap_or(1).max(1);
        for (label, n) in &tv.latency {
            v.push(line(format!("{:>8} {} {}", label, bar_string(*n as f64 / max as f64, 16, unicode), n), t.text));
        }
    }
    v
}

impl Page for StoragePage {
    fn title(&self) -> &'static str {
        "Storage"
    }
    fn short(&self) -> &'static str {
        "Sto"
    }
    fn draw(&mut self, cx: &mut DrawCx, area: Rect) {
        let t = cx.theme;
        self.md.left_pct = 45;
        let Some(blk) = cx.data.block.as_ref() else {
            let l = missing(t, "block devices");
            self.md.draw(cx, area, MdView { left_title: "Storage", left: Left::Lines(&l), detail_title: "Detail", detail: &[], live: None });
            return;
        };
        self.names = blk.devices.iter().map(|d| d.name.clone()).collect();
        let rows: Vec<Vec<Span>> = blk
            .devices
            .iter()
            .map(|d| {
                let (sm, sm_st) = match smart_of(cx.data, &d.name).map(|s| s.verdict.as_str()) {
                    Some("pass") => ("ok", t.ok),
                    Some("warn") => ("WARN", t.warn),
                    Some("fail") => ("FAIL", t.bad),
                    _ => ("-", t.dim),
                };
                let st = state(d);
                let st_style = match st {
                    "boot media" => t.warn,
                    "mounted" | "in use" => t.accent,
                    _ => t.text,
                };
                vec![
                    span(d.name.clone(), t.text),
                    span(d.kind.name(), t.dim),
                    span(fmt::bytes_dec(d.size_bytes), t.text),
                    span(format!("{} {}", d.vendor.as_deref().unwrap_or(""), d.model.as_deref().unwrap_or("")).trim().to_string(), t.text),
                    span(or_dash(d.serial.as_deref()), t.text),
                    span(sm, sm_st),
                    span(st, st_style),
                ]
            })
            .collect();
        let sel = self.md.list.selected.min(blk.devices.len().saturating_sub(1));
        let unicode = cx.unicode();
        let det = blk.devices.get(sel).map(|d| detail(d, cx.data, t, unicode)).unwrap_or_else(|| vec![line("no block devices", t.dim)]);
        self.md.draw(cx, area, MdView { left_title: "Disks", left: Left::Table(&COLS, &rows), detail_title: "Disk", detail: &det, live: None });
    }
    fn key(&mut self, key: Key, cx: &KeyCx) -> PageAction {
        let a = self.md.key(key, cx.focus);
        if !matches!(a, PageAction::Unhandled) {
            return a;
        }
        let Some(name) = self.names.get(self.md.list.selected).cloned() else { return PageAction::Unhandled };
        let dev = cx.data.block.as_ref().and_then(|b| b.devices.iter().find(|d| d.name == name));
        match key {
            Key::Char('t') => {
                let mut d = Dialog::confirm("Read test", &[&format!("Run a read-only surface test on /dev/{}?", name), "Nothing is written to the disk."]);
                d.kind = DialogKind::Info;
                PageAction::Ask { dialog: d, then: Then::Req(Request::BlockReadTest { dev: name }) }
            }
            Key::Char('w') => {
                if !cx.write_tests {
                    return PageAction::Status("write tests are not part of this console yet: use `i7labctl --cmd blk.write`".into());
                }
                let Some(dev) = dev else { return PageAction::Handled };
                if dev.write_safety.verdict == Verdict::Refused {
                    let mut body = vec![format!("/dev/{} cannot be written:", name)];
                    body.extend(dev.write_safety.absolute.iter().map(|r| format!("- {}", reason_text(r))));
                    let mut d = Dialog::new("Write test refused", &[], &["OK"]);
                    d.body = body;
                    d.kind = DialogKind::Danger;
                    return PageAction::Info(d);
                }
                let serial = dev.serial.clone().or_else(|| dev.wwid.clone());
                let Some(serial) = serial else { return PageAction::Status("no serial to confirm with: write refused".into()) };
                let mut body = vec![format!("This DESTROYS all data on /dev/{} ({}).", name, fmt::bytes_dec(dev.size_bytes))];
                body.extend(dev.write_safety.overridable.iter().map(|r| format!("- {}", reason_text(r))));
                body.push(format!("Type the full serial to confirm: {}", serial));
                let body_refs: Vec<&str> = body.iter().map(|s| s.as_str()).collect();
                PageAction::Ask { dialog: Dialog::typed("WRITE TEST", &body_refs, &serial), then: Then::Req(Request::BlockWriteTest { dev: name, serial }) }
            }
            _ => PageAction::Unhandled,
        }
    }
    fn help(&self) -> &'static [(&'static str, &'static str)] {
        &[("Up/Down", "select disk"), ("Enter", "details / scroll"), ("t", "read-only test"), ("w", "write test (full serial required)")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bar() {
        assert_eq!(bar_string(0.5, 4, false), "[##..]");
        assert_eq!(bar_string(2.0, 2, false), "[##]");
        assert_eq!(bar_string(f64::NAN, 2, false), "[..]");
    }
    #[test]
    fn reasons() {
        assert_eq!(reason_text(&Reason::Mounted("/mnt".into())), "mounted at /mnt");
        assert!(reason_text(&Reason::BootMedia).contains("boot"));
    }
}
