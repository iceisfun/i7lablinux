//! USB: tree of buses, hubs and devices. Owner: P5.

use std::collections::HashSet;

use labprobe::usb::UsbDevice;

use crate::buffer::Rect;
use crate::input::Key;
use crate::page::{missing, DrawCx, Focus, KeyCx, Left, Md, MdView, Page, PageAction};
use crate::widgets::{kv, line, span, tree_prefix, tree_rows, Col, Line, Span};

use super::or_dash;

#[derive(Default)]
pub struct UsbPage {
    md: Md,
    collapsed: HashSet<String>,
    visible: Vec<String>,
}

const COLS: [Col; 4] = [Col::new("Device", 20, 0), Col::new("Name", 0, 0), Col::new("ID", 9, 1), Col::new("Speed", 7, 2).right()];

pub fn class_name(c: u8) -> &'static str {
    match c {
        0x00 => "per interface",
        0x01 => "audio",
        0x02 => "communications",
        0x03 => "HID",
        0x05 => "physical",
        0x06 => "image",
        0x07 => "printer",
        0x08 => "mass storage",
        0x09 => "hub",
        0x0a => "CDC data",
        0x0b => "smart card",
        0x0e => "video",
        0xe0 => "wireless",
        0xef => "miscellaneous",
        0xff => "vendor specific",
        _ => "other",
    }
}

pub fn speed_text(mbps: Option<u32>) -> String {
    match mbps {
        None => "-".into(),
        Some(s) if s >= 1000 && s % 1000 == 0 => format!("{}G", s / 1000),
        Some(s) if s >= 1000 => format!("{:.1}G", s as f64 / 1000.0),
        Some(s) => format!("{}M", s),
    }
}

fn name(d: &UsbDevice) -> String {
    let n = format!("{} {}", d.manufacturer.as_deref().unwrap_or(""), d.product.as_deref().unwrap_or("")).trim().to_string();
    if n.is_empty() {
        format!("{:04x}:{:04x}", d.vid, d.pid)
    } else {
        n
    }
}

fn detail(d: &UsbDevice, t: &crate::theme::Theme) -> Vec<Line> {
    vec![
        kv("Path", d.path.clone(), t),
        kv("Name", name(d), t),
        kv("ID", format!("{:04x}:{:04x}", d.vid, d.pid), t),
        kv("Manufacturer", or_dash(d.manufacturer.as_deref()), t),
        kv("Product", or_dash(d.product.as_deref()), t),
        kv("Serial", or_dash(d.serial.as_deref()), t),
        kv("Class", format!("{} (0x{:02x})", class_name(d.class), d.class), t),
        kv("Speed", speed_text(d.speed_mbps), t),
        kv("Bus / device", format!("{} / {}", d.busnum, d.devnum), t),
        kv("Parent", or_dash(d.parent.as_deref()), t),
        kv("Drivers", if d.drivers.is_empty() { "-".to_string() } else { d.drivers.join(", ") }, t),
    ]
}

impl Page for UsbPage {
    fn title(&self) -> &'static str {
        "USB"
    }
    fn short(&self) -> &'static str {
        "USB"
    }
    fn draw(&mut self, cx: &mut DrawCx, area: Rect) {
        let t = cx.theme;
        self.md.left_pct = 45;
        let Some(usb) = cx.data.usb.as_ref() else {
            let l = missing(t, "USB");
            self.md.draw(cx, area, MdView { left_title: "USB", left: Left::Lines(&l), detail_title: "Detail", detail: &[], live: None });
            return;
        };
        let items: Vec<(String, Option<String>)> = usb.devices.iter().map(|d| (d.path.clone(), d.parent.clone())).collect();
        let rows = tree_rows(&items, &self.collapsed);
        self.visible = rows.iter().map(|r| usb.devices[r.index].path.clone()).collect();
        let unicode = cx.unicode();
        let table: Vec<Vec<Span>> = rows
            .iter()
            .map(|r| {
                let d = &usb.devices[r.index];
                vec![
                    span(format!("{}{}", tree_prefix(r, unicode), d.path), t.text),
                    span(name(d), if d.class == 0x09 { t.dim } else { t.text }),
                    span(format!("{:04x}:{:04x}", d.vid, d.pid), t.dim),
                    span(speed_text(d.speed_mbps), t.text),
                ]
            })
            .collect();
        let sel = self.md.list.selected.min(rows.len().saturating_sub(1));
        let det = rows.get(sel).map(|r| detail(&usb.devices[r.index], t)).unwrap_or_else(|| vec![line("no USB devices", t.dim)]);
        self.md.draw(cx, area, MdView { left_title: "USB devices", left: Left::Table(&COLS, &table), detail_title: "Device", detail: &det, live: None });
    }
    fn key(&mut self, key: Key, cx: &KeyCx) -> PageAction {
        if cx.focus == Focus::List {
            let p = self.visible.get(self.md.list.selected).cloned();
            match (key, p) {
                (Key::Left, Some(p)) => {
                    self.collapsed.insert(p);
                    return PageAction::Handled;
                }
                (Key::Right, Some(p)) => {
                    self.collapsed.remove(&p);
                    return PageAction::Handled;
                }
                _ => {}
            }
        }
        self.md.key(key, cx.focus)
    }
    fn help(&self) -> &'static [(&'static str, &'static str)] {
        &[("Up/Down", "select device"), ("Left/Right", "collapse / expand hub"), ("Enter", "details")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn speeds_and_classes() {
        assert_eq!(speed_text(Some(480)), "480M");
        assert_eq!(speed_text(Some(5000)), "5G");
        assert_eq!(speed_text(Some(1500)), "1.5G");
        assert_eq!(speed_text(None), "-");
        assert_eq!(class_name(9), "hub");
    }
}
