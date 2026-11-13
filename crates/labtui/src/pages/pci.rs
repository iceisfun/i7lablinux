//! PCIe: tree of bridges and devices, link state, AER, BARs. Owner: P5.

use std::collections::HashSet;

use labprobe::pci::PciDevice;

use crate::buffer::Rect;
use crate::fmt;
use crate::input::Key;
use crate::page::{missing, DrawCx, Focus, KeyCx, Left, Md, MdView, Page, PageAction, Request};
use crate::widgets::{kv, line, span, tree_prefix, tree_rows, Col, Line, Span};

use super::{blank, heading, or_dash, short_bdf};

#[derive(Default)]
pub struct PciPage {
    md: Md,
    collapsed: HashSet<String>,
    /// bdf of each visible row at the last draw
    visible: Vec<String>,
}

const COLS: [Col; 4] = [Col::new("Device", 20, 0), Col::new("Name", 0, 0), Col::new("Driver", 14, 2), Col::new("Link", 10, 1)];

fn display_name(d: &PciDevice) -> String {
    match (&d.vendor_name, &d.device_name) {
        (Some(v), Some(n)) => format!("{} {}", v, n),
        (Some(v), None) => format!("{} {:04x}:{:04x}", v, d.vendor, d.device),
        (None, Some(n)) => n.clone(),
        (None, None) => format!("{:04x}:{:04x}", d.vendor, d.device),
    }
}

fn detail(d: &PciDevice, t: &crate::theme::Theme) -> Vec<Line> {
    let mut v = vec![
        kv("Address", d.bdf.clone(), t),
        kv("Name", display_name(d), t),
        kv("IDs", format!("{:04x}:{:04x}  subsys {:04x}:{:04x}  rev {:02x}", d.vendor, d.device, d.subsys_vendor, d.subsys_device, d.revision), t),
        kv("Class", format!("{} (0x{:06x})", d.class_name, d.class), t),
        kv("Driver", or_dash(d.driver.as_deref()), t),
    ];
    match &d.link {
        Some(l) => v.push(vec![span(format!("{:<15}", "Link:"), t.dim), span(fmt::pcie_link(l), if l.degraded { t.bad } else { t.ok })]),
        None => v.push(kv("Link", "-", t)),
    }
    v.push(kv("IOMMU group", d.iommu_group.map(|g| g.to_string()).unwrap_or_else(|| "-".into()), t));
    v.push(kv("NUMA node", d.numa_node.map(|g| g.to_string()).unwrap_or_else(|| "-".into()), t));
    match &d.aer {
        Some(a) => {
            let st = if a.fatal > 0 { t.bad } else if a.nonfatal > 0 || a.correctable > 0 { t.warn } else { t.ok };
            v.push(vec![span(format!("{:<15}", "AER:"), t.dim), span(format!("correctable {}  non-fatal {}  fatal {}", a.correctable, a.nonfatal, a.fatal), st)]);
        }
        None => v.push(kv("AER", "not reported", t)),
    }
    if let Some(p) = &d.parent {
        v.push(kv("Parent", p.clone(), t));
    }
    v.push(blank());
    v.push(heading(t, "BARs"));
    if d.bars.is_empty() {
        v.push(line("(none listed; verbose probe adds BARs)", t.dim));
    }
    for b in &d.bars {
        v.push(line(
            format!("BAR{}  {:<5} {}0x{:012x}  {}", b.index, b.kind, if b.prefetch { "pf " } else { "   " }, b.base, fmt::bytes_bin(b.size)),
            t.text,
        ));
    }
    v.push(blank());
    v.push(heading(t, "Capabilities"));
    if d.caps.is_empty() {
        v.push(line("(none listed)", t.dim));
    }
    for c in &d.caps {
        v.push(line(c.clone(), t.text));
    }
    v
}

impl Page for PciPage {
    fn title(&self) -> &'static str {
        "PCIe"
    }
    fn short(&self) -> &'static str {
        "PCI"
    }
    fn draw(&mut self, cx: &mut DrawCx, area: Rect) {
        let t = cx.theme;
        self.md.left_pct = 42;
        let Some(pci) = cx.data.pci.as_ref() else {
            let l = missing(t, "PCIe");
            self.md.draw(cx, area, MdView { left_title: "PCIe", left: Left::Lines(&l), detail_title: "Detail", detail: &[], live: None });
            return;
        };
        let items: Vec<(String, Option<String>)> = pci.devices.iter().map(|d| (d.bdf.clone(), d.parent.clone())).collect();
        let rows = tree_rows(&items, &self.collapsed);
        self.visible = rows.iter().map(|r| pci.devices[r.index].bdf.clone()).collect();
        let unicode = cx.unicode();
        let table: Vec<Vec<Span>> = rows
            .iter()
            .map(|r| {
                let d = &pci.devices[r.index];
                let link_style = match &d.link {
                    Some(l) if l.degraded => t.bad,
                    _ => t.text,
                };
                vec![
                    span(format!("{}{}", tree_prefix(r, unicode), short_bdf(&d.bdf)), t.text),
                    span(display_name(d), t.text),
                    span(or_dash(d.driver.as_deref()), if d.driver.is_none() { t.dim } else { t.text }),
                    span(d.link.as_ref().and_then(|l| Some(format!("x{} Gen{}", l.cur_width?, l.cur_gen?))).unwrap_or_else(|| "-".into()), link_style),
                ]
            })
            .collect();
        let sel = self.md.list.selected.min(rows.len().saturating_sub(1));
        let det = rows.get(sel).map(|r| detail(&pci.devices[r.index], t)).unwrap_or_default();
        // wide: summary column
        let degraded = pci.devices.iter().filter(|d| d.link.as_ref().map(|l| l.degraded).unwrap_or(false)).count();
        let aer: u64 = pci.devices.iter().filter_map(|d| d.aer.as_ref()).map(|a| a.correctable + a.nonfatal + a.fatal).sum();
        let live: Vec<Line> = vec![
            kv("Devices", pci.devices.len().to_string(), t),
            kv("With driver", pci.devices.iter().filter(|d| d.driver.is_some()).count().to_string(), t),
            kv("Ethernet no driver", pci.unbound_ethernet().len().to_string(), t),
            kv("Wi-Fi no driver", pci.unbound_wifi().len().to_string(), t),
            kv("Degraded", degraded.to_string(), t),
            kv("AER errors", aer.to_string(), t),
            kv("IOMMU", if pci.iommu_enabled { "enabled" } else { "off" }, t),
        ];
        self.md.draw(
            cx,
            area,
            MdView { left_title: "PCIe devices", left: Left::Table(&COLS, &table), detail_title: "Device", detail: &det, live: Some(("Summary", &live)) },
        );
    }
    fn key(&mut self, key: Key, cx: &KeyCx) -> PageAction {
        if cx.focus == Focus::List {
            let bdf = self.visible.get(self.md.list.selected).cloned();
            match (key, bdf) {
                (Key::Left, Some(b)) => {
                    self.collapsed.insert(b);
                    return PageAction::Handled;
                }
                (Key::Right, Some(b)) => {
                    self.collapsed.remove(&b);
                    return PageAction::Handled;
                }
                (Key::Char('p'), _) => return PageAction::Do(Request::RescanPci),
                _ => {}
            }
        }
        self.md.key(key, cx.focus)
    }
    fn help(&self) -> &'static [(&'static str, &'static str)] {
        &[("Up/Down", "select device"), ("Left/Right", "collapse / expand bridge"), ("Enter", "show details"), ("p", "rescan PCI bus")]
    }
}
