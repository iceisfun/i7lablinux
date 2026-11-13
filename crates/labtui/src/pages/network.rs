//! Network: NICs with link, speed, addresses and rates; DHCP and ping actions. Owner: P5.

use labprobe::net::NetIface;

use crate::buffer::Rect;
use crate::fmt;
use crate::input::Key;
use crate::model::ViewData;
use crate::page::{missing, DrawCx, KeyCx, Left, Md, MdView, Page, PageAction, Request, Then};
use crate::theme::Theme;
use crate::widgets::{kv, line, span, spark_string, Col, Dialog, Line, Span};

use super::{blank, heading, or_dash};

#[derive(Default)]
pub struct NetworkPage {
    md: Md,
    names: Vec<String>,
}

const COLS: [Col; 7] = [
    Col::new("Iface", 10, 0),
    Col::new("Link", 6, 0),
    Col::new("Speed", 9, 3),
    Col::new("IPv4", 0, 0),
    Col::new("MAC", 17, 2),
    Col::new("RX", 10, 1).right(),
    Col::new("TX", 10, 1).right(),
];

fn is_up(i: &NetIface) -> bool {
    i.operstate == "up" || i.carrier == Some(true)
}

fn no_driver(i: &NetIface) -> bool {
    i.driver.is_none() && i.bus_info.is_some()
}

fn rate(data: &ViewData, kind: &str, iface: &str) -> Option<f32> {
    data.series.get(&format!("{}:{}", kind, iface)).and_then(|s| s.last().copied())
}

fn rate_text(r: Option<f32>) -> String {
    r.map(|v| fmt::bps(v as f64)).unwrap_or_else(|| "-".into())
}

fn series_line(label: &str, key: String, data: &ViewData, width: usize, unicode: bool, t: &Theme) -> Line {
    match data.series.get(&key) {
        Some(s) if !s.is_empty() => vec![span(format!("{:<4}", label), t.dim), span(spark_string(s, width, unicode), t.accent), span(format!(" {}", fmt::bps(*s.last().unwrap_or(&0.0) as f64)), t.text)],
        _ => vec![span(format!("{:<4}", label), t.dim), span("no samples", t.dim)],
    }
}

fn detail(i: &NetIface, data: &ViewData, t: &Theme, unicode: bool) -> Vec<Line> {
    let mut v = vec![
        kv("Interface", i.name.clone(), t),
        vec![
            span(format!("{:<15}", "State:"), t.dim),
            span(format!("{}{}", i.operstate, match i.carrier { Some(true) => ", carrier", Some(false) => ", NO CARRIER", None => "" }), if is_up(i) { t.ok } else { t.warn }),
        ],
        kv("MAC", or_dash(i.mac.as_deref()), t),
        kv("Permanent MAC", or_dash(i.perm_mac.as_deref()), t),
    ];
    if no_driver(i) {
        v.push(vec![span(format!("{:<15}", "Driver:"), t.dim), span("NONE (no kernel driver bound)", t.bad)]);
    } else {
        v.push(kv("Driver", or_dash(i.driver.as_deref()), t));
    }
    v.push(kv("Bus", or_dash(i.bus_info.as_deref()), t));
    v.push(kv("Speed", format!("{}{}", i.speed_mbps.map(|s| format!("{} Mb/s", s)).unwrap_or_else(|| "-".into()), i.duplex.as_deref().map(|d| format!(" {}", d)).unwrap_or_default()), t));
    v.push(kv("MTU", i.mtu.to_string(), t));
    if let (Some(p), Some(id)) = (&i.vlan_of, i.vlan_id) {
        v.push(kv("VLAN", format!("{} on {}", id, p), t));
    }
    v.push(blank());
    v.push(heading(t, "Addresses"));
    if i.ipv4.is_empty() && i.ipv6.is_empty() {
        v.push(line("none", t.dim));
    }
    for a in i.ipv4.iter().chain(i.ipv6.iter()) {
        v.push(line(a.clone(), t.text));
    }
    v.push(blank());
    v.push(heading(t, "Counters"));
    v.push(kv("RX", fmt::bytes_dec(i.rx_bytes), t));
    v.push(kv("TX", fmt::bytes_dec(i.tx_bytes), t));
    v.push(vec![span(format!("{:<15}", "Errors:"), t.dim), span(format!("rx {}  tx {}", i.rx_errors, i.tx_errors), if i.rx_errors + i.tx_errors > 0 { t.bad } else { t.text })]);
    v.push(kv("Carrier flaps", i.carrier_changes.to_string(), t));
    v.push(blank());
    v.push(heading(t, "Throughput"));
    v.push(series_line("rx", format!("rx:{}", i.name), data, 24, unicode, t));
    v.push(series_line("tx", format!("tx:{}", i.name), data, 24, unicode, t));
    v
}

impl Page for NetworkPage {
    fn title(&self) -> &'static str {
        "Network"
    }
    fn short(&self) -> &'static str {
        "Net"
    }
    fn draw(&mut self, cx: &mut DrawCx, area: Rect) {
        let t = cx.theme;
        self.md.left_pct = 45;
        let Some(net) = cx.data.net.as_ref() else {
            let l = missing(t, "network");
            self.md.draw(cx, area, MdView { left_title: "Network", left: Left::Lines(&l), detail_title: "Detail", detail: &[], live: None });
            return;
        };
        self.names = net.ifaces.iter().map(|i| i.name.clone()).collect();
        let rows: Vec<Vec<Span>> = net
            .ifaces
            .iter()
            .map(|i| {
                let (link, ls) = if no_driver(i) {
                    ("NODRV", t.bad)
                } else if is_up(i) {
                    ("up", t.ok)
                } else {
                    ("down", t.warn)
                };
                vec![
                    span(i.name.clone(), t.text),
                    span(link, ls),
                    span(i.speed_mbps.map(|s| format!("{} Mb/s", s)).unwrap_or_else(|| "-".into()), t.text),
                    span(i.ipv4.first().cloned().unwrap_or_else(|| "-".into()), t.text),
                    span(or_dash(i.mac.as_deref()), t.dim),
                    span(rate_text(rate(cx.data, "rx", &i.name)), t.text),
                    span(rate_text(rate(cx.data, "tx", &i.name)), t.text),
                ]
            })
            .collect();
        let sel = self.md.list.selected.min(net.ifaces.len().saturating_sub(1));
        let unicode = cx.unicode();
        let det = net.ifaces.get(sel).map(|i| detail(i, cx.data, t, unicode)).unwrap_or_else(|| vec![line("no interfaces", t.dim)]);
        // wide: live throughput graphs of every interface
        let mut live: Vec<Line> = Vec::new();
        for i in net.ifaces.iter().filter(|i| i.name != "lo") {
            live.push(line(i.name.clone(), t.title));
            live.push(series_line("rx", format!("rx:{}", i.name), cx.data, 30, unicode, t));
            live.push(series_line("tx", format!("tx:{}", i.name), cx.data, 30, unicode, t));
        }
        self.md.draw(cx, area, MdView { left_title: "Interfaces", left: Left::Table(&COLS, &rows), detail_title: "Interface", detail: &det, live: Some(("Live", &live)) });
    }
    fn key(&mut self, key: Key, cx: &KeyCx) -> PageAction {
        let a = self.md.key(key, cx.focus);
        if !matches!(a, PageAction::Unhandled) {
            return a;
        }
        let Some(iface) = self.names.get(self.md.list.selected).cloned() else { return PageAction::Unhandled };
        match key {
            Key::Char('d') => PageAction::Do(Request::Dhcp { iface }),
            Key::Char('p') => {
                let mut d = Dialog::new("Ping", &["Address to ping from this host"], &["Ping", "Cancel"]);
                d.input = Some(String::new());
                PageAction::Ask { dialog: d, then: Then::PingInput { iface } }
            }
            _ => PageAction::Unhandled,
        }
    }
    fn help(&self) -> &'static [(&'static str, &'static str)] {
        &[("Up/Down", "select interface"), ("Enter", "details / scroll"), ("d", "DHCP discover on the interface"), ("p", "ping an address")]
    }
}
