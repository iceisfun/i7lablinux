//! Actions: reboot, power off, boot next, rescan, shell, key fingerprint. Owner: P5.
//! Every disruptive action asks first. The console is physically present, but still confirms.

use crate::buffer::Rect;
use crate::input::Key;
use crate::page::{DrawCx, KeyCx, Left, Md, MdView, Page, PageAction, Request, Then};
use crate::widgets::{kv, line, span, Dialog, DialogKind, Line};

use super::{blank, heading};

#[derive(Default)]
pub struct ActionsPage {
    md: Md,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    /// changes nothing on the host
    Safe,
    /// disruptive: asks first
    Confirm,
    /// not implemented in this build
    Planned,
}

struct Item {
    name: String,
    desc: String,
    class: Class,
    /// what happens on Enter
    run: Run,
}

enum Run {
    Ask(Dialog, Then),
    Do(Request),
    Fingerprint,
    Planned(&'static str),
}

fn items(data: &crate::model::ViewData) -> Vec<Item> {
    let mut v = vec![
        Item {
            name: "Reboot".into(),
            desc: "Restart the host. Stops every job and drops all sessions.".into(),
            class: Class::Confirm,
            run: Run::Ask(Dialog::confirm("Reboot", &["Reboot this host now?"]), Then::Req(Request::Reboot)),
        },
        Item {
            name: "Power off".into(),
            desc: "Shut the host down. Someone must press the power button to start it again.".into(),
            class: Class::Confirm,
            run: Run::Ask(Dialog::confirm("Power off", &["Power this host off now?", "It will not come back by itself."]), Then::Req(Request::PowerOff)),
        },
    ];
    if let Some(fw) = &data.firmware {
        for e in &fw.boot_entries {
            let body = format!("Boot entry {:04X} ({}) on the next boot and reboot now?", e.num, e.description);
            v.push(Item {
                name: format!("Boot next: {:04X} {}", e.num, e.description),
                desc: format!("Set UEFI BootNext to {:04X}{} and reboot. The boot order itself is not changed.", e.num, e.device_path.as_deref().map(|p| format!(" ({})", p)).unwrap_or_default()),
                class: Class::Confirm,
                run: Run::Ask(Dialog::confirm("Boot next", &[&body]), Then::Req(Request::BootNext(e.num))),
            });
        }
    }
    v.push(Item { name: "Rescan PCI bus".into(), desc: "Ask the kernel to look for new PCI devices.".into(), class: Class::Safe, run: Run::Do(Request::RescanPci) });
    v.push(Item { name: "Probe now".into(), desc: "Run every hardware probe again and refresh the pages.".into(), class: Class::Safe, run: Run::Do(Request::ProbeNow) });
    v.push(Item { name: "Open shell".into(), desc: "Leave the TUI for the i7labsh shell on this console. Exit the shell to come back.".into(), class: Class::Safe, run: Run::Do(Request::Shell) });
    v.push(Item { name: "Show key fingerprints".into(), desc: "Which keys this image trusts (fingerprints only, never key material).".into(), class: Class::Safe, run: Run::Fingerprint });
    for (n, d, ver) in [
        ("Kexec into another kernel", "Load and boot another kernel without a firmware reset.", "v0.4"),
        ("Set wake-on-LAN", "Arm wake-on-LAN on a NIC.", "v0.2"),
        ("Run stress test", "CPU and memory burn-in.", "v0.2"),
        ("Enrol keys", "Replace the baked-in keys at run time.", "v0.3"),
        ("Wipe disk", "Use `i7labctl --cmd blk.write` with the device serial; no console shortcut.", "never from the console"),
    ] {
        v.push(Item { name: n.into(), desc: d.into(), class: Class::Planned, run: Run::Planned(ver) });
    }
    v
}

impl Page for ActionsPage {
    fn title(&self) -> &'static str {
        "Actions"
    }
    fn short(&self) -> &'static str {
        "Act"
    }
    fn draw(&mut self, cx: &mut DrawCx, area: Rect) {
        let t = cx.theme;
        let its = items(cx.data);
        let locked = cx.data.identity.console_locked;
        let rows: Vec<Line> = its
            .iter()
            .map(|i| {
                let st = match i.class {
                    Class::Planned => t.dim,
                    _ if locked && !matches!(i.run, Run::Fingerprint) => t.dim,
                    Class::Confirm => t.warn,
                    Class::Safe => t.text,
                };
                let tag = if i.class == Class::Planned { "  (planned)" } else { "" };
                vec![span(i.name.clone(), st), span(tag, t.dim)]
            })
            .collect();
        self.md.list.fix(rows.len(), self.md.page_rows.max(1));
        let sel = self.md.list.selected.min(its.len().saturating_sub(1));
        let mut det: Vec<Line> = Vec::new();
        if let Some(i) = its.get(sel) {
            det.push(heading(t, &i.name));
            det.push(blank());
            for l in crate::widgets::wrap(&i.desc, 60) {
                det.push(line(l, t.text));
            }
            det.push(blank());
            det.push(kv(
                "Class",
                match i.class {
                    Class::Safe => "no confirmation needed",
                    Class::Confirm => "asks for confirmation",
                    Class::Planned => "not available yet",
                },
                t,
            ));
            det.push(kv("Source", "local console (operator is physically present)", t));
            if locked {
                det.push(line("The console is locked (i7lab.console=locked): read-only.", t.bad));
            }
        }
        self.md.draw(cx, area, MdView { left_title: "Actions", left: Left::Lines(&rows), detail_title: "Action", detail: &det, live: None });
    }
    fn key(&mut self, key: Key, cx: &KeyCx) -> PageAction {
        if let (Key::Enter, crate::page::Focus::List) = (key, cx.focus) {
            let mut its = items(cx.data);
            if self.md.list.selected >= its.len() {
                return PageAction::Handled;
            }
            let item = its.swap_remove(self.md.list.selected);
            let locked = cx.console_locked || cx.data.identity.console_locked;
            if locked && !matches!(item.run, Run::Fingerprint) && item.class != Class::Planned {
                return PageAction::Status("console is locked: this action is disabled".into());
            }
            return match item.run {
                Run::Ask(d, then) => PageAction::Ask { dialog: d, then },
                Run::Do(r) => PageAction::Do(r),
                Run::Planned(ver) => PageAction::Status(format!("{} is planned ({}), not available yet", item.name, ver)),
                Run::Fingerprint => {
                    let summary = if cx.data.identity.key_summary.is_empty() { "no key information available".to_string() } else { cx.data.identity.key_summary.clone() };
                    let lines: Vec<&str> = summary.lines().collect();
                    let mut d = Dialog::new("Trusted keys", &lines, &["Close"]);
                    d.selected = 0;
                    d.kind = DialogKind::Info;
                    PageAction::Info(d)
                }
            };
        }
        self.md.key(key, cx.focus)
    }
    fn help(&self) -> &'static [(&'static str, &'static str)] {
        &[("Up/Down", "select action"), ("Enter", "run it (disruptive ones ask first)")]
    }
}
