//! The TUI application: header, tab bar, pages, key bar, modal dialogs, focus handling. Owner: P5.
//!
//! `App` is pure state: it takes keys and `ViewData`, draws into a `Buffer` and returns `Request`s for the host
//! to execute. It never touches the terminal, so the same code drives the real console, the headless test
//! backend and `tui.dump`.

use std::sync::Arc;

use crate::buffer::{Buffer, Rect};
use crate::input::Key;
use crate::model::ViewData;
use crate::page::{DrawCx, Focus, KeyCx, Page, PageAction, Request, Then};
use crate::pages::{all_pages, TAB_NAMES};
use crate::theme::Theme;
use crate::widgets::{self, span, BorderSet, Dialog, DialogKind, DialogResult};
use crate::{layout_class, LayoutClass, MIN_COLS, MIN_ROWS};

/// Ticks (event loop timeouts, ~100 ms) a status message stays visible.
const STATUS_TICKS: u64 = 40;

#[derive(Clone, Debug, Default)]
pub struct Options {
    /// ASCII frames and `?` for non-ASCII text (serial console, `i7lab.ascii=1`)
    pub ascii: bool,
    /// monochrome theme (`TERM=dumb`, `i7lab.mono=1`)
    pub mono: bool,
    /// enable the write-test dialog on the Storage page (v0.2; default off)
    pub write_tests: bool,
}

struct ActiveDialog {
    d: Dialog,
    then: Then,
}

pub struct App {
    opts: Options,
    pages: Vec<Box<dyn Page>>,
    tab: usize,
    focus: Focus,
    data: Arc<ViewData>,
    theme: Theme,
    ascii: bool,
    dialog: Option<ActiveDialog>,
    status: Option<(String, u64)>,
    tick: u64,
    last_class: LayoutClass,
}

impl App {
    pub fn new(opts: Options) -> App {
        let theme = if opts.mono { Theme::mono() } else { Theme::dark() };
        let ascii = opts.ascii;
        App { opts, pages: all_pages(), tab: 0, focus: Focus::Tabs, data: Arc::new(ViewData::default()), theme, ascii, dialog: None, status: None, tick: 0, last_class: LayoutClass::Standard }
    }

    pub fn set_data(&mut self, data: Arc<ViewData>) {
        self.data = data;
    }
    pub fn data(&self) -> &ViewData {
        &self.data
    }
    pub fn tab(&self) -> usize {
        self.tab
    }
    pub fn tab_name(&self) -> &'static str {
        TAB_NAMES[self.tab]
    }
    pub fn focus(&self) -> Focus {
        self.focus
    }
    pub fn ascii(&self) -> bool {
        self.ascii
    }
    pub fn dialog_open(&self) -> bool {
        self.dialog.is_some()
    }
    /// Select a page by name (case-insensitive); used by `tui tab <name>`.
    pub fn select_tab(&mut self, name: &str) -> bool {
        match TAB_NAMES.iter().position(|n| n.eq_ignore_ascii_case(name)) {
            Some(i) => {
                self.tab = i;
                true
            }
            None => false,
        }
    }
    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status = Some((msg.into(), self.tick + STATUS_TICKS));
    }
    /// Call on every event loop timeout / wake-up (drives status message expiry and frame counters).
    pub fn on_tick(&mut self) {
        self.tick += 1;
        if matches!(&self.status, Some((_, until)) if self.tick >= *until) {
            self.status = None;
        }
    }
    /// Open an information dialog from the host (job finished, test result ...).
    pub fn show_info(&mut self, title: &str, body: &[&str]) {
        let mut d = Dialog::new(title, body, &["Close"]);
        d.selected = 0;
        self.dialog = Some(ActiveDialog { d, then: Then::Nothing });
    }

    fn class(&self, w: u16, h: u16) -> LayoutClass {
        layout_class(w, h)
    }

    fn open_dialog(&mut self, d: Dialog, then: Then) {
        self.dialog = Some(ActiveDialog { d, then });
    }

    fn help_dialog(&self) -> Dialog {
        let mut body: Vec<String> = vec![self.pages[self.tab].title().to_string() + " page:"];
        for (k, d) in self.pages[self.tab].help() {
            body.push(format!("  {:<18} {}", k, d));
        }
        body.push(String::new());
        body.push("Everywhere:".into());
        for (k, d) in [
            ("Tab / Shift-Tab", "next / previous pane"),
            ("Left / Right", "previous / next page (page bar)"),
            ("1..8", "jump to a page"),
            ("Esc", "back"),
            ("F2", "probe now"),
            ("F5 / r", "refresh, Ctrl-L redraw"),
            ("F9", "ASCII / Unicode frames"),
            ("F10 / s", "shell"),
            ("F12", "about"),
            ("q / Ctrl-C", "quit"),
        ] {
            body.push(format!("  {:<18} {}", k, d));
        }
        let refs: Vec<&str> = body.iter().map(|s| s.as_str()).collect();
        let mut d = Dialog::new("Help", &refs, &["Close"]);
        d.selected = 0;
        d
    }

    fn about_dialog(&self) -> Dialog {
        let id = &self.data.identity;
        let mut body = vec![format!("i7lablinux {}", if id.version.is_empty() { "(unknown version)" } else { &id.version })];
        if let Some(b) = &id.build_id {
            body.push(format!("build {}", b));
        }
        body.push(format!("host {}", self.data.hostname()));
        if !id.key_summary.is_empty() {
            body.push(String::new());
            body.extend(id.key_summary.lines().map(|s| s.to_string()));
        }
        let refs: Vec<&str> = body.iter().map(|s| s.as_str()).collect();
        let mut d = Dialog::new("About", &refs, &["Close"]);
        d.selected = 0;
        d
    }

    fn finish_dialog(&mut self, ad: ActiveDialog, out: &mut Vec<Request>) {
        match ad.then {
            Then::Req(r) => out.push(r),
            Then::PingInput { .. } => {
                let target = ad.d.input.clone().unwrap_or_default();
                let target = target.trim().to_string();
                let ok = !target.is_empty() && target.len() <= 253 && target.chars().all(|c| c.is_ascii_alphanumeric() || ".:-_".contains(c));
                if ok {
                    out.push(Request::Ping { target });
                } else {
                    self.set_status("not a valid address or host name");
                }
            }
            Then::LogSearch => {
                let text = ad.d.input.clone().unwrap_or_default();
                self.pages[self.tab].dialog_input(&Then::LogSearch, text.trim());
            }
            Then::Nothing => {}
        }
    }

    fn apply(&mut self, a: PageAction, out: &mut Vec<Request>) -> bool {
        match a {
            PageAction::Unhandled => return false,
            PageAction::Handled => {}
            PageAction::FocusDetail => self.focus = Focus::Detail,
            PageAction::FocusList => self.focus = Focus::List,
            PageAction::Do(r) => {
                if matches!(r, Request::Shell) && self.data.identity.console_locked {
                    self.set_status("console is locked: no shell");
                } else {
                    out.push(r);
                }
            }
            PageAction::Ask { dialog, then } => self.open_dialog(dialog, then),
            PageAction::Info(d) => self.open_dialog(d, Then::Nothing),
            PageAction::Status(s) => self.set_status(s),
        }
        true
    }

    /// Handle one key; returns what the host must do.
    pub fn handle_key(&mut self, key: Key) -> Vec<Request> {
        let mut out = Vec::new();
        // 1. a modal dialog takes everything
        if let Some(mut ad) = self.dialog.take() {
            match ad.d.key(key) {
                DialogResult::Open => self.dialog = Some(ad),
                DialogResult::Cancel => {}
                DialogResult::Button(0) => self.finish_dialog(ad, &mut out),
                DialogResult::Button(_) => {}
            }
            return out;
        }
        // 2. keys that mean the same on every page
        match key {
            Key::F(1) | Key::Char('?') => {
                let d = self.help_dialog();
                self.open_dialog(d, Then::Nothing);
                return out;
            }
            Key::F(2) => {
                out.push(Request::ProbeNow);
                return out;
            }
            Key::F(5) | Key::Char('r') => {
                out.push(Request::Refresh);
                out.push(Request::Redraw);
                return out;
            }
            Key::Ctrl('l') => {
                out.push(Request::Redraw);
                return out;
            }
            Key::F(9) => {
                self.ascii = !self.ascii;
                out.push(Request::Redraw);
                return out;
            }
            Key::F(10) | Key::Char('s') => {
                if self.data.identity.console_locked {
                    self.set_status("console is locked: no shell");
                } else {
                    out.push(Request::Shell);
                }
                return out;
            }
            Key::F(12) => {
                let d = self.about_dialog();
                self.open_dialog(d, Then::Nothing);
                return out;
            }
            Key::F(6) => {
                self.select_tab("Log");
                return out;
            }
            Key::F(7) => {
                self.select_tab("Actions");
                return out;
            }
            Key::F(8) => {
                self.select_tab("Overview");
                return out;
            }
            Key::Char('q') | Key::Ctrl('c') => {
                let mut d = Dialog::confirm("Quit", &["Leave the TUI?", "The shell stays available on this console."]);
                d.kind = DialogKind::Info;
                self.open_dialog(d, Then::Req(Request::Quit));
                return out;
            }
            _ => {}
        }
        // 3. the page, unless the tab bar has the focus
        if self.focus != Focus::Tabs {
            let cx = KeyCx { data: &self.data, focus: self.focus, class: self.last_class, console_locked: self.data.identity.console_locked, write_tests: self.opts.write_tests };
            let action = self.pages[self.tab].key(key, &cx);
            if self.apply(action, &mut out) {
                return out;
            }
        }
        // 4. navigation
        let n = self.pages.len();
        match key {
            Key::Char(c @ '1'..='8') => {
                let i = (c as u8 - b'1') as usize;
                if i < n {
                    self.tab = i;
                    if self.focus == Focus::Detail {
                        self.focus = Focus::List;
                    }
                }
            }
            Key::Tab => {
                self.focus = match self.focus {
                    Focus::Tabs => Focus::List,
                    Focus::List => Focus::Detail,
                    Focus::Detail => Focus::Tabs,
                }
            }
            Key::BackTab => {
                self.focus = match self.focus {
                    Focus::Tabs => Focus::Detail,
                    Focus::List => Focus::Tabs,
                    Focus::Detail => Focus::List,
                }
            }
            Key::Esc => {
                self.focus = match self.focus {
                    Focus::Detail => Focus::List,
                    _ => Focus::Tabs,
                }
            }
            Key::Left if self.focus == Focus::Tabs => self.tab = (self.tab + n - 1) % n,
            Key::Right if self.focus == Focus::Tabs => self.tab = (self.tab + 1) % n,
            Key::Down | Key::Enter if self.focus == Focus::Tabs => self.focus = Focus::List,
            _ => {}
        }
        out
    }

    /// Draw the whole screen into `buf` (cleared first).
    pub fn draw(&mut self, buf: &mut Buffer) {
        buf.set_ascii(self.ascii);
        buf.clear();
        let (w, h) = (buf.width(), buf.height());
        let class = self.class(w, h);
        self.last_class = class;
        let theme = self.theme;
        if class == LayoutClass::TooSmall {
            let msg = format!("terminal too small (need {}x{}, have {}x{})", MIN_COLS, MIN_ROWS, w, h);
            let r = buf.area().centered(msg.len().min(w as usize) as u16, 1);
            buf.put_str_fit(r.x, r.y, r.w, &msg, theme.warn);
            return;
        }
        let set = if self.ascii { BorderSet::Ascii } else { BorderSet::Unicode };
        self.draw_header(buf, w);
        // banners (NO KEYS, NO CONTROL PATH) under the tab bar
        let banners = self.data.banners();
        let tabs_y = 1;
        let labels_full: Vec<&str> = TAB_NAMES.to_vec();
        let labels_short: Vec<&str> = self.pages.iter().map(|p| p.short()).collect();
        let labels = if widgets::tabs_width(&labels_full) <= w as usize { labels_full } else { labels_short };
        widgets::tabs(buf, Rect::new(0, tabs_y, w, 1), &labels, self.tab, &theme);
        let mut y = tabs_y + 1;
        let max_banners = (h as usize).saturating_sub(12).min(3);
        for b in banners.iter().take(max_banners) {
            buf.fill(Rect::new(0, y, w, 1), ' ', theme.banner);
            buf.put_str_fit(1, y, w.saturating_sub(2), b, theme.banner);
            y += 1;
        }
        let body = Rect::new(0, y, w, h.saturating_sub(y + 1));
        let data = self.data.clone();
        {
            let mut cx = DrawCx { buf, theme: &theme, set, class, data: &data, focus: self.focus, tick: self.tick };
            self.pages[self.tab].draw(&mut cx, body);
        }
        self.draw_keybar(buf, w, h);
        if let Some(ad) = &self.dialog {
            widgets::dialog(buf, buf.area(), &ad.d, &theme, set);
        }
    }

    fn draw_header(&self, buf: &mut Buffer, w: u16) {
        let t = &self.theme;
        let d = &self.data;
        let id = &d.identity;
        let mut hdr = vec![span(" i7lablinux ", t.title)];
        if !id.version.is_empty() {
            hdr.push(span(format!("{}  ", id.version), t.dim));
        }
        hdr.push(span(format!("host:{}  ", d.hostname()), t.text));
        if let Some(s) = &d.system {
            hdr.push(span(format!("up {}  ", crate::fmt::uptime(s.uptime_s)), t.text));
        }
        if let Some(ip) = id.ips.first() {
            hdr.push(span(format!("ip {}  ", ip), t.text));
        }
        if let Some(m) = &id.mac {
            hdr.push(span(format!("mac {}", m), t.dim));
        }
        let att = d.attention();
        let right = if att.is_empty() { String::new() } else { format!("attention: {} ", att.len()) };
        let rw = right.chars().count() as u16;
        widgets::put_line(buf, 0, 0, w.saturating_sub(rw + 1), &hdr);
        if rw > 0 {
            let st = if att.iter().any(|a| a.severity == crate::model::Severity::Bad) { t.bad } else { t.warn };
            buf.put_str(w.saturating_sub(rw), 0, &right, st);
        }
    }

    fn draw_keybar(&self, buf: &mut Buffer, w: u16, h: u16) {
        let r = Rect::new(0, h - 1, w, 1);
        if let Some((msg, _)) = &self.status {
            buf.fill(r, ' ', self.theme.warn);
            buf.put_str_fit(1, r.y, w.saturating_sub(2), msg, self.theme.warn);
            return;
        }
        let shell = if self.data.identity.console_locked { ("", "") } else { ("F10", "Shell") };
        let mut items: Vec<(&str, &str)> = vec![("F1", "Help"), ("F2", "Probe"), ("F5", "Refresh"), ("Tab", "Pane")];
        if !shell.0.is_empty() {
            items.push(shell);
        }
        items.push(("q", "Quit"));
        widgets::keybar(buf, r, &items, &self.theme);
    }

    /// Convenience for tests and `tui.dump`: draw into a fresh buffer of the given size.
    pub fn render(&mut self, w: u16, h: u16) -> Buffer {
        let mut b = Buffer::new(w, h);
        self.draw(&mut b);
        b
    }
}
