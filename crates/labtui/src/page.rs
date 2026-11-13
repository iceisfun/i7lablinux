//! The `Page` trait, the request/action types pages and the app exchange, and the master/detail layout helper
//! most pages use. Owner: P5.

use crate::buffer::{Buffer, Rect};
use crate::input::Key;
use crate::model::ViewData;
use crate::theme::Theme;
use crate::widgets::{self, BorderSet, Col, Dialog, Line, ListState, Span};
use crate::LayoutClass;

/// Which part of the screen has the keyboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Focus {
    Tabs,
    List,
    Detail,
}

/// Something the host (i7labd console) must do. The TUI never does I/O itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// leave the TUI (the daemon then runs `i7labsh` on the tty if the console is open)
    Quit,
    /// F10: hand the tty to `i7labsh`, resume the TUI when it exits
    Shell,
    /// repaint everything (Ctrl-L, F5)
    Redraw,
    /// refresh the data now (F5)
    Refresh,
    /// run all probes now (F2)
    ProbeNow,
    Reboot,
    PowerOff,
    /// UEFI boot entry number for BootNext, then reboot
    BootNext(u16),
    RescanPci,
    BlockReadTest { dev: String },
    /// only emitted when the app was built with `Options::write_tests`; `serial` was typed in full by the operator
    BlockWriteTest { dev: String, serial: String },
    Dhcp { iface: String },
    Ping { target: String },
}

/// What a confirmed dialog turns into.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Then {
    Req(Request),
    /// the dialog's input text is the ping target
    PingInput { iface: String },
    /// nothing: information only
    Nothing,
    /// the dialog's input text is a log search
    LogSearch,
}

/// Result of a page handling a key.
#[derive(Clone, Debug)]
pub enum PageAction {
    /// not for this page; the app applies its own meaning (Esc = go back, digits = tabs ...)
    Unhandled,
    Handled,
    FocusDetail,
    FocusList,
    /// run something now
    Do(Request),
    /// ask first; `then` runs when the dialog's confirm button is chosen
    Ask { dialog: Dialog, then: Then },
    /// information dialog
    Info(Dialog),
    /// message on the status line
    Status(String),
}

pub struct DrawCx<'a> {
    pub buf: &'a mut Buffer,
    pub theme: &'a Theme,
    pub set: BorderSet,
    pub class: LayoutClass,
    pub data: &'a ViewData,
    pub focus: Focus,
    /// frame counter, for blinking / follow marks
    pub tick: u64,
}

impl DrawCx<'_> {
    pub fn unicode(&self) -> bool {
        self.set != BorderSet::Ascii
    }
}

pub struct KeyCx<'a> {
    pub data: &'a ViewData,
    pub focus: Focus,
    pub class: LayoutClass,
    pub console_locked: bool,
    pub write_tests: bool,
}

pub trait Page {
    fn title(&self) -> &'static str;
    /// 3-letter tab label for the compact layout
    fn short(&self) -> &'static str;
    fn draw(&mut self, cx: &mut DrawCx, area: Rect);
    fn key(&mut self, key: Key, cx: &KeyCx) -> PageAction;
    /// (key, description) lines for the F1 overlay
    fn help(&self) -> &'static [(&'static str, &'static str)];
    /// Dialog input text for `Then::LogSearch` and similar page-private follow ups.
    fn dialog_input(&mut self, _then: &Then, _text: &str) {}
}

/// Left pane content of a master/detail page.
pub enum Left<'a> {
    Lines(&'a [Line]),
    Table(&'a [Col], &'a [Vec<Span>]),
}

impl Left<'_> {
    pub fn len(&self) -> usize {
        match self {
            Left::Lines(l) => l.len(),
            Left::Table(_, r) => r.len(),
        }
    }
}

/// Everything `Md::draw` needs for one frame.
pub struct MdView<'a> {
    pub left_title: &'a str,
    pub left: Left<'a>,
    pub detail_title: &'a str,
    pub detail: &'a [Line],
    /// optional third column for the wide layout (live graphs, extra facts)
    pub live: Option<(&'a str, &'a [Line])>,
}

/// Selection and scrolling state of a master/detail page.
#[derive(Clone, Debug, Default)]
pub struct Md {
    pub list: ListState,
    pub detail_scroll: usize,
    /// rows visible in the list pane at the last draw (page size for PgUp / PgDn)
    pub page_rows: usize,
    pub len: usize,
    last_selected: usize,
    /// width of the list pane in percent of the area, standard/wide layouts (0 = 35)
    pub left_pct: u16,
}

impl Md {
    /// Split the area by layout class and draw the panes. Compact shows one pane at a time (list, or detail
    /// when it has focus); standard 35/65; wide 28/44/28 when a live pane is given.
    pub fn draw(&mut self, cx: &mut DrawCx, area: Rect, v: MdView) {
        self.len = v.left.len();
        if self.list.selected != self.last_selected {
            self.detail_scroll = 0;
            self.last_selected = self.list.selected;
        }
        let pct = if self.left_pct == 0 { 35 } else { self.left_pct as u32 };
        let (lr, dr, third) = match cx.class {
            LayoutClass::Compact | LayoutClass::TooSmall => {
                if cx.focus == Focus::Detail {
                    (None, Some(area), None)
                } else {
                    (Some(area), None, None)
                }
            }
            LayoutClass::Standard => {
                let lw = (area.w as u32 * pct / 100) as u16;
                let (l, d) = area.split_h(lw);
                (Some(l), Some(d), None)
            }
            LayoutClass::Wide => {
                if v.live.is_some() {
                    let lw = (area.w as u32 * 28 / 100) as u16;
                    let dw = (area.w as u32 * 44 / 100) as u16;
                    let (l, rest) = area.split_h(lw);
                    let (d, t) = rest.split_h(dw);
                    (Some(l), Some(d), Some(t))
                } else {
                    let lw = (area.w as u32 * pct / 100) as u16;
                    let (l, d) = area.split_h(lw);
                    (Some(l), Some(d), None)
                }
            }
        };
        let theme = cx.theme;
        let set = cx.set;
        if let Some(r) = lr {
            let inner = widgets::pane(cx.buf, r, v.left_title, cx.focus != Focus::Detail, theme, set);
            self.page_rows = (inner.h as usize).saturating_sub(if matches!(v.left, Left::Table(..)) { 1 } else { 0 });
            let focused = cx.focus == Focus::List;
            match v.left {
                Left::Lines(l) => widgets::list(cx.buf, inner, &mut self.list, l, theme, focused),
                Left::Table(c, r) => widgets::table(cx.buf, inner, &mut self.list, c, r, theme, focused),
            }
        } else {
            // list not drawn: still keep the selection valid
            self.list.fix(self.len, self.page_rows.max(1));
        }
        if let Some(r) = dr {
            let inner = widgets::pane(cx.buf, r, v.detail_title, cx.focus == Focus::Detail, theme, set);
            let max = v.detail.len().saturating_sub(inner.h as usize);
            self.detail_scroll = self.detail_scroll.min(max);
            widgets::text(cx.buf, inner, v.detail, self.detail_scroll, theme);
        }
        if let (Some(r), Some((title, lines))) = (third, v.live) {
            let inner = widgets::pane(cx.buf, r, title, false, theme, set);
            widgets::text(cx.buf, inner, lines, 0, theme);
        }
    }

    /// Navigation: list focus moves the selection, detail focus scrolls. Returns Handled for those keys.
    pub fn key(&mut self, key: Key, focus: Focus) -> PageAction {
        match focus {
            Focus::List => {
                if self.list.key(key, self.len, self.page_rows) {
                    return PageAction::Handled;
                }
                if key == Key::Enter && self.len > 0 {
                    return PageAction::FocusDetail;
                }
            }
            Focus::Detail => {
                let page = self.page_rows.max(4);
                match key {
                    Key::Up | Key::Char('k') => self.detail_scroll = self.detail_scroll.saturating_sub(1),
                    Key::Down | Key::Char('j') => self.detail_scroll += 1,
                    Key::PgUp => self.detail_scroll = self.detail_scroll.saturating_sub(page),
                    Key::PgDn => self.detail_scroll += page,
                    Key::Home => self.detail_scroll = 0,
                    Key::End => self.detail_scroll = usize::MAX / 2,
                    _ => return PageAction::Unhandled,
                }
                return PageAction::Handled;
            }
            Focus::Tabs => {}
        }
        PageAction::Unhandled
    }
}

/// "no data yet" placeholder lines.
pub fn missing(theme: &Theme, what: &str) -> Vec<Line> {
    vec![widgets::line(format!("{} not probed yet", what), theme.dim)]
}
