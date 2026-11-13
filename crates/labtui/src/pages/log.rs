//! Log: kernel + lab log with level colours, search, follow mode and tag filter. Owner: P5.

use labprobe::kmsg::KmsgLine;

use crate::buffer::Rect;
use crate::fmt;
use crate::input::Key;
use crate::page::{missing, DrawCx, Focus, KeyCx, Page, PageAction, Then};
use crate::theme::Theme;
use crate::widgets::{self, line, span, Dialog, Line, ListState};

pub struct LogPage {
    list: ListState,
    follow: bool,
    search: String,
    /// show records with level <= this (7 = everything)
    level_max: u8,
    tag: Option<String>,
    /// rows visible in the list at the last draw
    page_rows: usize,
    /// indices into the report's lines that pass the filters (last draw)
    shown: Vec<usize>,
    /// full text of the report lines, for the Enter dialog (last draw)
    texts: Vec<String>,
}

impl Default for LogPage {
    fn default() -> Self {
        LogPage { list: ListState::default(), follow: true, search: String::new(), level_max: 7, tag: None, page_rows: 10, shown: Vec::new(), texts: Vec::new() }
    }
}

pub fn level_name(l: u8) -> &'static str {
    ["emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"].get(l as usize).copied().unwrap_or("?")
}

fn level_style(l: u8, t: &Theme) -> crate::buffer::Style {
    match l {
        0..=3 => t.bad,
        4 => t.warn,
        5 | 6 => t.text,
        _ => t.dim,
    }
}

fn matches_search(l: &KmsgLine, needle: &str) -> bool {
    !needle.is_empty() && l.text.to_lowercase().contains(&needle.to_lowercase())
}

fn row_text(l: &KmsgLine) -> String {
    format!("{} {}", fmt::kmsg_time(l.ts_us), l.text)
}

impl LogPage {
    fn all_tags(data: &crate::model::ViewData) -> Vec<String> {
        let mut tags: Vec<String> = Vec::new();
        if let Some(k) = &data.kmsg {
            for l in &k.lines {
                for t in &l.tags {
                    if !tags.contains(t) {
                        tags.push(t.clone());
                    }
                }
            }
        }
        tags.sort();
        tags
    }
    fn next_level(l: u8) -> u8 {
        match l {
            7 => 6,
            6 => 4,
            4 => 3,
            _ => 7,
        }
    }
    fn jump_match(&mut self, data: &crate::model::ViewData, forward: bool) -> PageAction {
        let Some(k) = &data.kmsg else { return PageAction::Handled };
        if self.search.is_empty() || self.shown.is_empty() {
            return PageAction::Status("no search set (press /)".into());
        }
        let n = self.shown.len();
        for step in 1..=n {
            let pos = if forward { (self.list.selected + step) % n } else { (self.list.selected + n - step % n) % n };
            if matches_search(&k.lines[self.shown[pos]], &self.search) {
                self.list.selected = pos;
                self.follow = false;
                return PageAction::Handled;
            }
        }
        PageAction::Status(format!("'{}' not found", self.search))
    }
}

impl Page for LogPage {
    fn title(&self) -> &'static str {
        "Log"
    }
    fn short(&self) -> &'static str {
        "Log"
    }
    fn draw(&mut self, cx: &mut DrawCx, area: Rect) {
        let t = cx.theme;
        let Some(k) = cx.data.kmsg.as_ref() else {
            let inner = widgets::pane(cx.buf, area, "Kernel log", true, t, cx.set);
            let l = missing(t, "kernel log");
            widgets::text(cx.buf, inner, &l, 0, t);
            return;
        };
        self.shown = k
            .lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.level <= self.level_max && self.tag.as_ref().map(|t| l.tags.contains(t)).unwrap_or(true))
            .map(|(i, _)| i)
            .collect();
        self.texts = k.lines.iter().map(row_text).collect();
        let focused = cx.focus != Focus::Tabs;
        let inner = widgets::pane(cx.buf, area, "Kernel log", focused, t, cx.set);
        if inner.h < 2 {
            return;
        }
        // filter line
        let mut f: Line = vec![span(format!("{}/{} lines  ", self.shown.len(), k.lines.len()), t.dim)];
        f.push(span(format!("level<={}  ", level_name(self.level_max)), if self.level_max < 7 { t.warn } else { t.dim }));
        if let Some(tag) = &self.tag {
            f.push(span(format!("tag:{}  ", tag), t.warn));
        }
        if !self.search.is_empty() {
            f.push(span(format!("search:'{}'  ", self.search), t.warn));
        }
        f.push(span(if self.follow { "FOLLOW" } else { "paused (f)" }, if self.follow { t.ok } else { t.dim }));
        widgets::put_line(cx.buf, inner.x, inner.y, inner.w, &f);
        let body = Rect::new(inner.x, inner.y + 1, inner.w, inner.h - 1);
        self.page_rows = body.h as usize;
        if self.follow && !self.shown.is_empty() {
            self.list.selected = self.shown.len() - 1;
        }
        let rows: Vec<Line> = self
            .shown
            .iter()
            .map(|&i| {
                let l = &k.lines[i];
                let hit = matches_search(l, &self.search);
                let mut v = vec![span(format!("{} ", fmt::kmsg_time(l.ts_us)), t.dim), span(l.text.clone(), if hit { t.accent } else { level_style(l.level, t) })];
                if !l.tags.is_empty() {
                    v.push(span(format!("  [{}]", l.tags.join(",")), t.warn));
                }
                v
            })
            .collect();
        if rows.is_empty() {
            widgets::text(cx.buf, body, &[line("no lines match the filters (c clears them)", t.dim)], 0, t);
        } else {
            widgets::list(cx.buf, body, &mut self.list, &rows, t, cx.focus == Focus::List);
        }
    }
    fn key(&mut self, key: Key, cx: &KeyCx) -> PageAction {
        if cx.focus == Focus::Tabs {
            return PageAction::Unhandled;
        }
        let len = self.shown.len();
        match key {
            Key::Up | Key::Down | Key::PgUp | Key::PgDn | Key::Home | Key::Char('k') | Key::Char('j') => {
                self.follow = false;
                self.list.key(key, len, self.page_rows);
                PageAction::Handled
            }
            Key::End | Key::Char('G') => {
                self.follow = true;
                PageAction::Handled
            }
            Key::Char('f') => {
                self.follow = !self.follow;
                PageAction::Handled
            }
            Key::Char('l') => {
                self.level_max = Self::next_level(self.level_max);
                PageAction::Handled
            }
            Key::Char('t') => {
                let tags = Self::all_tags(cx.data);
                self.tag = match &self.tag {
                    None => tags.first().cloned(),
                    Some(cur) => tags.iter().position(|t| t == cur).and_then(|i| tags.get(i + 1)).cloned(),
                };
                PageAction::Handled
            }
            Key::Char('c') => {
                self.tag = None;
                self.level_max = 7;
                self.search.clear();
                PageAction::Handled
            }
            Key::Char('/') => {
                let mut d = Dialog::new("Search log", &["Text to find (case-insensitive, empty clears)"], &["Search", "Cancel"]);
                d.input = Some(self.search.clone());
                PageAction::Ask { dialog: d, then: Then::LogSearch }
            }
            Key::Char('n') => self.jump_match(cx.data, true),
            Key::Char('N') => self.jump_match(cx.data, false),
            Key::Enter => match self.shown.get(self.list.selected).and_then(|&i| self.texts.get(i)) {
                Some(txt) => {
                    let mut d = Dialog::new("Log line", &[txt.as_str()], &["Close"]);
                    d.selected = 0;
                    PageAction::Info(d)
                }
                None => PageAction::Handled,
            },
            _ => PageAction::Unhandled,
        }
    }
    fn dialog_input(&mut self, then: &Then, text: &str) {
        if *then == Then::LogSearch {
            self.search = text.to_string();
        }
    }
    fn help(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("Up/Down/PgUp/PgDn", "scroll (pauses follow)"),
            ("End / f", "follow new lines / toggle"),
            ("/  n  N", "search, next, previous match"),
            ("l", "cycle minimum level"),
            ("t", "cycle tag filter"),
            ("c", "clear filters"),
            ("Enter", "show the whole line"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn levels_and_levels_cycle() {
        assert_eq!(level_name(3), "err");
        assert_eq!(level_name(9), "?");
        assert_eq!(LogPage::next_level(7), 6);
        assert_eq!(LogPage::next_level(3), 7);
    }
}
