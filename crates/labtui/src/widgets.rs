//! Widgets: plain functions drawing into a Buffer region. Owner: P5.
//! Every widget is pure over the `Buffer`, so it can be golden-tested through `Buffer::to_text()`.

use std::collections::HashSet;

use crate::buffer::{Attr, Buffer, Cell, Color, Rect, Style};
use crate::input::Key;
use crate::theme::Theme;
use crate::width::{char_width, str_width};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BorderSet {
    Unicode,
    Ascii,
    Double,
}

impl BorderSet {
    /// (top-left, top-right, bottom-left, bottom-right, horizontal, vertical)
    pub fn chars(self) -> (char, char, char, char, char, char) {
        match self {
            BorderSet::Unicode => ('┌', '┐', '└', '┘', '─', '│'),
            BorderSet::Ascii => ('+', '+', '+', '+', '-', '|'),
            BorderSet::Double => ('╔', '╗', '╚', '╝', '═', '║'),
        }
    }
    /// Unicode frames unless the terminal cannot draw them.
    pub fn for_caps(unicode: bool) -> BorderSet {
        if unicode {
            BorderSet::Unicode
        } else {
            BorderSet::Ascii
        }
    }
}

// ---------------------------------------------------------------------------------------------- text model

/// A run of text in one style.
#[derive(Clone, Debug, PartialEq)]
pub struct Span {
    pub text: String,
    pub style: Style,
}

/// One display line made of styled spans.
pub type Line = Vec<Span>;

pub fn span(text: impl Into<String>, style: Style) -> Span {
    Span { text: text.into(), style }
}

/// A one-span line.
pub fn line(text: impl Into<String>, style: Style) -> Line {
    vec![span(text, style)]
}

/// `label: value` line with a dim label.
pub fn kv(label: &str, value: impl Into<String>, theme: &Theme) -> Line {
    vec![span(format!("{:<15}", format!("{}:", label)), theme.dim), span(value, theme.text)]
}

pub fn line_width(l: &Line) -> usize {
    l.iter().map(|s| str_width(&s.text)).sum()
}

/// Draw a line's spans from (x, y), at most `w` columns; when the line is too long the span that crosses the
/// edge ends in the ellipsis marker. Returns the columns used.
pub fn put_line(buf: &mut Buffer, x: u16, y: u16, w: u16, l: &Line) -> u16 {
    let mut used = 0u16;
    for s in l {
        let room = w.saturating_sub(used);
        if room == 0 {
            break;
        }
        if buf.text_width(&s.text) <= room as usize {
            used += buf.put_str(x + used, y, &s.text, s.style);
        } else {
            used += buf.put_str_fit(x + used, y, room, &s.text, s.style);
            break;
        }
    }
    used
}

/// Word-wrap plain text to `width` cells (long words are hard-cut). Always returns at least one line.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut out = Vec::new();
    for para in text.split('\n') {
        let mut cur = String::new();
        let mut cw = 0usize;
        for word in para.split(' ') {
            let ww = str_width(word);
            if !cur.is_empty() && cw + 1 + ww > width {
                out.push(std::mem::take(&mut cur));
                cw = 0;
            }
            if ww > width {
                // hard cut
                for c in word.chars() {
                    let w1 = char_width(c);
                    if cw + w1 > width {
                        out.push(std::mem::take(&mut cur));
                        cw = 0;
                    }
                    cur.push(c);
                    cw += w1;
                }
                continue;
            }
            if !cur.is_empty() {
                cur.push(' ');
                cw += 1;
            }
            cur.push_str(word);
            cw += ww;
        }
        out.push(cur);
    }
    out
}

// ---------------------------------------------------------------------------------------------- frame, tabs

pub fn frame(buf: &mut Buffer, r: Rect, title: &str, style: Style, set: BorderSet) {
    if r.w < 2 || r.h < 2 {
        return;
    }
    let (tl, tr, bl, br, hz, vt) = set.chars();
    let c = |ch| Cell { ch, fg: style.fg, bg: style.bg, attr: style.attr };
    for x in r.x + 1..r.x + r.w - 1 {
        buf.set(x, r.y, c(hz));
        buf.set(x, r.y + r.h - 1, c(hz));
    }
    for y in r.y + 1..r.y + r.h - 1 {
        buf.set(r.x, y, c(vt));
        buf.set(r.x + r.w - 1, y, c(vt));
    }
    buf.set(r.x, r.y, c(tl));
    buf.set(r.x + r.w - 1, r.y, c(tr));
    buf.set(r.x, r.y + r.h - 1, c(bl));
    buf.set(r.x + r.w - 1, r.y + r.h - 1, c(br));
    if !title.is_empty() && r.w > 6 {
        buf.put_str_fit(r.x + 2, r.y, r.w - 4, &format!(" {} ", title), style);
    }
}

/// Frame whose title is drawn in `title_style` (so the focused pane stands out), body cleared.
pub fn pane(buf: &mut Buffer, r: Rect, title: &str, focused: bool, theme: &Theme, set: BorderSet) -> Rect {
    let st = if focused { theme.title } else { theme.frame };
    buf.fill(r, ' ', theme.text);
    frame(buf, r, title, st, set);
    r.inset(1)
}

/// Tab bar; the active label is drawn as `[Label]`. Labels that do not fit are cut off the right edge.
pub fn tabs(buf: &mut Buffer, r: Rect, labels: &[&str], active: usize, theme: &Theme) {
    buf.fill(Rect::new(r.x, r.y, r.w, 1), ' ', theme.tab_inactive);
    let mut x = r.x;
    for (i, l) in labels.iter().enumerate() {
        let (txt, st) = if i == active { (format!("[{}]", l), theme.tab_active) } else { (format!(" {} ", l), theme.tab_inactive) };
        if x >= r.x + r.w {
            break;
        }
        let room = r.x + r.w - x;
        x += buf.put_str_fit(x, r.y, room, &txt, st) + 1;
    }
}

/// Total width the labels need (for choosing the abbreviated labels in the compact layout).
pub fn tabs_width(labels: &[&str]) -> usize {
    labels.iter().map(|l| str_width(l) + 3).sum()
}

/// Key hint bar: `F1 Help  F5 Refresh ...` with keys highlighted.
pub fn keybar(buf: &mut Buffer, r: Rect, items: &[(&str, &str)], theme: &Theme) {
    buf.fill(Rect::new(r.x, r.y, r.w, 1), ' ', theme.bar);
    let mut x = r.x;
    for (k, d) in items {
        if x + 2 >= r.x + r.w {
            break;
        }
        x += buf.put_str_fit(x, r.y, r.x + r.w - x, k, theme.bar_key);
        x += buf.put_str_fit(x, r.y, (r.x + r.w).saturating_sub(x), &format!(" {}  ", d), theme.bar);
    }
}

// ---------------------------------------------------------------------------------------------- scrolling

/// Selection + scroll offset shared by `list` and `table`.
#[derive(Clone, Debug, Default)]
pub struct ListState {
    pub selected: usize,
    pub offset: usize,
}

pub type TableState = ListState;

impl ListState {
    /// Keep `selected` inside 0..len and inside the window of `h` rows.
    pub fn fix(&mut self, len: usize, h: usize) {
        if len == 0 {
            self.selected = 0;
            self.offset = 0;
            return;
        }
        self.selected = self.selected.min(len - 1);
        let h = h.max(1);
        if self.selected < self.offset {
            self.offset = self.selected;
        } else if self.selected >= self.offset + h {
            self.offset = self.selected + 1 - h;
        }
        self.offset = self.offset.min(len.saturating_sub(h));
    }
    /// Up/Down/PgUp/PgDn/Home/End. Returns true when the key was a navigation key.
    pub fn key(&mut self, key: Key, len: usize, page: usize) -> bool {
        if len == 0 {
            return matches!(key, Key::Up | Key::Down | Key::PgUp | Key::PgDn | Key::Home | Key::End);
        }
        let page = page.max(1);
        match key {
            Key::Up | Key::Char('k') => self.selected = self.selected.saturating_sub(1),
            Key::Down | Key::Char('j') => self.selected = (self.selected + 1).min(len - 1),
            Key::PgUp => self.selected = self.selected.saturating_sub(page),
            Key::PgDn => self.selected = (self.selected + page).min(len - 1),
            Key::Home => self.selected = 0,
            Key::End => self.selected = len - 1,
            _ => return false,
        }
        true
    }
}

/// Scroll bar in the last column of `r`: a track with a thumb; draws nothing when everything fits.
pub fn scrollbar(buf: &mut Buffer, r: Rect, total: usize, offset: usize, theme: &Theme) {
    let h = r.h as usize;
    if total <= h || h < 2 || r.w == 0 {
        return;
    }
    let x = r.x + r.w - 1;
    let thumb = ((h * h) / total).clamp(1, h);
    let max_off = total - h;
    let pos = if max_off == 0 { 0 } else { offset.min(max_off) * (h - thumb) / max_off };
    let (track, bar) = if buf.is_ascii() { (':', '#') } else { ('░', '█') };
    for i in 0..h {
        let on = i >= pos && i < pos + thumb;
        buf.set(x, r.y + i as u16, Cell { ch: if on { bar } else { track }, fg: theme.dim.fg, bg: theme.dim.bg, attr: theme.dim.attr });
    }
}

fn add_attr(buf: &mut Buffer, r: Rect, attr: Attr) {
    for y in r.y..r.y.saturating_add(r.h).min(buf.height()) {
        for x in r.x..r.x.saturating_add(r.w).min(buf.width()) {
            if let Some(c) = buf.get(x, y).copied() {
                buf.set(x, y, Cell { attr: c.attr | attr, ..c });
            }
        }
    }
}

/// Selection highlight that keeps the text colours: reverse video (bright when focused, dim when not).
fn highlight(buf: &mut Buffer, r: Rect, focused: bool) {
    add_attr(buf, r, if focused { Attr::REVERSE | Attr::BOLD } else { Attr::REVERSE });
}

/// Selectable list of single-line rows with scrolling and a scroll bar.
pub fn list(buf: &mut Buffer, r: Rect, state: &mut ListState, rows: &[Line], theme: &Theme, focused: bool) {
    if r.w == 0 || r.h == 0 {
        return;
    }
    state.fix(rows.len(), r.h as usize);
    let bar = rows.len() > r.h as usize;
    let w = if bar { r.w - 1 } else { r.w };
    for (i, row) in rows.iter().skip(state.offset).take(r.h as usize).enumerate() {
        let y = r.y + i as u16;
        put_line(buf, r.x, y, w, row);
        if i + state.offset == state.selected {
            highlight(buf, Rect::new(r.x, y, w, 1), focused);
        }
    }
    scrollbar(buf, r, rows.len(), state.offset, theme);
}

/// Column description for `table`.
#[derive(Clone, Copy, Debug)]
pub struct Col {
    pub title: &'static str,
    /// fixed width in cells; 0 = flexible (shares the leftover space)
    pub width: u16,
    /// 0 = always shown; higher numbers are dropped first when the table is too narrow
    pub prio: u8,
    pub right: bool,
}

impl Col {
    pub const fn new(title: &'static str, width: u16, prio: u8) -> Col {
        Col { title, width, prio, right: false }
    }
    pub const fn right(mut self) -> Col {
        self.right = true;
        self
    }
}

const FLEX_MIN: u16 = 8;

/// Which columns are shown and how wide, for `avail` cells (1 cell gap between columns). Returns
/// (column index, width) pairs in column order.
pub fn column_layout(cols: &[Col], avail: u16) -> Vec<(usize, u16)> {
    let mut shown: Vec<usize> = (0..cols.len()).collect();
    let need = |shown: &[usize]| -> u32 {
        let gaps = shown.len().saturating_sub(1) as u32;
        gaps + shown.iter().map(|&i| if cols[i].width == 0 { FLEX_MIN } else { cols[i].width } as u32).sum::<u32>()
    };
    while need(&shown) > avail as u32 {
        // drop the shown column with the highest prio (the last one on ties); prio 0 never goes
        let victim = shown.iter().copied().filter(|&i| cols[i].prio > 0).max_by_key(|&i| (cols[i].prio, i));
        match victim {
            Some(v) => shown.retain(|&i| i != v),
            None => break,
        }
    }
    let fixed: u32 = shown.iter().filter(|&&i| cols[i].width > 0).map(|&i| cols[i].width as u32).sum();
    let gaps = shown.len().saturating_sub(1) as u32;
    let flex_n = shown.iter().filter(|&&i| cols[i].width == 0).count() as u32;
    let left = (avail as u32).saturating_sub(fixed + gaps);
    let flex_w = if flex_n > 0 { (left / flex_n).max(1) as u16 } else { 0 };
    let mut extra = if flex_n > 0 { left.saturating_sub(flex_w as u32 * flex_n) } else { 0 };
    shown
        .into_iter()
        .map(|i| {
            if cols[i].width > 0 {
                (i, cols[i].width)
            } else {
                // the first flexible columns take the division remainder
                let add = if extra > 0 { 1 } else { 0 };
                extra = extra.saturating_sub(add as u32);
                (i, flex_w + add)
            }
        })
        .collect()
}

/// Table with a header row; `rows[n][c]` is the cell for column `c` (all columns, shown or not).
pub fn table(buf: &mut Buffer, r: Rect, state: &mut TableState, cols: &[Col], rows: &[Vec<Span>], theme: &Theme, focused: bool) {
    if r.w == 0 || r.h < 2 {
        return;
    }
    let body_h = (r.h - 1) as usize;
    state.fix(rows.len(), body_h);
    let bar = rows.len() > body_h;
    let w = if bar { r.w - 1 } else { r.w };
    let layout = column_layout(cols, w);
    // header
    let mut x = r.x;
    buf.fill(Rect::new(r.x, r.y, r.w, 1), ' ', theme.header);
    for (i, cw) in &layout {
        let c = &cols[*i];
        let t = crate::width::truncate(c.title, *cw as usize, buf.ellipsis());
        let pad = if c.right { (*cw as usize).saturating_sub(str_width(&t)) as u16 } else { 0 };
        buf.put_str(x + pad, r.y, &t, theme.header);
        x += cw + 1;
    }
    for (n, row) in rows.iter().skip(state.offset).take(body_h).enumerate() {
        let y = r.y + 1 + n as u16;
        let mut x = r.x;
        for (i, cw) in &layout {
            if let Some(sp) = row.get(*i) {
                let tw = buf.text_width(&sp.text).min(*cw as usize) as u16;
                let px = if cols[*i].right { x + cw.saturating_sub(tw) } else { x };
                buf.put_str_fit(px, y, *cw, &sp.text, sp.style);
            }
            x += cw + 1;
        }
        if n + state.offset == state.selected {
            highlight(buf, Rect::new(r.x, y, w, 1), focused);
        }
    }
    scrollbar(buf, Rect::new(r.x, r.y + 1, r.w, r.h - 1), rows.len(), state.offset, theme);
}

// ---------------------------------------------------------------------------------------------- tree

/// One visible row of a flattened forest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeRow {
    /// index into the caller's item slice
    pub index: usize,
    pub depth: usize,
    pub has_children: bool,
    pub collapsed: bool,
}

/// Depth-first order of items given as (id, parent id); items whose parent is missing become roots, cycles
/// are cut. Children of ids in `collapsed` are hidden.
pub fn tree_rows(items: &[(String, Option<String>)], collapsed: &HashSet<String>) -> Vec<TreeRow> {
    let ids: HashSet<&str> = items.iter().map(|(i, _)| i.as_str()).collect();
    let mut kids: std::collections::HashMap<&str, Vec<usize>> = std::collections::HashMap::new();
    let mut roots = Vec::new();
    for (n, (id, parent)) in items.iter().enumerate() {
        match parent {
            Some(p) if ids.contains(p.as_str()) && p != id => kids.entry(p.as_str()).or_default().push(n),
            _ => roots.push(n),
        }
    }
    let mut out = Vec::new();
    let mut seen = vec![false; items.len()];
    fn walk(
        n: usize,
        depth: usize,
        items: &[(String, Option<String>)],
        kids: &std::collections::HashMap<&str, Vec<usize>>,
        collapsed: &HashSet<String>,
        seen: &mut [bool],
        out: &mut Vec<TreeRow>,
        shown: bool,
    ) {
        if seen[n] {
            return;
        }
        seen[n] = true;
        let id = items[n].0.as_str();
        let children = kids.get(id).map(|v| v.as_slice()).unwrap_or(&[]);
        let is_collapsed = collapsed.contains(id) && !children.is_empty();
        if shown {
            out.push(TreeRow { index: n, depth, has_children: !children.is_empty(), collapsed: is_collapsed });
        }
        // descendants of a collapsed node are walked too (marked seen, not listed) so only real cycles are left over
        for &c in children {
            walk(c, depth + 1, items, kids, collapsed, seen, out, shown && !is_collapsed);
        }
    }
    for &n in &roots {
        walk(n, 0, items, &kids, collapsed, &mut seen, &mut out, true);
    }
    // anything unreachable (a parent cycle) is shown as a root so it is never silently hidden
    for n in 0..items.len() {
        if !seen[n] {
            walk(n, 0, items, &kids, collapsed, &mut seen, &mut out, true);
        }
    }
    out
}

/// Indent + fold marker for a tree row.
pub fn tree_prefix(row: &TreeRow, unicode: bool) -> String {
    let marker = match (row.has_children, row.collapsed, unicode) {
        (false, _, true) => "  ",
        (false, _, false) => "  ",
        (true, true, true) => "▸ ",
        (true, false, true) => "▾ ",
        (true, true, false) => "+ ",
        (true, false, false) => "- ",
    };
    format!("{}{}", "  ".repeat(row.depth.min(12)), marker)
}

// ---------------------------------------------------------------------------------------------- text

/// Scrollable block of lines (no selection); a scroll bar appears when the text is longer than the area.
pub fn text(buf: &mut Buffer, r: Rect, lines: &[Line], scroll: usize, theme: &Theme) {
    if r.w == 0 || r.h == 0 {
        return;
    }
    let scroll = scroll.min(lines.len().saturating_sub(r.h as usize));
    let bar = lines.len() > r.h as usize;
    let w = if bar { r.w - 1 } else { r.w };
    for (i, l) in lines.iter().skip(scroll).take(r.h as usize).enumerate() {
        put_line(buf, r.x, r.y + i as u16, w, l);
    }
    scrollbar(buf, r, lines.len(), scroll, theme);
}

/// Horizontal bar. The label is written over the bar; the filled part is the status colour (green, yellow from
/// 70 %, red from 90 %), reverse video on mono terminals.
pub fn gauge(buf: &mut Buffer, r: Rect, ratio: f32, label: &str, theme: &Theme) {
    if r.w == 0 || r.h == 0 {
        return;
    }
    let ratio = if ratio.is_finite() { ratio.clamp(0.0, 1.0) } else { 0.0 };
    let status = if ratio >= 0.9 {
        theme.bad
    } else if ratio >= 0.7 {
        theme.warn
    } else {
        theme.ok
    };
    let fill = if status.fg == Color::Default {
        Style { fg: Color::Default, bg: Color::Default, attr: Attr::REVERSE }
    } else {
        Style { fg: Color::Ansi(0), bg: status.fg, attr: Attr::BOLD }
    };
    let filled = (ratio * r.w as f32).round() as u16;
    let label: Vec<char> = buf.fit_text(label, r.w as usize).chars().filter(|c| char_width(*c) == 1).collect();
    for i in 0..r.w {
        let ch = label.get(i as usize).copied().unwrap_or(' ');
        let st = if i < filled { fill } else { theme.dim };
        buf.set(r.x + i, r.y, Cell { ch, fg: st.fg, bg: st.bg, attr: st.attr });
    }
}

/// Sparkline as a string of `width` cells (newest right, left padded), for use inside `Line`s.
pub fn spark_string(samples: &[f32], width: usize, unicode: bool) -> String {
    let glyphs: Vec<char> = if unicode { "▁▂▃▄▅▆▇█".chars().collect() } else { "_.:-=+*#".chars().collect() };
    let start = samples.len().saturating_sub(width);
    let win = &samples[start..];
    let lo = win.iter().cloned().fold(f32::MAX, f32::min);
    let hi = win.iter().cloned().fold(f32::MIN, f32::max);
    let span = (hi - lo).max(1.0);
    let mut s = " ".repeat(width.saturating_sub(win.len()));
    for v in win {
        s.push(glyphs[(((v - lo) / span) * 7.0).round().clamp(0.0, 7.0) as usize]);
    }
    s
}

/// Mini graph of recent samples, newest at the right, scaled between the window's min and max.
pub fn sparkline(buf: &mut Buffer, r: Rect, samples: &[f32], unicode: bool, theme: &Theme) {
    if r.w == 0 || samples.is_empty() {
        return;
    }
    let glyphs: Vec<char> = if unicode { "▁▂▃▄▅▆▇█".chars().collect() } else { "_.:-=+*#".chars().collect() };
    let start = samples.len().saturating_sub(r.w as usize);
    let win = &samples[start..];
    let lo = win.iter().cloned().fold(f32::MAX, f32::min);
    let hi = win.iter().cloned().fold(f32::MIN, f32::max);
    let span = (hi - lo).max(1.0);
    let x0 = r.x + r.w - win.len() as u16;
    for (i, s) in win.iter().enumerate() {
        let level = (((s - lo) / span) * 7.0).round().clamp(0.0, 7.0) as usize;
        buf.set(x0 + i as u16, r.y, Cell { ch: glyphs[level], fg: theme.accent.fg, bg: theme.accent.bg, attr: theme.accent.attr });
    }
}

// ---------------------------------------------------------------------------------------------- dialog

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DialogKind {
    #[default]
    Info,
    Warn,
    Danger,
}

/// Result of feeding a key to a dialog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialogResult {
    /// still open
    Open,
    /// button index chosen
    Button(usize),
    Cancel,
}

#[derive(Clone, Debug, Default)]
pub struct Dialog {
    pub title: String,
    pub body: Vec<String>,
    pub buttons: Vec<String>,
    pub selected: usize,
    pub kind: DialogKind,
    /// typed confirmation (e.g. the device serial): when `expect` is set, `confirm` stays disabled until the
    /// typed text matches
    pub input: Option<String>,
    pub expect: Option<String>,
    /// the button that needs the typed text (default 0)
    pub confirm: usize,
}

impl Dialog {
    pub fn new(title: &str, body: &[&str], buttons: &[&str]) -> Dialog {
        Dialog { title: title.into(), body: body.iter().map(|s| s.to_string()).collect(), buttons: buttons.iter().map(|s| s.to_string()).collect(), ..Default::default() }
    }
    /// "Yes / No" confirmation with No selected (the safe default).
    pub fn confirm(title: &str, body: &[&str]) -> Dialog {
        let mut d = Dialog::new(title, body, &["Yes", "No"]);
        d.selected = 1;
        d
    }
    /// Confirmation that needs `token` typed in full (serial number, `yes`...).
    pub fn typed(title: &str, body: &[&str], token: &str) -> Dialog {
        let mut d = Dialog::new(title, body, &["Confirm", "Cancel"]);
        d.kind = DialogKind::Danger;
        d.input = Some(String::new());
        d.expect = Some(token.to_string());
        d.selected = 1;
        d
    }
    pub fn typed_ok(&self) -> bool {
        match (&self.expect, &self.input) {
            (Some(e), Some(i)) => e == i,
            _ => true,
        }
    }
    pub fn key(&mut self, key: Key) -> DialogResult {
        let n = self.buttons.len().max(1);
        let typing = self.input.is_some();
        match key {
            Key::Esc | Key::Ctrl('c') => return DialogResult::Cancel,
            Key::Left | Key::BackTab => self.selected = (self.selected + n - 1) % n,
            Key::Right | Key::Tab => self.selected = (self.selected + 1) % n,
            Key::Enter => {
                if self.selected == self.confirm && !self.typed_ok() {
                    return DialogResult::Open; // refused until the token matches
                }
                return DialogResult::Button(self.selected);
            }
            Key::Backspace if typing => {
                if let Some(i) = &mut self.input {
                    i.pop();
                }
            }
            Key::Char(c) if typing => {
                if let Some(i) = &mut self.input {
                    if i.chars().count() < 80 {
                        i.push(c);
                    }
                }
            }
            Key::Char('y') | Key::Char('Y') if !typing && self.buttons.first().map(|b| b == "Yes").unwrap_or(false) => return DialogResult::Button(0),
            Key::Char('n') | Key::Char('N') if !typing && self.buttons.get(1).map(|b| b == "No").unwrap_or(false) => return DialogResult::Button(1),
            _ => {}
        }
        DialogResult::Open
    }
}

/// Modal dialog centred on `screen`: title, wrapped body, optional typed-confirmation field, buttons.
pub fn dialog(buf: &mut Buffer, screen: Rect, d: &Dialog, theme: &Theme, set: BorderSet) {
    let max_w = screen.w.saturating_sub(4).clamp(20, 72) as usize;
    let want = d.body.iter().map(|l| str_width(l)).max().unwrap_or(0).max(str_width(&d.title) + 4).max(30);
    let inner_w = want.min(max_w);
    let mut lines: Vec<String> = Vec::new();
    for b in &d.body {
        lines.extend(wrap(b, inner_w));
    }
    let extra_rows = if d.input.is_some() { 2 } else { 0 };
    let max_body = (screen.h as usize).saturating_sub(6 + extra_rows).max(1);
    lines.truncate(max_body);
    let w = inner_w as u16 + 4;
    let h = lines.len() as u16 + 4 + extra_rows as u16;
    let r = screen.centered(w, h);
    let (border, title_style) = match d.kind {
        DialogKind::Info => (theme.frame, theme.title),
        DialogKind::Warn => (theme.warn, theme.warn),
        DialogKind::Danger => (theme.bad, theme.bad),
    };
    buf.fill(r, ' ', theme.text);
    let set = if d.kind == DialogKind::Danger && set == BorderSet::Unicode { BorderSet::Double } else { set };
    frame(buf, r, "", border, set);
    if r.w > 6 {
        buf.put_str_fit(r.x + 2, r.y, r.w - 4, &format!(" {} ", d.title), title_style);
    }
    for (i, l) in lines.iter().enumerate() {
        buf.put_str_fit(r.x + 2, r.y + 1 + i as u16, r.w.saturating_sub(4), l, theme.text);
    }
    let mut row = r.y + 1 + lines.len() as u16;
    if let Some(inp) = &d.input {
        let ok = d.typed_ok();
        let st = if ok { theme.ok } else { theme.warn };
        let shown = format!("> {}_", inp);
        row += 1;
        buf.put_str_fit(r.x + 2, row, r.w.saturating_sub(4), &shown, st);
        row += 1;
    }
    let _ = row;
    let by = r.y + r.h - 2;
    let mut x = r.x + 2;
    for (i, b) in d.buttons.iter().enumerate() {
        let disabled = i == d.confirm && !d.typed_ok();
        let mut st = if i == d.selected { theme.selection } else { theme.text };
        if disabled {
            st = if i == d.selected { Style { attr: st.attr | Attr::DIM, ..st } } else { theme.dim };
        }
        x += buf.put_str(x, by, &format!("<{}>", b), st) + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Style;

    #[test]
    fn ascii_frame_golden() {
        let mut b = Buffer::new(12, 3);
        let a = b.area();
        frame(&mut b, a, "Hi", Style::default(), BorderSet::Ascii);
        assert_eq!(b.to_text(), "+- Hi -----+\n|          |\n+----------+\n");
    }

    #[test]
    fn unicode_and_double_frames() {
        let mut b = Buffer::new(6, 3);
        let a = b.area();
        frame(&mut b, a, "", Style::default(), BorderSet::Unicode);
        assert_eq!(b.to_text(), "┌────┐\n│    │\n└────┘\n");
        frame(&mut b, a, "", Style::default(), BorderSet::Double);
        assert_eq!(b.row_text(0), "╔════╗");
    }

    #[test]
    fn tabs_golden() {
        let t = Theme::dark();
        let mut b = Buffer::new(30, 1);
        tabs(&mut b, Rect::new(0, 0, 30, 1), &["Overview", "PCIe", "Storage"], 1, &t);
        assert_eq!(b.to_text(), " Overview  [PCIe]  Storage\n");
        assert_eq!(b.get(11, 0).unwrap().bg, t.tab_active.bg);
        assert_eq!(tabs_width(&["ab", "c"]), 9);
    }

    #[test]
    fn list_scrolls_and_selects() {
        let t = Theme::dark();
        let rows: Vec<Line> = (0..10).map(|i| line(format!("row{}", i), Style::default())).collect();
        let mut st = ListState { selected: 7, offset: 0 };
        let mut b = Buffer::new(10, 3);
        list(&mut b, Rect::new(0, 0, 10, 3), &mut st, &rows, &t, true);
        assert_eq!(st.offset, 5);
        assert!(b.row_text(2).starts_with("row7"));
        assert!(b.get(0, 2).unwrap().attr.contains(Attr::REVERSE));
        assert!(!b.get(0, 0).unwrap().attr.contains(Attr::REVERSE));
        // scroll bar in the last column
        assert_ne!(b.get(9, 0).unwrap().ch, ' ');
    }

    #[test]
    fn list_state_keys() {
        let mut s = ListState::default();
        assert!(s.key(Key::Down, 5, 3));
        assert_eq!(s.selected, 1);
        s.key(Key::PgDn, 5, 3);
        assert_eq!(s.selected, 4);
        s.key(Key::Down, 5, 3);
        assert_eq!(s.selected, 4);
        s.key(Key::Home, 5, 3);
        assert_eq!(s.selected, 0);
        s.key(Key::End, 5, 3);
        assert_eq!(s.selected, 4);
        assert!(!s.key(Key::Char('x'), 5, 3));
        let mut e = ListState::default();
        e.fix(0, 4);
        assert_eq!((e.selected, e.offset), (0, 0));
    }

    #[test]
    fn column_layout_drops_low_priority() {
        let cols = [Col::new("Name", 0, 0), Col::new("Size", 8, 1), Col::new("Serial", 12, 3), Col::new("Model", 10, 2)];
        let wide = column_layout(&cols, 60);
        assert_eq!(wide.len(), 4);
        assert_eq!(wide.iter().map(|(_, w)| *w as u32).sum::<u32>() + 3, 60);
        let mid = column_layout(&cols, 30);
        assert_eq!(mid.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![0, 1, 3]); // serial dropped first
        let tiny = column_layout(&cols, 12);
        assert_eq!(tiny.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![0]);
    }

    #[test]
    fn table_golden() {
        let t = Theme::mono();
        let cols = [Col::new("Dev", 6, 0), Col::new("Size", 6, 0).right()];
        let rows = vec![vec![span("sda", t.text), span("1T", t.text)], vec![span("nvme0n1x", t.text), span("500G", t.text)]];
        let mut st = TableState::default();
        let mut b = Buffer::new(13, 3);
        table(&mut b, Rect::new(0, 0, 13, 3), &mut st, &cols, &rows, &t, true);
        assert_eq!(b.to_text(), "Dev      Size\nsda        1T\nnvme0…   500G\n");
    }

    #[test]
    fn tree_order_collapse_and_cycles() {
        let items: Vec<(String, Option<String>)> = vec![
            ("00:00.0".into(), None),
            ("00:1c.0".into(), Some("00:00.0".into())),
            ("01:00.0".into(), Some("00:1c.0".into())),
            ("00:02.0".into(), Some("00:00.0".into())),
            ("ff:00.0".into(), Some("zz".into())), // unknown parent: becomes a root
        ];
        let rows = tree_rows(&items, &HashSet::new());
        let order: Vec<(usize, usize)> = rows.iter().map(|r| (r.index, r.depth)).collect();
        assert_eq!(order, vec![(0, 0), (1, 1), (2, 2), (3, 1), (4, 0)]);
        let mut col = HashSet::new();
        col.insert("00:1c.0".to_string());
        let rows = tree_rows(&items, &col);
        assert_eq!(rows.iter().map(|r| r.index).collect::<Vec<_>>(), vec![0, 1, 3, 4]);
        assert!(rows[1].collapsed && rows[1].has_children);
        // cycle a -> b -> a still shows both
        let cyc: Vec<(String, Option<String>)> = vec![("a".into(), Some("b".into())), ("b".into(), Some("a".into()))];
        assert_eq!(tree_rows(&cyc, &HashSet::new()).len(), 2);
        // self parent
        let me: Vec<(String, Option<String>)> = vec![("a".into(), Some("a".into()))];
        assert_eq!(tree_rows(&me, &HashSet::new()).len(), 1);
        assert_eq!(tree_prefix(&TreeRow { index: 0, depth: 1, has_children: true, collapsed: true }, false), "  + ");
    }

    #[test]
    fn wrap_text() {
        assert_eq!(wrap("aaa bbb ccc", 7), vec!["aaa bbb", "ccc"]);
        assert_eq!(wrap("abcdefghij", 4), vec!["abcd", "efgh", "ij"]);
        assert_eq!(wrap("a\nb", 10), vec!["a", "b"]);
        assert_eq!(wrap("", 5), vec![""]);
    }

    #[test]
    fn gauge_and_sparkline() {
        let t = Theme::dark();
        let mut b = Buffer::new(10, 2);
        gauge(&mut b, Rect::new(0, 0, 10, 1), 0.5, "50%", &t);
        assert!(b.row_text(0).starts_with("50%"));
        assert_eq!(b.get(0, 0).unwrap().bg, t.ok.fg);
        assert_eq!(b.get(9, 0).unwrap().bg, t.dim.bg);
        gauge(&mut b, Rect::new(0, 0, 10, 1), 0.95, "x", &t);
        assert_eq!(b.get(0, 0).unwrap().bg, t.bad.fg);
        gauge(&mut b, Rect::new(0, 0, 10, 1), f32::NAN, "x", &t); // must not panic
        sparkline(&mut b, Rect::new(0, 1, 8, 1), &[1.0, 2.0, 3.0, 4.0], true, &t);
        assert_eq!(b.row_text(1).trim(), "▁▃▆█");
        let mut a = Buffer::new(8, 1);
        sparkline(&mut a, Rect::new(0, 0, 8, 1), &[5.0, 5.0], false, &t); // flat input
        assert_eq!(a.row_text(0).trim_start(), "__");
    }

    #[test]
    fn dialog_flow_and_typed_confirmation() {
        let mut d = Dialog::confirm("Reboot", &["Reboot the host now?"]);
        assert_eq!(d.selected, 1); // safe default
        assert_eq!(d.key(Key::Enter), DialogResult::Button(1));
        assert_eq!(d.key(Key::Char('y')), DialogResult::Button(0));
        assert_eq!(d.key(Key::Esc), DialogResult::Cancel);
        d.key(Key::Left);
        assert_eq!(d.selected, 0);

        let mut t = Dialog::typed("Wipe", &["type the serial"], "S3X1");
        t.selected = 0;
        assert_eq!(t.key(Key::Enter), DialogResult::Open, "gated until the token matches");
        for c in "S3X".chars() {
            t.key(Key::Char(c));
        }
        assert_eq!(t.key(Key::Enter), DialogResult::Open);
        t.key(Key::Char('1'));
        assert!(t.typed_ok());
        assert_eq!(t.key(Key::Enter), DialogResult::Button(0));
        t.key(Key::Backspace);
        assert!(!t.typed_ok());
        // 'y' is text while typing, not a shortcut
        let mut t2 = Dialog::typed("x", &["x"], "y");
        assert_eq!(t2.key(Key::Char('y')), DialogResult::Open);
        assert!(t2.typed_ok());
    }

    #[test]
    fn dialog_golden() {
        let t = Theme::mono();
        let mut b = Buffer::new(40, 9);
        let d = Dialog::confirm("Reboot", &["Reboot the host now?"]);
        let a = b.area();
        dialog(&mut b, a, &d, &t, BorderSet::Ascii);
        let txt = b.to_text();
        assert!(txt.contains("+- Reboot "), "{}", txt);
        assert!(txt.contains("Reboot the host now?"));
        assert!(txt.contains("<Yes> <No>"));
        // the dialog is centred: first/last screen rows stay empty
        assert_eq!(b.row_text(0).trim(), "");
    }

    #[test]
    fn put_line_cuts_with_marker() {
        let mut b = Buffer::new(20, 1);
        let l = vec![span("hello ", Style::default()), span("wonderful world", Style::default())];
        put_line(&mut b, 0, 0, 12, &l);
        assert_eq!(b.row_text(0).trim_end(), "hello wonde\u{2026}");
    }

    #[test]
    fn keybar_golden() {
        let t = Theme::mono();
        let mut b = Buffer::new(30, 1);
        keybar(&mut b, Rect::new(0, 0, 30, 1), &[("F1", "Help"), ("q", "Quit")], &t);
        assert_eq!(b.to_text(), "F1 Help  q Quit\n");
    }
}
