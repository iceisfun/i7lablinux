//! Cell buffer and geometry. Pure (golden-testable via `to_text`). Owner: P5.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Color {
    Default,
    /// 0..15
    Ansi(u8),
    Idx(u8),
    Rgb(u8, u8, u8),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Attr(pub u8);

impl Attr {
    pub const NONE: Attr = Attr(0);
    pub const BOLD: Attr = Attr(1);
    pub const DIM: Attr = Attr(2);
    pub const REVERSE: Attr = Attr(4);
    pub const UNDERLINE: Attr = Attr(8);
    pub fn contains(self, o: Attr) -> bool {
        self.0 & o.0 == o.0
    }
}

impl std::ops::BitOr for Attr {
    type Output = Attr;
    fn bitor(self, o: Attr) -> Attr {
        Attr(self.0 | o.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Style {
    pub fg: Color,
    pub bg: Color,
    pub attr: Attr,
}

impl Default for Style {
    fn default() -> Self {
        Style { fg: Color::Default, bg: Color::Default, attr: Attr::NONE }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    pub fg: Color,
    pub bg: Color,
    pub attr: Attr,
}

impl Default for Cell {
    fn default() -> Self {
        Cell { ch: ' ', fg: Color::Default, bg: Color::Default, attr: Attr::NONE }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

impl Rect {
    pub fn new(x: u16, y: u16, w: u16, h: u16) -> Rect {
        Rect { x, y, w, h }
    }
    /// Left part `left` columns wide, right part the rest.
    pub fn split_h(&self, left: u16) -> (Rect, Rect) {
        let l = left.min(self.w);
        (Rect::new(self.x, self.y, l, self.h), Rect::new(self.x + l, self.y, self.w - l, self.h))
    }
    pub fn split_v(&self, top: u16) -> (Rect, Rect) {
        let t = top.min(self.h);
        (Rect::new(self.x, self.y, self.w, t), Rect::new(self.x, self.y + t, self.w, self.h - t))
    }
    pub fn inset(&self, n: u16) -> Rect {
        let n2 = n.saturating_mul(2);
        Rect::new(self.x + n.min(self.w), self.y + n.min(self.h), self.w.saturating_sub(n2), self.h.saturating_sub(n2))
    }
    pub fn centered(&self, w: u16, h: u16) -> Rect {
        let (w, h) = (w.min(self.w), h.min(self.h));
        Rect::new(self.x + (self.w - w) / 2, self.y + (self.h - h) / 2, w, h)
    }
}

/// Marker stored in the cell to the right of a double-width character. Never drawn.
pub const CONT: char = '\0';

#[derive(Clone, Debug)]
pub struct Buffer {
    w: u16,
    h: u16,
    cells: Vec<Cell>,
    ascii: bool,
}

impl Buffer {
    pub fn new(w: u16, h: u16) -> Buffer {
        Buffer { w, h, cells: vec![Cell::default(); w as usize * h as usize], ascii: false }
    }
    pub fn width(&self) -> u16 {
        self.w
    }
    pub fn height(&self) -> u16 {
        self.h
    }
    pub fn area(&self) -> Rect {
        Rect::new(0, 0, self.w, self.h)
    }
    /// Resize and clear (keeps the ASCII flag).
    pub fn resize(&mut self, w: u16, h: u16) {
        let a = self.ascii;
        *self = Buffer::new(w, h);
        self.ascii = a;
    }
    /// ASCII mode (serial console / `i7lab.ascii=1`): `put_str` turns every non-ASCII character into `?` and
    /// truncation uses `~` instead of an ellipsis character.
    pub fn set_ascii(&mut self, on: bool) {
        self.ascii = on;
    }
    pub fn is_ascii(&self) -> bool {
        self.ascii
    }
    /// The marker drawn where text was cut.
    pub fn ellipsis(&self) -> char {
        if self.ascii {
            '~'
        } else {
            '\u{2026}'
        }
    }
    pub fn clear(&mut self) {
        self.cells.fill(Cell::default());
    }
    pub fn get(&self, x: u16, y: u16) -> Option<&Cell> {
        (x < self.w && y < self.h).then(|| &self.cells[y as usize * self.w as usize + x as usize])
    }
    fn idx(&self, x: u16, y: u16) -> usize {
        y as usize * self.w as usize + x as usize
    }
    /// Store one cell. Overwriting half of a double-width character blanks the other half, so the screen
    /// never shows a torn glyph.
    pub fn set(&mut self, x: u16, y: u16, cell: Cell) {
        if x >= self.w || y >= self.h {
            return;
        }
        let i = self.idx(x, y);
        if self.cells[i].ch == CONT && x > 0 {
            let j = self.idx(x - 1, y);
            self.cells[j].ch = ' ';
        }
        if x + 1 < self.w && self.cells[i + 1].ch == CONT && cell.ch != CONT && crate::width::char_width(self.cells[i].ch) == 2 {
            self.cells[i + 1].ch = ' ';
        }
        self.cells[i] = cell;
    }
    /// Draw sanitised text clipped at the buffer edge; returns columns written. Wide characters take two
    /// cells; zero-width characters are dropped; a wide character that does not fit is not drawn.
    pub fn put_str(&mut self, x: u16, y: u16, s: &str, style: Style) -> u16 {
        let clean = self.clean(s);
        self.put_cells(x, y, self.w.saturating_sub(x) as usize, &clean, style)
    }
    /// Like `put_str` but confined to `maxw` columns; text that does not fit ends in the ellipsis marker.
    pub fn put_str_fit(&mut self, x: u16, y: u16, maxw: u16, s: &str, style: Style) -> u16 {
        let clean = self.clean(s);
        let room = (maxw as usize).min(self.w.saturating_sub(x) as usize);
        let fitted = crate::width::truncate(&clean, room, self.ellipsis());
        self.put_cells(x, y, room, &fitted, style)
    }
    /// The one place untrusted text is made safe: escape control / bidi / zero-width code points, then (ASCII
    /// mode) replace every non-ASCII character.
    fn clean(&self, s: &str) -> String {
        let t = labproto::text::sanitize(s);
        if self.ascii {
            t.chars().map(|c| if c.is_ascii() { c } else { '?' }).collect()
        } else {
            t.into_owned()
        }
    }
    /// Width in cells that `put_str` would use for `s` (after sanitising).
    pub fn text_width(&self, s: &str) -> usize {
        crate::width::str_width(&self.clean(s))
    }
    /// Sanitised text cut to `max` cells with the ellipsis marker.
    pub fn fit_text(&self, s: &str, max: usize) -> String {
        crate::width::truncate(&self.clean(s), max, self.ellipsis())
    }
    /// Place already-clean text.
    fn put_cells(&mut self, x: u16, y: u16, room: usize, clean: &str, style: Style) -> u16 {
        let mut used = 0usize;
        for ch in clean.chars() {
            let cw = crate::width::char_width(ch);
            if cw == 0 {
                continue;
            }
            if used + cw > room {
                break;
            }
            let cx = x as usize + used;
            if cx >= self.w as usize {
                break;
            }
            self.set(cx as u16, y, Cell { ch, fg: style.fg, bg: style.bg, attr: style.attr });
            if cw == 2 {
                self.set(cx as u16 + 1, y, Cell { ch: CONT, fg: style.fg, bg: style.bg, attr: style.attr });
            }
            used += cw;
        }
        used as u16
    }
    pub fn fill(&mut self, r: Rect, ch: char, style: Style) {
        for y in r.y..r.y.saturating_add(r.h).min(self.h) {
            for x in r.x..r.x.saturating_add(r.w).min(self.w) {
                self.set(x, y, Cell { ch, fg: style.fg, bg: style.bg, attr: style.attr });
            }
        }
    }
    /// Change only the style of the cells in `r` (keeps the characters).
    pub fn restyle(&mut self, r: Rect, style: Style) {
        for y in r.y..r.y.saturating_add(r.h).min(self.h) {
            for x in r.x..r.x.saturating_add(r.w).min(self.w) {
                let i = self.idx(x, y);
                let c = &mut self.cells[i];
                c.fg = style.fg;
                c.bg = style.bg;
                c.attr = style.attr;
            }
        }
    }
    /// Plain text dump (one line per row, trailing spaces trimmed) for golden tests.
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        for y in 0..self.h {
            let row: String = (0..self.w).filter_map(|x| self.get(x, y).map(|c| c.ch)).filter(|c| *c != CONT).collect();
            s.push_str(row.trim_end());
            s.push('\n');
        }
        s
    }
    /// One row of the dump as text (no trailing newline, trailing spaces kept), for assertions.
    pub fn row_text(&self, y: u16) -> String {
        (0..self.w).filter_map(|x| self.get(x, y).map(|c| c.ch)).filter(|c| *c != CONT).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn put_str_clips_and_sanitises() {
        let mut b = Buffer::new(10, 1);
        assert_eq!(b.put_str(7, 0, "abcdef", Style::default()), 3);
        b.put_str(0, 0, "\x1b", Style::default());
        assert_eq!(b.to_text(), "\\u{001b}bc\n");
    }
    #[test]
    fn wide_chars_take_two_cells() {
        let mut b = Buffer::new(6, 1);
        assert_eq!(b.put_str(0, 0, "a\u{4e2d}b", Style::default()), 4);
        assert_eq!(b.get(2, 0).unwrap().ch, CONT);
        assert_eq!(b.to_text(), "a\u{4e2d}b\n");
        // a wide char that does not fit at the edge is skipped
        let mut b = Buffer::new(3, 1);
        assert_eq!(b.put_str(2, 0, "\u{4e2d}", Style::default()), 0);
        // overwriting half of it blanks the other half
        let mut b = Buffer::new(4, 1);
        b.put_str(0, 0, "\u{4e2d}", Style::default());
        b.put_str(1, 0, "x", Style::default());
        assert_eq!(b.row_text(0), " x  ");
    }
    #[test]
    fn fit_adds_ellipsis_and_ascii_mode_replaces() {
        let mut b = Buffer::new(20, 1);
        assert_eq!(b.put_str_fit(0, 0, 5, "abcdefgh", Style::default()), 5);
        assert_eq!(b.row_text(0).trim_end(), "abcd\u{2026}");
        b.set_ascii(true);
        b.clear();
        b.put_str_fit(0, 0, 5, "abcdefgh", Style::default());
        b.put_str(8, 0, "\u{e9}\u{2500}", Style::default());
        assert_eq!(b.row_text(0).trim_end(), "abcd~   ??");
    }
    #[test]
    fn hostile_strings_are_inert() {
        let mut b = Buffer::new(40, 1);
        b.put_str(0, 0, "x\x1b[2J\x07\u{9b}31m", Style::default());
        assert!(b.row_text(0).chars().all(|c| c >= ' ' && c != '\x7f' && !('\u{80}'..='\u{9f}').contains(&c)));
    }
}
