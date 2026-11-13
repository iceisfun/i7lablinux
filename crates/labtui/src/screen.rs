//! Double-buffered screen with diff output (minimal CSI + SGR). Owner: P5.
//!
//! Draw into `buffer()`, call `present()`: the difference between the back and the front buffer is encoded as
//! cursor moves plus SGR changes and written with a single write(2). Colours are degraded to the terminal's
//! `ColorMode`. The Linux console and serial terminals get 16 colours and no alternate screen.

use std::io;

use crate::buffer::{Attr, Buffer, Cell, Color, CONT};
use crate::term::{self, RawTerm};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorMode {
    Mono,
    Ansi16,
    Idx256,
    TrueColor,
}

#[derive(Clone, Copy, Debug)]
pub struct Caps {
    pub color: ColorMode,
    /// box drawing glyphs available (false on serial / i7lab.ascii=1)
    pub unicode: bool,
    pub alt_screen: bool,
}

impl Caps {
    /// From $TERM and the tty name (ttyS* => ASCII, 16 colours).
    pub fn detect(term: Option<&str>, tty: &str) -> Caps {
        let serial = tty.contains("ttyS") || tty.contains("ttyUSB") || tty.contains("ttyAMA");
        match term {
            Some("dumb") => Caps { color: ColorMode::Mono, unicode: false, alt_screen: false },
            Some("linux") | None => Caps { color: ColorMode::Ansi16, unicode: !serial, alt_screen: false },
            Some(t) if serial && t.starts_with("vt") => Caps { color: ColorMode::Ansi16, unicode: false, alt_screen: false },
            Some(t) if t.contains("truecolor") || t.contains("direct") => Caps { color: ColorMode::TrueColor, unicode: !serial, alt_screen: true },
            _ => Caps { color: ColorMode::Idx256, unicode: !serial, alt_screen: true },
        }
    }
    /// Apply the kernel command line knobs: `i7lab.ascii=1` forces ASCII frames, `i7lab.mono=1` forces mono.
    pub fn with_overrides(mut self, ascii: bool, mono: bool) -> Caps {
        if ascii {
            self.unicode = false;
        }
        if mono {
            self.color = ColorMode::Mono;
        }
        self
    }
}

/// The 16 ANSI colours as RGB (xterm defaults), used to degrade 256 / true colour.
const ANSI_RGB: [(u8, u8, u8); 16] = [
    (0, 0, 0),
    (205, 0, 0),
    (0, 205, 0),
    (205, 205, 0),
    (0, 0, 238),
    (205, 0, 205),
    (0, 205, 205),
    (229, 229, 229),
    (127, 127, 127),
    (255, 0, 0),
    (0, 255, 0),
    (255, 255, 0),
    (92, 92, 255),
    (255, 0, 255),
    (0, 255, 255),
    (255, 255, 255),
];

/// RGB of a 256-colour index.
pub fn idx_to_rgb(i: u8) -> (u8, u8, u8) {
    match i {
        0..=15 => ANSI_RGB[i as usize],
        16..=231 => {
            let n = i - 16;
            let lv = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
            (lv(n / 36), lv((n / 6) % 6), lv(n % 6))
        }
        232..=255 => {
            let g = 8 + (i - 232) * 10;
            (g, g, g)
        }
    }
}

pub fn rgb_to_ansi16(r: u8, g: u8, b: u8) -> u8 {
    let d = |a: u8, b: u8| (a as i32 - b as i32).pow(2);
    (0..16u8)
        .min_by_key(|&i| {
            let (cr, cg, cb) = ANSI_RGB[i as usize];
            d(r, cr) + d(g, cg) + d(b, cb)
        })
        .unwrap_or(7)
}

pub fn rgb_to_256(r: u8, g: u8, b: u8) -> u8 {
    let cube = |v: u8| if v < 48 { 0 } else if v < 115 { 1 } else { (v - 35) / 40 };
    let (cr, cg, cb) = (cube(r), cube(g), cube(b));
    let cube_idx = 16 + 36 * cr + 6 * cg + cb;
    let grey_level = ((r as u32 + g as u32 + b as u32) / 3) as u8;
    let grey_idx = if grey_level < 8 { 16 } else if grey_level > 238 { 231 } else { 232 + (grey_level - 8) / 10 };
    let dist = |i: u8| {
        let (pr, pg, pb) = idx_to_rgb(i);
        (r as i32 - pr as i32).pow(2) + (g as i32 - pg as i32).pow(2) + (b as i32 - pb as i32).pow(2)
    };
    if dist(grey_idx) < dist(cube_idx) {
        grey_idx
    } else {
        cube_idx
    }
}

/// SGR parameter text for a colour (`fg` selects 30s/90s vs 40s/100s); None for Default or Mono.
fn color_params(c: Color, fg: bool, mode: ColorMode) -> Option<String> {
    if mode == ColorMode::Mono {
        return None;
    }
    let base = if fg { 30 } else { 40 };
    let ansi = |n: u8| -> String {
        if n < 8 {
            format!("{}", base + n as u32)
        } else {
            format!("{}", base + 60 + (n - 8) as u32)
        }
    };
    let ext = if fg { 38 } else { 48 };
    match c {
        Color::Default => None,
        Color::Ansi(n) => Some(ansi(n.min(15))),
        Color::Idx(n) => match mode {
            ColorMode::Ansi16 => {
                let (r, g, b) = idx_to_rgb(n);
                Some(ansi(rgb_to_ansi16(r, g, b)))
            }
            _ => Some(format!("{};5;{}", ext, n)),
        },
        Color::Rgb(r, g, b) => match mode {
            ColorMode::TrueColor => Some(format!("{};2;{};{};{}", ext, r, g, b)),
            ColorMode::Idx256 => Some(format!("{};5;{}", ext, rgb_to_256(r, g, b))),
            _ => Some(ansi(rgb_to_ansi16(r, g, b))),
        },
    }
}

/// Full SGR sequence selecting exactly this style (starts with a reset, so state never accumulates).
pub fn sgr(fg: Color, bg: Color, attr: Attr, mode: ColorMode) -> String {
    let mut p = vec!["0".to_string()];
    if attr.contains(Attr::BOLD) {
        p.push("1".into());
    }
    if attr.contains(Attr::DIM) {
        p.push("2".into());
    }
    if attr.contains(Attr::UNDERLINE) {
        p.push("4".into());
    }
    if attr.contains(Attr::REVERSE) {
        p.push("7".into());
    }
    p.extend(color_params(fg, true, mode));
    p.extend(color_params(bg, false, mode));
    format!("\x1b[{}m", p.join(";"))
}

/// Bytes sent once when the UI starts.
pub fn enter_sequence(caps: Caps) -> Vec<u8> {
    let mut v = Vec::new();
    if caps.alt_screen {
        v.extend_from_slice(b"\x1b[?1049h");
    }
    if caps.unicode {
        // select UTF-8 on the Linux console (harmless elsewhere)
        v.extend_from_slice(b"\x1b%G");
    }
    v.extend_from_slice(b"\x1b[?25l\x1b[?7l\x1b[0m\x1b[2J\x1b[H");
    v
}

pub struct Screen {
    front: Buffer,
    back: Buffer,
    caps: Caps,
    full: bool,
    fd: i32,
    /// fd < 0: nothing is written, `present` appends here (tests, `tui.dump`)
    sink: Vec<u8>,
}

impl Screen {
    pub fn new(term: &RawTerm, caps: Caps) -> Screen {
        let (w, h) = term.size();
        Screen::with_size(w, h, caps, term.fd())
    }
    /// A screen of a given size writing to `fd`, or capturing output when `fd < 0`.
    pub fn with_size(w: u16, h: u16, caps: Caps, fd: i32) -> Screen {
        let mut s = Screen { front: Buffer::new(w, h), back: Buffer::new(w, h), caps, full: true, fd, sink: Vec::new() };
        s.back.set_ascii(!caps.unicode);
        s.front.set_ascii(!caps.unicode);
        s
    }
    /// Capture-only screen for tests.
    pub fn headless(w: u16, h: u16, caps: Caps) -> Screen {
        Screen::with_size(w, h, caps, -1)
    }
    pub fn caps(&self) -> Caps {
        self.caps
    }
    pub fn size(&self) -> (u16, u16) {
        (self.back.width(), self.back.height())
    }
    /// Send the start-up sequence (alternate screen, hide cursor, wrap off) and mark the term accordingly.
    pub fn begin(&mut self, term: &mut RawTerm) -> io::Result<()> {
        term.set_alt_screen(self.caps.alt_screen);
        self.emit(&enter_sequence(self.caps))?;
        self.full = true;
        Ok(())
    }
    pub fn resize(&mut self, w: u16, h: u16) {
        self.front.resize(w, h);
        self.back.resize(w, h);
        self.full = true;
    }
    /// Draw here, then `present`. The buffer starts each frame as the previous frame's content; call
    /// `buffer().clear()` for a fresh frame.
    pub fn buffer(&mut self) -> &mut Buffer {
        &mut self.back
    }
    /// Captured bytes of a headless screen (drains them).
    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.sink)
    }
    fn emit(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.fd < 0 {
            self.sink.extend_from_slice(bytes);
            Ok(())
        } else {
            term::write_all(self.fd, bytes)
        }
    }

    /// Encode the difference between back and front as ANSI bytes (pure; used by `present` and tests).
    pub fn diff_bytes(&self) -> Vec<u8> {
        let mode = self.caps.color;
        let (w, h) = (self.back.width(), self.back.height());
        let mut out: Vec<u8> = Vec::new();
        if self.full {
            out.extend_from_slice(b"\x1b[0m\x1b[2J");
        }
        let mut cur: Option<(Color, Color, Attr)> = None;
        // cursor position the terminal is at after the last char we wrote (col, row), 0-based
        let mut cursor: Option<(u16, u16)> = None;
        for y in 0..h {
            let mut x = 0;
            while x < w {
                let b = *self.back.get(x, y).unwrap();
                if b.ch == CONT {
                    x += 1;
                    continue;
                }
                let changed = self.full && !is_blank(&b) || (!self.full && self.front.get(x, y) != Some(&b));
                // after a full clear the screen is blank in default colours: only draw what differs from that
                if !changed {
                    x += 1;
                    continue;
                }
                if cursor != Some((x, y)) {
                    out.extend_from_slice(format!("\x1b[{};{}H", y + 1, x + 1).as_bytes());
                }
                let style = (b.fg, b.bg, b.attr);
                if cur != Some(style) {
                    out.extend_from_slice(sgr(b.fg, b.bg, b.attr, mode).as_bytes());
                    cur = Some(style);
                }
                let mut tmp = [0u8; 4];
                out.extend_from_slice(b.ch.encode_utf8(&mut tmp).as_bytes());
                let cw = crate::width::char_width(b.ch).max(1) as u16;
                x += cw;
                cursor = Some((x, y));
            }
        }
        if cur.is_some() {
            out.extend_from_slice(b"\x1b[0m");
        }
        out
    }

    /// One write(2) per frame, then the back buffer becomes the front one.
    pub fn present(&mut self) -> io::Result<()> {
        let bytes = self.diff_bytes();
        if !bytes.is_empty() {
            self.emit(&bytes)?;
        }
        self.front.clone_from(&self.back);
        self.full = false;
        Ok(())
    }
    /// Force a full repaint on the next `present` (after resize, Ctrl-L, returning from a shell).
    pub fn invalidate(&mut self) {
        self.full = true;
    }
    /// Send the leave sequence (used when not going through RawTerm::restore).
    pub fn end(&mut self) -> io::Result<()> {
        self.emit(&term::leave_sequence(self.caps.alt_screen))
    }
}

fn is_blank(c: &Cell) -> bool {
    *c == Cell::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Style;

    fn caps(mode: ColorMode) -> Caps {
        Caps { color: mode, unicode: true, alt_screen: false }
    }
    fn s(fg: Color) -> Style {
        Style { fg, bg: Color::Default, attr: Attr::NONE }
    }

    #[test]
    fn caps_detection() {
        assert_eq!(Caps::detect(Some("linux"), "/dev/tty1").color, ColorMode::Ansi16);
        assert!(!Caps::detect(Some("linux"), "/dev/tty1").alt_screen);
        assert!(!Caps::detect(Some("linux"), "/dev/ttyS0").unicode);
        assert_eq!(Caps::detect(Some("xterm-256color"), "/dev/pts/0").color, ColorMode::Idx256);
        assert_eq!(Caps::detect(Some("dumb"), "x").color, ColorMode::Mono);
        assert!(!Caps::detect(Some("linux"), "/dev/tty1").with_overrides(true, false).unicode);
        assert_eq!(Caps::detect(Some("linux"), "/dev/tty1").with_overrides(false, true).color, ColorMode::Mono);
    }

    #[test]
    fn sgr_by_mode() {
        assert_eq!(sgr(Color::Ansi(1), Color::Ansi(12), Attr::BOLD, ColorMode::Ansi16), "\x1b[0;1;31;104m");
        assert_eq!(sgr(Color::Idx(196), Color::Default, Attr::NONE, ColorMode::Idx256), "\x1b[0;38;5;196m");
        assert_eq!(sgr(Color::Rgb(1, 2, 3), Color::Rgb(4, 5, 6), Attr::REVERSE, ColorMode::TrueColor), "\x1b[0;7;38;2;1;2;3;48;2;4;5;6m");
        assert_eq!(sgr(Color::Ansi(1), Color::Ansi(2), Attr::BOLD | Attr::UNDERLINE, ColorMode::Mono), "\x1b[0;1;4m");
        // degradation
        assert_eq!(sgr(Color::Idx(196), Color::Default, Attr::NONE, ColorMode::Ansi16), "\x1b[0;91m");
        assert_eq!(sgr(Color::Rgb(255, 0, 0), Color::Default, Attr::NONE, ColorMode::Ansi16), "\x1b[0;91m");
        assert!(sgr(Color::Rgb(255, 0, 0), Color::Default, Attr::NONE, ColorMode::Idx256).contains("38;5;196"));
    }

    #[test]
    fn rgb_mapping() {
        assert_eq!(rgb_to_256(255, 0, 0), 196);
        assert_eq!(rgb_to_256(0, 0, 0), 16);
        assert_eq!(idx_to_rgb(16), (0, 0, 0));
        assert_eq!(idx_to_rgb(231), (255, 255, 255));
        assert_eq!(rgb_to_ansi16(0, 0, 0), 0);
    }

    #[test]
    fn first_frame_clears_then_only_changes() {
        let mut sc = Screen::headless(10, 3, caps(ColorMode::Ansi16));
        sc.buffer().put_str(2, 1, "hi", s(Color::Ansi(2)));
        sc.present().unwrap();
        let first = String::from_utf8(sc.take_output()).unwrap();
        assert!(first.starts_with("\x1b[0m\x1b[2J"));
        assert!(first.contains("\x1b[2;3H"));
        assert!(first.contains("\x1b[0;32mhi"));
        // identical frame: nothing to send
        sc.present().unwrap();
        assert!(sc.take_output().is_empty());
        // change one cell: one move, no clear, one char
        sc.buffer().put_str(3, 1, "o", s(Color::Ansi(2)));
        sc.present().unwrap();
        let d = String::from_utf8(sc.take_output()).unwrap();
        assert_eq!(d, "\x1b[2;4H\x1b[0;32mo\x1b[0m");
    }

    #[test]
    fn adjacent_changes_share_one_move_and_sgr() {
        let mut sc = Screen::headless(20, 2, caps(ColorMode::Ansi16));
        sc.present().unwrap();
        sc.take_output();
        sc.buffer().put_str(0, 0, "abc", s(Color::Ansi(1)));
        sc.buffer().put_str(3, 0, "def", s(Color::Ansi(4)));
        sc.present().unwrap();
        let d = String::from_utf8(sc.take_output()).unwrap();
        assert_eq!(d.matches("H").count(), 1);
        assert_eq!(d, "\x1b[1;1H\x1b[0;31mabc\x1b[0;34mdef\x1b[0m");
    }

    #[test]
    fn invalidate_repaints_everything() {
        let mut sc = Screen::headless(6, 1, caps(ColorMode::Mono));
        sc.buffer().put_str(0, 0, "abc", Style::default());
        sc.present().unwrap();
        sc.take_output();
        sc.invalidate();
        sc.present().unwrap();
        let d = String::from_utf8(sc.take_output()).unwrap();
        assert!(d.starts_with("\x1b[0m\x1b[2J"));
        assert!(d.contains("abc"));
    }

    #[test]
    fn wide_char_is_written_once() {
        let mut sc = Screen::headless(6, 1, caps(ColorMode::Mono));
        sc.buffer().put_str(0, 0, "\u{4e2d}x", Style::default());
        sc.present().unwrap();
        let d = String::from_utf8(sc.take_output()).unwrap();
        assert!(d.contains("\u{4e2d}x"));
        assert!(!d.contains('\0'));
    }

    #[test]
    fn mono_mode_has_no_colour_codes() {
        let mut sc = Screen::headless(6, 1, caps(ColorMode::Mono));
        sc.buffer().put_str(0, 0, "a", Style { fg: Color::Ansi(1), bg: Color::Ansi(2), attr: Attr::REVERSE });
        sc.present().unwrap();
        let d = String::from_utf8(sc.take_output()).unwrap();
        assert!(d.contains("\x1b[0;7ma"));
        assert!(!d.contains(";31") && !d.contains(";42"));
    }
}
