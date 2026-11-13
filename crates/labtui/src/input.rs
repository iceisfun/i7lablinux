//! Key decoder: pure byte-at-a-time state machine (xterm + Linux console sequences, UTF-8). Owner: P5.
//!
//! Handled: CSI `ESC[A..D`, `ESC[H/F`, `ESC[Z`, modified forms `ESC[1;5C`, tilde keys `ESC[3~` .. `ESC[34~`,
//! xterm `ESC O P..S` (F1-F4, also application cursor mode `ESC O A..D`), Linux console `ESC[[A..E` (F1-F5),
//! cursor position reports `ESC[r;cR` (-> `Key::CursorReport`, used for the serial size query) and UTF-8.
//! A lone ESC is told apart from a sequence by the caller: when no byte follows within ~50 ms it calls
//! `flush_escape`.

use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Ctrl(char),
    Enter,
    Tab,
    BackTab,
    Backspace,
    Esc,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PgUp,
    PgDn,
    Insert,
    Delete,
    F(u8),
    /// Answer to `term::size_query()`: (rows, cols). A report with row 1 is read as modified F3 instead.
    CursorReport(u16, u16),
}

#[derive(Debug)]
enum State {
    Ground,
    Esc,
    Ss3,
    Csi(Vec<u8>),
    /// ESC [ [ : next byte A..E is F1..F5 on the Linux console
    LinuxFn,
    Utf8 { buf: Vec<u8>, need: usize },
}

pub struct Decoder {
    state: State,
    extra: VecDeque<Key>,
}

impl Default for Decoder {
    fn default() -> Self {
        Decoder { state: State::Ground, extra: VecDeque::new() }
    }
}

const MAX_CSI: usize = 24;

impl Decoder {
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// True while an escape sequence is half-received (the caller then waits ~50 ms before `flush_escape`).
    pub fn has_pending(&self) -> bool {
        !matches!(self.state, State::Ground)
    }

    /// Feed one byte; returns a key when a sequence completes. Rarely one byte completes two keys (ESC followed
    /// by a plain key): the second is queued and returned by `pop_extra` / the next `feed`. Prefer `feed_all`.
    pub fn feed(&mut self, b: u8) -> Option<Key> {
        let mut out = Vec::new();
        self.step(b, &mut out);
        let mut it = out.into_iter();
        let first = it.next();
        self.extra.extend(it);
        match first {
            Some(k) => Some(k),
            None => self.extra.pop_front(),
        }
    }

    pub fn pop_extra(&mut self) -> Option<Key> {
        self.extra.pop_front()
    }

    /// Feed many bytes, collect every completed key.
    pub fn feed_all(&mut self, bytes: &[u8]) -> Vec<Key> {
        let mut out: Vec<Key> = self.extra.drain(..).collect();
        for &b in bytes {
            self.step(b, &mut out);
        }
        out
    }

    fn step(&mut self, b: u8, out: &mut Vec<Key>) {
        let st = std::mem::replace(&mut self.state, State::Ground);
        match st {
            State::Ground => self.ground(b, out),
            State::Esc => match b {
                b'[' => self.state = State::Csi(Vec::new()),
                b'O' => self.state = State::Ss3,
                0x1b => {
                    // ESC ESC: first is a lone Escape, the second starts again
                    out.push(Key::Esc);
                    self.state = State::Esc;
                }
                _ => {
                    out.push(Key::Esc);
                    self.ground(b, out);
                }
            },
            State::Ss3 => {
                let k = match b {
                    b'P'..=b'S' => Some(Key::F(b - b'P' + 1)),
                    b'A' => Some(Key::Up),
                    b'B' => Some(Key::Down),
                    b'C' => Some(Key::Right),
                    b'D' => Some(Key::Left),
                    b'H' => Some(Key::Home),
                    b'F' => Some(Key::End),
                    b'M' => Some(Key::Enter),
                    0x1b => {
                        self.state = State::Esc;
                        None
                    }
                    _ => None,
                };
                out.extend(k);
            }
            State::LinuxFn => {
                if let b'A'..=b'E' = b {
                    out.push(Key::F(b - b'A' + 1));
                } else if b == 0x1b {
                    self.state = State::Esc;
                }
            }
            State::Csi(mut buf) => {
                if b == 0x1b {
                    self.state = State::Esc;
                } else if buf.is_empty() && b == b'[' {
                    self.state = State::LinuxFn;
                } else if (0x20..=0x3f).contains(&b) {
                    // parameter / intermediate bytes
                    if buf.len() < MAX_CSI {
                        buf.push(b);
                        self.state = State::Csi(buf);
                    } // else: overlong, drop the whole sequence silently
                } else if (0x40..=0x7e).contains(&b) {
                    out.extend(csi_key(&buf, b));
                }
                // any other byte aborts the sequence
            }
            State::Utf8 { mut buf, need } => {
                if (0x80..0xc0).contains(&b) {
                    buf.push(b);
                    if buf.len() == need {
                        let c = std::str::from_utf8(&buf).ok().and_then(|s| s.chars().next()).unwrap_or('\u{fffd}');
                        out.push(Key::Char(c));
                    } else {
                        self.state = State::Utf8 { buf, need };
                    }
                } else {
                    out.push(Key::Char('\u{fffd}'));
                    self.ground(b, out);
                }
            }
        }
    }

    fn ground(&mut self, b: u8, out: &mut Vec<Key>) {
        match b {
            0x1b => self.state = State::Esc,
            b'\r' | b'\n' => out.push(Key::Enter),
            b'\t' => out.push(Key::Tab),
            0x7f | 0x08 => out.push(Key::Backspace),
            1..=26 => out.push(Key::Ctrl((b'a' + b - 1) as char)),
            0x20..=0x7e => out.push(Key::Char(b as char)),
            0xc2..=0xdf => self.state = State::Utf8 { buf: vec![b], need: 2 },
            0xe0..=0xef => self.state = State::Utf8 { buf: vec![b], need: 3 },
            0xf0..=0xf4 => self.state = State::Utf8 { buf: vec![b], need: 4 },
            0x80..=0xff => out.push(Key::Char('\u{fffd}')),
            _ => {}
        }
    }

    /// Called when no byte followed within ~50 ms: a lone ESC is the Escape key; a half sequence is dropped.
    pub fn flush_escape(&mut self) -> Option<Key> {
        let was_esc = matches!(self.state, State::Esc);
        self.state = State::Ground;
        was_esc.then_some(Key::Esc)
    }
}

/// Parse `n;m` style parameters (empty fields = None).
fn params(buf: &[u8]) -> Vec<Option<u32>> {
    let s: String = buf.iter().filter(|b| b.is_ascii_digit() || **b == b';').map(|b| *b as char).collect();
    if s.is_empty() {
        return Vec::new();
    }
    s.split(';').map(|p| p.parse().ok()).collect()
}

fn csi_key(buf: &[u8], fin: u8) -> Option<Key> {
    let p = params(buf);
    let p0 = p.first().copied().flatten();
    match fin {
        b'A' => Some(Key::Up),
        b'B' => Some(Key::Down),
        b'C' => Some(Key::Right),
        b'D' => Some(Key::Left),
        b'H' => Some(Key::Home),
        b'F' => Some(Key::End),
        b'Z' => Some(Key::BackTab),
        b'P' | b'Q' | b'S' => Some(Key::F(fin - b'P' + 1)),
        b'R' => match (p0, p.get(1).copied().flatten()) {
            // ESC[1;<mod>R is modified F3; any other row is a cursor position report
            (Some(1), _) | (None, _) => Some(Key::F(3)),
            (Some(r), Some(c)) => Some(Key::CursorReport(r.min(u16::MAX as u32) as u16, c.min(u16::MAX as u32) as u16)),
            _ => None,
        },
        b'~' => match p0? {
            1 | 7 => Some(Key::Home),
            2 => Some(Key::Insert),
            3 => Some(Key::Delete),
            4 | 8 => Some(Key::End),
            5 => Some(Key::PgUp),
            6 => Some(Key::PgDn),
            n @ 11..=15 => Some(Key::F((n - 10) as u8)),
            n @ 17..=21 => Some(Key::F((n - 11) as u8)),
            n @ 23..=26 => Some(Key::F((n - 12) as u8)),
            n @ 28..=29 => Some(Key::F((n - 13) as u8)),
            n @ 31..=34 => Some(Key::F((n - 14) as u8)),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn feed(s: &[u8]) -> Vec<Key> {
        Decoder::new().feed_all(s)
    }
    #[test]
    fn arrows_tab_f1() {
        assert_eq!(feed(b"\x1b[A\x1b[Z\tq\x1bOP"), vec![Key::Up, Key::BackTab, Key::Tab, Key::Char('q'), Key::F(1)]);
        let mut d = Decoder::new();
        assert_eq!(d.feed(0x1b), None);
        assert!(d.has_pending());
        assert_eq!(d.flush_escape(), Some(Key::Esc));
        assert!(!d.has_pending());
    }
    #[test]
    fn xterm_and_application_cursor() {
        assert_eq!(feed(b"\x1bOA\x1bOB\x1bOC\x1bOD\x1bOH\x1bOF"), vec![Key::Up, Key::Down, Key::Right, Key::Left, Key::Home, Key::End]);
        assert_eq!(feed(b"\x1bOP\x1bOQ\x1bOR\x1bOS"), vec![Key::F(1), Key::F(2), Key::F(3), Key::F(4)]);
    }
    #[test]
    fn modifiers_are_accepted() {
        assert_eq!(feed(b"\x1b[1;5C\x1b[1;2A\x1b[1;3D"), vec![Key::Right, Key::Up, Key::Left]);
        assert_eq!(feed(b"\x1b[1;2P"), vec![Key::F(1)]);
        assert_eq!(feed(b"\x1b[1;5R"), vec![Key::F(3)]);
    }
    #[test]
    fn tilde_keys_and_function_keys() {
        assert_eq!(
            feed(b"\x1b[1~\x1b[2~\x1b[3~\x1b[4~\x1b[5~\x1b[6~"),
            vec![Key::Home, Key::Insert, Key::Delete, Key::End, Key::PgUp, Key::PgDn]
        );
        assert_eq!(feed(b"\x1b[15~\x1b[17~\x1b[21~\x1b[24~"), vec![Key::F(5), Key::F(6), Key::F(10), Key::F(12)]);
        assert_eq!(feed(b"\x1b[11~\x1b[14~"), vec![Key::F(1), Key::F(4)]);
    }
    #[test]
    fn linux_console_function_keys() {
        assert_eq!(feed(b"\x1b[[A\x1b[[B\x1b[[E"), vec![Key::F(1), Key::F(2), Key::F(5)]);
    }
    #[test]
    fn controls_and_text() {
        assert_eq!(feed(b"\r\n\x7f\x03\x0c"), vec![Key::Enter, Key::Enter, Key::Backspace, Key::Ctrl('c'), Key::Ctrl('l')]);
        assert_eq!(feed("é中😀".as_bytes()), vec![Key::Char('é'), Key::Char('中'), Key::Char('😀')]);
    }
    #[test]
    fn invalid_utf8_and_garbage_do_not_wedge() {
        assert_eq!(feed(b"\xc3a"), vec![Key::Char('\u{fffd}'), Key::Char('a')]);
        assert_eq!(feed(b"\xffx"), vec![Key::Char('\u{fffd}'), Key::Char('x')]);
        // overlong CSI is dropped; decoder returns to normal
        let mut v = b"\x1b[".to_vec();
        v.extend(std::iter::repeat(b'1').take(100));
        v.push(b'~');
        v.extend_from_slice(b"q");
        let mut d = Decoder::new();
        let keys = d.feed_all(&v);
        assert!(keys.contains(&Key::Char('q')));
        assert!(!d.has_pending());
    }
    #[test]
    fn esc_followed_by_key_gives_both() {
        assert_eq!(feed(b"\x1bx"), vec![Key::Esc, Key::Char('x')]);
        assert_eq!(feed(b"\x1b\x1b[A"), vec![Key::Esc, Key::Up]);
        let mut d = Decoder::new();
        d.feed(0x1b);
        assert_eq!(d.feed(b'x'), Some(Key::Esc));
        assert_eq!(d.pop_extra(), Some(Key::Char('x')));
    }
    #[test]
    fn cursor_report() {
        assert_eq!(feed(b"\x1b[43;132R"), vec![Key::CursorReport(43, 132)]);
    }
    #[test]
    fn byte_at_a_time_matches_bulk() {
        let s = b"\x1b[1;5C\x1b[15~a\x1bOP";
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for &b in s.iter() {
            got.extend(d.feed(b));
            got.extend(d.pop_extra());
        }
        assert_eq!(got, feed(s));
    }
}
