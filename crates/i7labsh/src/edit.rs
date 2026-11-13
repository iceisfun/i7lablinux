//! Line editor: key decoder, edit buffer, history, tab completion. Pure; the terminal side is in `repl.rs`.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Enter,
    Backspace,
    Delete,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    Tab,
    /// ^C
    Interrupt,
    /// ^D
    Eof,
    /// ^L
    Clear,
    /// ^U
    KillLine,
    /// ^K
    KillToEnd,
    /// ^W
    KillWord,
}

/// Bytes -> keys. Handles UTF-8 and the CSI/SS3 sequences terminals send for arrows, Home/End, Delete.
#[derive(Default)]
pub struct KeyDecoder {
    state: St,
    params: Vec<u8>,
    utf: Vec<u8>,
    utf_left: usize,
}

#[derive(Default, PartialEq, Eq, Clone, Copy)]
enum St {
    #[default]
    Ground,
    Esc,
    Csi,
    Ss3,
    Utf8,
}

impl KeyDecoder {
    pub fn feed(&mut self, b: u8) -> Option<Key> {
        match self.state {
            St::Ground => self.ground(b),
            St::Esc => match b {
                b'[' => {
                    self.state = St::Csi;
                    self.params.clear();
                    None
                }
                b'O' => {
                    self.state = St::Ss3;
                    None
                }
                0x1b => None, // ESC ESC: stay
                _ => {
                    self.state = St::Ground;
                    self.ground(b) // a lone ESC followed by a key: drop the ESC
                }
            },
            St::Csi => match b {
                b'0'..=b'9' | b';' => {
                    if self.params.len() < 8 {
                        self.params.push(b);
                    }
                    None
                }
                0x40..=0x7e => {
                    self.state = St::Ground;
                    match (b, self.params.as_slice()) {
                        (b'A', _) => Some(Key::Up),
                        (b'B', _) => Some(Key::Down),
                        (b'C', _) => Some(Key::Right),
                        (b'D', _) => Some(Key::Left),
                        (b'H', _) => Some(Key::Home),
                        (b'F', _) => Some(Key::End),
                        (b'~', b"3") => Some(Key::Delete),
                        (b'~', b"1") | (b'~', b"7") => Some(Key::Home),
                        (b'~', b"4") | (b'~', b"8") => Some(Key::End),
                        _ => None,
                    }
                }
                _ => {
                    self.state = St::Ground;
                    None
                }
            },
            St::Ss3 => {
                self.state = St::Ground;
                match b {
                    b'A' => Some(Key::Up),
                    b'B' => Some(Key::Down),
                    b'C' => Some(Key::Right),
                    b'D' => Some(Key::Left),
                    b'H' => Some(Key::Home),
                    b'F' => Some(Key::End),
                    _ => None,
                }
            }
            St::Utf8 => {
                if b & 0xC0 != 0x80 {
                    self.state = St::Ground;
                    return self.ground(b);
                }
                self.utf.push(b);
                self.utf_left -= 1;
                if self.utf_left == 0 {
                    self.state = St::Ground;
                    return std::str::from_utf8(&self.utf).ok().and_then(|s| s.chars().next()).map(Key::Char);
                }
                None
            }
        }
    }

    fn ground(&mut self, b: u8) -> Option<Key> {
        match b {
            0x1b => {
                self.state = St::Esc;
                None
            }
            b'\r' | b'\n' => Some(Key::Enter),
            0x7f | 0x08 => Some(Key::Backspace),
            b'\t' => Some(Key::Tab),
            0x03 => Some(Key::Interrupt),
            0x04 => Some(Key::Eof),
            0x0c => Some(Key::Clear),
            0x15 => Some(Key::KillLine),
            0x0b => Some(Key::KillToEnd),
            0x17 => Some(Key::KillWord),
            0x01 => Some(Key::Home),
            0x05 => Some(Key::End),
            0x02 => Some(Key::Left),
            0x06 => Some(Key::Right),
            0x10 => Some(Key::Up),
            0x0e => Some(Key::Down),
            0x20..=0x7e => Some(Key::Char(b as char)),
            0xC2..=0xDF => self.start_utf(b, 1),
            0xE0..=0xEF => self.start_utf(b, 2),
            0xF0..=0xF4 => self.start_utf(b, 3),
            _ => None,
        }
    }

    fn start_utf(&mut self, b: u8, more: usize) -> Option<Key> {
        self.state = St::Utf8;
        self.utf.clear();
        self.utf.push(b);
        self.utf_left = more;
        None
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Edit {
    /// nothing visible changed
    None,
    Redraw,
    /// the line was accepted (already added to history when non-empty)
    Line(String),
    /// ^C: abandon the line
    Interrupt,
    /// ^D on an empty line
    Eof,
    /// ^L: clear the screen, then redraw
    Clear,
    /// Tab with several candidates: show them, then redraw
    Candidates(Vec<String>),
}

pub const HISTORY_MAX: usize = 200;

#[derive(Default)]
pub struct Editor {
    buf: Vec<char>,
    cur: usize,
    hist: Vec<String>,
    /// index into hist while browsing (hist.len() = the line being typed)
    pos: Option<usize>,
    saved: Vec<char>,
}

/// What the completer needs from the shell.
pub trait Completer {
    /// names of builtins and executables matching `prefix` (for the first word)
    fn commands(&self, prefix: &str) -> Vec<String>;
    /// entries of `dir` ("." when empty); directory entries carry a trailing '/'
    fn entries(&self, dir: &str) -> Vec<String>;
}

impl Editor {
    pub fn new() -> Editor {
        Editor::default()
    }

    pub fn text(&self) -> String {
        self.buf.iter().collect()
    }
    pub fn cursor(&self) -> usize {
        self.cur
    }
    pub fn len(&self) -> usize {
        self.buf.len()
    }
    pub fn history(&self) -> &[String] {
        &self.hist
    }
    pub fn reset(&mut self) {
        self.buf.clear();
        self.cur = 0;
        self.pos = None;
        self.saved.clear();
    }

    fn add_history(&mut self, line: &str) {
        if line.trim().is_empty() || self.hist.last().map(String::as_str) == Some(line) {
            return;
        }
        self.hist.push(line.to_string());
        if self.hist.len() > HISTORY_MAX {
            self.hist.remove(0);
        }
    }

    fn set_from(&mut self, s: &str) {
        self.buf = s.chars().collect();
        self.cur = self.buf.len();
    }

    pub fn feed(&mut self, key: Key, comp: &dyn Completer) -> Edit {
        match key {
            Key::Char(c) => {
                self.buf.insert(self.cur, c);
                self.cur += 1;
                Edit::Redraw
            }
            Key::Enter => {
                let line = self.text();
                self.add_history(&line);
                self.reset();
                Edit::Line(line)
            }
            Key::Backspace => {
                if self.cur > 0 {
                    self.cur -= 1;
                    self.buf.remove(self.cur);
                    Edit::Redraw
                } else {
                    Edit::None
                }
            }
            Key::Delete => {
                if self.cur < self.buf.len() {
                    self.buf.remove(self.cur);
                    Edit::Redraw
                } else {
                    Edit::None
                }
            }
            Key::Left => self.moved(self.cur.saturating_sub(1)),
            Key::Right => self.moved((self.cur + 1).min(self.buf.len())),
            Key::Home => self.moved(0),
            Key::End => self.moved(self.buf.len()),
            Key::Up => self.browse(true),
            Key::Down => self.browse(false),
            Key::Interrupt => {
                self.reset();
                Edit::Interrupt
            }
            Key::Eof => {
                if self.buf.is_empty() {
                    Edit::Eof
                } else if self.cur < self.buf.len() {
                    self.buf.remove(self.cur);
                    Edit::Redraw
                } else {
                    Edit::None
                }
            }
            Key::Clear => Edit::Clear,
            Key::KillLine => {
                self.buf.drain(..self.cur);
                self.cur = 0;
                Edit::Redraw
            }
            Key::KillToEnd => {
                self.buf.truncate(self.cur);
                Edit::Redraw
            }
            Key::KillWord => {
                let mut i = self.cur;
                while i > 0 && self.buf[i - 1] == ' ' {
                    i -= 1;
                }
                while i > 0 && self.buf[i - 1] != ' ' {
                    i -= 1;
                }
                self.buf.drain(i..self.cur);
                self.cur = i;
                Edit::Redraw
            }
            Key::Tab => self.complete(comp),
        }
    }

    fn moved(&mut self, to: usize) -> Edit {
        if to == self.cur {
            Edit::None
        } else {
            self.cur = to;
            Edit::Redraw
        }
    }

    fn browse(&mut self, up: bool) -> Edit {
        if self.hist.is_empty() {
            return Edit::None;
        }
        let n = self.hist.len();
        let next = match (self.pos, up) {
            (None, true) => {
                self.saved = self.buf.clone();
                n - 1
            }
            (None, false) => return Edit::None,
            (Some(0), true) => return Edit::None,
            (Some(p), true) => p - 1,
            (Some(p), false) => p + 1,
        };
        if next >= n {
            self.pos = None;
            self.buf = std::mem::take(&mut self.saved);
            self.cur = self.buf.len();
        } else {
            self.pos = Some(next);
            let h = self.hist[next].clone();
            self.set_from(&h);
        }
        Edit::Redraw
    }

    fn complete(&mut self, comp: &dyn Completer) -> Edit {
        let upto: String = self.buf[..self.cur].iter().collect();
        let start = upto.rfind(' ').map(|i| i + 1).unwrap_or(0);
        let word = &upto[start..];
        let first_word = upto[..start].trim().is_empty();
        let mut cands: Vec<String> = if first_word && !word.contains('/') {
            comp.commands(word)
        } else {
            let (dir, base) = match word.rfind('/') {
                Some(i) => (&word[..=i], &word[i + 1..]),
                None => ("", word),
            };
            comp.entries(dir).into_iter().filter(|e| e.starts_with(base) && (base.starts_with('.') || !e.starts_with('.'))).map(|e| format!("{dir}{e}")).collect()
        };
        cands.sort();
        cands.dedup();
        match cands.len() {
            0 => Edit::None,
            1 => {
                let c = &cands[0];
                let mut ins = c[word.len()..].to_string();
                if !c.ends_with('/') {
                    ins.push(' ');
                }
                self.insert_str(&ins);
                Edit::Redraw
            }
            _ => {
                let common = common_prefix(&cands);
                if common.len() > word.len() {
                    let ins = common[word.len()..].to_string();
                    self.insert_str(&ins);
                    Edit::Redraw
                } else {
                    Edit::Candidates(cands)
                }
            }
        }
    }

    fn insert_str(&mut self, s: &str) {
        for c in s.chars() {
            self.buf.insert(self.cur, c);
            self.cur += 1;
        }
    }

    /// Escape sequence that redraws the current line after the prompt: carriage return, prompt, text, erase to end of
    /// line, cursor back to its column. Single-row only: the terminal is assumed wide enough for the line.
    pub fn render(&self, prompt: &str) -> String {
        let mut s = String::new();
        s.push('\r');
        s.push_str(prompt);
        s.push_str(&self.text());
        s.push_str("\x1b[K");
        let back = self.buf.len() - self.cur;
        if back > 0 {
            s.push_str(&format!("\x1b[{}D", back));
        }
        s
    }
}

fn common_prefix(v: &[String]) -> String {
    let mut p = v[0].clone();
    for s in &v[1..] {
        let n = p.chars().zip(s.chars()).take_while(|(a, b)| a == b).count();
        p = p.chars().take(n).collect();
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake;
    impl Completer for Fake {
        fn commands(&self, prefix: &str) -> Vec<String> {
            ["ls", "lsblk", "lspci", "cat", "cd"].iter().filter(|c| c.starts_with(prefix)).map(|s| s.to_string()).collect()
        }
        fn entries(&self, dir: &str) -> Vec<String> {
            match dir {
                "" => vec!["notes.txt".into(), "nodes/".into(), ".git/".into()],
                "/etc/" => vec!["passwd".into(), "profile".into()],
                _ => vec![],
            }
        }
    }

    fn type_str(e: &mut Editor, s: &str) {
        for c in s.chars() {
            e.feed(Key::Char(c), &Fake);
        }
    }

    fn decode(bytes: &[u8]) -> Vec<Key> {
        let mut d = KeyDecoder::default();
        bytes.iter().filter_map(|&b| d.feed(b)).collect()
    }

    #[test]
    fn decoder_arrows_and_friends() {
        assert_eq!(decode(b"\x1b[A\x1b[B\x1b[C\x1b[D"), vec![Key::Up, Key::Down, Key::Right, Key::Left]);
        assert_eq!(decode(b"\x1bOH\x1bOF\x1b[3~\x1b[1~\x1b[4~"), vec![Key::Home, Key::End, Key::Delete, Key::Home, Key::End]);
        assert_eq!(decode(b"a\r\x7f\t\x03\x04"), vec![Key::Char('a'), Key::Enter, Key::Backspace, Key::Tab, Key::Interrupt, Key::Eof]);
        assert_eq!(decode("é€".as_bytes()), vec![Key::Char('é'), Key::Char('€')]);
        assert_eq!(decode(b"\x1b[1;5C"), vec![Key::Right]); // modifiers are ignored
        assert_eq!(decode(b"\x1b[2~").len(), 0); // unknown CSI is swallowed whole
        assert_eq!(decode(b"\x1bx"), vec![Key::Char('x')]); // lone ESC dropped
    }

    #[test]
    fn decoder_recovers_from_a_broken_utf8_sequence() {
        assert_eq!(decode(&[0xE2, 0x82, b'a']), vec![Key::Char('a')]);
    }

    #[test]
    fn typing_and_cursor_editing() {
        let mut e = Editor::new();
        type_str(&mut e, "helo");
        e.feed(Key::Left, &Fake);
        e.feed(Key::Char('l'), &Fake);
        assert_eq!(e.text(), "hello");
        assert_eq!(e.cursor(), 4);
        e.feed(Key::Home, &Fake);
        e.feed(Key::Delete, &Fake);
        assert_eq!(e.text(), "ello");
        e.feed(Key::End, &Fake);
        e.feed(Key::Backspace, &Fake);
        assert_eq!(e.text(), "ell");
        assert_eq!(e.feed(Key::Backspace, &Fake), Edit::Redraw);
    }

    #[test]
    fn backspace_at_start_is_a_noop() {
        let mut e = Editor::new();
        assert_eq!(e.feed(Key::Backspace, &Fake), Edit::None);
    }

    #[test]
    fn kill_keys() {
        let mut e = Editor::new();
        type_str(&mut e, "echo one two");
        e.feed(Key::KillWord, &Fake);
        assert_eq!(e.text(), "echo one ");
        e.feed(Key::Left, &Fake);
        e.feed(Key::Left, &Fake);
        e.feed(Key::KillToEnd, &Fake);
        assert_eq!(e.text(), "echo on");
        e.feed(Key::Left, &Fake);
        e.feed(Key::KillLine, &Fake);
        assert_eq!(e.text(), "n"); // killed everything before the cursor
        // ^D: deletes under the cursor when not empty, EOF when empty
        e.feed(Key::Home, &Fake);
        e.feed(Key::Eof, &Fake);
        assert_eq!(e.feed(Key::Eof, &Fake), Edit::Eof);
    }

    #[test]
    fn history_browse_and_restore() {
        let mut e = Editor::new();
        for l in ["one", "two", "two", "three"] {
            type_str(&mut e, l);
            assert_eq!(e.feed(Key::Enter, &Fake), Edit::Line(l.to_string()));
        }
        assert_eq!(e.history(), ["one", "two", "three"]); // consecutive duplicate dropped
        type_str(&mut e, "dra");
        e.feed(Key::Up, &Fake);
        assert_eq!(e.text(), "three");
        e.feed(Key::Up, &Fake);
        e.feed(Key::Up, &Fake);
        assert_eq!(e.text(), "one");
        assert_eq!(e.feed(Key::Up, &Fake), Edit::None); // at the oldest
        e.feed(Key::Down, &Fake);
        assert_eq!(e.text(), "two");
        e.feed(Key::Down, &Fake);
        e.feed(Key::Down, &Fake);
        assert_eq!(e.text(), "dra"); // the line being typed comes back
        assert_eq!(e.feed(Key::Down, &Fake), Edit::None);
    }

    #[test]
    fn blank_lines_are_not_remembered_and_history_is_bounded() {
        let mut e = Editor::new();
        e.feed(Key::Enter, &Fake);
        type_str(&mut e, "   ");
        e.feed(Key::Enter, &Fake);
        assert!(e.history().is_empty());
        for i in 0..HISTORY_MAX + 20 {
            type_str(&mut e, &format!("c{i}"));
            e.feed(Key::Enter, &Fake);
        }
        assert_eq!(e.history().len(), HISTORY_MAX);
        assert_eq!(e.history()[0], "c20");
    }

    #[test]
    fn interrupt_clears_the_line() {
        let mut e = Editor::new();
        type_str(&mut e, "abc");
        assert_eq!(e.feed(Key::Interrupt, &Fake), Edit::Interrupt);
        assert_eq!(e.text(), "");
    }

    #[test]
    fn completion_of_commands() {
        let mut e = Editor::new();
        type_str(&mut e, "ca");
        e.feed(Key::Tab, &Fake);
        assert_eq!(e.text(), "cat "); // unique: completed with a space
        e.reset();
        type_str(&mut e, "ls");
        // ls, lsblk, lspci share "ls": no progress, candidates are shown
        match e.feed(Key::Tab, &Fake) {
            Edit::Candidates(c) => assert_eq!(c, vec!["ls", "lsblk", "lspci"]),
            other => panic!("{other:?}"),
        }
        e.reset();
        type_str(&mut e, "lsb");
        e.feed(Key::Tab, &Fake);
        assert_eq!(e.text(), "lsblk ");
    }

    #[test]
    fn completion_of_paths_and_common_prefix() {
        let mut e = Editor::new();
        type_str(&mut e, "cat no");
        e.feed(Key::Tab, &Fake);
        assert_eq!(e.text(), "cat no"); // notes.txt and nodes/ share only "no": candidates shown, nothing inserted
        type_str(&mut e, "t");
        e.feed(Key::Tab, &Fake);
        assert_eq!(e.text(), "cat notes.txt ");
        e.reset();
        type_str(&mut e, "cat /etc/pa");
        e.feed(Key::Tab, &Fake);
        assert_eq!(e.text(), "cat /etc/passwd ");
        e.reset();
        type_str(&mut e, "cat no");
        e.feed(Key::Tab, &Fake);
        type_str(&mut e, "d");
        e.feed(Key::Tab, &Fake);
        assert_eq!(e.text(), "cat nodes/"); // directory: no trailing space
        e.reset();
        type_str(&mut e, "cat .");
        e.feed(Key::Tab, &Fake);
        assert_eq!(e.text(), "cat .git/"); // hidden entries only when asked
    }

    #[test]
    fn render_positions_the_cursor() {
        let mut e = Editor::new();
        type_str(&mut e, "abc");
        e.feed(Key::Left, &Fake);
        e.feed(Key::Left, &Fake);
        assert_eq!(e.render("# "), "\r# abc\x1b[K\x1b[2D");
        e.feed(Key::End, &Fake);
        assert_eq!(e.render("# "), "\r# abc\x1b[K");
    }
}
