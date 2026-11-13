//! Shell grammar. Pure.
//!
//! ```text
//! list     := and_or ( (';' | NEWLINE) and_or )*
//! and_or   := pipeline ( ('&&' | '||') pipeline )*
//! pipeline := command ( '|' command )*
//! command  := ( NAME=word )* word* with redirections  <f  >f  >>f  N>f  N>>f  N<f  N>&M  anywhere among the words
//! word     := unquoted text, 'single', "double" (\" \\ \$ \` escapes), \x, $VAR ${VAR} $? $$
//! ```
//! Not supported (a clear ParseError, never silently ignored): background `&`, subshells `( )`, command
//! substitution `$( )` and backticks, `if/for/while`, here-documents, arithmetic.

use std::fmt;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn err<T>(m: &str) -> Result<T, ParseError> {
    Err(ParseError(m.to_string()))
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Seg {
    Lit { s: String, quoted: bool },
    Var { name: String, quoted: bool },
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Word(pub Vec<Seg>);

impl Word {
    /// A word made of one unquoted-or-quoted literal (tests, internal use).
    pub fn lit(s: &str) -> Word {
        Word(vec![Seg::Lit { s: s.to_string(), quoted: false }])
    }
    /// The literal text when the word has no variables (for assignment/redirect checks and tests).
    pub fn as_lit(&self) -> Option<String> {
        let mut out = String::new();
        for s in &self.0 {
            match s {
                Seg::Lit { s, .. } => out.push_str(s),
                Seg::Var { .. } => return None,
            }
        }
        Some(out)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RedirOp {
    In,
    Out,
    Append,
    /// `N>&M`: duplicate fd M onto N
    Dup,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Redir {
    pub fd: i32,
    pub op: RedirOp,
    pub target: Word,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Command {
    pub assigns: Vec<(String, Word)>,
    pub words: Vec<Word>,
    pub redirs: Vec<Redir>,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Pipeline {
    pub cmds: Vec<Command>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Conn {
    Seq,
    And,
    Or,
}

/// A whole input: pipelines with the connector that PRECEDES each (the first is always Seq).
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct List {
    pub items: Vec<(Conn, Pipeline)>,
}

// ---------------------------------------------------------------- lexer

#[derive(Debug, PartialEq, Eq, Clone)]
enum Tok {
    Word(Word),
    Pipe,
    And,
    Or,
    Semi,
    Newline,
    Redir { fd: Option<i32>, op: RedirOp },
}

pub fn is_name(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(ch) if ch.is_ascii_alphabetic() || ch == '_') && c.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

struct WordBuf {
    segs: Vec<Seg>,
    /// any quote seen (so `""` is a real empty word)
    touched: bool,
}

impl WordBuf {
    fn new() -> WordBuf {
        WordBuf { segs: Vec::new(), touched: false }
    }
    fn push_lit(&mut self, c: char, quoted: bool) {
        self.touched = true;
        if let Some(Seg::Lit { s, quoted: q }) = self.segs.last_mut() {
            if *q == quoted {
                s.push(c);
                return;
            }
        }
        self.segs.push(Seg::Lit { s: c.to_string(), quoted });
    }
    fn push_var(&mut self, name: String, quoted: bool) {
        self.touched = true;
        // drop the placeholder `open_quote` left for an otherwise empty quoted word
        if matches!(self.segs.last(), Some(Seg::Lit { s, quoted: true }) if s.is_empty()) {
            self.segs.pop();
        }
        self.segs.push(Seg::Var { name, quoted });
    }
    fn is_empty(&self) -> bool {
        !self.touched
    }
    /// A quote opens: the word exists even if it stays empty (`""`).
    fn open_quote(&mut self) {
        self.touched = true;
        if self.segs.is_empty() {
            self.segs.push(Seg::Lit { s: String::new(), quoted: true });
        }
    }
    /// If the buffer is a plain unquoted number, take it as an fd.
    fn as_fd(&self) -> Option<i32> {
        match self.segs.as_slice() {
            [Seg::Lit { s, quoted: false }] if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && s.len() <= 2 => s.parse().ok(),
            _ => None,
        }
    }
    fn take(&mut self) -> Word {
        self.touched = false;
        Word(std::mem::take(&mut self.segs))
    }
}

fn flush(toks: &mut Vec<Tok>, w: &mut WordBuf) {
    if !w.is_empty() {
        toks.push(Tok::Word(w.take()));
    }
}

/// Parse `$` at `chars[i]` (which is the '$'). Returns the variable name and the index after it, or None for a
/// literal `$`.
fn dollar(chars: &[char], i: usize) -> Result<Option<(String, usize)>, ParseError> {
    match chars.get(i + 1) {
        Some('(') => err("command substitution $( ) is not supported"),
        Some('{') => {
            let mut j = i + 2;
            let mut name = String::new();
            while let Some(&c) = chars.get(j) {
                if c == '}' {
                    return if is_name(&name) || name == "?" { Ok(Some((name, j + 1))) } else { err("bad ${...} substitution") };
                }
                name.push(c);
                j += 1;
            }
            err("unterminated ${")
        }
        Some(&c) if c == '?' || c == '$' => Ok(Some((c.to_string(), i + 2))),
        Some(&c) if c.is_ascii_alphabetic() || c == '_' => {
            let mut j = i + 1;
            let mut name = String::new();
            while let Some(&c) = chars.get(j) {
                if c.is_ascii_alphanumeric() || c == '_' {
                    name.push(c);
                    j += 1;
                } else {
                    break;
                }
            }
            Ok(Some((name, j)))
        }
        _ => Ok(None),
    }
}

fn lex(input: &str) -> Result<Vec<Tok>, ParseError> {
    let chars: Vec<char> = input.chars().collect();
    let mut toks = Vec::new();
    let mut w = WordBuf::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' | '\r' => {
                flush(&mut toks, &mut w);
                i += 1;
            }
            '\n' => {
                flush(&mut toks, &mut w);
                toks.push(Tok::Newline);
                i += 1;
            }
            '#' if w.is_empty() => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '|' => {
                flush(&mut toks, &mut w);
                if chars.get(i + 1) == Some(&'|') {
                    toks.push(Tok::Or);
                    i += 2;
                } else {
                    toks.push(Tok::Pipe);
                    i += 1;
                }
            }
            '&' => {
                if chars.get(i + 1) == Some(&'&') {
                    flush(&mut toks, &mut w);
                    toks.push(Tok::And);
                    i += 2;
                } else {
                    return err("background jobs (&) are not supported");
                }
            }
            ';' => {
                if chars.get(i + 1) == Some(&';') {
                    return err("';;' is not supported");
                }
                flush(&mut toks, &mut w);
                toks.push(Tok::Semi);
                i += 1;
            }
            '<' | '>' => {
                let fd = w.as_fd();
                if fd.is_some() {
                    w.take();
                } else {
                    flush(&mut toks, &mut w);
                }
                let op;
                if c == '<' {
                    if chars.get(i + 1) == Some(&'<') {
                        return err("here-documents (<<) are not supported");
                    }
                    if chars.get(i + 1) == Some(&'&') {
                        return err("'<&' is not supported");
                    }
                    op = RedirOp::In;
                    i += 1;
                } else if chars.get(i + 1) == Some(&'>') {
                    op = RedirOp::Append;
                    i += 2;
                } else if chars.get(i + 1) == Some(&'&') {
                    op = RedirOp::Dup;
                    i += 2;
                } else {
                    op = RedirOp::Out;
                    i += 1;
                }
                toks.push(Tok::Redir { fd, op });
            }
            '(' | ')' => return err("subshells ( ) are not supported"),
            '`' => return err("backtick command substitution is not supported"),
            '\'' => {
                i += 1;
                w.open_quote();
                loop {
                    match chars.get(i) {
                        None => return err("unterminated single quote"),
                        Some('\'') => {
                            i += 1;
                            break;
                        }
                        Some(&ch) => {
                            w.push_lit(ch, true);
                            i += 1;
                        }
                    }
                }
            }
            '"' => {
                i += 1;
                w.open_quote();
                loop {
                    match chars.get(i) {
                        None => return err("unterminated double quote"),
                        Some('"') => {
                            i += 1;
                            break;
                        }
                        Some('\\') => match chars.get(i + 1) {
                            Some(&n @ ('"' | '\\' | '$' | '`')) => {
                                w.push_lit(n, true);
                                i += 2;
                            }
                            Some('\n') => i += 2,
                            _ => {
                                w.push_lit('\\', true);
                                i += 1;
                            }
                        },
                        Some('`') => return err("backtick command substitution is not supported"),
                        Some('$') => match dollar(&chars, i)? {
                            Some((name, next)) => {
                                w.push_var(name, true);
                                i = next;
                            }
                            None => {
                                w.push_lit('$', true);
                                i += 1;
                            }
                        },
                        Some(&ch) => {
                            w.push_lit(ch, true);
                            i += 1;
                        }
                    }
                }
            }
            '\\' => match chars.get(i + 1) {
                None => return err("trailing backslash"),
                Some('\n') => i += 2,
                Some(&n) => {
                    w.push_lit(n, true);
                    i += 2;
                }
            },
            '$' => match dollar(&chars, i)? {
                Some((name, next)) => {
                    w.push_var(name, false);
                    i = next;
                }
                None => {
                    w.push_lit('$', false);
                    i += 1;
                }
            },
            _ => {
                w.push_lit(c, false);
                i += 1;
            }
        }
    }
    flush(&mut toks, &mut w);
    Ok(toks)
}

// ---------------------------------------------------------------- parser

/// `NAME=value` as the first segment of a word: (name, remainder word).
fn split_assign(w: &Word) -> Option<(String, Word)> {
    let Some(Seg::Lit { s, quoted: false }) = w.0.first() else { return None };
    let (name, rest) = s.split_once('=')?;
    if !is_name(name) {
        return None;
    }
    let mut segs = Vec::new();
    if !rest.is_empty() {
        segs.push(Seg::Lit { s: rest.to_string(), quoted: false });
    }
    segs.extend(w.0[1..].iter().cloned());
    Some((name.to_string(), Word(segs)))
}

pub fn parse(input: &str) -> Result<List, ParseError> {
    let toks = lex(input)?;
    let mut list = List::default();
    let mut conn = Conn::Seq;
    let mut i = 0;
    loop {
        while matches!(toks.get(i), Some(Tok::Semi | Tok::Newline)) {
            i += 1;
        }
        if i >= toks.len() {
            break;
        }
        let (p, next) = parse_pipeline(&toks, i)?;
        list.items.push((conn, p));
        i = next;
        match toks.get(i) {
            None => break,
            Some(Tok::Semi | Tok::Newline) => {
                conn = Conn::Seq;
                i += 1;
            }
            Some(Tok::And) => {
                conn = Conn::And;
                i += 1;
                if matches!(toks.get(i), None | Some(Tok::Semi | Tok::Newline)) {
                    return err("'&&' needs a command after it");
                }
            }
            Some(Tok::Or) => {
                conn = Conn::Or;
                i += 1;
                if matches!(toks.get(i), None | Some(Tok::Semi | Tok::Newline)) {
                    return err("'||' needs a command after it");
                }
            }
            Some(t) => return Err(ParseError(format!("unexpected {:?}", t))),
        }
    }
    Ok(list)
}

fn parse_pipeline(toks: &[Tok], mut i: usize) -> Result<(Pipeline, usize), ParseError> {
    let mut p = Pipeline::default();
    loop {
        let (c, next) = parse_command(toks, i)?;
        p.cmds.push(c);
        i = next;
        if toks.get(i) == Some(&Tok::Pipe) {
            i += 1;
            if matches!(toks.get(i), None | Some(Tok::Semi | Tok::Newline | Tok::And | Tok::Or)) {
                return err("'|' needs a command after it");
            }
        } else {
            return Ok((p, i));
        }
    }
}

fn parse_command(toks: &[Tok], mut i: usize) -> Result<(Command, usize), ParseError> {
    let mut c = Command::default();
    loop {
        match toks.get(i) {
            Some(Tok::Word(w)) => {
                if c.words.is_empty() {
                    if let Some((n, v)) = split_assign(w) {
                        c.assigns.push((n, v));
                        i += 1;
                        continue;
                    }
                }
                c.words.push(w.clone());
                i += 1;
            }
            Some(Tok::Redir { fd, op }) => {
                let Some(Tok::Word(target)) = toks.get(i + 1) else { return err("redirection needs a target") };
                let fd = fd.unwrap_or(if *op == RedirOp::In { 0 } else { 1 });
                c.redirs.push(Redir { fd, op: *op, target: target.clone() });
                i += 2;
            }
            _ => break,
        }
    }
    if c.words.is_empty() && c.assigns.is_empty() && c.redirs.is_empty() {
        return match toks.get(i) {
            Some(Tok::Pipe) => err("empty command before '|'"),
            Some(Tok::And | Tok::Or) => err("empty command before '&&'/'||'"),
            _ => err("empty command"),
        };
    }
    Ok((c, i))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> List {
        parse(s).unwrap_or_else(|e| panic!("{s:?}: {e}"))
    }
    fn words(c: &Command) -> Vec<String> {
        c.words.iter().map(|w| w.as_lit().unwrap_or_else(|| "<var>".into())).collect()
    }

    #[test]
    fn simple_and_empty() {
        assert!(p("").items.is_empty());
        assert!(p("   # just a comment\n\n").items.is_empty());
        let l = p("echo a  b");
        assert_eq!(l.items.len(), 1);
        assert_eq!(words(&l.items[0].1.cmds[0]), vec!["echo", "a", "b"]);
    }

    #[test]
    fn pipelines_and_connectors() {
        let l = p("a | b | c && d || e ; f\ng");
        let conns: Vec<Conn> = l.items.iter().map(|(c, _)| *c).collect();
        assert_eq!(conns, vec![Conn::Seq, Conn::And, Conn::Or, Conn::Seq, Conn::Seq]);
        assert_eq!(l.items[0].1.cmds.len(), 3);
    }

    #[test]
    fn quoting() {
        let l = p(r#"echo 'a  b' "c d" e\ f "x\"y" 'it''s'"#);
        let c = &l.items[0].1.cmds[0];
        assert_eq!(words(c), vec!["echo", "a  b", "c d", "e f", "x\"y", "its"]);
        // a quoted segment next to an unquoted one is one word
        let l = p(r#"echo a"b c"d"#);
        assert_eq!(words(&l.items[0].1.cmds[0])[1], "ab cd");
    }

    #[test]
    fn empty_quotes_are_a_word() {
        let l = p(r#"echo "" ''"#);
        assert_eq!(l.items[0].1.cmds[0].words.len(), 3);
    }

    #[test]
    fn variables() {
        let l = p("echo $A ${B}x $? $$ \"$C\" '$D' \\$E $ 5");
        let c = &l.items[0].1.cmds[0];
        assert_eq!(c.words[1].0, vec![Seg::Var { name: "A".into(), quoted: false }]);
        assert_eq!(c.words[2].0, vec![Seg::Var { name: "B".into(), quoted: false }, Seg::Lit { s: "x".into(), quoted: false }]);
        assert_eq!(c.words[3].0, vec![Seg::Var { name: "?".into(), quoted: false }]);
        assert_eq!(c.words[4].0, vec![Seg::Var { name: "$".into(), quoted: false }]);
        assert_eq!(c.words[5].0, vec![Seg::Var { name: "C".into(), quoted: true }]);
        assert_eq!(c.words[6].as_lit().unwrap(), "$D");
        assert_eq!(c.words[7].as_lit().unwrap(), "$E");
        assert_eq!(c.words[8].as_lit().unwrap(), "$"); // lone dollar
    }

    #[test]
    fn redirections() {
        let l = p("cmd <in >out 2>>err 2>&1 3>x");
        let c = &l.items[0].1.cmds[0];
        assert_eq!(words(c), vec!["cmd"]);
        let r: Vec<(i32, RedirOp, String)> = c.redirs.iter().map(|r| (r.fd, r.op, r.target.as_lit().unwrap())).collect();
        assert_eq!(
            r,
            vec![
                (0, RedirOp::In, "in".into()),
                (1, RedirOp::Out, "out".into()),
                (2, RedirOp::Append, "err".into()),
                (2, RedirOp::Dup, "1".into()),
                (3, RedirOp::Out, "x".into()),
            ]
        );
        // `2` in word position is a word, not an fd, when not glued to the operator
        let l = p("echo 2 > f");
        assert_eq!(words(&l.items[0].1.cmds[0]), vec!["echo", "2"]);
        assert_eq!(l.items[0].1.cmds[0].redirs[0].fd, 1);
    }

    #[test]
    fn assignments_only_before_the_command_word() {
        let l = p("A=1 B=\"x y\" cmd C=3");
        let c = &l.items[0].1.cmds[0];
        assert_eq!(c.assigns.len(), 2);
        assert_eq!(c.assigns[0].0, "A");
        assert_eq!(c.assigns[1].1.as_lit().unwrap(), "x y");
        assert_eq!(words(c), vec!["cmd", "C=3"]);
        let l = p("X=1");
        assert!(l.items[0].1.cmds[0].words.is_empty());
        // not an assignment: bad name
        assert_eq!(words(&p("1A=b").items[0].1.cmds[0]), vec!["1A=b"]);
    }

    #[test]
    fn comments() {
        let l = p("echo a # comment | here\necho b#c");
        assert_eq!(l.items.len(), 2);
        assert_eq!(words(&l.items[0].1.cmds[0]), vec!["echo", "a"]);
        assert_eq!(words(&l.items[1].1.cmds[0]), vec!["echo", "b#c"]);
    }

    #[test]
    fn line_continuation() {
        let l = p("echo a\\\nb");
        assert_eq!(words(&l.items[0].1.cmds[0]), vec!["echo", "ab"]);
    }

    #[test]
    fn errors_are_clear() {
        for (src, needle) in [
            ("echo |", "'|'"),
            ("| echo", "empty"),
            ("a && ", "'&&'"),
            ("a ||", "'||'"),
            ("echo 'x", "single quote"),
            ("echo \"x", "double quote"),
            ("sleep 1 &", "background"),
            ("echo $(id)", "substitution"),
            ("echo `id`", "backtick"),
            ("(a)", "subshell"),
            ("cat <<EOF", "here-doc"),
            ("echo >", "target"),
            ("a ;; b", "';;'"),
            ("echo ${", "unterminated"),
            ("echo ${a b}", "bad"),
            ("echo x\\", "backslash"),
        ] {
            let e = parse(src).expect_err(src);
            assert!(e.0.contains(needle), "{src:?}: {:?} lacks {needle:?}", e.0);
        }
    }

    #[test]
    fn pipeline_with_redirects_per_stage() {
        let l = p("a 2>&1 | b >out");
        let cmds = &l.items[0].1.cmds;
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].redirs.len(), 1);
        assert_eq!(cmds[1].redirs[0].fd, 1);
    }
}
