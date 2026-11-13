//! Word expansion: `~`, `$VAR` (with field splitting when unquoted), pathname globbing (`*`, `?`, `[..]`). Pure given
//! a variable lookup and a directory lister, so it is host-testable without touching the real filesystem.

use crate::parse::{Seg, Word};

/// A character and whether it came from quoting (quoted wildcards are literal).
type QChar = (char, bool);

fn is_ifs(c: char) -> bool {
    c == ' ' || c == '\t' || c == '\n'
}

/// Expand one word into zero or more fields (before globbing).
pub fn fields(w: &Word, var: &dyn Fn(&str) -> Option<String>, home: &str) -> Vec<Vec<QChar>> {
    let mut out: Vec<Vec<QChar>> = Vec::new();
    let mut cur: Vec<QChar> = Vec::new();
    let mut started = false;

    // tilde: only a leading unquoted `~` followed by `/` or the end of the first literal
    let mut first = true;
    for seg in &w.0 {
        match seg {
            Seg::Lit { s, quoted } => {
                let mut text = s.as_str();
                if first && !*quoted && (text == "~" || text.starts_with("~/")) {
                    for c in home.chars() {
                        cur.push((c, true));
                    }
                    text = &text[1..];
                }
                for c in text.chars() {
                    cur.push((c, *quoted));
                }
                started = true;
            }
            Seg::Var { name, quoted } => {
                let val = var(name).unwrap_or_default();
                if *quoted {
                    for c in val.chars() {
                        cur.push((c, true));
                    }
                    started = true;
                } else {
                    for c in val.chars() {
                        if is_ifs(c) {
                            if !cur.is_empty() {
                                out.push(std::mem::take(&mut cur));
                            }
                            started = false;
                        } else {
                            cur.push((c, false));
                            started = true;
                        }
                    }
                }
            }
        }
        first = false;
    }
    if started || !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn has_glob(f: &[QChar]) -> bool {
    f.iter().any(|&(c, q)| !q && matches!(c, '*' | '?' | '['))
}

/// Pattern text with quoted wildcards escaped by a backslash; and the literal text.
fn pattern_and_literal(f: &[QChar]) -> (String, String) {
    let (mut pat, mut lit) = (String::new(), String::new());
    for &(c, q) in f {
        if q && matches!(c, '*' | '?' | '[' | '\\' | ']') {
            pat.push('\\');
        }
        pat.push(c);
        lit.push(c);
    }
    (pat, lit)
}

/// fnmatch-style: `*` `?` `[abc]` `[a-z]` `[!x]`, backslash escapes the next char.
pub fn glob_match(pat: &str, text: &str) -> bool {
    fn m(p: &[char], t: &[char]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some('*') => (0..=t.len()).any(|i| m(&p[1..], &t[i..])),
            Some('?') => !t.is_empty() && m(&p[1..], &t[1..]),
            Some('\\') if p.len() > 1 => !t.is_empty() && t[0] == p[1] && m(&p[2..], &t[1..]),
            Some('[') => {
                let Some(c) = t.first() else { return false };
                match class(p, *c) {
                    Some((ok, used)) => ok && m(&p[used..], &t[1..]),
                    None => *c == '[' && m(&p[1..], &t[1..]),
                }
            }
            Some(&c) => !t.is_empty() && t[0] == c && m(&p[1..], &t[1..]),
        }
    }
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    m(&p, &t)
}

fn class(p: &[char], c: char) -> Option<(bool, usize)> {
    let mut i = 1;
    let neg = matches!(p.get(i), Some('!') | Some('^'));
    if neg {
        i += 1;
    }
    let mut hit = false;
    let mut first = true;
    loop {
        let &b = p.get(i)?;
        if b == ']' && !first {
            return Some((hit != neg, i + 1));
        }
        first = false;
        if p.get(i + 1) == Some(&'-') && p.get(i + 2).map(|&e| e != ']').unwrap_or(false) {
            if b <= c && c <= p[i + 2] {
                hit = true;
            }
            i += 3;
        } else {
            if b == c {
                hit = true;
            }
            i += 1;
        }
    }
}

/// Expand a glob pattern against a directory lister (`list(dir)` -> entry names). Matches are sorted; hidden entries
/// only match a pattern component that itself starts with '.'.
pub fn glob_paths(pattern: &str, list: &dyn Fn(&str) -> Vec<String>) -> Vec<String> {
    let absolute = pattern.starts_with('/');
    let comps: Vec<&str> = pattern.split('/').filter(|c| !c.is_empty()).collect();
    let mut cur: Vec<String> = vec![if absolute { "/".to_string() } else { String::new() }];
    for comp in comps.iter() {
        let mut next = Vec::new();
        for base in &cur {
            let wild = comp.chars().any(|c| matches!(c, '*' | '?' | '[' | '\\'));
            if !wild {
                let dir = if base.is_empty() { "." } else { base.as_str() };
                if list(dir).iter().any(|e| e == comp) {
                    next.push(join(base, comp));
                }
                continue;
            }
            let dir = if base.is_empty() { "." } else { base.as_str() };
            for e in list(dir) {
                if e.starts_with('.') && !comp.starts_with('.') {
                    continue;
                }
                if glob_match(comp, &e) {
                    next.push(join(base, &e));
                }
            }
        }
        cur = next;
        if cur.is_empty() {
            break;
        }
    }
    cur.sort();
    cur
}

fn join(base: &str, name: &str) -> String {
    if base.is_empty() {
        name.to_string()
    } else if base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

/// Full expansion of a command's words into argv.
pub fn expand_words(words: &[Word], var: &dyn Fn(&str) -> Option<String>, home: &str, list: &dyn Fn(&str) -> Vec<String>) -> Vec<String> {
    let mut argv = Vec::new();
    for w in words {
        for f in fields(w, var, home) {
            if has_glob(&f) {
                let (pat, lit) = pattern_and_literal(&f);
                let hits = glob_paths(&pat, list);
                if hits.is_empty() {
                    argv.push(lit);
                } else {
                    argv.extend(hits);
                }
            } else {
                argv.push(f.into_iter().map(|(c, _)| c).collect());
            }
        }
    }
    argv
}

/// Expansion to exactly one string (redirect targets, assignment values): no splitting into several words and no
/// globbing; a `$VAR` is substituted verbatim.
pub fn expand_one(w: &Word, var: &dyn Fn(&str) -> Option<String>, home: &str) -> String {
    let mut s = String::new();
    for (i, seg) in w.0.iter().enumerate() {
        match seg {
            Seg::Lit { s: t, quoted } => {
                if i == 0 && !*quoted && (t == "~" || t.starts_with("~/")) {
                    s.push_str(home);
                    s.push_str(&t[1..]);
                } else {
                    s.push_str(t);
                }
            }
            Seg::Var { name, .. } => s.push_str(&var(name).unwrap_or_default()),
        }
    }
    s
}

/// The real directory lister.
pub fn fs_list(dir: &str) -> Vec<String> {
    std::fs::read_dir(dir).map(|rd| rd.flatten().filter_map(|e| e.file_name().into_string().ok()).collect()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse;

    fn words_of(src: &str) -> Vec<Word> {
        parse(src).unwrap().items[0].1.cmds[0].words.clone()
    }
    fn var(n: &str) -> Option<String> {
        match n {
            "A" => Some("one two".into()),
            "E" => Some(String::new()),
            "P" => Some("*.txt".into()),
            "?" => Some("3".into()),
            _ => None,
        }
    }
    fn fake(dir: &str) -> Vec<String> {
        let v: &[&str] = match dir {
            "." => &["a.txt", "b.txt", "c.log", ".hidden", "sub"],
            "sub" => &["x.txt", "y.c"],
            "/etc" => &["passwd", "hostname"],
            "/" => &["etc", "sys"],
            _ => &[],
        };
        v.iter().map(|s| s.to_string()).collect()
    }
    fn ex(src: &str) -> Vec<String> {
        expand_words(&words_of(src), &var, "/root", &fake)
    }

    #[test]
    fn unquoted_var_splits_quoted_does_not() {
        assert_eq!(ex("echo $A"), vec!["echo", "one", "two"]);
        assert_eq!(ex("echo \"$A\""), vec!["echo", "one two"]);
        assert_eq!(ex("echo x$A"), vec!["echo", "xone", "two"]);
    }

    #[test]
    fn empty_and_unset_variables() {
        assert_eq!(ex("echo $E $NOPE x"), vec!["echo", "x"]); // unquoted empty vanishes
        assert_eq!(ex("echo \"$E\""), vec!["echo", ""]); // quoted empty stays
        assert_eq!(ex("echo \"\""), vec!["echo", ""]);
        assert_eq!(ex("echo $?"), vec!["echo", "3"]);
    }

    #[test]
    fn tilde() {
        assert_eq!(ex("ls ~ ~/x '~' a~b"), vec!["ls", "/root", "/root/x", "~", "a~b"]);
    }

    #[test]
    fn globs() {
        assert_eq!(ex("ls *.txt"), vec!["ls", "a.txt", "b.txt"]);
        assert_eq!(ex("ls *"), vec!["ls", "a.txt", "b.txt", "c.log", "sub"]); // no dotfiles
        assert_eq!(ex("ls .h*"), vec!["ls", ".hidden"]);
        assert_eq!(ex("ls sub/*.txt"), vec!["ls", "sub/x.txt"]);
        assert_eq!(ex("ls /etc/p*"), vec!["ls", "/etc/passwd"]);
        assert_eq!(ex("ls [ab].txt"), vec!["ls", "a.txt", "b.txt"]);
        assert_eq!(ex("ls ?.log"), vec!["ls", "c.log"]);
    }

    #[test]
    fn no_match_keeps_the_literal_and_quoting_disables_globbing() {
        assert_eq!(ex("ls *.zip"), vec!["ls", "*.zip"]);
        assert_eq!(ex("ls '*.txt'"), vec!["ls", "*.txt"]);
        assert_eq!(ex("ls \\*"), vec!["ls", "*"]);
        // a glob character coming from an unquoted variable IS a pattern
        assert_eq!(ex("ls $P"), vec!["ls", "a.txt", "b.txt"]);
        assert_eq!(ex("ls \"$P\""), vec!["ls", "*.txt"]);
    }

    #[test]
    fn expand_one_substitutes_verbatim() {
        let w = &words_of("x$A")[0];
        assert_eq!(expand_one(w, &var, "/root"), "xone two");
    }

    #[test]
    fn matcher() {
        assert!(glob_match("a*b?c", "aXXbYc") && !glob_match("a*b?c", "aXXbc"));
        assert!(glob_match("[a-c]x", "bx") && !glob_match("[a-c]x", "dx") && glob_match("[!a-c]x", "dx"));
        assert!(glob_match("\\*", "*") && !glob_match("\\*", "a"));
        assert!(glob_match("*", "") && glob_match("", ""));
    }
}
