//! Terminal/HTML injection sanitiser for hardware-supplied strings. Owner: P1.
//! Port of the earlier lab-proxy prototype + unsafe_ranges.txt (add the table as
//! `src/unsafe_ranges.txt` and a parity test). Also escapes a literal backslash (prior-art bug 9).

use std::borrow::Cow;

fn is_unsafe(c: char) -> bool {
    let u = c as u32;
    u < 0x20
        || (0x7f..=0x9f).contains(&u)          // DEL, C1
        || u == 0x061c                          // Arabic letter mark
        || (0x200b..=0x200f).contains(&u)       // zero-width, LRM/RLM
        || (0x2028..=0x202e).contains(&u)       // line/paragraph separators, bidi embeddings
        || (0x2060..=0x206f).contains(&u)       // word joiner, invisible operators, bidi isolates
        || u == 0xfeff                          // BOM / ZWNBSP
        || (0xfff0..=0xffff).contains(&u)       // specials, noncharacters
        || (0xe000..=0xf8ff).contains(&u)       // private use
        || (0xe0000..=0xe007f).contains(&u)     // tag characters
        || (0xf0000..=0x10ffff).contains(&u)    // supplementary private use
        || (u & 0xfffe) == 0xfffe               // noncharacters in every plane
}

/// Replace unsafe code points with a visible `\u{XXXX}` form and `\` with `\\`.
pub fn sanitize(s: &str) -> Cow<'_, str> {
    if !s.chars().any(|c| c == '\\' || is_unsafe(c)) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if c == '\\' {
            out.push_str("\\\\");
        } else if is_unsafe(c) {
            out.push_str(&format!("\\u{{{:04x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// Bytes that may not be UTF-8: invalid bytes become `\xNN`, then `sanitize`.
pub fn sanitize_bytes(b: &[u8]) -> String {
    let mut out = String::new();
    for chunk in b.utf8_chunks() {
        out.push_str(&sanitize(chunk.valid()));
        for x in chunk.invalid() {
            out.push_str(&format!("\\x{:02x}", x));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escapes() {
        assert_eq!(sanitize("plain"), "plain");
        assert_eq!(sanitize("a\x1b[2Jb"), "a\\u{001b}[2Jb");
        assert_eq!(sanitize("x\\y"), "x\\\\y");
        assert_eq!(sanitize_bytes(b"ok\xff"), "ok\\xff");
    }
}
