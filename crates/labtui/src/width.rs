//! Display width of characters in terminal cells (small wcwidth table) and cell-based truncation. Owner: P5.
//! The lab expects ASCII and box drawing, but device names and USB strings can hold anything, so East Asian
//! wide characters (2 cells) and combining / zero-width characters (0 cells) are handled.

/// Zero-width ranges (combining marks, variation selectors, zero-width format characters).
const ZERO: &[(u32, u32)] = &[
    (0x0300, 0x036F),
    (0x0483, 0x0489),
    (0x0591, 0x05BD),
    (0x0610, 0x061A),
    (0x064B, 0x065F),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x2064),
    (0x20D0, 0x20FF),
    (0xFE00, 0xFE0F),
    (0xFE20, 0xFE2F),
    (0xFEFF, 0xFEFF),
    (0xE0100, 0xE01EF),
];

/// Double-width ranges (East Asian Wide / Fullwidth, common emoji blocks).
const WIDE: &[(u32, u32)] = &[
    (0x1100, 0x115F),
    (0x2E80, 0x303E),
    (0x3041, 0x33FF),
    (0x3400, 0x4DBF),
    (0x4E00, 0xA4CF),
    (0xA960, 0xA97F),
    (0xAC00, 0xD7A3),
    (0xF900, 0xFAFF),
    (0xFE30, 0xFE6F),
    (0xFF00, 0xFF60),
    (0xFFE0, 0xFFE6),
    (0x1F300, 0x1F64F),
    (0x1F900, 0x1F9FF),
    (0x20000, 0x3FFFD),
];

fn in_table(t: &[(u32, u32)], u: u32) -> bool {
    t.iter().any(|&(a, b)| u >= a && u <= b)
}

/// Columns a character occupies: 0, 1 or 2. Control characters count 0 (they never reach the screen).
pub fn char_width(c: char) -> usize {
    let u = c as u32;
    if u < 0x20 || (0x7f..0xa0).contains(&u) {
        0
    } else if u < 0x300 {
        1
    } else if in_table(ZERO, u) {
        0
    } else if in_table(WIDE, u) {
        2
    } else {
        1
    }
}

/// Width of a string in cells.
pub fn str_width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

/// Cut `s` to at most `max` cells. When something is cut, the last cell is `ell` (width 1) so the reader sees
/// the text was shortened. `max == 0` gives an empty string.
pub fn truncate(s: &str, max: usize, ell: char) -> String {
    if str_width(s) <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut w = 0;
    for c in s.chars() {
        let cw = char_width(c);
        if w + cw > max - 1 {
            break;
        }
        out.push(c);
        w += cw;
    }
    out.push(ell);
    out
}

/// Pad with spaces on the right up to `w` cells (or truncate to it).
pub fn pad_right(s: &str, w: usize, ell: char) -> String {
    let mut t = truncate(s, w, ell);
    let cur = str_width(&t);
    for _ in cur..w {
        t.push(' ');
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn widths() {
        assert_eq!(char_width('a'), 1);
        assert_eq!(char_width('\u{4e2d}'), 2);
        assert_eq!(char_width('\u{0301}'), 0);
        assert_eq!(char_width('\u{200b}'), 0);
        assert_eq!(char_width('─'), 1);
        assert_eq!(str_width("ab\u{4e2d}"), 4);
    }
    #[test]
    fn truncation() {
        assert_eq!(truncate("hello", 10, '~'), "hello");
        assert_eq!(truncate("hello world", 6, '~'), "hello~");
        assert_eq!(truncate("hello", 0, '~'), "");
        // a wide char that would straddle the cut is dropped
        assert_eq!(truncate("a\u{4e2d}\u{4e2d}", 3, '~'), "a~");
        assert_eq!(pad_right("ab", 4, '~'), "ab  ");
        assert_eq!(pad_right("abcdef", 4, '~'), "abc~");
    }
}
