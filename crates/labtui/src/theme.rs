//! Semantic colours. Owner: P5.

use crate::buffer::{Attr, Color, Style};

#[derive(Clone, Copy, Debug)]
pub struct Theme {
    pub frame: Style,
    pub title: Style,
    pub tab_active: Style,
    pub tab_inactive: Style,
    pub ok: Style,
    pub warn: Style,
    pub bad: Style,
    pub dim: Style,
    pub selection: Style,
    pub accent: Style,
    pub text: Style,
    /// table header row
    pub header: Style,
    /// bottom key bar and its key labels
    pub bar: Style,
    pub bar_key: Style,
    /// red banner strip (NO KEYS, NO CONTROL PATH)
    pub banner: Style,
}

fn s(fg: Color, attr: Attr) -> Style {
    Style { fg, bg: Color::Default, attr }
}

impl Theme {
    pub fn dark() -> Theme {
        Theme {
            frame: s(Color::Ansi(4), Attr::NONE),
            title: s(Color::Ansi(14), Attr::BOLD),
            tab_active: Style { fg: Color::Ansi(0), bg: Color::Ansi(6), attr: Attr::BOLD },
            tab_inactive: s(Color::Ansi(7), Attr::NONE),
            ok: s(Color::Ansi(10), Attr::NONE),
            warn: s(Color::Ansi(11), Attr::BOLD),
            bad: s(Color::Ansi(9), Attr::BOLD),
            dim: s(Color::Ansi(8), Attr::NONE),
            selection: s(Color::Default, Attr::REVERSE),
            accent: s(Color::Ansi(13), Attr::NONE),
            text: Style::default(),
            header: Style { fg: Color::Ansi(14), bg: Color::Default, attr: Attr::UNDERLINE },
            bar: Style { fg: Color::Ansi(0), bg: Color::Ansi(7), attr: Attr::NONE },
            bar_key: Style { fg: Color::Ansi(0), bg: Color::Ansi(14), attr: Attr::BOLD },
            banner: Style { fg: Color::Ansi(15), bg: Color::Ansi(1), attr: Attr::BOLD },
        }
    }
    /// TERM=dumb or i7lab.mono=1: bold / reverse only.
    pub fn mono() -> Theme {
        let p = Style::default();
        let b = s(Color::Default, Attr::BOLD);
        let r = s(Color::Default, Attr::REVERSE);
        Theme { frame: p, title: b, tab_active: r, tab_inactive: p, ok: p, warn: b, bad: b, dim: p, selection: r, accent: b, text: p, header: Style { fg: Color::Default, bg: Color::Default, attr: Attr::UNDERLINE }, bar: r, bar_key: b, banner: r }
    }
}
