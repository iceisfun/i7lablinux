//! labtui: immediate-mode terminal renderer for the console TUI (docs/TUI.md, PLAN.md 4.3). Owner: P5.
//! No terminfo, no curses: a VT100/xterm subset that the Linux console and serial terminals understand.
//! Every string drawn goes through `labproto::text::sanitize` inside `Buffer::put_str`.

pub mod app;
pub mod buffer;
pub mod event;
pub mod fmt;
pub mod headless;
pub mod input;
pub mod model;
pub mod page;
pub mod pages;
pub mod sample;
pub mod screen;
pub mod term;
pub mod theme;
pub mod widgets;
pub mod width;

pub use app::{App, Options};
pub use buffer::{Attr, Buffer, Cell, Color, Rect, Style};
pub use event::{Event, EventLoop, Waker};
pub use input::{Decoder, Key};
pub use model::{Identity, ViewData};
pub use page::{Focus, Page, PageAction, Request};
pub use screen::{Caps, ColorMode, Screen};
pub use term::RawTerm;
pub use theme::Theme;
pub use widgets::BorderSet;

/// Smallest supported grid.
pub const MIN_COLS: u16 = 80;
pub const MIN_ROWS: u16 = 25;

/// Layout class from the grid size (TUI.md "Responsive rules").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutClass {
    TooSmall,
    Compact,
    Standard,
    Wide,
}

pub fn layout_class(cols: u16, rows: u16) -> LayoutClass {
    if cols < MIN_COLS || rows < MIN_ROWS {
        LayoutClass::TooSmall
    } else if cols >= 200 && rows >= 50 {
        LayoutClass::Wide
    } else if cols >= 120 && rows >= 30 {
        LayoutClass::Standard
    } else {
        LayoutClass::Compact
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classes() {
        assert_eq!(layout_class(79, 25), LayoutClass::TooSmall);
        assert_eq!(layout_class(80, 25), LayoutClass::Compact);
        assert_eq!(layout_class(132, 43), LayoutClass::Standard);
        assert_eq!(layout_class(240, 67), LayoutClass::Wide);
    }
}
