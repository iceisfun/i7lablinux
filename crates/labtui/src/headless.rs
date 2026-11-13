//! Headless test backend: drives an `App` with key bytes and renders frames to plain text. Owner: P5.

use std::sync::Arc;

use crate::app::{App, Options};
use crate::buffer::Buffer;
use crate::input::Decoder;
use crate::model::ViewData;
use crate::page::Request;

pub struct Headless {
    pub app: App,
    pub w: u16,
    pub h: u16,
    dec: Decoder,
}

impl Headless {
    pub fn new(w: u16, h: u16, data: ViewData, opts: Options) -> Headless {
        let mut app = App::new(opts);
        app.set_data(Arc::new(data));
        Headless { app, w, h, dec: Decoder::new() }
    }
    pub fn resize(&mut self, w: u16, h: u16) {
        self.w = w;
        self.h = h;
    }
    /// Feed raw terminal bytes (`b"\x1b[B"`, `b"q"` ...); returns every request the app produced.
    pub fn keys(&mut self, bytes: &[u8]) -> Vec<Request> {
        let mut out = Vec::new();
        for k in self.dec.feed_all(bytes) {
            // the real loop draws before it waits for the next key; pages size their lists while drawing
            self.buffer();
            out.extend(self.app.handle_key(k));
        }
        out
    }
    /// Draw and return the buffer.
    pub fn buffer(&mut self) -> Buffer {
        self.app.render(self.w, self.h)
    }
    /// Draw and return the plain-text frame (rows separated by newlines, trailing spaces trimmed).
    pub fn frame(&mut self) -> String {
        self.buffer().to_text()
    }
}

/// One frame of one page of `data` at a given size (focus on the page list, first row selected).
pub fn render_page(data: &ViewData, tab: &str, w: u16, h: u16, ascii: bool) -> String {
    let mut hl = Headless::new(w, h, data.clone(), Options { ascii, ..Default::default() });
    hl.app.select_tab(tab);
    hl.frame()
}
