//! `cargo run -p labtui --example demo` : the console TUI on fixture data.
//!
//!   demo                  interactive (needs a terminal); q then Enter on "Yes" quits
//!   demo --dump WxH [tab] print one frame as plain text and exit (no terminal needed), e.g. `--dump 132x43 Storage`
//!   demo --ascii | --mono force ASCII frames / monochrome
//!   demo --no-control     demo host with a NIC that has no driver and a DEMO banner
//!
//! Requests the TUI makes (reboot, shell ...) are only shown on the status line; nothing is executed.

use std::io::IsTerminal;
use std::sync::Arc;
use std::time::Duration;

use labtui::{sample, term, App, Caps, Event, EventLoop, Options, RawTerm, Request, Screen};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |f: &str| args.iter().any(|a| a == f);
    let data = if flag("--no-control") { sample::demo_data_no_control_path() } else { sample::demo_data_with_test() };

    if let Some(i) = args.iter().position(|a| a == "--dump") {
        let size = args.get(i + 1).map(|s| s.as_str()).unwrap_or("132x43");
        let (w, h) = size.split_once('x').and_then(|(w, h)| Some((w.parse().ok()?, h.parse().ok()?))).unwrap_or((132, 43));
        let mut app = App::new(Options { ascii: flag("--ascii"), mono: flag("--mono"), ..Default::default() });
        app.set_data(Arc::new(data));
        if let Some(tab) = args.get(i + 2) {
            if !app.select_tab(tab) {
                eprintln!("unknown tab {}", tab);
                std::process::exit(2);
            }
        }
        print!("{}", app.render(w, h).to_text());
        return;
    }

    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        eprintln!("demo needs a terminal; use --dump WxH [tab] to print a frame");
        std::process::exit(2);
    }
    let mut raw = match RawTerm::enter(0) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot enter raw mode: {}", e);
            std::process::exit(1);
        }
    };
    term::install_panic_hook();
    let caps = Caps::detect(std::env::var("TERM").ok().as_deref(), "/dev/tty").with_overrides(flag("--ascii"), flag("--mono"));
    let mut app = App::new(Options { ascii: !caps.unicode, mono: caps.color == labtui::ColorMode::Mono, ..Default::default() });
    app.set_data(Arc::new(data));
    let mut screen = Screen::new(&raw, caps);
    if screen.begin(&mut raw).is_err() {
        return;
    }
    let mut ev = EventLoop::new(0);
    loop {
        screen.buffer().clear();
        app.draw(screen.buffer());
        if screen.present().is_err() {
            break;
        }
        match ev.next(Duration::from_millis(250)) {
            Event::Key(k) => {
                for r in app.handle_key(k) {
                    match r {
                        Request::Quit => {
                            raw.restore();
                            return;
                        }
                        Request::Redraw => screen.invalidate(),
                        other => app.set_status(format!("(demo) would run: {:?}", other)),
                    }
                }
            }
            Event::Resize(w, h) => {
                screen.resize(w, h);
            }
            Event::Tick => app.on_tick(),
            Event::Quit => break,
        }
    }
    raw.restore();
}
