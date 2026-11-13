//! Console TUI application on tty1 (and the serial tty when configured), built on labtui. Actions run through
//! `Registry::dispatch` with `Source::Console`. F10 / quit hands the tty to i7labsh and resumes when it exits
//! (ConsoleMode::Open only). Pages: TUI.md.
//!
//! Threads: the UI loop (this function) never probes; a data thread builds an immutable `ViewData` every 2 s
//! (slow sections every 30 s) and wakes the loop. Actions are small `dispatch` calls with `Source::Console` and the
//! admin role (whoever sits at the console owns the machine; `i7lab.console=locked` removes the shell and the
//! writing actions altogether).

use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use labproto::keys::Role;
use labtui::{term, App, Caps, Event, EventLoop, Options, RawTerm, Request, Screen, ViewData, Waker};

use crate::config::ConsoleMode;
use crate::daemon::Daemon;
use crate::registry::{Ctx, NullSink, Source};

pub const TABS: &[&str] = &["Overview", "PCIe", "Storage", "Network", "USB", "Sensors", "Log", "Actions"];

const FAST_EVERY: Duration = Duration::from_secs(2);
const SLOW_EVERY: Duration = Duration::from_secs(30);

/// Run the console UI on `tty` until the daemon exits.
pub fn run(daemon: Arc<Daemon>, tty: &str) -> std::io::Result<()> {
    let tty_path = if tty.starts_with('/') { tty.to_string() } else { format!("/dev/{}", tty) };
    let file = match OpenOptions::new().read(true).write(true).custom_flags(0o400 /* O_NOCTTY */ | 0o2000000).open(&tty_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            daemon.log(&format!("console: {} does not exist, no TUI there", tty_path));
            return Err(std::io::Error::from(std::io::ErrorKind::Unsupported));
        }
        Err(e) => return Err(e),
    };
    let fd = file.as_raw_fd();
    let mut raw = match RawTerm::enter(fd) {
        Ok(r) => r,
        Err(e) => {
            daemon.log(&format!("console: {} is not a terminal ({}), no TUI there", tty_path, e));
            return Err(std::io::Error::from(std::io::ErrorKind::Unsupported));
        }
    };
    term::install_panic_hook();
    let env_term = std::env::var("TERM").ok();
    let term_name = env_term.as_deref().unwrap_or(if tty_path.contains("ttyS") { "vt100" } else { "linux" });
    let caps = Caps::detect(Some(term_name), &tty_path).with_overrides(daemon.config.ascii, false);
    let mut app = App::new(Options { ascii: !caps.unicode, mono: caps.color == labtui::ColorMode::Mono, write_tests: false });
    let mut screen = Screen::new(&raw, caps);
    screen.begin(&mut raw)?;
    let mut events = EventLoop::new(fd);

    // data thread
    let shared: Arc<Mutex<Option<Arc<ViewData>>>> = Arc::default();
    let stop = Arc::new(AtomicBool::new(false));
    let force = Arc::new(AtomicBool::new(true));
    {
        let (d, sh, st, fo, w) = (daemon.clone(), shared.clone(), stop.clone(), force.clone(), events.waker());
        std::thread::Builder::new().name("console-data".into()).spawn(move || data_thread(d, sh, st, fo, w))?;
    }
    let _ = std::fs::write(daemon.config.run_dir.join("tui.up"), tty_path.as_bytes());
    daemon.log(&format!("console: TUI on {} ({})", tty_path, term_name));

    let result = ui_loop(&daemon, &tty_path, &file, &mut raw, &mut screen, &mut events, &mut app, &shared, &force);
    stop.store(true, Ordering::SeqCst);
    let _ = std::fs::remove_file(daemon.config.run_dir.join("tui.up"));
    let _ = screen.end();
    raw.restore();
    result
}

#[allow(clippy::too_many_arguments)]
fn ui_loop(
    daemon: &Arc<Daemon>,
    tty: &str,
    file: &std::fs::File,
    raw: &mut RawTerm,
    screen: &mut Screen,
    events: &mut EventLoop,
    app: &mut App,
    shared: &Arc<Mutex<Option<Arc<ViewData>>>>,
    force: &Arc<AtomicBool>,
) -> std::io::Result<()> {
    loop {
        if let Some(d) = shared.lock().unwrap().take() {
            app.set_data(d);
        }
        screen.buffer().clear();
        app.draw(screen.buffer());
        screen.present()?;
        match events.next(Duration::from_millis(250)) {
            Event::Key(k) => {
                for r in app.handle_key(k) {
                    match r {
                        Request::Quit => {
                            if daemon.config.console == ConsoleMode::Open {
                                shell(daemon, file, raw, screen, tty);
                                screen.invalidate();
                            } else {
                                app.set_status("console is locked: the TUI cannot be left");
                            }
                        }
                        Request::Shell => {
                            shell(daemon, file, raw, screen, tty);
                            screen.invalidate();
                        }
                        Request::Redraw => screen.invalidate(),
                        Request::Refresh | Request::ProbeNow | Request::RescanPci => {
                            force.store(true, Ordering::SeqCst);
                            app.set_status("refreshing");
                        }
                        other => {
                            let msg = action(daemon, tty, &other);
                            app.set_status(msg);
                        }
                    }
                }
            }
            Event::Resize(w, h) => screen.resize(w, h),
            Event::Tick => app.on_tick(),
            Event::Quit => return Ok(()),
        }
    }
}

/// Hand the tty to `i7labsh -l` and take it back when the shell exits.
fn shell(daemon: &Daemon, file: &std::fs::File, raw: &mut RawTerm, screen: &mut Screen, tty: &str) {
    use std::os::unix::process::CommandExt;
    let _ = screen.end();
    raw.suspend();
    let prog = if std::path::Path::new("/bin/i7labsh").exists() { "/bin/i7labsh" } else { "/sbin/i7labsh" };
    let mut cmd = std::process::Command::new(prog);
    cmd.arg("-l");
    let dup = |f: &std::fs::File| f.try_clone().map(std::process::Stdio::from);
    if let (Ok(a), Ok(b), Ok(c)) = (dup(file), dup(file), dup(file)) {
        cmd.stdin(a).stdout(b).stderr(c);
    }
    // SAFETY: setsid and TIOCSCTTY are async-signal-safe and touch only this child.
    unsafe {
        cmd.pre_exec(|| {
            crate::ffi::setsid().ok();
            crate::ffi::set_ctty(0).ok();
            Ok(())
        });
    }
    daemon.log(&format!("console: shell on {}", tty));
    match cmd.status() {
        Ok(s) => daemon.log(&format!("console: shell exited ({})", s)),
        Err(e) => daemon.log(&format!("console: cannot start {}: {}", prog, e)),
    }
    let _ = raw.resume();
    let _ = screen.begin(raw);
}

fn dispatch(daemon: &Daemon, tty: &str, name: &str, args: &[&str]) -> Result<String, String> {
    let cmd = daemon.registry.get(name).ok_or_else(|| format!("{}: no such command", name))?;
    let mut sink = NullSink;
    let mut ctx = Ctx {
        daemon,
        source: Source::Console { tty: tty.to_string() },
        role: Role::Admin,
        actor: format!("console {}", tty),
        args: args.iter().map(|s| s.to_string()).collect(),
        sink: &mut sink,
        cancel: Arc::new(AtomicBool::new(false)),
    };
    let reply = daemon.registry.dispatch(&mut ctx, cmd);
    let body = String::from_utf8_lossy(&reply.body).into_owned();
    if reply.status == labproto::Status::Ok {
        Ok(body)
    } else {
        // `{"error":{"code":"..","message":".."}}` -> the message
        let msg = labproto::json::parse(&body, &labproto::json::Limits::default())
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str().map(String::from)))
            .unwrap_or(body);
        Err(msg)
    }
}

/// Run a TUI request through the registry; returns the status line text.
fn action(daemon: &Daemon, tty: &str, r: &Request) -> String {
    if daemon.config.console == ConsoleMode::Locked && matches!(r, Request::Reboot | Request::PowerOff | Request::BootNext(_) | Request::BlockWriteTest { .. } | Request::Dhcp { .. }) {
        return "console is locked: read-only".into();
    }
    let res = match r {
        Request::Reboot => dispatch(daemon, tty, "reboot", &[]).map(|_| "rebooting".to_string()),
        Request::PowerOff => dispatch(daemon, tty, "poweroff", &[]).map(|_| "powering off".to_string()),
        Request::BootNext(n) => dispatch(daemon, tty, "reboot", &["--uefi", &n.to_string()]).map(|_| format!("boot entry {} next, rebooting", n)),
        Request::BlockReadTest { dev } => dispatch(daemon, tty, "blk.read", &[dev, "--mb", "64"]).map(|_| format!("read test of {} finished", dev)),
        Request::BlockWriteTest { .. } => Err("write tests are not enabled on the console (use i7labctl blk write)".to_string()),
        Request::Dhcp { iface } => dispatch(daemon, tty, "net.set", &[iface, "--dhcp"]).map(|_| format!("DHCP started on {}", iface)),
        Request::Ping { target } => ping(target),
        other => Err(format!("{:?} is not handled", other)),
    };
    match res {
        Ok(m) => m,
        Err(e) => format!("failed: {}", e),
    }
}

/// No ICMP socket without a library: a TCP connect to port 7/80/8080 or a refused answer both prove the path.
fn ping(target: &str) -> Result<String, String> {
    use std::net::{TcpStream, ToSocketAddrs};
    let started = Instant::now();
    let addr = (target, 80u16).to_socket_addrs().map_err(|e| format!("cannot resolve {}: {}", target, e))?.next().ok_or("no address")?;
    match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        Ok(_) => Ok(format!("{} answers (tcp/80 open, {} ms)", target, started.elapsed().as_millis())),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Ok(format!("{} answers (tcp/80 refused, {} ms)", target, started.elapsed().as_millis())),
        Err(e) => Err(format!("{}: {}", target, e)),
    }
}

fn data_thread(daemon: Arc<Daemon>, shared: Arc<Mutex<Option<Arc<ViewData>>>>, stop: Arc<AtomicBool>, force: Arc<AtomicBool>, waker: Waker) {
    let mut cur = ViewData::default();
    let mut last_slow: Option<Instant> = None;
    let mut last_net: Option<(Instant, u64, u64)> = None;
    while !stop.load(Ordering::SeqCst) {
        let slow = force.swap(false, Ordering::SeqCst) || last_slow.map(|t| t.elapsed() >= SLOW_EVERY).unwrap_or(true);
        collect(&daemon, &mut cur, slow, &mut last_net);
        if slow {
            last_slow = Some(Instant::now());
        }
        *shared.lock().unwrap() = Some(Arc::new(cur.clone()));
        waker.wake();
        let until = Instant::now() + FAST_EVERY;
        while Instant::now() < until && !stop.load(Ordering::SeqCst) && !force.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Refresh `cur` in place: fast sections every round, `slow` ones (disks, PCIe, USB, firmware, DMI) on request.
fn collect(d: &Daemon, cur: &mut ViewData, slow: bool, last_net: &mut Option<(Instant, u64, u64)>) {
    let ctx = &d.probe;
    cur.system = labprobe::system::probe(ctx).ok();
    cur.cpu = cur.cpu.take().or_else(|| labprobe::cpu::probe(ctx).ok());
    cur.mem = labprobe::mem::probe(ctx).ok();
    cur.thermal = labprobe::thermal::probe(ctx).ok();
    cur.net = labprobe::net::probe(ctx).ok();
    cur.kmsg = labprobe::kmsg::read(ctx, &labprobe::kmsg::KmsgOpts { last: Some(300), ..Default::default() }).ok();
    if slow {
        cur.dmi = labprobe::dmi::probe(ctx).ok();
        cur.pci = labprobe::pci::probe(ctx, &labprobe::pci::PciOpts::default()).ok();
        cur.usb = labprobe::usb::probe(ctx).ok();
        cur.block = labprobe::block::probe(ctx, false).ok();
        cur.firmware = labprobe::firmware::probe(ctx).ok();
    }
    cur.audit = d.audit.recent(50);

    // sparkline history: bytes/s per interface, temperatures
    if let Some(n) = &cur.net {
        let (rx, tx) = n.ifaces.iter().filter(|i| i.name != "lo").fold((0u64, 0u64), |a, i| (a.0 + i.rx_bytes, a.1 + i.tx_bytes));
        if let Some((t, prx, ptx)) = *last_net {
            let dt = t.elapsed().as_secs_f32().max(0.1);
            push(&mut cur.series, "rx:total", rx.saturating_sub(prx) as f32 / dt);
            push(&mut cur.series, "tx:total", tx.saturating_sub(ptx) as f32 / dt);
        }
        *last_net = Some((Instant::now(), rx, tx));
        for i in &n.ifaces {
            if i.name != "lo" {
                let key = format!("rx:{}", i.name);
                let prev = cur.series.get(&format!("rxb:{}", i.name)).and_then(|v| v.last().copied()).unwrap_or(i.rx_bytes as f32);
                push(&mut cur.series, &key, ((i.rx_bytes as f32) - prev).max(0.0) / FAST_EVERY.as_secs_f32());
                cur.series.insert(format!("rxb:{}", i.name), vec![i.rx_bytes as f32]);
            }
        }
    }
    if let Some(t) = &cur.thermal {
        for h in &t.hwmon {
            for s in &h.temps {
                push(&mut cur.series, &format!("temp:{}/{}", h.name, s.label), s.value as f32);
            }
        }
    }

    // identity
    let st = d.state.read().unwrap().clone();
    let ips: Vec<String> = cur.net.as_ref().map(|n| n.ifaces.iter().flat_map(|i| i.ipv4.iter().cloned()).collect()).unwrap_or_default();
    let mac = cur.net.as_ref().and_then(|n| n.ifaces.iter().find(|i| i.driver.is_some() && i.mac.is_some() && i.name != "lo" && !i.name.starts_with("dummy")).or_else(|| n.ifaces.iter().find(|i| i.name != "lo" && i.mac.is_some())).and_then(|i| i.mac.clone()));
    let mut banners = Vec::new();
    if d.keys.read().unwrap().admin.is_none() {
        banners.push("NO KEYS: the host cannot be controlled remotely (bake keys with scripts/bake-keys)".to_string());
    }
    if let Some(m) = st.console_message {
        banners.push(m);
    }
    cur.identity = labtui::Identity {
        version: labproto::VERSION.to_string(),
        build_id: Some(d.config.image_build.clone()),
        hostname: d.config.hostname.clone(),
        ips,
        mac,
        key_summary: d.key_summary(),
        banners,
        console_locked: d.config.console == ConsoleMode::Locked,
    };
}

fn push(series: &mut std::collections::HashMap<String, Vec<f32>>, key: &str, v: f32) {
    let s = series.entry(key.to_string()).or_default();
    s.push(v);
    if s.len() > 120 {
        s.remove(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_fills_view_data_on_this_machine() {
        let d = crate::registry::tests_support::test_daemon();
        let mut cur = ViewData::default();
        let mut ln = None;
        collect(&d, &mut cur, true, &mut ln);
        assert!(cur.system.is_some(), "system probe works anywhere");
        assert_eq!(cur.identity.version, labproto::VERSION);
        // a headless frame renders from it
        let mut app = App::new(Options::default());
        app.set_data(Arc::new(cur));
        let text = app.render(100, 30).to_text();
        assert!(text.contains("Overview"), "{}", text);
    }

    #[test]
    fn series_is_bounded() {
        let mut m = std::collections::HashMap::new();
        for i in 0..500 {
            push(&mut m, "k", i as f32);
        }
        assert_eq!(m["k"].len(), 120);
        assert_eq!(*m["k"].last().unwrap(), 499.0);
    }

    #[test]
    fn missing_tty_is_unsupported_not_retried() {
        let d = Arc::new(crate::registry::tests_support::test_daemon());
        let e = run(d, "/dev/does-not-exist-i7ll").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::Unsupported);
    }
}
