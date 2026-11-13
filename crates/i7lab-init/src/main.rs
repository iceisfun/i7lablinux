//! i7lab-init: PID 1 of i7lablinux (PLAN.md section 4.5). Owner: P2.
//!
//! Duties, in order: mounts, console fds, cmdline, run dirs, hostname from DMI, `lo` up, modules by modalias scan,
//! device nodes, optional data partition, watchdog; then supervise `/sbin/i7labd` (backoff 1 s -> 30 s; 5 failures in
//! 60 s puts `/bin/i7labsh -l` on the console ttys), reap zombies, handle TERM/INT (reboot), USR1 (halt), USR2
//! (poweroff). It never exits: every duty runs under `catch_unwind`, a panicking supervisor loop is restarted, and
//! repeated panics reboot the machine. No busybox, no dropbear: the image ships no other userland than ours.
//!
//! Networking beyond `lo` (DHCP, static, VLAN) belongs to i7labd (PLAN.md C8); the TUI and its F10 hotkey into
//! i7labsh live in i7labd (C2). Init only provides the console fallback shells.

#[macro_use]
mod log;
mod cmdline;
mod console;
mod datapart;
mod devnodes;
mod ffi;
mod hostname;
mod modules;
mod mounts;
mod spawn;
mod supervisor;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use supervisor::{Action, Kind, Supervisor};

const TUI_UP: &str = "/run/i7lab/tui.up";
const TICK_MS: i32 = 200;
const FLUSH_MS: u64 = 2_000;
const DOG_PET_MS: u64 = 10_000;
const DOG_TIMEOUT_S: i32 = 60;
const BOOT_ATTEMPTS: u32 = 3;
const PANIC_LIMIT: usize = 5;

static PENDING: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_sig(sig: i32) {
    PENDING.fetch_or(1u32 << (sig as u32 & 31), Ordering::SeqCst);
}

fn now_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

fn guard<T>(what: &str, f: impl FnOnce() -> T) -> Option<T> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => Some(v),
        Err(_) => {
            logf!("PANIC in {what}; continuing");
            None
        }
    }
}

/// Which power action a pending-signal bitmask asks for. Poweroff beats halt beats reboot.
fn power_for(mask: u32) -> Option<ffi::Power> {
    let has = |s: i32| mask & (1u32 << s as u32) != 0;
    if has(ffi::SIGUSR2) {
        Some(ffi::Power::Off)
    } else if has(ffi::SIGUSR1) {
        Some(ffi::Power::Halt)
    } else if has(ffi::SIGTERM) || has(ffi::SIGINT) {
        Some(ffi::Power::Reboot)
    } else {
        None
    }
}

struct Init {
    flags: cmdline::Flags,
    sup: Supervisor,
    dog: Option<ffi::Dog>,
    tui_up: bool,
    fallback_logged: bool,
    last_dog: u64,
    last_flush: u64,
}

fn make_dirs() {
    use std::os::unix::fs::DirBuilderExt;
    let _ = std::fs::create_dir_all("/run/i7lab");
    let _ = std::fs::DirBuilder::new().mode(0o700).create("/run/i7lab/blk");
}

fn boot() -> Init {
    mounts::mount_all();
    ffi::open_console();
    make_dirs();
    ffi::disable_cad();
    std::env::set_var("PATH", spawn::PATH_ENV);
    std::env::set_var("HOME", "/root");
    std::env::set_var("TERM", "linux");
    for s in [ffi::SIGTERM, ffi::SIGINT, ffi::SIGUSR1, ffi::SIGUSR2] {
        ffi::on_signal(s, on_sig);
    }
    let release = modules::kernel_release();
    logf!("i7lab-init {} up, kernel {}", labproto::VERSION, release);

    let cmdline_text = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let flags = cmdline::Flags::parse(&cmdline_text);
    if flags.debug {
        ffi::console_loglevel(7);
        log::set_echo(false); // the kernel already prints /dev/kmsg at this level
    }

    guard("hostname", || {
        let h = match &flags.hostname {
            Some(h) if hostname::valid(h) => h.clone(),
            _ => hostname::from_serials(&hostname::dmi_serials()),
        };
        match ffi::set_hostname(&h) {
            Ok(()) => {
                let _ = std::fs::write("/etc/hostname", format!("{h}\n"));
                logf!("hostname {h}");
            }
            Err(e) => logf!("sethostname {h}: {e}"),
        }
    });
    guard("lo", || {
        if let Err(e) = ffi::if_up("lo") {
            logf!("lo up: {e}");
        }
    });
    guard("modules", || match modules::load_by_modalias(&now_ms) {
        Some(s) => logf!("modules: {} loaded, {} failed ({} round(s))", s.loaded, s.failed, s.rounds),
        None => logf!("no modules.dep for this kernel; relying on built-in drivers"),
    });
    guard("devnodes", || {
        let n = devnodes::create_missing();
        if n > 0 {
            logf!("created {n} missing device node(s)");
        }
    });
    if let Some(spec) = &flags.data {
        guard("data partition", || {
            if let Some(dev) = datapart::mount_by_label(&spec.label, spec.rw) {
                logf!("data partition {} ({}) mounted on /data {}", spec.label, dev, if spec.rw { "rw" } else { "ro" });
            }
        });
    }
    let dog = if flags.watchdog && Path::new("/dev/watchdog0").exists() {
        match ffi::Dog::open("/dev/watchdog0", DOG_TIMEOUT_S) {
            Ok(d) => {
                logf!("watchdog armed ({DOG_TIMEOUT_S} s)");
                Some(d)
            }
            Err(e) => {
                logf!("watchdog: {e}");
                None
            }
        }
    } else {
        None
    };

    let ttys = console::shell_ttys(&flags, &|n| Path::new("/dev").join(n).exists());
    let shells_allowed = flags.console == cmdline::Console::Open;
    match flags.console {
        cmdline::Console::Open => logf!("console: open (fallback shells on {})", ttys.join(" ")),
        cmdline::Console::Locked => logf!("console: locked (no shell)"),
        cmdline::Console::Off => logf!("console: off"),
    }
    let shell_ttys: &[String] = if shells_allowed { &ttys } else { &[] };
    let sup = Supervisor::new(shell_ttys, shells_allowed, !flags.tui);
    Init { flags, sup, dog, tui_up: false, fallback_logged: false, last_dog: 0, last_flush: 0 }
}

/// Stop everything and call reboot(2). Never returns.
fn power_down(init: &mut Init, p: ffi::Power) -> ! {
    logf!("{:?}: stopping services", p);
    log::flush();
    if let Some(d) = init.dog.take() {
        d.disarm();
    }
    ffi::kill_all(ffi::SIGTERM);
    for _ in 0..10 {
        ffi::sleep_ms(200);
        while ffi::reap_one().is_some() {}
    }
    ffi::kill_all(ffi::SIGKILL);
    ffi::sleep_ms(100);
    while ffi::reap_one().is_some() {}
    ffi::sys_sync();
    let _ = ffi::do_umount("/data");
    let mut e = ffi::power(p);
    // reboot(2) failed (should not happen as PID 1): stay alive and keep trying
    loop {
        logf!("reboot(2) failed: {e}");
        ffi::sleep_ms(5000);
        e = ffi::power(p);
    }
}

fn perform(init: &mut Init, now: u64, a: Action) {
    match a {
        Action::Start { idx, tui_off } => {
            let (name, kind) = {
                let s = &init.sup.services()[idx];
                (s.name.clone(), s.kind.clone())
            };
            let r = match &kind {
                Kind::Daemon => spawn::daemon(tui_off || !init.flags.tui),
                Kind::Shell(tty) => spawn::shell(tty),
            };
            match r {
                Ok(pid) => {
                    logf!("started {name} pid {pid}{}", if matches!(kind, Kind::Daemon) && (tui_off || !init.flags.tui) { " (TUI off)" } else { "" });
                    init.sup.spawned(idx, pid, now);
                }
                Err(e) => {
                    logf!("cannot start {name}: {e}");
                    init.sup.spawn_failed(idx, now);
                }
            }
        }
        Action::Stop { pid } => {
            logf!("restarting i7labd (pid {pid}) so it leaves the console to the fallback shell");
            ffi::send_signal(pid, ffi::SIGTERM);
        }
    }
}

fn supervise(init: &mut Init) {
    loop {
        let now = now_ms();

        let mask = PENDING.swap(0, Ordering::SeqCst);
        if let Some(p) = power_for(mask) {
            power_down(init, p);
        }

        while let Some((pid, status)) = ffi::reap_one() {
            if let Some(idx) = init.sup.on_exit(now, pid) {
                let name = init.sup.services()[idx].name.clone();
                logf!("{name} (pid {pid}) exited, status {:#x}", status);
                if idx == 0 && init.tui_up {
                    // the TUI is gone: show kernel and init messages on the console again
                    init.tui_up = false;
                    let _ = std::fs::remove_file(TUI_UP);
                    if !init.flags.debug {
                        log::set_echo(true);
                        ffi::console_loglevel(4);
                    }
                }
            }
        }

        for a in init.sup.tick(now) {
            perform(init, now, a);
        }
        if init.sup.fallback_active() && !init.fallback_logged {
            init.fallback_logged = true;
            logf!("i7labd keeps failing: console shell fallback active, i7labd now starts with the TUI off");
        }

        if !init.tui_up && Path::new(TUI_UP).exists() {
            init.tui_up = true;
            log::set_echo(false);
            if !init.flags.debug {
                ffi::console_loglevel(1); // the TUI owns tty1: no kernel chatter over it
            }
            logf!("TUI is up");
        }

        if let Some(d) = &init.dog {
            if now.saturating_sub(init.last_dog) >= DOG_PET_MS {
                d.pet();
                init.last_dog = now;
            }
        }
        if now.saturating_sub(init.last_flush) >= FLUSH_MS {
            log::flush();
            init.last_flush = now;
        }
        ffi::sleep_ms(TICK_MS);
    }
}

fn main() {
    if ffi::pid() != 1 && std::env::var_os("I7LAB_INIT_ALLOW_NON_PID1").is_none() {
        eprintln!("i7lab-init: must run as PID 1 (it mounts filesystems and reboots; set I7LAB_INIT_ALLOW_NON_PID1=1 for tests)");
        std::process::exit(2);
    }
    std::panic::set_hook(Box::new(|info| {
        logf!("panic: {info}");
    }));

    let mut attempt = 0u32;
    let mut init = loop {
        match catch_unwind(boot) {
            Ok(i) => break i,
            Err(_) => {
                attempt += 1;
                if attempt < BOOT_ATTEMPTS {
                    logf!("PANIC during boot (attempt {attempt}); retrying in 5 s");
                    std::thread::sleep(Duration::from_secs(5));
                } else {
                    logf!("PANIC during boot {attempt} times; rebooting in 10 s");
                    log::flush();
                    std::thread::sleep(Duration::from_secs(10));
                    ffi::sys_sync();
                    ffi::power(ffi::Power::Reboot);
                    // reboot(2) failed: stay alive with the daemon only rather than exit
                    let flags = cmdline::Flags::parse("");
                    break Init { flags, sup: Supervisor::new(&[], false, false), dog: None, tui_up: false, fallback_logged: false, last_dog: 0, last_flush: 0 };
                }
            }
        }
    };

    let mut panics: Vec<u64> = Vec::new();
    loop {
        if catch_unwind(AssertUnwindSafe(|| supervise(&mut init))).is_err() {
            let now = now_ms();
            panics.retain(|t| now.saturating_sub(*t) < 60_000);
            panics.push(now);
            logf!("PANIC in the supervisor loop ({} in 60 s)", panics.len());
            if panics.len() >= PANIC_LIMIT {
                logf!("too many panics; rebooting in 30 s");
                log::flush();
                std::thread::sleep(Duration::from_secs(30));
                ffi::sys_sync();
                ffi::power(ffi::Power::Reboot);
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signal_to_power_mapping_and_precedence() {
        assert_eq!(power_for(0), None);
        assert_eq!(power_for(1 << ffi::SIGTERM), Some(ffi::Power::Reboot));
        assert_eq!(power_for(1 << ffi::SIGINT), Some(ffi::Power::Reboot));
        assert_eq!(power_for(1 << ffi::SIGUSR1), Some(ffi::Power::Halt));
        assert_eq!(power_for((1 << ffi::SIGUSR1) | (1 << ffi::SIGTERM)), Some(ffi::Power::Halt));
        assert_eq!(power_for((1 << ffi::SIGUSR2) | (1 << ffi::SIGUSR1)), Some(ffi::Power::Off));
    }
}
