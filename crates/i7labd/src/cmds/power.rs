//! reboot, poweroff (kexec is planned v0.4: UNSUPPORTED from the catalogue). The RESP goes out first; the action
//! runs `--delay` seconds later (default 1) so the reply and a final `state=shutdown` beacon leave the box.

use std::time::Duration;

use labproto::json::JsonWriter;
use labproto::sys::RebootCmd;
use labproto::Status;

use crate::opts_or_bad;
use crate::registry::{Ctx, Handler, Reply};

pub const TABLE: &[(&str, Handler)] = &[("reboot", reboot), ("poweroff", poweroff)];

pub const DEFAULT_DELAY_S: u64 = 1;
pub const MAX_DELAY_S: u64 = 3600;

fn probe_err(e: &labprobe::ProbeError) -> Status {
    match e {
        labprobe::ProbeError::Unsupported => Status::Unsupported,
        labprobe::ProbeError::NotFound(_) => Status::NotFound,
        labprobe::ProbeError::Timeout => Status::Timeout,
        _ => Status::Io,
    }
}

fn delay_of(o: &labproto::args::Opts) -> Result<u64, Reply> {
    match o.value("delay").map(|d| d.parse::<u64>()) {
        None => Ok(DEFAULT_DELAY_S),
        Some(Ok(d)) if d <= MAX_DELAY_S => Ok(d),
        _ => Err(Reply::error(Status::BadArgs, "bad --delay (0..3600 seconds)")),
    }
}

/// Announce shutdown (beacon, console) and perform `cmd` after `delay_s`. In dry-run mode (tests) only the
/// announcement happens.
fn schedule(ctx: &Ctx, cmd: RebootCmd, delay_s: u64) {
    ctx.daemon.set_state("shutdown");
    if ctx.daemon.config.power_dry_run {
        return;
    }
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(delay_s));
        labproto::sys::sync();
        let _ = labproto::sys::reboot(cmd);
    });
}

fn answer(action: &str, delay: u64, extra: impl FnOnce(&mut JsonWriter)) -> Reply {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_u64("v", 1);
    w.field_str("action", action);
    w.field_u64("in_s", delay);
    extra(&mut w);
    w.end_object();
    Reply::json(w.finish())
}

/// `[--force] [--delay S] [--uefi] [--to-os]`
fn reboot(ctx: &mut Ctx) -> Reply {
    let o = opts_or_bad!(ctx, &["force", "uefi", "to-os"], &["delay"]);
    let delay = match delay_of(&o) {
        Ok(d) => d,
        Err(r) => return r,
    };
    if o.flag("uefi") && o.flag("to-os") {
        return Reply::error(Status::BadArgs, "--uefi and --to-os exclude each other");
    }
    let probe = &ctx.daemon.probe;
    if o.flag("uefi") {
        // EFI_OS_INDICATIONS_BOOT_TO_FW_UI
        if let Err(e) = labprobe::firmware::set_os_indications(probe, 1) {
            return Reply::error(probe_err(&e), &format!("cannot request firmware setup: {}", e));
        }
    }
    if o.flag("to-os") {
        let entry = match labprobe::firmware::probe(probe) {
            Ok(info) => match labprobe::firmware::internal_os_entry(&info) {
                Some(e) => e,
                None => return Reply::error(Status::NotFound, "no internal OS boot entry found in the UEFI boot list"),
            },
            Err(e) => return Reply::error(probe_err(&e), &format!("cannot read UEFI boot entries: {}", e)),
        };
        if let Err(e) = labprobe::firmware::set_boot_next(probe, entry) {
            return Reply::error(probe_err(&e), &format!("cannot set BootNext: {}", e));
        }
    }
    schedule(ctx, RebootCmd::Restart, delay);
    answer("reboot", delay, |w| {
        w.field_bool("uefi", o.flag("uefi"));
        w.field_bool("to_os", o.flag("to-os"));
        w.field_bool("force", o.flag("force"));
    })
}

fn poweroff(ctx: &mut Ctx) -> Reply {
    let o = opts_or_bad!(ctx, &[], &["delay"]);
    let delay = match delay_of(&o) {
        Ok(d) => d,
        Err(r) => return r,
    };
    schedule(ctx, RebootCmd::PowerOff, delay);
    answer("poweroff", delay, |_| {})
}

#[cfg(test)]
mod tests {
    use crate::registry::tests_support::*;
    use labproto::keys::Role;
    use labproto::Status;

    #[test]
    fn reboot_announces_shutdown_and_validates() {
        let d = test_daemon();
        d.set_state("ready");
        let (r, _) = run_with(&d, Role::Admin, "reboot", &["--delay", "5"]);
        assert_eq!(r.status, Status::Ok);
        let j = String::from_utf8(r.body).unwrap();
        assert!(j.contains("\"action\":\"reboot\"") && j.contains("\"in_s\":5"), "{}", j);
        assert_eq!(d.state_str(), "shutdown");
        assert_eq!(run_with(&d, Role::Admin, "reboot", &["--delay", "99999"]).0.status, Status::BadArgs);
        assert_eq!(run_with(&d, Role::Admin, "reboot", &["--uefi", "--to-os"]).0.status, Status::BadArgs);
        assert_eq!(run_with(&d, Role::Ro, "poweroff", &[]).0.status, Status::Eperm);
        assert_eq!(run_with(&d, Role::Admin, "poweroff", &[]).0.status, Status::Ok);
        assert_eq!(run_with(&d, Role::Admin, "kexec", &["--kernel", "/x"]).0.status, Status::Unsupported);
    }
}
