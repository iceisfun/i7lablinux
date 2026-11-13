//! ping, id, cmds, stats, time.set.

use labproto::catalog::Access;
use labproto::json::JsonWriter;
use labproto::Status;

use crate::registry::{Ctx, Handler, Reply};

pub const TABLE: &[(&str, Handler)] = &[("ping", ping), ("id", id), ("cmds", cmds), ("stats", stats), ("time.set", time_set)];

pub const ECHO_MAX: usize = 1024;

fn load_avg() -> [f64; 3] {
    let s = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let mut it = s.split_whitespace().map(|x| x.parse::<f64>().unwrap_or(0.0));
    [it.next().unwrap_or(0.0), it.next().unwrap_or(0.0), it.next().unwrap_or(0.0)]
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn ping(ctx: &mut Ctx) -> Reply {
    let echo = ctx.args.join(" ");
    if echo.len() > ECHO_MAX {
        return Reply::error(Status::TooBig, "echo longer than 1024 bytes");
    }
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_str("echo", &echo);
    w.field_u64("uptime_ms", labproto::sys::uptime_ms());
    w.field_str("boot_id", &labproto::crypto::hex(&ctx.daemon.boot_id));
    w.key("load");
    w.begin_array();
    for l in load_avg() {
        w.f64(l);
    }
    w.end_array();
    w.field_u64("time", unix_now());
    w.end_object();
    Reply::json(w.finish())
}

fn id(ctx: &mut Ctx) -> Reply {
    let d = ctx.daemon;
    let ident = &d.ident;
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_u64("v", 1);
    w.field_str("version", labproto::VERSION);
    w.field_str("build", &d.config.image_build);
    w.field_str("hostname", &d.config.hostname);
    w.field_str("boot_id", &labproto::crypto::hex(&d.boot_id));
    w.field_str("role", ctx.role.name());
    w.field_str("kid", &d.kid());
    w.field_str("state", &d.state_str());
    w.field_u64("proto", labproto::frame::VERSION as u64);
    w.field_u64("caps", labproto::catalog::caps_bits() as u64);
    w.field_str("product", &ident.product);
    w.field_str("vendor", &ident.vendor);
    w.field_str("serial", &ident.serial);
    w.field_str("board", &ident.board);
    w.field_str("board_serial", &ident.board_serial);
    w.field_str("kernel", &ident.kernel);
    w.field_u64("uptime_s", labproto::sys::uptime_ms() / 1000);
    w.field_opt_u64("http_port", d.flags.http_port().map(u64::from));
    w.field_bool("ether", d.flags.ether_up());
    w.end_object();
    Reply::json(w.finish())
}

fn cmds(ctx: &mut Ctx) -> Reply {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_u64("v", 1);
    w.field_str("release", labproto::catalog::CURRENT_RELEASE);
    w.key("commands");
    w.begin_array();
    for c in ctx.daemon.registry.commands() {
        w.begin_object();
        w.field_u64("id", c.spec.id as u64);
        w.field_str("name", c.spec.name);
        w.field_u64("group", c.spec.group as u64);
        w.field_str("access", match c.spec.access { Access::Ro => "ro", Access::Admin => "admin", Access::RoLimitedPaths => "ro-limited" });
        w.field_bool("streams", c.spec.streams);
        w.field_bool("planned", c.spec.planned());
        w.field_str("since", c.spec.since);
        w.field_str("usage", c.spec.usage);
        w.field_str("summary", c.spec.summary);
        w.end_object();
    }
    w.end_array();
    w.end_object();
    Reply::json(w.finish())
}

fn stats(ctx: &mut Ctx) -> Reply {
    Reply::json(ctx.daemon.stats.to_json(ctx.daemon.sessions_open.load(std::sync::atomic::Ordering::Relaxed)))
}

/// `time.set UNIX_SECONDS`: audit timestamps before SNTP. Accepts 2020-01-01 .. 2200-01-01 only.
fn time_set(ctx: &mut Ctx) -> Reply {
    let secs: i64 = match ctx.args.as_slice() {
        [s] => match s.parse() {
            Ok(v) if (1_577_836_800..7_258_118_400).contains(&v) => v,
            _ => return Reply::error(Status::BadArgs, "UNIX_SECONDS must be between 2020-01-01 and 2200-01-01"),
        },
        _ => return Reply::error(Status::BadArgs, "usage: time.set UNIX_SECONDS"),
    };
    if ctx.daemon.config.power_dry_run {
        // tests never touch the clock
    } else if let Err(e) = crate::ffi::clock_settime(secs) {
        return Reply::error(if e.kind() == std::io::ErrorKind::PermissionDenied { Status::Eperm } else { Status::Io }, &e.to_string());
    }
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_u64("v", 1);
    w.field_i64("set", secs);
    w.end_object();
    Reply::json(w.finish())
}

#[cfg(test)]
mod tests {
    use crate::registry::tests_support::*;
    use labproto::keys::Role;
    use labproto::Status;

    #[test]
    fn core_commands() {
        let d = test_daemon();
        let (r, _) = run_with(&d, Role::Ro, "ping", &["hello", "there"]);
        assert!(String::from_utf8(r.body).unwrap().contains("\"echo\":\"hello there\""));
        let (r, _) = run_with(&d, Role::Ro, "ping", &[&"x".repeat(2000)]);
        assert_eq!(r.status, Status::TooBig);
        let (r, _) = run_with(&d, Role::Ro, "id", &[]);
        let j = String::from_utf8(r.body).unwrap();
        assert!(j.contains("\"role\":\"ro\"") && j.contains("\"kid\":\"a:-,r:-\""), "{}", j);
        let (r, _) = run_with(&d, Role::Ro, "cmds", &[]);
        let j = String::from_utf8(r.body).unwrap();
        assert!(j.contains("\"name\":\"blk.write\"") && j.contains("\"planned\":true"));
        assert_eq!(run_with(&d, Role::Ro, "stats", &[]).0.status, Status::Ok);
        assert_eq!(run_with(&d, Role::Admin, "time.set", &["1800000000"]).0.status, Status::Ok);
        assert_eq!(run_with(&d, Role::Admin, "time.set", &["5"]).0.status, Status::BadArgs);
        assert_eq!(run_with(&d, Role::Ro, "time.set", &["1800000000"]).0.status, Status::Eperm);
    }
}
