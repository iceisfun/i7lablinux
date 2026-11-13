//! Hardware and agent builtins: lspci lsblk lsusb sensors probe blk lab. Thin wrappers over `labprobe` and the
//! local control socket; the logic (probes, write gate, test engine) lives in those crates.

use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::sync::atomic::AtomicBool;

use labproto::args::Opts;
use labproto::json::to_json;
use labprobe::block::{self, Pattern, TestMode, TestSpec, WriteGuard, WriteRequest};
use labprobe::{inventory, ProbeCtx, Section};

use super::{fail, human, usage};
use super::fs::hexdump_lines;
use crate::{Io, Shell};

/// The live probe context with the boot media identity from `i7lab.boot=PARTUUID=..` filled in, so `blk` refuses the
/// stick it booted from even when i7labd is not running.
fn live_ctx() -> ProbeCtx {
    let mut ctx = ProbeCtx::live();
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    if let Some((_, v)) = labproto::cmdline::i7lab_args(&cmdline).into_iter().rev().find(|(k, _)| k == "boot") {
        let pu = v.strip_prefix("PARTUUID=").unwrap_or(&v).to_string();
        ctx.boot_disk = block::resolve_boot_disk(&ctx, &pu);
        ctx.boot_partuuid = Some(pu);
    }
    ctx
}

// ---------------------------------------------------------------- lspci lsblk lsusb sensors

pub fn lspci(_: &mut Shell, _: &[String], io: &mut Io) -> i32 {
    let rep = match labprobe::pci::probe(&ProbeCtx::live(), &labprobe::pci::PciOpts::default()) {
        Ok(r) => r,
        Err(e) => return fail(io, "lspci", e),
    };
    for d in &rep.devices {
        let name = match (&d.vendor_name, &d.device_name) {
            (Some(v), Some(n)) => format!("{v} {n}"),
            (Some(v), None) => v.clone(),
            _ => String::new(),
        };
        let drv = d.driver.as_deref().map(|d| format!(" [{d}]")).unwrap_or_else(|| " [no driver]".into());
        let line = format!("{} {} {} [{:04x}:{:04x}]{}\n", d.bdf, d.class_name, name, d.vendor, d.device, drv);
        if !io.try_out(&labproto::text::sanitize(&line)) {
            return 1;
        }
    }
    0
}

pub fn lsusb(_: &mut Shell, _: &[String], io: &mut Io) -> i32 {
    let rep = match labprobe::usb::probe(&ProbeCtx::live()) {
        Ok(r) => r,
        Err(e) => return fail(io, "lsusb", e),
    };
    for d in &rep.devices {
        let line = format!("Bus {:03} Device {:03}: ID {:04x}:{:04x} {} {}\n", d.busnum, d.devnum, d.vid, d.pid, d.manufacturer.as_deref().unwrap_or(""), d.product.as_deref().unwrap_or(""));
        if !io.try_out(&labproto::text::sanitize(&line)) {
            return 1;
        }
    }
    0
}

pub fn lsblk(_: &mut Shell, _: &[String], io: &mut Io) -> i32 {
    list_blocks(io)
}

fn list_blocks(io: &mut Io) -> i32 {
    let rep = match block::probe(&live_ctx(), false) {
        Ok(r) => r,
        Err(e) => return fail(io, "lsblk", e),
    };
    io.out(&format!("{:<10} {:>8} {:<6} {:<24} {:<20} {:<9} {}\n", "NAME", "SIZE", "KIND", "MODEL", "SERIAL", "WRITE", "MOUNTS/FLAGS"));
    for d in &rep.devices {
        let mut flags: Vec<String> = d.mounts.clone();
        if d.boot_media {
            flags.push("BOOT-MEDIA".into());
        }
        if d.read_only {
            flags.push("ro".into());
        }
        let line = format!(
            "{:<10} {:>8} {:<6} {:<24} {:<20} {:<9} {}\n",
            d.name,
            human(d.size_bytes),
            d.kind.name(),
            d.model.as_deref().unwrap_or("-"),
            d.serial.as_deref().unwrap_or("-"),
            format!("{:?}", d.write_safety.verdict),
            flags.join(",")
        );
        if !io.try_out(&labproto::text::sanitize(&line)) {
            return 1;
        }
    }
    0
}

pub fn sensors(_: &mut Shell, _: &[String], io: &mut Io) -> i32 {
    let rep = match labprobe::thermal::probe(&ProbeCtx::live()) {
        Ok(r) => r,
        Err(e) => return fail(io, "sensors", e),
    };
    for z in &rep.zones {
        if let Some(t) = z.temp_c {
            io.out(&format!("{}/{}: {:.1} C{}\n", z.kind, z.name, t, z.crit_c.map(|c| format!(" (crit {c:.0})")).unwrap_or_default()));
        }
    }
    for h in &rep.hwmon {
        for (unit, list) in [("C", &h.temps), ("rpm", &h.fans), ("mV", &h.volts), ("mW", &h.power)] {
            for s in list {
                io.out(&format!("{}/{}: {:.1} {}\n", h.name, s.label, s.value, unit));
            }
        }
    }
    for a in &rep.alarms {
        io.out(&format!("ALARM {a}\n"));
    }
    0
}

pub fn probe(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let Some(which) = args.first() else {
        io.out(&format!("sections: {} (or all)\n", Section::ALL.iter().map(|s| s.name()).collect::<Vec<_>>().join(" ")));
        return 0;
    };
    let sections: Vec<Section> = if which == "all" {
        Section::ALL.to_vec()
    } else {
        match Section::parse(which) {
            Some(s) => vec![s],
            None => return fail(io, "probe", format!("unknown section '{which}'")),
        }
    };
    let inv = inventory(&live_ctx(), &sections);
    io.out(&format!("{}\n", to_json(&inv)));
    0
}

// ---------------------------------------------------------------- blk

/// `4096`, `0x1000`, `1k`, `4m`, `2g`
pub fn parse_num(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x") {
        return u64::from_str_radix(h, 16).ok();
    }
    let (num, mul) = match s.chars().last()? {
        'k' | 'K' => (&s[..s.len() - 1], 1u64 << 10),
        'm' | 'M' => (&s[..s.len() - 1], 1 << 20),
        'g' | 'G' => (&s[..s.len() - 1], 1 << 30),
        _ => (s, 1),
    };
    num.parse::<u64>().ok()?.checked_mul(mul)
}

pub fn parse_pattern(s: &str) -> Option<Pattern> {
    match s {
        "zeros" => Some(Pattern::Zeros),
        "ones" => Some(Pattern::Ones),
        "aa55" => Some(Pattern::Aa55),
        _ => s.strip_prefix("seed=").and_then(parse_num).map(Pattern::Seeded),
    }
}

const BLK_READ_MAX: u64 = 1 << 20;

pub fn blk(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let Some((sub, rest)) = args.split_first() else { return usage(io, "blk") };
    match sub.as_str() {
        "ls" => list_blocks(io),
        "read" => blk_read(rest, io),
        "test" | "write" => blk_test(sub == "write", rest, io),
        _ => usage(io, "blk"),
    }
}

fn blk_read(args: &[String], io: &mut Io) -> i32 {
    let o = match Opts::parse(args, &[], &["offset", "count"]) {
        Ok(o) => o,
        Err(e) => return fail(io, "blk", e),
    };
    let [dev] = o.positional() else { return usage(io, "blk") };
    if !block::valid_dev_name(dev) {
        return fail(io, "blk", format!("bad device name '{dev}'"));
    }
    let offset = match o.value("offset").map(parse_num) {
        Some(Some(v)) => v,
        Some(None) => return fail(io, "blk", "bad --offset"),
        None => 0,
    };
    let count = match o.value("count").map(parse_num) {
        Some(Some(v)) => v.min(BLK_READ_MAX),
        Some(None) => return fail(io, "blk", "bad --count"),
        None => 512,
    };
    // read-only open; the gate is for writes only
    let f = match std::fs::File::open(format!("/dev/{dev}")) {
        Ok(f) => f,
        Err(e) => return fail(io, "blk", format!("/dev/{dev}: {e}")),
    };
    let mut buf = vec![0u8; count as usize];
    let n = match f.read_at(&mut buf, offset) {
        Ok(n) => n,
        Err(e) => return fail(io, "blk", format!("read at {offset}: {e}")),
    };
    for l in hexdump_lines(&buf[..n], offset) {
        if !io.try_out(&format!("{l}\n")) {
            return 1;
        }
    }
    0
}

fn blk_test(write: bool, args: &[String], io: &mut Io) -> i32 {
    // `blk write DEV ...`  ==  `blk test DEV write ...`
    let o = match Opts::parse(args, &["destructive"], &["serial", "mb", "pattern", "seed"]) {
        Ok(o) => o,
        Err(e) => return fail(io, "blk", e),
    };
    let (dev, mode) = match (write, o.positional()) {
        (true, [d]) => (d, TestMode::Write),
        (false, [d, m]) => (d, match m.as_str() {
            "read" => TestMode::Read,
            "verify" => TestMode::Verify,
            "write" => TestMode::Write,
            _ => return usage(io, "blk"),
        }),
        _ => return usage(io, "blk"),
    };
    if !block::valid_dev_name(dev) {
        return fail(io, "blk", format!("bad device name '{dev}'"));
    }
    let mb = o.value("mb").and_then(parse_num).unwrap_or(64);
    let pattern = match (o.value("pattern"), o.value("seed")) {
        (Some(p), _) => match parse_pattern(p) {
            Some(p) => p,
            None => return fail(io, "blk", "bad --pattern (zeros|ones|aa55|seed=N)"),
        },
        (None, Some(s)) => match parse_num(s) {
            Some(s) => Pattern::Seeded(s),
            None => return fail(io, "blk", "bad --seed"),
        },
        (None, None) => Pattern::Seeded(0x1757_AB11),
    };
    let ctx = live_ctx();
    let Some(device) = block::probe(&ctx, true).ok().and_then(|r| r.devices.into_iter().find(|d| &d.name == dev)) else {
        return fail(io, "blk", format!("{dev}: no such disk"));
    };
    let mut spec = TestSpec::new(dev, mode, pattern);
    spec.regions = TestSpec::default_regions(device.size_bytes, mb);
    spec.progress_ms = 500;

    // Writes only through the gate: a refused request never reaches the device.
    let guard = if mode == TestMode::Write {
        let req = WriteRequest { dev: dev.clone(), destructive: o.flag("destructive"), serial: o.value("serial").map(str::to_string), actor: "console".to_string() };
        match WriteGuard::acquire(&ctx, &req) {
            Ok(g) => Some(g),
            Err(r) => {
                io.err(&format!("blk: write to {dev} REFUSED by the safety gate:\n"));
                for reason in &r.reasons {
                    io.err(&format!("  - {}{}\n", reason.code(), reason.detail().map(|d| format!(": {d}")).unwrap_or_default()));
                }
                io.err("  (a write needs --destructive and --serial <the disk's serial>; mounted, boot, partitioned or signed disks stay refused unless the policy says otherwise; see docs/SAFETY.md)\n");
                return 3;
            }
        }
    } else {
        None
    };

    let cancel = AtomicBool::new(false);
    let errfd = io.stderr;
    let mut progress = |p: &block::Progress| {
        let mut e = Io { stdin: 0, stdout: errfd, stderr: errfd };
        e.out(&format!("\r{} {}/{} MiB {:.0} MiB/s   ", p.region, p.done_bytes >> 20, p.total_bytes >> 20, p.mib_s));
    };
    let rep = labprobe::block::run_test(&ctx, &spec, guard.as_ref(), &mut progress, &cancel);
    io.err("\r\x1b[K");
    if let Some(g) = &guard {
        let _ = g.reread_partitions();
    }
    match rep {
        Ok(r) => {
            io.out(&format!("{}\n", to_json(&r)));
            if r.ok {
                0
            } else {
                1
            }
        }
        Err(e) => fail(io, "blk", e),
    }
}

// ---------------------------------------------------------------- lab

pub fn lab(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let Some((cmd, rest)) = args.split_first() else { return usage(io, "lab") };
    if cmd == "help" {
        for c in labproto::catalog::CATALOG {
            let planned = if c.planned() { format!("  (planned {})", c.since) } else { String::new() };
            io.out(&format!("{:<12} {:<28} {}{}\n", c.name, c.usage, c.summary, planned));
        }
        return 0;
    }
    let Some(spec) = labproto::catalog::by_name(cmd) else { return fail(io, "lab", format!("unknown command '{cmd}' (lab help)")) };
    if spec.planned() {
        return fail(io, "lab", format!("{cmd} is planned for {}", spec.since));
    }
    match lab_call(spec.id, rest) {
        Ok((status, exit, body)) => {
            let _ = io.write_out(labproto::text::sanitize_bytes(&body).as_bytes());
            if !body.ends_with(b"\n") && !body.is_empty() {
                io.out("\n");
            }
            if status == labproto::Status::Ok {
                exit
            } else {
                io.err(&format!("lab: {} -> {}\n", cmd, status.name()));
                1
            }
        }
        Err(e) => fail(io, "lab", e),
    }
}

fn lab_call(id: u16, argv: &[String]) -> Result<(labproto::Status, i32, Vec<u8>), String> {
    let mut s = std::os::unix::net::UnixStream::connect(labproto::local::PATH).map_err(|e| format!("{}: {e} (is i7labd running?)", labproto::local::PATH))?;
    let t = Some(std::time::Duration::from_secs(30));
    let _ = s.set_read_timeout(t);
    let _ = s.set_write_timeout(t);
    s.write_all(&labproto::local::encode_request(id, argv)).map_err(|e| e.to_string())?;
    let mut len = [0u8; 4];
    s.read_exact(&mut len).map_err(|e| format!("reply: {e}"))?;
    let n = u32::from_be_bytes(len) as usize;
    if n > labproto::local::MAX_REPLY {
        return Err("reply too large".into());
    }
    let mut msg = vec![0u8; n];
    s.read_exact(&mut msg).map_err(|e| format!("reply: {e}"))?;
    let (st, exit, body) = labproto::local::decode_reply(&msg).ok_or("malformed reply")?;
    Ok((st, exit, body.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn numbers() {
        assert_eq!(parse_num("4096"), Some(4096));
        assert_eq!(parse_num("0x1000"), Some(4096));
        assert_eq!(parse_num("4k"), Some(4096));
        assert_eq!(parse_num("2M"), Some(2 << 20));
        assert_eq!(parse_num("1g"), Some(1 << 30));
        assert_eq!(parse_num("x"), None);
        assert_eq!(parse_num(""), None);
        assert_eq!(parse_num("99999999999999999g"), None);
    }

    #[test]
    fn patterns() {
        assert!(matches!(parse_pattern("zeros"), Some(Pattern::Zeros)));
        assert!(matches!(parse_pattern("aa55"), Some(Pattern::Aa55)));
        assert!(matches!(parse_pattern("seed=0x10"), Some(Pattern::Seeded(16))));
        assert!(parse_pattern("seed=").is_none());
        assert!(parse_pattern("random").is_none());
    }

    #[test]
    fn probe_lists_sections_and_rejects_unknown() {
        let mut s = sh();
        let (st, out, _) = run(&mut s, "probe");
        assert_eq!(st, 0);
        assert!(out.contains("pci") && out.contains("block") && out.contains("all"));
        assert_eq!(run(&mut s, "probe nonesuch").0, 1);
        let (st, out, _) = run(&mut s, "probe cpu");
        assert_eq!(st, 0);
        assert!(out.starts_with('{') && out.contains("\"cpu\""), "{out}");
    }

    #[test]
    fn simple_probes_run() {
        let mut s = sh();
        for c in ["lspci", "lsusb", "lsblk", "sensors"] {
            let (st, _, err) = run(&mut s, c);
            assert_eq!(st, 0, "{c}: {err}");
        }
    }

    #[test]
    fn blk_usage_and_name_validation() {
        let mut s = sh();
        assert_eq!(run(&mut s, "blk").0, 2);
        assert_eq!(run(&mut s, "blk frobnicate").0, 2);
        let (st, _, err) = run(&mut s, "blk read ../etc/passwd");
        assert_eq!(st, 1);
        assert!(err.contains("bad device name"));
        assert_eq!(run(&mut s, "blk read").0, 2);
        // a name that cannot exist never reaches the gate or any device
        let (st, out, err) = run(&mut s, "blk write nosuchdisk0 --destructive --serial X");
        assert_eq!((st, out.as_str()), (1, ""));
        assert!(err.contains("no such disk"), "{err}");
        assert_eq!(run(&mut s, "blk test nosuchdisk0 sideways").0, 2);
        assert_eq!(run(&mut s, "blk read nosuchdisk0").0, 1);
    }

    #[test]
    fn lab_help_lists_the_catalog_and_missing_socket_is_clear() {
        let mut s = sh();
        let (st, out, _) = run(&mut s, "lab help");
        assert_eq!(st, 0);
        assert!(out.contains("ping") && out.contains("blk.write") && out.contains("(planned v0.4)"));
        assert_eq!(run(&mut s, "lab").0, 2);
        let (st, _, err) = run(&mut s, "lab nonesuch");
        assert_eq!(st, 1);
        assert!(err.contains("unknown command"));
        let (st, _, err) = run(&mut s, "lab kexec");
        assert_eq!(st, 1);
        assert!(err.contains("planned"));
        if !std::path::Path::new(labproto::local::PATH).exists() {
            let (st, _, err) = run(&mut s, "lab ping");
            assert_eq!(st, 1);
            assert!(err.contains("is i7labd running"), "{err}");
        }
    }

    #[test]
    fn lab_roundtrip_over_a_unix_socket() {
        // The wire format is labproto::local; check the client against a one-shot server speaking it.
        use std::os::unix::net::UnixListener;
        let t = Tmp::new();
        let sock = t.path("ctl.sock");
        let l = UnixListener::bind(&sock).unwrap();
        let srv = std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut len = [0u8; 4];
            c.read_exact(&mut len).unwrap();
            let mut msg = vec![0u8; u32::from_be_bytes(len) as usize];
            c.read_exact(&mut msg).unwrap();
            let (cmd, argv) = labproto::local::decode_request(&msg).unwrap();
            assert_eq!((cmd, argv), (0x0001, vec!["hi".to_string()]));
            c.write_all(&labproto::local::encode_reply(labproto::Status::Ok, 0, b"{\"pong\":1}")).unwrap();
        });
        // lab_call talks to the fixed path; here we exercise encode/decode symmetrically instead of rebinding /run
        let mut c = std::os::unix::net::UnixStream::connect(&sock).unwrap();
        c.write_all(&labproto::local::encode_request(1, &["hi".to_string()])).unwrap();
        let mut len = [0u8; 4];
        c.read_exact(&mut len).unwrap();
        let mut msg = vec![0u8; u32::from_be_bytes(len) as usize];
        c.read_exact(&mut msg).unwrap();
        let (st, exit, body) = labproto::local::decode_reply(&msg).unwrap();
        assert_eq!((st, exit, body), (labproto::Status::Ok, 0, &b"{\"pong\":1}"[..]));
        srv.join().unwrap();
    }
}
