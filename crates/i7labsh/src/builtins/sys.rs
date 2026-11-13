//! System builtins: mount umount dmesg ps kill free df uptime uname date sync reboot poweroff halt lsmod insmod.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;

use super::{civil_from_days, fail, human, short_flags, usage};
use crate::ffi::{self, mount_flags as mf};
use crate::{Io, Shell};

// ---------------------------------------------------------------- mount / umount

/// `ro,nosuid,nodev,noexec,noatime,remount,bind,rw` become flags; everything else is the filesystem data string.
pub fn parse_mount_opts(opts: &str) -> (u64, String) {
    let mut flags = 0u64;
    let mut data = Vec::new();
    for o in opts.split(',').filter(|o| !o.is_empty()) {
        match o {
            "ro" => flags |= mf::MS_RDONLY,
            "rw" | "defaults" => {}
            "nosuid" => flags |= mf::MS_NOSUID,
            "nodev" => flags |= mf::MS_NODEV,
            "noexec" => flags |= mf::MS_NOEXEC,
            "noatime" => flags |= mf::MS_NOATIME,
            "remount" => flags |= mf::MS_REMOUNT,
            "bind" => flags |= mf::MS_BIND,
            other => data.push(other),
        }
    }
    (flags, data.join(","))
}

const AUTO_TYPES: &[&str] = &["ext4", "vfat", "iso9660", "xfs", "btrfs", "squashfs", "exfat"];

pub fn mount(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    if args.is_empty() {
        return match std::fs::read_to_string("/proc/mounts") {
            Ok(t) => {
                for l in t.lines() {
                    let f: Vec<&str> = l.split_whitespace().collect();
                    if f.len() >= 4 && !io.try_out(&format!("{} on {} type {} ({})\n", f[0], f[1], f[2], f[3])) {
                        return 1;
                    }
                }
                0
            }
            Err(e) => fail(io, "mount", format!("/proc/mounts: {e}")),
        };
    }
    let (mut fstype, mut opts, mut bind) = (None::<String>, String::new(), false);
    let mut ops = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-t" => {
                i += 1;
                fstype = args.get(i).cloned();
            }
            "-o" => {
                i += 1;
                opts = args.get(i).cloned().unwrap_or_default();
            }
            "--bind" | "-B" => bind = true,
            a if a.starts_with('-') => return fail(io, "mount", format!("invalid option -- '{a}'")),
            a => ops.push(a.to_string()),
        }
        i += 1;
    }
    if fstype.is_none() && args.iter().any(|a| a == "-t") {
        return usage(io, "mount");
    }
    let (mut flags, data) = parse_mount_opts(&opts);
    if bind {
        flags |= mf::MS_BIND;
    }
    let (src, target) = match ops.as_slice() {
        [t] => ("none".to_string(), t.clone()),
        [s, t] => (s.clone(), t.clone()),
        _ => return usage(io, "mount"),
    };
    let pseudo = flags & (mf::MS_BIND | mf::MS_REMOUNT) != 0;
    let r = match (&fstype, pseudo) {
        (Some(t), _) => ffi::do_mount(&src, &target, t, flags, &data),
        (None, true) => ffi::do_mount(&src, &target, "none", flags, &data),
        (None, false) => {
            let mut last = None;
            let mut ok = false;
            for t in AUTO_TYPES {
                match ffi::do_mount(&src, &target, t, flags, &data) {
                    Ok(()) => {
                        ok = true;
                        break;
                    }
                    Err(e) => last = Some(e),
                }
                // EINVAL/ENODEV: wrong filesystem type, try the next; anything else is final
                if !matches!(last.as_ref().and_then(|e| e.raw_os_error()), Some(22) | Some(19)) {
                    break;
                }
            }
            if ok {
                Ok(())
            } else {
                Err(last.unwrap_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput)))
            }
        }
    };
    match r {
        Ok(()) => 0,
        Err(e) => fail(io, "mount", format!("{src} on {target}: {e}")),
    }
}

pub fn umount(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let (flags, ops) = match short_flags(args, "l") {
        Ok(x) => x,
        Err(e) => return fail(io, "umount", e),
    };
    if ops.is_empty() {
        return usage(io, "umount");
    }
    let mut st = 0;
    for t in ops {
        if let Err(e) = ffi::do_umount(t, flags.contains('l')) {
            st = fail(io, "umount", format!("{t}: {e}"));
        }
    }
    st
}

// ---------------------------------------------------------------- dmesg

/// One /dev/kmsg record `pri,seq,usec,flags[,..];text` -> `[ secs.micros] text`. Continuation lines (leading space,
/// `KEY=value` dictionary entries) return None.
pub fn format_kmsg(rec: &str, timestamps: bool) -> Option<String> {
    if rec.starts_with(' ') {
        return None;
    }
    let (head, text) = rec.split_once(';')?;
    let text = text.lines().next().unwrap_or("");
    if !timestamps {
        return Some(text.to_string());
    }
    let usec: u64 = head.split(',').nth(2)?.parse().ok()?;
    Some(format!("[{:5}.{:06}] {}", usec / 1_000_000, usec % 1_000_000, text))
}

pub fn dmesg(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let (flags, _) = match short_flags(args, "t") {
        Ok(x) => x,
        Err(e) => return fail(io, "dmesg", e),
    };
    let mut f = match std::fs::OpenOptions::new().read(true).custom_flags(0o4000 /* O_NONBLOCK */).open("/dev/kmsg") {
        Ok(f) => f,
        Err(e) => return fail(io, "dmesg", format!("/dev/kmsg: {e}")),
    };
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match f.read(&mut buf) {
            Ok(0) => return 0,
            Ok(n) => {
                if let Some(l) = format_kmsg(&String::from_utf8_lossy(&buf[..n]), !flags.contains('t')) {
                    if !io.try_out(&format!("{l}\n")) {
                        return 1;
                    }
                }
            }
            Err(e) if e.raw_os_error() == Some(32) => continue, // EPIPE: records were overwritten, keep reading
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return 0,
            Err(e) => return fail(io, "dmesg", e),
        }
    }
}

// ---------------------------------------------------------------- ps / kill

#[derive(Debug, PartialEq, Eq)]
pub struct ProcStat {
    pub pid: i32,
    pub comm: String,
    pub state: char,
    pub ppid: i32,
}

/// /proc/PID/stat: `pid (comm) S ppid ...`; comm may contain spaces and parentheses, so split at the LAST ')'.
pub fn parse_stat(s: &str) -> Option<ProcStat> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    let pid = s[..open].trim().parse().ok()?;
    let mut rest = s[close + 1..].split_whitespace();
    let state = rest.next()?.chars().next()?;
    let ppid = rest.next()?.parse().ok()?;
    Some(ProcStat { pid, comm: s[open + 1..close].to_string(), state, ppid })
}

pub fn ps(_: &mut Shell, _: &[String], io: &mut Io) -> i32 {
    let mut procs: Vec<(ProcStat, String)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            let name = e.file_name();
            let Some(n) = name.to_str().filter(|n| n.bytes().all(|b| b.is_ascii_digit())) else { continue };
            let Some(st) = std::fs::read_to_string(format!("/proc/{n}/stat")).ok().and_then(|s| parse_stat(&s)) else { continue };
            let cmd = std::fs::read(format!("/proc/{n}/cmdline")).map(|b| b.split(|&c| c == 0).filter(|a| !a.is_empty()).map(|a| String::from_utf8_lossy(a).into_owned()).collect::<Vec<_>>().join(" ")).unwrap_or_default();
            let cmd = if cmd.is_empty() { format!("[{}]", st.comm) } else { cmd };
            procs.push((st, labproto::text::sanitize(&cmd).into_owned()));
        }
    }
    procs.sort_by_key(|(s, _)| s.pid);
    io.out("  PID  PPID S COMMAND\n");
    for (s, c) in procs {
        if !io.try_out(&format!("{:5} {:5} {} {}\n", s.pid, s.ppid, s.state, c)) {
            return 1;
        }
    }
    0
}

pub const SIGNALS: &[(&str, i32)] = &[
    ("HUP", 1), ("INT", 2), ("QUIT", 3), ("ILL", 4), ("TRAP", 5), ("ABRT", 6), ("BUS", 7), ("FPE", 8), ("KILL", 9), ("USR1", 10),
    ("SEGV", 11), ("USR2", 12), ("PIPE", 13), ("ALRM", 14), ("TERM", 15), ("CHLD", 17), ("CONT", 18), ("STOP", 19), ("TSTP", 20),
];

/// `9`, `KILL`, `SIGKILL`, `kill` -> 9
pub fn parse_signal(s: &str) -> Option<i32> {
    if let Ok(n) = s.parse::<i32>() {
        return (0..=64).contains(&n).then_some(n);
    }
    let u = s.to_ascii_uppercase();
    let u = u.strip_prefix("SIG").unwrap_or(&u);
    SIGNALS.iter().find(|(n, _)| *n == u).map(|(_, v)| *v)
}

pub fn kill(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    if args.first().map(String::as_str) == Some("-l") {
        io.out(&SIGNALS.iter().map(|(n, v)| format!("{v}) SIG{n}")).collect::<Vec<_>>().join("\n"));
        io.out("\n");
        return 0;
    }
    let (mut sig, mut rest) = (ffi::SIGTERM, args);
    if let Some(a) = args.first() {
        if a == "-s" {
            let Some(s) = args.get(1).and_then(|s| parse_signal(s)) else { return usage(io, "kill") };
            sig = s;
            rest = &args[2..];
        } else if let Some(spec) = a.strip_prefix('-').filter(|s| !s.is_empty()) {
            let Some(s) = parse_signal(spec) else { return fail(io, "kill", format!("{spec}: invalid signal specification")) };
            sig = s;
            rest = &args[1..];
        }
    }
    if rest.is_empty() {
        return usage(io, "kill");
    }
    let mut st = 0;
    for p in rest {
        match p.parse::<i32>() {
            Ok(pid) => {
                if let Err(e) = ffi::send_signal(pid, sig) {
                    st = fail(io, "kill", format!("({pid}): {e}"));
                }
            }
            Err(_) => st = fail(io, "kill", format!("{p}: arguments must be process IDs")),
        }
    }
    st
}

// ---------------------------------------------------------------- free / df / uptime / uname / date

/// `Key:   123 kB` lines -> (key, kB)
pub fn parse_meminfo(text: &str) -> std::collections::HashMap<String, u64> {
    text.lines().filter_map(|l| {
        let (k, v) = l.split_once(':')?;
        Some((k.to_string(), v.split_whitespace().next()?.parse().ok()?))
    }).collect()
}

pub fn free(_: &mut Shell, _: &[String], io: &mut Io) -> i32 {
    let text = match std::fs::read_to_string("/proc/meminfo") {
        Ok(t) => t,
        Err(e) => return fail(io, "free", format!("/proc/meminfo: {e}")),
    };
    let m = parse_meminfo(&text);
    let g = |k: &str| m.get(k).copied().unwrap_or(0) / 1024;
    let (total, avail, free_, buf, cache, shmem) = (g("MemTotal"), g("MemAvailable"), g("MemFree"), g("Buffers"), g("Cached"), g("Shmem"));
    io.out("              total        used        free      shared  buff/cache   available   (MiB)\n");
    io.out(&format!("Mem:   {:>12}{:>12}{:>12}{:>12}{:>12}{:>12}\n", total, total.saturating_sub(avail), free_, shmem, buf + cache, avail));
    io.out(&format!("Swap:  {:>12}{:>12}{:>12}\n", g("SwapTotal"), g("SwapTotal").saturating_sub(g("SwapFree")), g("SwapFree")));
    0
}

pub fn df(_: &mut Shell, _: &[String], io: &mut Io) -> i32 {
    let text = match std::fs::read_to_string("/proc/mounts") {
        Ok(t) => t,
        Err(e) => return fail(io, "df", format!("/proc/mounts: {e}")),
    };
    io.out(&format!("{:<20} {:>8} {:>8} {:>8} {:>4} {}\n", "Filesystem", "Size", "Used", "Avail", "Use%", "Mounted on"));
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 3 {
            continue;
        }
        let Ok(u) = ffi::fs_usage(f[1]) else { continue };
        if u.total == 0 {
            continue; // proc, sysfs, devpts, ...
        }
        let used = u.total - u.free;
        let pct = if used + u.avail == 0 { 0 } else { (used * 100).div_ceil(used + u.avail) };
        if !io.try_out(&format!("{:<20} {:>8} {:>8} {:>8} {:>3}% {}\n", f[0], human(u.total), human(used), human(u.avail), pct, f[1])) {
            return 1;
        }
    }
    0
}

pub fn uptime(_: &mut Shell, _: &[String], io: &mut Io) -> i32 {
    let up: f64 = std::fs::read_to_string("/proc/uptime").ok().and_then(|s| s.split_whitespace().next()?.parse().ok()).unwrap_or(0.0);
    let load = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let l: Vec<&str> = load.split_whitespace().take(3).collect();
    let secs = up as u64;
    let (d, h, m) = (secs / 86400, secs % 86400 / 3600, secs % 3600 / 60);
    let span = if d > 0 { format!("{d} days, {h}:{m:02}") } else if h > 0 { format!("{h}:{m:02}") } else { format!("{m} min") };
    io.out(&format!("up {}, load average: {}\n", span, l.join(", ")));
    0
}

pub fn uname(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let (flags, _) = match short_flags(args, "asnrvm") {
        Ok(x) => x,
        Err(e) => return fail(io, "uname", e),
    };
    let rd = |f: &str| std::fs::read_to_string(format!("/proc/sys/kernel/{f}")).map(|s| s.trim().to_string()).unwrap_or_default();
    let all = flags.contains('a');
    let mut parts = Vec::new();
    if flags.is_empty() || all || flags.contains('s') {
        parts.push(rd("ostype"));
    }
    if all || flags.contains('n') {
        parts.push(rd("hostname"));
    }
    if all || flags.contains('r') {
        parts.push(rd("osrelease"));
    }
    if all || flags.contains('v') {
        parts.push(rd("version"));
    }
    if all || flags.contains('m') {
        parts.push(std::env::consts::ARCH.to_string());
    }
    io.out(&format!("{}\n", parts.join(" ")));
    0
}

/// "Thu Nov 12 10:20:30 UTC 2026"
pub fn fmt_date(secs: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"]; // 1970-01-01 was a Thursday
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let days = secs.div_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let t = secs.rem_euclid(86_400);
    format!("{} {} {:2} {:02}:{:02}:{:02} UTC {}", DAYS[days.rem_euclid(7) as usize], MONTHS[(m - 1) as usize], d, t / 3600, t % 3600 / 60, t % 60, y)
}

pub fn date(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let mut fmt = None;
    for a in args {
        match a.as_str() {
            "-u" => {}
            f if f.starts_with('+') => fmt = Some(f[1..].to_string()),
            a => return fail(io, "date", format!("{a}: unsupported (UTC only; `date [-u] [+%s]`; use `lab time.set` to set the clock)")),
        }
    }
    match fmt.as_deref() {
        None => io.out(&format!("{}\n", fmt_date(now))),
        Some("%s") => io.out(&format!("{now}\n")),
        Some(other) => return fail(io, "date", format!("format '+{other}' unsupported (only +%s)")),
    }
    0
}

// ---------------------------------------------------------------- sync / power / modules

pub fn sync(_: &mut Shell, _: &[String], _: &mut Io) -> i32 {
    ffi::do_sync();
    0
}

/// Power actions go through init (PID 1) so services are stopped cleanly. Refuses when PID 1 is not our init, so a
/// shell run on a development machine cannot signal someone else's init.
fn power(io: &mut Io, name: &str, sig: i32) -> i32 {
    let comm = std::fs::read_to_string("/proc/1/comm").unwrap_or_default();
    if !matches!(comm.trim(), "init" | "i7lab-init") {
        return fail(io, name, format!("PID 1 is '{}', not i7lab-init: refusing", comm.trim()));
    }
    ffi::do_sync();
    match ffi::send_signal(1, sig) {
        Ok(()) => 0,
        Err(e) => fail(io, name, e),
    }
}

pub fn reboot(_: &mut Shell, _: &[String], io: &mut Io) -> i32 {
    power(io, "reboot", ffi::SIGTERM)
}
pub fn poweroff(_: &mut Shell, _: &[String], io: &mut Io) -> i32 {
    power(io, "poweroff", ffi::SIGUSR2)
}
pub fn halt(_: &mut Shell, _: &[String], io: &mut Io) -> i32 {
    power(io, "halt", ffi::SIGUSR1)
}

pub fn lsmod(_: &mut Shell, _: &[String], io: &mut Io) -> i32 {
    let text = match std::fs::read_to_string("/proc/modules") {
        Ok(t) => t,
        Err(e) => return fail(io, "lsmod", format!("/proc/modules: {e}")),
    };
    io.out(&format!("{:<28} {:>9}  Used by\n", "Module", "Size"));
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 4 {
            let by = f[3].trim_end_matches(',');
            let by = if by == "-" { "" } else { by };
            if !io.try_out(&format!("{:<28} {:>9}  {} {}\n", f[0], f[1], f[2], by)) {
                return 1;
            }
        }
    }
    0
}

pub fn insmod(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let Some((path, params)) = args.split_first() else { return usage(io, "insmod") };
    match ffi::finit_module(path, &params.join(" ")) {
        Ok(()) => 0,
        Err(e) => fail(io, "insmod", format!("{path}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn mount_options() {
        assert_eq!(parse_mount_opts("ro,nosuid,nodev,noexec"), (mf::MS_RDONLY | mf::MS_NOSUID | mf::MS_NODEV | mf::MS_NOEXEC, String::new()));
        assert_eq!(parse_mount_opts("rw,defaults"), (0, String::new()));
        assert_eq!(parse_mount_opts("remount,ro"), (mf::MS_REMOUNT | mf::MS_RDONLY, String::new()));
        assert_eq!(parse_mount_opts("size=64m,mode=0755,noatime"), (mf::MS_NOATIME, "size=64m,mode=0755".to_string()));
        assert_eq!(parse_mount_opts(""), (0, String::new()));
    }

    #[test]
    fn mount_list_and_usage() {
        let mut s = sh();
        let (st, out, _) = run(&mut s, "mount");
        assert_eq!(st, 0);
        assert!(out.contains(" on / type "), "{out}");
        assert_eq!(run(&mut s, "mount -t").0, 2);
        assert_eq!(run(&mut s, "mount -z x").0, 1);
        assert_eq!(run(&mut s, "umount").0, 2);
    }

    #[test]
    fn kmsg_records() {
        assert_eq!(format_kmsg("6,339,5140900,-;Linux version 6.18\n SUBSYSTEM=x\n", true).as_deref(), Some("[    5.140900] Linux version 6.18"));
        assert_eq!(format_kmsg("6,339,5140900,-;hi\n", false).as_deref(), Some("hi"));
        assert_eq!(format_kmsg(" DEVICE=+pci:0000\n", true), None);
        assert_eq!(format_kmsg("garbage", true), None);
        assert_eq!(format_kmsg("6,1,2,-;x", true).as_deref(), Some("[    0.000002] x"));
    }

    #[test]
    fn proc_stat_parsing() {
        let s = parse_stat("42 (my (weird) cmd) S 1 42 42 0 -1 4194560").unwrap();
        assert_eq!(s, ProcStat { pid: 42, comm: "my (weird) cmd".into(), state: 'S', ppid: 1 });
        assert_eq!(parse_stat("junk"), None);
        assert_eq!(parse_stat("1 (init) R"), None);
    }

    #[test]
    fn ps_lists_ourselves() {
        let mut s = sh();
        let (st, out, _) = run(&mut s, "ps");
        assert_eq!(st, 0);
        assert!(out.starts_with("  PID  PPID S COMMAND"));
        assert!(out.lines().any(|l| l.trim_start().starts_with(&std::process::id().to_string())), "{out}");
    }

    #[test]
    fn signal_names() {
        assert_eq!(parse_signal("9"), Some(9));
        assert_eq!(parse_signal("KILL"), Some(9));
        assert_eq!(parse_signal("sigterm"), Some(15));
        assert_eq!(parse_signal("usr1"), Some(10));
        assert_eq!(parse_signal("NOPE"), None);
        assert_eq!(parse_signal("99"), None);
    }

    #[test]
    fn kill_a_child() {
        let mut s = sh();
        let mut c = std::process::Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let (st, _, _) = run(&mut s, &format!("kill -KILL {}", c.id()));
        assert_eq!(st, 0);
        let status = c.wait().unwrap();
        assert!(!status.success());
        assert_eq!(run(&mut s, "kill").0, 2);
        assert_eq!(run(&mut s, "kill -NOPE 1").0, 1);
        assert_eq!(run(&mut s, "kill abc").0, 1);
        assert!(run(&mut s, "kill -l").1.contains("9) SIGKILL"));
    }

    #[test]
    fn meminfo() {
        let m = parse_meminfo("MemTotal:       16314232 kB\nMemFree:  100 kB\nHugePages_Total:       0\nbad line\n");
        assert_eq!(m["MemTotal"], 16314232);
        assert_eq!(m["HugePages_Total"], 0);
        let mut s = sh();
        let (_, out, _) = run(&mut s, "free");
        assert!(out.contains("Mem:") && out.contains("Swap:"));
    }

    #[test]
    fn df_uptime_uname_run() {
        let mut s = sh();
        let (st, out, _) = run(&mut s, "df");
        assert_eq!(st, 0);
        assert!(out.starts_with("Filesystem") && out.lines().count() > 1);
        assert!(run(&mut s, "uptime").1.starts_with("up "));
        assert_eq!(run(&mut s, "uname").1, "Linux\n");
        assert!(run(&mut s, "uname -m").1.trim() == "x86_64" || cfg!(not(target_arch = "x86_64")));
        assert_eq!(run(&mut s, "uname -a").1.split(' ').next(), Some("Linux"));
    }

    #[test]
    fn date_formats() {
        assert_eq!(fmt_date(0), "Thu Jan  1 00:00:00 UTC 1970");
        assert_eq!(fmt_date(1_700_000_000), "Tue Nov 14 22:13:20 UTC 2023");
        let mut s = sh();
        assert!(run(&mut s, "date +%s").1.trim().parse::<u64>().unwrap() > 1_700_000_000);
        assert!(run(&mut s, "date -u").1.contains("UTC"));
        assert_eq!(run(&mut s, "date -s x").0, 1);
    }

    #[test]
    fn power_refuses_when_pid1_is_not_ours() {
        // on a development host or CI container PID 1 is systemd/docker-init/tini, never "i7lab-init"
        let comm = std::fs::read_to_string("/proc/1/comm").unwrap_or_default();
        if comm.trim() == "init" || comm.trim() == "i7lab-init" {
            return; // could be the real thing: do not signal it from a test
        }
        let mut s = sh();
        let (st, _, err) = run(&mut s, "reboot");
        assert_eq!(st, 1);
        assert!(err.contains("refusing"));
    }

    #[test]
    fn lsmod_and_dmesg_run() {
        let mut s = sh();
        assert_eq!(run(&mut s, "lsmod").0, 0);
        // /dev/kmsg is not readable in every CI container: either it works or the error names the file
        let (st, _, err) = run(&mut s, "dmesg -t");
        assert!(st == 0 || err.contains("/dev/kmsg"), "{err}");
    }
}
