//! The builtin table and helpers shared by the builtins. Every applet of the image is here: there is no busybox.

use crate::{BuiltinSpec, Io, Shell};

mod core;
mod fs;
mod net;
mod probe;
mod sys;

macro_rules! b {
    ($name:expr, $usage:expr, $f:path) => {
        BuiltinSpec { name: $name, usage: $usage, run: $f }
    };
}

pub static TABLE: &[BuiltinSpec] = &[
    // shell state
    b!("cd", "cd [DIR|-]", core::cd),
    b!("pwd", "pwd", core::pwd),
    b!("echo", "echo [-n] [-e] [WORD..]", core::echo),
    b!("export", "export [NAME=VALUE..]   (every variable is exported)", core::export),
    b!("unset", "unset NAME..", core::unset),
    b!("env", "env", core::env),
    b!("exit", "exit [CODE]", core::exit),
    b!("help", "help [NAME]", core::help),
    b!("true", "true", core::true_),
    b!("false", "false", core::false_),
    b!("sleep", "sleep SECONDS", core::sleep),
    b!("source", "source FILE   (also: . FILE)", core::source),
    b!(".", ". FILE", core::source),
    // files
    b!("ls", "ls [-1alhd] [PATH..]", fs::ls),
    b!("cat", "cat [FILE..]   (- or none: stdin)", fs::cat),
    b!("cp", "cp [-r] SRC.. DST", fs::cp),
    b!("mv", "mv SRC.. DST", fs::mv),
    b!("rm", "rm [-rf] PATH..", fs::rm),
    b!("mkdir", "mkdir [-p] DIR..", fs::mkdir),
    b!("rmdir", "rmdir DIR..", fs::rmdir),
    b!("ln", "ln [-s] TARGET LINK", fs::ln),
    b!("touch", "touch FILE..", fs::touch),
    b!("head", "head [-n N] [FILE]", fs::head),
    b!("tail", "tail [-n N] [FILE]", fs::tail),
    b!("wc", "wc [-lwc] [FILE..]", fs::wc),
    b!("grep", "grep [-vicnF] TEXT [FILE..]   (substring match, no regex)", fs::grep),
    b!("hexdump", "hexdump [FILE]   (canonical -C layout)", fs::hexdump),
    b!("sha256sum", "sha256sum [FILE..]", fs::sha256sum),
    // system
    b!("mount", "mount [-t TYPE] [-o OPTS] [--bind] [SRC] TARGET   (no args: list)", sys::mount),
    b!("umount", "umount [-l] TARGET", sys::umount),
    b!("dmesg", "dmesg [-t]", sys::dmesg),
    b!("ps", "ps", sys::ps),
    b!("kill", "kill [-SIGNAL] PID..   |   kill -l", sys::kill),
    b!("free", "free", sys::free),
    b!("df", "df", sys::df),
    b!("uptime", "uptime", sys::uptime),
    b!("uname", "uname [-asnrvm]", sys::uname),
    b!("date", "date [-u] [+%s]   (UTC)", sys::date),
    b!("sync", "sync", sys::sync),
    b!("reboot", "reboot", sys::reboot),
    b!("poweroff", "poweroff", sys::poweroff),
    b!("halt", "halt", sys::halt),
    b!("lsmod", "lsmod", sys::lsmod),
    b!("insmod", "insmod FILE.ko[.zst] [PARAM..]", sys::insmod),
    // network
    b!("ip", "ip addr|link|route [show] | link set IF up|down|mtu N | addr add|del A/P dev IF | route add|del ...", net::ip),
    // probes
    b!("lspci", "lspci", probe::lspci),
    b!("lsblk", "lsblk", probe::lsblk),
    b!("lsusb", "lsusb", probe::lsusb),
    b!("sensors", "sensors", probe::sensors),
    b!("probe", "probe [SECTION|all]   (JSON; no argument lists the sections)", probe::probe),
    b!("blk", "blk ls | read DEV [--offset N] [--count N] | test DEV read|verify [--mb N] | write DEV --destructive --serial S [--allow-boot-media] [--mb N] [--pattern zeros|ones|aa55|seed=N]", probe::blk),
    b!("lab", "lab CMD [ARG..]   (command of the local agent over /run/i7lab/ctl.sock; `lab help` lists them)", probe::lab),
];

/// Clustered short flags (`-la`). Returns the flag characters seen and the operands. `--` ends the flags, a lone `-`
/// is an operand. An unknown flag is an error naming it.
pub fn short_flags<'a>(args: &'a [String], allowed: &str) -> Result<(String, Vec<&'a String>), String> {
    let mut flags = String::new();
    let mut rest = Vec::new();
    let mut done = false;
    for a in args {
        if done || a == "-" || !a.starts_with('-') {
            rest.push(a);
        } else if a == "--" {
            done = true;
        } else {
            for c in a[1..].chars() {
                if !allowed.contains(c) {
                    return Err(format!("invalid option -- '{c}'"));
                }
                flags.push(c);
            }
        }
    }
    Ok((flags, rest))
}

/// Print `name: message` to stderr, return 1.
pub fn fail(io: &mut Io, name: &str, msg: impl std::fmt::Display) -> i32 {
    io.err(&format!("{name}: {msg}\n"));
    1
}

pub fn usage(io: &mut Io, name: &str) -> i32 {
    let u = crate::find_builtin(name).map(|b| b.usage).unwrap_or(name);
    io.err(&format!("usage: {u}\n"));
    2
}

/// 1536 -> "1.5K", 1<<30 -> "1.0G"
pub fn human(bytes: u64) -> String {
    const U: [&str; 6] = ["B", "K", "M", "G", "T", "P"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes}B")
    } else {
        format!("{:.1}{}", v, U[i])
    }
}

/// Days since 1970-01-01 -> (year, month 1-12, day 1-31) (proleptic Gregorian, Hinnant's algorithm).
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// "2026-11-12 10:20:30" (UTC)
pub fn fmt_time(secs: i64) -> String {
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let t = secs.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", t / 3600, t % 3600 / 60, t % 60)
}

/// `drwxr-xr-x` from st_mode.
pub fn mode_string(mode: u32) -> String {
    let t = match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        0o060000 => 'b',
        0o020000 => 'c',
        0o010000 => 'p',
        0o140000 => 's',
        _ => '-',
    };
    let mut s = String::from(t);
    for (i, c) in "rwxrwxrwx".chars().enumerate() {
        s.push(if mode & (0o400 >> i) != 0 { c } else { '-' });
    }
    let b = |idx: usize, on: u32, lower: char, upper: char, s: &mut Vec<char>| {
        if mode & on != 0 {
            s[idx] = if s[idx] == 'x' { lower } else { upper };
        }
    };
    let mut v: Vec<char> = s.chars().collect();
    b(3, 0o4000, 's', 'S', &mut v);
    b(6, 0o2000, 's', 'S', &mut v);
    b(9, 0o1000, 't', 'T', &mut v);
    v.into_iter().collect()
}

/// Run `f` on each operand's contents (or stdin when there are none / `-`), the way cat, wc, grep, head do.
/// `f` gets (display name, bytes). Returns the number of operands that failed to read.
pub fn each_input(io: &mut Io, name: &str, files: &[&String], mut f: impl FnMut(&mut Io, &str, &[u8])) -> i32 {
    let mut bad = 0;
    if files.is_empty() {
        match io.read_all_in() {
            Ok(b) => f(io, "-", &b),
            Err(e) => bad += fail(io, name, e),
        }
        return bad;
    }
    for p in files {
        let data = if p.as_str() == "-" { io.read_all_in() } else { std::fs::read(p.as_str()) };
        match data {
            Ok(b) => f(io, p, &b),
            Err(e) => bad += fail(io, name, format!("{p}: {e}")),
        }
    }
    bad
}

#[allow(dead_code)]
pub(crate) fn _shell_unused(_: &Shell) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn short_flag_clusters() {
        let a = v(&["-la", "x", "-", "--", "-n"]);
        let (f, rest) = short_flags(&a, "la1").unwrap();
        assert_eq!(f, "la");
        assert_eq!(rest, vec!["x", "-", "-n"]);
        assert_eq!(short_flags(&v(&["-z"]), "la").unwrap_err(), "invalid option -- 'z'");
    }

    #[test]
    fn table_names_are_unique_and_documented() {
        let mut seen = std::collections::HashSet::new();
        for b in TABLE {
            assert!(seen.insert(b.name), "duplicate builtin {}", b.name);
            assert!(!b.usage.is_empty());
        }
        // the v1 list of PLAN.md 4.6
        for n in "cd pwd echo export unset env exit help true false sleep ls cat cp mv rm mkdir rmdir ln touch head tail wc grep hexdump sha256sum mount umount ip dmesg ps kill free df uptime uname date sync reboot poweroff halt lsmod insmod lspci lsblk lsusb sensors probe blk lab".split(' ') {
            assert!(seen.contains(n), "missing builtin {n}");
        }
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human(0), "0B");
        assert_eq!(human(1023), "1023B");
        assert_eq!(human(1536), "1.5K");
        assert_eq!(human(1 << 30), "1.0G");
    }

    #[test]
    fn dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(fmt_time(0), "1970-01-01 00:00:00");
        assert_eq!(fmt_time(1_700_000_000), "2023-11-14 22:13:20");
        assert_eq!(fmt_time(951_782_400), "2000-02-29 00:00:00"); // leap day
    }

    #[test]
    fn mode_strings() {
        assert_eq!(mode_string(0o100644), "-rw-r--r--");
        assert_eq!(mode_string(0o040755), "drwxr-xr-x");
        assert_eq!(mode_string(0o120777), "lrwxrwxrwx");
        assert_eq!(mode_string(0o104755), "-rwsr-xr-x");
        assert_eq!(mode_string(0o041777), "drwxrwxrwt");
        assert_eq!(mode_string(0o100600), "-rw-------");
        assert_eq!(mode_string(0o060660), "brw-rw----");
    }
}
