//! Shell-state builtins: cd pwd echo export unset env exit help true false sleep source.

use super::{fail, short_flags, usage};
use crate::{ffi, find_builtin, builtins, Io, Shell};

pub fn cd(sh: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    if args.len() > 1 {
        return usage(io, "cd");
    }
    let target = match args.first().map(String::as_str) {
        None => sh.home(),
        Some("-") => match sh.get_var("OLDPWD") {
            Some(p) => p.to_string(),
            None => return fail(io, "cd", "OLDPWD not set"),
        },
        Some(p) => p.to_string(),
    };
    let new = if target.starts_with('/') { std::path::PathBuf::from(&target) } else { sh.cwd.join(&target) };
    let canon = match std::fs::canonicalize(&new) {
        Ok(c) => c,
        Err(e) => return fail(io, "cd", format!("{target}: {e}")),
    };
    if !canon.is_dir() {
        return fail(io, "cd", format!("{target}: Not a directory"));
    }
    if !sh.subshell {
        if let Err(e) = std::env::set_current_dir(&canon) {
            return fail(io, "cd", format!("{target}: {e}"));
        }
    }
    let old = sh.cwd.display().to_string();
    sh.cwd = canon;
    sh.set("OLDPWD", &old);
    let pwd = sh.cwd.display().to_string();
    sh.set("PWD", &pwd);
    if args.first().map(String::as_str) == Some("-") {
        io.out(&format!("{pwd}\n"));
    }
    0
}

pub fn pwd(sh: &mut Shell, _: &[String], io: &mut Io) -> i32 {
    io.out(&format!("{}\n", sh.cwd.display()));
    0
}

/// Backslash escapes of `echo -e`: \n \t \r \\ \e \a \0NNN \xHH. Unknown escapes stay as written. `\c` stops output.
pub fn unescape(s: &str) -> (String, bool) {
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('a') => out.push('\x07'),
            Some('e') => out.push('\x1b'),
            Some('\\') => out.push('\\'),
            Some('c') => return (out, true),
            Some('x') => {
                let mut v = 0u32;
                let mut n = 0;
                while n < 2 {
                    match it.peek().and_then(|c| c.to_digit(16)) {
                        Some(d) => {
                            v = v * 16 + d;
                            it.next();
                            n += 1;
                        }
                        None => break,
                    }
                }
                if n == 0 {
                    out.push_str("\\x");
                } else {
                    out.push(char::from_u32(v).unwrap_or('?'));
                }
            }
            Some('0') => {
                let mut v = 0u32;
                let mut n = 0;
                while n < 3 {
                    match it.peek().and_then(|c| c.to_digit(8)) {
                        Some(d) => {
                            v = v * 8 + d;
                            it.next();
                            n += 1;
                        }
                        None => break,
                    }
                }
                out.push(char::from_u32(v).unwrap_or('?'));
            }
            Some(o) => {
                out.push('\\');
                out.push(o);
            }
            None => out.push('\\'),
        }
    }
    (out, false)
}

pub fn echo(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    // only leading words made purely of the flag letters n/e are flags, like sh's echo
    let mut nl = true;
    let mut esc = false;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.len() > 1 && a.starts_with('-') && a[1..].chars().all(|c| c == 'n' || c == 'e') {
            for c in a[1..].chars() {
                if c == 'n' {
                    nl = false;
                } else {
                    esc = true;
                }
            }
            i += 1;
        } else {
            break;
        }
    }
    let mut s = args[i..].join(" ");
    let mut stop = false;
    if esc {
        let (u, st) = unescape(&s);
        s = u;
        stop = st;
    }
    if nl && !stop {
        s.push('\n');
    }
    if io.try_out(&s) {
        0
    } else {
        1
    }
}

pub fn export(sh: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    if args.is_empty() {
        return env(sh, args, io);
    }
    let mut st = 0;
    for a in args {
        match a.split_once('=') {
            Some((k, v)) if crate::parse::is_name(k) => sh.set(k, v),
            None if crate::parse::is_name(a) => {} // already exported: every variable is
            _ => st = fail(io, "export", format!("'{a}': not a valid identifier")),
        }
    }
    st
}

pub fn unset(sh: &mut Shell, args: &[String], _: &mut Io) -> i32 {
    for a in args {
        sh.unset(a);
    }
    0
}

pub fn env(sh: &mut Shell, _: &[String], io: &mut Io) -> i32 {
    for (k, v) in &sh.env {
        if !io.try_out(&format!("{k}={v}\n")) {
            return 1;
        }
    }
    0
}

pub fn exit(sh: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let code = match args.first() {
        None => sh.last_status,
        Some(a) => match a.parse::<i32>() {
            Ok(c) => c & 0xff,
            Err(_) => {
                io.err(&format!("exit: {a}: numeric argument required\n"));
                2
            }
        },
    };
    if !sh.subshell {
        sh.exit_requested = Some(code);
    }
    code
}

pub fn help(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    if let Some(n) = args.first() {
        return match find_builtin(n) {
            Some(b) => {
                io.out(&format!("{}\n", b.usage));
                0
            }
            None => fail(io, "help", format!("{n}: no such builtin")),
        };
    }
    io.out("i7labsh builtins (there are no other userland tools in this image; programs run by absolute path or PATH=/sbin:/bin):\n");
    for b in builtins() {
        if !io.try_out(&format!("  {:10} {}\n", b.name, b.usage)) {
            return 1;
        }
    }
    io.out("\nSyntax: quotes, $VAR, ~, globs, | < > >> 2>&1, ; && ||, # comments. No background jobs, subshells, $(...), if/for.\nKeys: arrows, ^A ^E ^U ^K ^W ^L, Tab completes, ^C cancels, ^D leaves.\n");
    0
}

pub fn true_(_: &mut Shell, _: &[String], _: &mut Io) -> i32 {
    0
}

pub fn false_(_: &mut Shell, _: &[String], _: &mut Io) -> i32 {
    1
}

pub fn sleep(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let Some(secs) = args.first().and_then(|a| a.parse::<f64>().ok()).filter(|s| *s >= 0.0 && s.is_finite()) else {
        return usage(io, "sleep");
    };
    let end = std::time::Instant::now() + std::time::Duration::from_secs_f64(secs);
    loop {
        if ffi::take_interrupt() {
            return 130;
        }
        let now = std::time::Instant::now();
        if now >= end {
            return 0;
        }
        std::thread::sleep((end - now).min(std::time::Duration::from_millis(50)));
    }
}

pub fn source(sh: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let (_, files) = match short_flags(args, "") {
        Ok(x) => x,
        Err(e) => return fail(io, "source", e),
    };
    let [file] = files.as_slice() else { return usage(io, "source") };
    match std::fs::read_to_string(file.as_str()) {
        Ok(text) => {
            let io2 = *io;
            sh.run_line_io(&text, &io2)
        }
        Err(e) => fail(io, "source", format!("{file}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn echo_flags_and_escapes() {
        let mut s = sh();
        assert_eq!(run(&mut s, "echo a b").1, "a b\n");
        assert_eq!(run(&mut s, "echo -n a").1, "a");
        assert_eq!(run(&mut s, "echo -e 'a\\tb\\n'").1, "a\tb\n\n");
        assert_eq!(run(&mut s, "echo -ne 'x\\cy'").1, "x");
        assert_eq!(run(&mut s, "echo -x").1, "-x\n"); // not a flag: printed
        assert_eq!(run(&mut s, "echo").1, "\n");
        assert_eq!(run(&mut s, "echo 'a\\tb'").1, "a\\tb\n"); // no -e: literal
    }

    #[test]
    fn unescape_forms() {
        assert_eq!(unescape("\\x41\\0101\\\\").0, "AA\\");
        assert_eq!(unescape("\\q\\x").0, "\\q\\x");
        assert_eq!(unescape("a\\e[0m").0, "a\x1b[0m");
    }

    #[test]
    fn cd_pwd_and_oldpwd() {
        let mut s = sh();
        // subshell mode: tracks sh.cwd without calling chdir(2), which would race with the parallel tests
        s.subshell = true;
        let t = Tmp::new();
        let d = std::fs::canonicalize(&t.0).unwrap();
        let before = s.cwd.clone();
        let (st, out, _) = run(&mut s, &format!("cd {} && pwd", d.display()));
        assert_eq!((st, out), (0, format!("{}\n", d.display())));
        assert_eq!(s.get_var("OLDPWD"), Some(before.display().to_string().as_str()));
        std::fs::create_dir(d.join("sub")).unwrap();
        run(&mut s, "cd sub");
        assert_eq!(s.cwd, d.join("sub"));
        let (_, out, _) = run(&mut s, "cd - ; pwd");
        assert_eq!(out, format!("{0}\n{0}\n", d.display()));
        let (st, _, err) = run(&mut s, "cd /nonexistent");
        assert_eq!(st, 1);
        assert!(err.contains("/nonexistent"));
        let (st, _, err) = run(&mut s, "cd /etc/passwd");
        assert_eq!(st, 1);
        assert!(err.contains("Not a directory"));
    }

    #[test]
    fn export_unset_env() {
        let mut s = sh();
        run(&mut s, "export A=1 B=two");
        assert_eq!(s.get_var("A"), Some("1"));
        let (_, out, _) = run(&mut s, "env");
        assert!(out.contains("B=two\n"));
        run(&mut s, "unset A");
        assert_eq!(s.get_var("A"), None);
        let (st, _, err) = run(&mut s, "export 1x=3");
        assert_eq!(st, 1);
        assert!(err.contains("not a valid identifier"));
    }

    #[test]
    fn exit_codes() {
        let mut s = sh();
        run(&mut s, "exit 300");
        assert_eq!(s.exit_requested, Some(300 & 0xff));
        let mut s = sh();
        let (st, _, err) = run(&mut s, "exit abc");
        assert_eq!(st, 2);
        assert!(err.contains("numeric"));
        let mut s = sh();
        run(&mut s, "false; exit");
        assert_eq!(s.exit_requested, Some(1));
    }

    #[test]
    fn help_lists_and_describes() {
        let mut s = sh();
        let (_, out, _) = run(&mut s, "help");
        assert!(out.contains("sha256sum") && out.contains("blk"));
        assert!(run(&mut s, "help ls").1.starts_with("ls [-1alhd]"));
        assert_eq!(run(&mut s, "help nonesuch").0, 1);
    }

    #[test]
    fn sleep_validates_and_waits() {
        let mut s = sh();
        assert_eq!(run(&mut s, "sleep 0.05").0, 0);
        assert_eq!(run(&mut s, "sleep x").0, 2);
        assert_eq!(run(&mut s, "sleep -1").0, 2);
    }

    #[test]
    fn source_runs_a_script_with_comments() {
        let mut s = sh();
        let t = Tmp::new();
        std::fs::write(t.path("s.sh"), "#!/bin/i7labsh\nX=7\necho got $X\n# done\n").unwrap();
        // the assignment line and echo are separate commands of one script: $X is expanded when its command runs
        let (st, out, _) = run(&mut s, &format!("source {}", t.path("s.sh")));
        assert_eq!((st, out.as_str()), (0, "got 7\n"));
        assert_eq!(run(&mut s, "source /nonexistent").0, 1);
    }
}
