//! File builtins: ls cat cp mv rm mkdir rmdir ln touch head tail wc grep hexdump sha256sum.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::{each_input, fail, fmt_time, human, mode_string, short_flags, usage};
use crate::{Io, Shell};

// ---------------------------------------------------------------- ls

fn ls_long(io: &mut Io, name: &str, path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(m) => {
            let mut line = format!("{} {:>3} {:>5} {:>5} {:>10} {} {}", mode_string(m.mode()), m.nlink(), m.uid(), m.gid(), m.size(), fmt_time(m.mtime()), name);
            if m.file_type().is_symlink() {
                if let Ok(t) = std::fs::read_link(path) {
                    line.push_str(&format!(" -> {}", t.display()));
                }
            }
            line.push('\n');
            io.try_out(&line)
        }
        Err(e) => {
            io.err(&format!("ls: {}: {}\n", path.display(), e));
            true
        }
    }
}

pub fn ls(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let (flags, ops) = match short_flags(args, "1alhd") {
        Ok(x) => x,
        Err(e) => return fail(io, "ls", e),
    };
    let (all, long, human_sz, dirs_as_files) = (flags.contains('a'), flags.contains('l'), flags.contains('h'), flags.contains('d'));
    let targets: Vec<String> = if ops.is_empty() { vec![".".into()] } else { ops.iter().map(|s| s.to_string()).collect() };
    let mut st = 0;
    let show = |io: &mut Io, name: &str, path: &Path| -> bool {
        if long {
            if human_sz {
                // -h only changes the size column; keep one code path by formatting here
                return match std::fs::symlink_metadata(path) {
                    Ok(m) => io.try_out(&format!("{} {:>3} {:>5} {:>5} {:>7} {} {}\n", mode_string(m.mode()), m.nlink(), m.uid(), m.gid(), human(m.size()), fmt_time(m.mtime()), name)),
                    Err(e) => {
                        io.err(&format!("ls: {}: {}\n", path.display(), e));
                        true
                    }
                };
            }
            ls_long(io, name, path)
        } else {
            io.try_out(&format!("{name}\n"))
        }
    };
    let multiple = targets.len() > 1;
    let mut first = true;
    // files first, then directories, like ls
    let mut dirs = Vec::new();
    for t in &targets {
        let p = Path::new(t);
        match std::fs::symlink_metadata(p) {
            Err(e) => {
                io.err(&format!("ls: {t}: {e}\n"));
                st = 2;
            }
            Ok(m) if m.is_dir() && !dirs_as_files => dirs.push(t.clone()),
            Ok(_) => {
                if !show(io, t, p) {
                    return 1;
                }
                first = false;
            }
        }
    }
    for d in dirs {
        if multiple {
            if !first {
                io.out("\n");
            }
            io.out(&format!("{d}:\n"));
        }
        first = false;
        let mut names: Vec<String> = match std::fs::read_dir(&d) {
            Ok(rd) => rd.flatten().filter_map(|e| e.file_name().into_string().ok()).collect(),
            Err(e) => {
                io.err(&format!("ls: {d}: {e}\n"));
                st = 2;
                continue;
            }
        };
        if all {
            names.push(".".into());
            names.push("..".into());
        } else {
            names.retain(|n| !n.starts_with('.'));
        }
        names.sort();
        for n in names {
            if !show(io, &n, &Path::new(&d).join(&n)) {
                return 1;
            }
        }
    }
    st
}

// ---------------------------------------------------------------- cat head tail wc grep hexdump sha256sum

pub fn cat(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let files: Vec<&String> = args.iter().collect();
    let mut broken = false;
    let bad = each_input(io, "cat", &files, |io, _, data| {
        if !broken && io.write_out(data).is_err() {
            broken = true;
        }
    });
    if bad > 0 || broken {
        1
    } else {
        0
    }
}

/// `-n N`, `-nN` or `-N` -> N; the remaining operands.
fn count_opt<'a>(args: &'a [String], name: &str, io: &mut Io) -> Result<(usize, Vec<&'a String>), i32> {
    let mut n = 10usize;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let val = if a == "-n" {
            i += 1;
            args.get(i).map(String::as_str)
        } else if let Some(v) = a.strip_prefix("-n") {
            Some(v)
        } else if a.len() > 1 && a.starts_with('-') && a[1..].bytes().all(|b| b.is_ascii_digit()) {
            Some(&a[1..])
        } else {
            rest.push(a);
            i += 1;
            continue;
        };
        match val.and_then(|v| v.parse::<usize>().ok()) {
            Some(v) => n = v,
            None => {
                io.err(&format!("{name}: invalid number of lines\n"));
                return Err(2);
            }
        }
        i += 1;
    }
    Ok((n, rest))
}

pub fn head(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let (n, files) = match count_opt(args, "head", io) {
        Ok(x) => x,
        Err(c) => return c,
    };
    let multi = files.len() > 1;
    each_input(io, "head", &files, |io, name, data| {
        if multi {
            io.out(&format!("==> {name} <==\n"));
        }
        let end = nth_line_end(data, n);
        let _ = io.write_out(&data[..end]);
    })
}

/// Byte offset just after the `n`th newline-terminated line (or the end of data).
fn nth_line_end(data: &[u8], n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let mut seen = 0;
    for (i, &b) in data.iter().enumerate() {
        if b == b'\n' {
            seen += 1;
            if seen == n {
                return i + 1;
            }
        }
    }
    data.len()
}

/// Byte offset where the last `n` lines start.
fn last_lines_start(data: &[u8], n: usize) -> usize {
    if n == 0 {
        return data.len();
    }
    let end = if data.last() == Some(&b'\n') { data.len() - 1 } else { data.len() };
    let mut seen = 0;
    for i in (0..end).rev() {
        if data[i] == b'\n' {
            seen += 1;
            if seen == n {
                return i + 1;
            }
        }
    }
    0
}

pub fn tail(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let (n, files) = match count_opt(args, "tail", io) {
        Ok(x) => x,
        Err(c) => return c,
    };
    let multi = files.len() > 1;
    each_input(io, "tail", &files, |io, name, data| {
        if multi {
            io.out(&format!("==> {name} <==\n"));
        }
        let _ = io.write_out(&data[last_lines_start(data, n)..]);
    })
}

pub fn wc(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let (flags, files) = match short_flags(args, "lwc") {
        Ok(x) => x,
        Err(e) => return fail(io, "wc", e),
    };
    let all = flags.is_empty();
    let (fl, fw, fc) = (all || flags.contains('l'), all || flags.contains('w'), all || flags.contains('c'));
    let multi = files.len() > 1;
    let mut tot = (0usize, 0usize, 0usize);
    let st = each_input(io, "wc", &files, |io, name, data| {
        let lines = data.iter().filter(|&&b| b == b'\n').count();
        let words = data.split(|b| b.is_ascii_whitespace()).filter(|w| !w.is_empty()).count();
        tot = (tot.0 + lines, tot.1 + words, tot.2 + data.len());
        io.out(&wc_line(lines, words, data.len(), (fl, fw, fc), if name == "-" { "" } else { name }));
    });
    if multi {
        io.out(&wc_line(tot.0, tot.1, tot.2, (fl, fw, fc), "total"));
    }
    st
}

fn wc_line(l: usize, w: usize, c: usize, sel: (bool, bool, bool), name: &str) -> String {
    let mut s = String::new();
    for (on, v) in [(sel.0, l), (sel.1, w), (sel.2, c)] {
        if on {
            s.push_str(&format!("{v:>7} "));
        }
    }
    let mut s = s.trim_end().to_string();
    if !name.is_empty() {
        s.push(' ');
        s.push_str(name);
    }
    s.push('\n');
    s
}

pub fn grep(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let (flags, ops) = match short_flags(args, "vicnF") {
        Ok(x) => x,
        Err(e) => return fail(io, "grep", e),
    };
    let Some((pat, files)) = ops.split_first() else { return usage(io, "grep") };
    let (invert, icase, count, number) = (flags.contains('v'), flags.contains('i'), flags.contains('c'), flags.contains('n'));
    let needle = if icase { pat.to_lowercase() } else { pat.to_string() };
    let multi = files.len() > 1;
    let mut any = false;
    let st = each_input(io, "grep", files, |io, name, data| {
        let text = String::from_utf8_lossy(data);
        let mut n = 0;
        for (i, line) in text.lines().enumerate() {
            let hay = if icase { line.to_lowercase() } else { line.to_string() };
            if hay.contains(&needle) != invert {
                n += 1;
                any = true;
                if !count {
                    let mut o = String::new();
                    if multi {
                        o.push_str(name);
                        o.push(':');
                    }
                    if number {
                        o.push_str(&format!("{}:", i + 1));
                    }
                    o.push_str(line);
                    o.push('\n');
                    if !io.try_out(&o) {
                        return;
                    }
                }
            }
        }
        if count {
            io.out(&if multi { format!("{name}:{n}\n") } else { format!("{n}\n") });
        }
    });
    if st > 0 {
        2
    } else if any {
        0
    } else {
        1
    }
}

/// `hexdump -C` lines for `data` whose first byte is at `base`.
pub fn hexdump_lines(data: &[u8], base: u64) -> Vec<String> {
    let mut out = Vec::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let mut l = format!("{:08x}  ", base + (i * 16) as u64);
        for j in 0..16 {
            match chunk.get(j) {
                Some(b) => l.push_str(&format!("{b:02x} ")),
                None => l.push_str("   "),
            }
            if j == 7 {
                l.push(' ');
            }
        }
        l.push_str(" |");
        l.extend(chunk.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }));
        l.push('|');
        out.push(l);
    }
    out.push(format!("{:08x}", base + data.len() as u64));
    out
}

pub fn hexdump(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let (_, files) = match short_flags(args, "C") {
        Ok(x) => x,
        Err(e) => return fail(io, "hexdump", e),
    };
    each_input(io, "hexdump", &files, |io, _, data| {
        for l in hexdump_lines(data, 0) {
            if !io.try_out(&format!("{l}\n")) {
                return;
            }
        }
    })
}

pub fn sha256sum(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let files: Vec<&String> = args.iter().collect();
    each_input(io, "sha256sum", &files, |io, name, data| {
        let h = labproto::crypto::hex(&labproto::crypto::sha256(data));
        io.out(&format!("{h}  {name}\n"));
    })
}

// ---------------------------------------------------------------- cp mv rm mkdir rmdir ln touch

fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    let m = std::fs::symlink_metadata(src)?;
    if m.file_type().is_symlink() {
        let t = std::fs::read_link(src)?;
        let _ = std::fs::remove_file(dst);
        std::os::unix::fs::symlink(t, dst)
    } else if m.is_dir() {
        match std::fs::create_dir(dst) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && dst.is_dir() => {}
            Err(e) => return Err(e),
        }
        for e in std::fs::read_dir(src)? {
            let e = e?;
            copy_tree(&e.path(), &dst.join(e.file_name()))?;
        }
        std::fs::set_permissions(dst, std::fs::Permissions::from_mode(m.mode() & 0o7777))
    } else {
        std::fs::copy(src, dst).map(|_| ())
    }
}

/// Where `src` lands for destination `dst`: inside it when it is an existing directory.
fn dest_for(src: &str, dst: &str) -> PathBuf {
    let d = Path::new(dst);
    if d.is_dir() {
        d.join(Path::new(src).file_name().unwrap_or_default())
    } else {
        d.to_path_buf()
    }
}

pub fn cp(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let (flags, ops) = match short_flags(args, "rR") {
        Ok(x) => x,
        Err(e) => return fail(io, "cp", e),
    };
    let rec = !flags.is_empty();
    let Some((dst, srcs)) = ops.split_last() else { return usage(io, "cp") };
    if srcs.is_empty() {
        return usage(io, "cp");
    }
    if srcs.len() > 1 && !Path::new(dst.as_str()).is_dir() {
        return fail(io, "cp", format!("target '{dst}' is not a directory"));
    }
    let mut st = 0;
    for s in srcs {
        let to = dest_for(s, dst);
        if Path::new(s.as_str()).is_dir() && !rec {
            st = fail(io, "cp", format!("-r not specified; omitting directory '{s}'"));
            continue;
        }
        if let Err(e) = copy_tree(Path::new(s.as_str()), &to) {
            st = fail(io, "cp", format!("{s}: {e}"));
        }
    }
    st
}

pub fn mv(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let (_, ops) = match short_flags(args, "") {
        Ok(x) => x,
        Err(e) => return fail(io, "mv", e),
    };
    let Some((dst, srcs)) = ops.split_last() else { return usage(io, "mv") };
    if srcs.is_empty() {
        return usage(io, "mv");
    }
    if srcs.len() > 1 && !Path::new(dst.as_str()).is_dir() {
        return fail(io, "mv", format!("target '{dst}' is not a directory"));
    }
    let mut st = 0;
    for s in srcs {
        let to = dest_for(s, dst);
        if let Err(e) = std::fs::rename(s.as_str(), &to) {
            // EXDEV (18): across filesystems, copy then remove
            let r = if e.raw_os_error() == Some(18) {
                copy_tree(Path::new(s.as_str()), &to).and_then(|_| if Path::new(s.as_str()).is_dir() { std::fs::remove_dir_all(s.as_str()) } else { std::fs::remove_file(s.as_str()) })
            } else {
                Err(e)
            };
            if let Err(e) = r {
                st = fail(io, "mv", format!("{s}: {e}"));
            }
        }
    }
    st
}

pub fn rm(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let (flags, ops) = match short_flags(args, "rRf") {
        Ok(x) => x,
        Err(e) => return fail(io, "rm", e),
    };
    let (rec, force) = (flags.contains('r') || flags.contains('R'), flags.contains('f'));
    if ops.is_empty() && !force {
        return usage(io, "rm");
    }
    let mut st = 0;
    for p in ops {
        if p == "/" || p == "." || p == ".." {
            st = fail(io, "rm", format!("refusing to remove '{p}'"));
            continue;
        }
        let path = Path::new(p.as_str());
        let r = match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && force => continue,
            Err(e) => Err(e),
            Ok(m) if m.is_dir() => {
                if rec {
                    std::fs::remove_dir_all(path)
                } else {
                    st = fail(io, "rm", format!("{p}: is a directory (use -r)"));
                    continue;
                }
            }
            Ok(_) => std::fs::remove_file(path),
        };
        if let Err(e) = r {
            if !force {
                st = fail(io, "rm", format!("{p}: {e}"));
            }
        }
    }
    st
}

pub fn mkdir(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let (flags, ops) = match short_flags(args, "p") {
        Ok(x) => x,
        Err(e) => return fail(io, "mkdir", e),
    };
    if ops.is_empty() {
        return usage(io, "mkdir");
    }
    let mut st = 0;
    for p in ops {
        let r = if flags.contains('p') { std::fs::create_dir_all(p.as_str()) } else { std::fs::create_dir(p.as_str()) };
        if let Err(e) = r {
            st = fail(io, "mkdir", format!("{p}: {e}"));
        }
    }
    st
}

pub fn rmdir(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    if args.is_empty() {
        return usage(io, "rmdir");
    }
    let mut st = 0;
    for p in args {
        if let Err(e) = std::fs::remove_dir(p) {
            st = fail(io, "rmdir", format!("{p}: {e}"));
        }
    }
    st
}

pub fn ln(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    let (flags, ops) = match short_flags(args, "sf") {
        Ok(x) => x,
        Err(e) => return fail(io, "ln", e),
    };
    let [target, link] = ops.as_slice() else { return usage(io, "ln") };
    let link = dest_for(target, link);
    if flags.contains('f') {
        let _ = std::fs::remove_file(&link);
    }
    let r = if flags.contains('s') { std::os::unix::fs::symlink(target.as_str(), &link) } else { std::fs::hard_link(target.as_str(), &link) };
    match r {
        Ok(()) => 0,
        Err(e) => fail(io, "ln", format!("{}: {e}", link.display())),
    }
}

pub fn touch(_: &mut Shell, args: &[String], io: &mut Io) -> i32 {
    if args.is_empty() {
        return usage(io, "touch");
    }
    let mut st = 0;
    for p in args {
        let r = std::fs::OpenOptions::new().create(true).append(true).open(p).and_then(|f| f.set_modified(std::time::SystemTime::now()));
        if let Err(e) = r {
            st = fail(io, "touch", format!("{p}: {e}"));
        }
    }
    st
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn ls_plain_all_and_long() {
        let mut s = sh();
        let t = Tmp::new();
        for f in ["b", "a", ".h"] {
            std::fs::write(t.path(f), "xy").unwrap();
        }
        std::fs::create_dir(t.path("d")).unwrap();
        std::fs::set_permissions(t.path("a"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let d = t.0.display();
        assert_eq!(run(&mut s, &format!("ls {d}")).1, "a\nb\nd\n");
        assert_eq!(run(&mut s, &format!("ls -a {d}")).1, ".\n..\n.h\na\nb\nd\n");
        let (_, out, _) = run(&mut s, &format!("ls -l {d}/a"));
        assert!(out.starts_with("-rw-r--r--") && out.contains(" 2 ") && out.trim_end().ends_with("/a"), "{out}");
        assert_eq!(run(&mut s, &format!("ls -d {d}")).1, format!("{d}\n"));
        let (st, _, err) = run(&mut s, &format!("ls {d}/nope"));
        assert_eq!(st, 2);
        assert!(err.contains("nope"));
        // several operands: headers
        let (_, out, _) = run(&mut s, &format!("ls {d}/a {d}"));
        assert!(out.starts_with(&format!("{d}/a\n\n{d}:\n")), "{out:?}");
    }

    #[test]
    fn ls_symlink_long() {
        let mut s = sh();
        let t = Tmp::new();
        std::os::unix::fs::symlink("target", t.path("l")).unwrap();
        let (_, out, _) = run(&mut s, &format!("ls -l {}/l", t.0.display()));
        assert!(out.starts_with('l') && out.contains(" -> target"), "{out}");
    }

    #[test]
    fn cat_files_stdin_and_errors() {
        let mut s = sh();
        let t = Tmp::new();
        std::fs::write(t.path("a"), "A\n").unwrap();
        std::fs::write(t.path("b"), "B\n").unwrap();
        assert_eq!(run(&mut s, &format!("cat {0} {1}", t.path("a"), t.path("b"))).1, "A\nB\n");
        let (st, out, err) = run(&mut s, &format!("cat {} /nonexistent", t.path("a")));
        assert_eq!((st, out.as_str()), (1, "A\n"));
        assert!(err.contains("/nonexistent"));
        assert_eq!(run(&mut s, &format!("cat < {}", t.path("b"))).1, "B\n");
    }

    #[test]
    fn head_and_tail() {
        let mut s = sh();
        let t = Tmp::new();
        let text: String = (1..=12).map(|i| format!("l{i}\n")).collect();
        std::fs::write(t.path("f"), &text).unwrap();
        let f = t.path("f");
        assert_eq!(run(&mut s, &format!("head {f}")).1.lines().count(), 10);
        assert_eq!(run(&mut s, &format!("head -n 2 {f}")).1, "l1\nl2\n");
        assert_eq!(run(&mut s, &format!("head -3 {f}")).1, "l1\nl2\nl3\n");
        assert_eq!(run(&mut s, &format!("tail -n 2 {f}")).1, "l11\nl12\n");
        assert_eq!(run(&mut s, &format!("tail -n2 < {f}")).1, "l11\nl12\n");
        assert_eq!(run(&mut s, &format!("tail -n 100 {f}")).1, text);
        assert_eq!(run(&mut s, &format!("head -n 0 {f}")).1, "");
        assert_eq!(run(&mut s, &format!("tail -n 0 {f}")).1, "");
        assert_eq!(run(&mut s, &format!("head -n x {f}")).0, 2);
    }

    #[test]
    fn tail_without_trailing_newline() {
        assert_eq!(&b"a\nb\nc"[last_lines_start(b"a\nb\nc", 2)..], b"b\nc");
        assert_eq!(&b"a\nb\nc\n"[last_lines_start(b"a\nb\nc\n", 2)..], b"b\nc\n");
        assert_eq!(last_lines_start(b"abc", 1), 0);
        assert_eq!(nth_line_end(b"a\nb", 5), 3);
    }

    #[test]
    fn wc_counts() {
        let mut s = sh();
        let t = Tmp::new();
        std::fs::write(t.path("f"), "one two\nthree\n").unwrap();
        let f = t.path("f");
        assert_eq!(run(&mut s, &format!("wc -l {f}")).1.trim(), format!("2 {f}"));
        assert_eq!(run(&mut s, &format!("wc -w < {f}")).1.trim(), "3");
        assert_eq!(run(&mut s, &format!("wc -c < {f}")).1.trim(), "14");
        let (_, out, _) = run(&mut s, &format!("wc {f} {f}"));
        assert!(out.lines().last().unwrap().ends_with("total"));
    }

    #[test]
    fn grep_substring() {
        let mut s = sh();
        let t = Tmp::new();
        std::fs::write(t.path("f"), "Alpha\nbeta\nalphabet\n").unwrap();
        let f = t.path("f");
        assert_eq!(run(&mut s, &format!("grep alpha {f}")).1, "alphabet\n");
        assert_eq!(run(&mut s, &format!("grep -i alpha {f}")).1, "Alpha\nalphabet\n");
        assert_eq!(run(&mut s, &format!("grep -v beta {f}")).1, "Alpha\nalphabet\n");
        assert_eq!(run(&mut s, &format!("grep -c et {f}")).1, "2\n");
        assert_eq!(run(&mut s, &format!("grep -n beta {f}")).1, "2:beta\n");
        assert_eq!(run(&mut s, &format!("grep zzz {f}")).0, 1);
        assert_eq!(run(&mut s, &format!("grep a {f} /nonexistent")).0, 2);
        assert_eq!(run(&mut s, &format!("echo xay | grep ay")).1, "xay\n");
        let (_, out, _) = run(&mut s, &format!("grep beta {f} {f}"));
        assert_eq!(out, format!("{f}:beta\n{f}:beta\n"));
    }

    #[test]
    fn hexdump_layout_matches_hexdump_c() {
        let l = hexdump_lines(b"hello, world\n\x00\xff", 0);
        assert_eq!(l[0], "00000000  68 65 6c 6c 6f 2c 20 77  6f 72 6c 64 0a 00 ff     |hello, world...|");
        assert_eq!(l[1], "0000000f");
        let l = hexdump_lines(&[0x41; 16], 0x10);
        assert_eq!(l[0], "00000010  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|");
        assert_eq!(hexdump_lines(b"", 0), vec!["00000000"]);
    }

    #[test]
    fn sha256sum_vector() {
        let mut s = sh();
        let t = Tmp::new();
        std::fs::write(t.path("abc"), "abc").unwrap();
        let (_, out, _) = run(&mut s, &format!("sha256sum {}", t.path("abc")));
        assert!(out.starts_with("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  "), "{out}");
        assert!(run(&mut s, "echo -n abc | sha256sum").1.starts_with("ba7816bf"));
    }

    #[test]
    fn cp_mv_rm_mkdir_ln_touch() {
        let mut s = sh();
        let t = Tmp::new();
        let p = |n: &str| t.path(n);
        assert_eq!(run(&mut s, &format!("mkdir -p {}/x/y", t.0.display())).0, 0);
        std::fs::write(p("x/y/f"), "data").unwrap();
        assert_eq!(run(&mut s, &format!("cp {} {}", p("x/y/f"), p("g"))).0, 0);
        assert_eq!(std::fs::read_to_string(p("g")).unwrap(), "data");
        // directory copy needs -r; into an existing dir lands inside
        let (st, _, err) = run(&mut s, &format!("cp {} {}", p("x"), p("x2")));
        assert_eq!(st, 1);
        assert!(err.contains("-r not specified"));
        assert_eq!(run(&mut s, &format!("cp -r {} {}", p("x"), p("x2"))).0, 0);
        assert_eq!(std::fs::read_to_string(p("x2/y/f")).unwrap(), "data");
        std::fs::create_dir(p("dir")).unwrap();
        run(&mut s, &format!("cp {} {}", p("g"), p("dir")));
        assert!(Path::new(&p("dir/g")).exists());
        // mv
        assert_eq!(run(&mut s, &format!("mv {} {}", p("g"), p("h"))).0, 0);
        assert!(!Path::new(&p("g")).exists() && Path::new(&p("h")).exists());
        run(&mut s, &format!("mv {} {}", p("h"), p("dir")));
        assert!(Path::new(&p("dir/h")).exists());
        // ln
        run(&mut s, &format!("ln -s target {}", p("sl")));
        assert_eq!(std::fs::read_link(p("sl")).unwrap().display().to_string(), "target");
        run(&mut s, &format!("ln {} {}", p("dir/h"), p("hard")));
        assert_eq!(std::fs::read_to_string(p("hard")).unwrap(), "data");
        // touch
        run(&mut s, &format!("touch {}", p("new")));
        assert!(Path::new(&p("new")).exists());
        // rm: dirs need -r, -f ignores missing, "/" refused
        let (st, _, err) = run(&mut s, &format!("rm {}", p("x")));
        assert_eq!(st, 1);
        assert!(err.contains("is a directory"));
        assert_eq!(run(&mut s, &format!("rm -rf {} {}", p("x"), p("nonexistent"))).0, 0);
        assert!(!Path::new(&p("x")).exists());
        assert_eq!(run(&mut s, &format!("rm {}", p("nonexistent"))).0, 1);
        assert_eq!(run(&mut s, "rm -rf /").0, 1);
        // rmdir
        std::fs::create_dir(p("e")).unwrap();
        assert_eq!(run(&mut s, &format!("rmdir {}", p("e"))).0, 0);
        assert_eq!(run(&mut s, &format!("rmdir {}", p("dir"))).0, 1); // not empty
    }

    #[test]
    fn usage_errors() {
        let mut s = sh();
        assert_eq!(run(&mut s, "cp").0, 2);
        assert_eq!(run(&mut s, "ls -z").0, 1);
        assert_eq!(run(&mut s, "grep").0, 2);
        assert_eq!(run(&mut s, "mkdir").0, 2);
    }
}
