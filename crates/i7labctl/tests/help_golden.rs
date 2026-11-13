//! Golden help texts (the help is part of the interface) and structural checks on every command's help.
mod common;

use common::*;

fn golden(name: &str, actual: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden").join(format!("{}.txt", name));
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing golden file {} (run with UPDATE_GOLDEN=1)", path.display()));
    if want != actual {
        // show the first differing line, not two walls of text
        let (w, a): (Vec<&str>, Vec<&str>) = (want.lines().collect(), actual.lines().collect());
        let n = w.iter().zip(a.iter()).position(|(x, y)| x != y).unwrap_or(w.len().min(a.len()));
        panic!("golden {} differs at line {}:\n  want: {:?}\n  got:  {:?}\n(UPDATE_GOLDEN=1 cargo test -p i7labctl --test help_golden)", name, n + 1, w.get(n), a.get(n));
    }
}

fn help(args: &[&str]) -> String {
    let t = T::new("help");
    let (code, o, e) = t.run(args);
    assert_eq!(code, 0, "{:?}: {}", args, e);
    assert!(e.is_empty(), "help writes nothing to stderr: {}", e);
    o
}

#[test]
fn top_level_help() {
    golden("help", &help(&["help"]));
    assert_eq!(help(&["help"]), help(&["--help"]));
}

#[test]
fn per_command_help_golden() {
    for c in ["blk", "discover", "exec", "put", "key", "ether", "lab-boot", "reboot"] {
        golden(&format!("help-{}", c), &help(&["help", c]));
    }
}

#[test]
fn reference_topics_golden() {
    golden("help-exit-codes", &help(&["help", "exit-codes"]));
    golden("help-json", &help(&["help", "json"]));
    golden("help-ether", &help(&["help", "ether"]));
    golden("help-boot-keys", &help(&["help", "boot-keys"]));
}

#[test]
fn every_command_has_complete_help_both_ways() {
    for s in i7labctl::cli::SUBS {
        let a = help(&["help", s.name]);
        let b = help(&[s.name, "--help"]);
        // `help ether` is the wire command list; `ether --help` is the command's own help
        if s.name != "ether" {
            assert_eq!(a, b, "{}", s.name);
        }
        assert!(b.contains("usage: i7labctl "), "{}", s.name);
        assert!(b.contains("examples"), "{} has no examples", s.name);
        assert!(b.contains("transports:"), "{}", s.name);
        let h = b.to_ascii_lowercase();
        assert!(!h.contains("busybox"), "{}", s.name);
    }
}

#[test]
fn manual_is_complete() {
    let m = help(&["help", "--all"]);
    assert!(m.lines().count() > 400, "the full manual is long: {} lines", m.lines().count());
    for s in i7labctl::cli::SUBS {
        assert!(m.contains(&format!("usage: i7labctl {}", s.synopsis)), "{}", s.name);
    }
    for c in labproto::catalog::CATALOG {
        assert!(m.contains(c.name), "wire command {} missing", c.name);
    }
    golden("help-all", &m);
}

#[test]
fn exit_code_table_matches_the_implementation() {
    let t = help(&["help", "exit-codes"]);
    for (code, st) in [(5, labproto::Status::Eperm), (7, labproto::Status::Refused), (9, labproto::Status::Busy), (10, labproto::Status::Unsupported), (6, labproto::Status::NotFound)] {
        assert_eq!(st.cli_exit(), code);
        assert!(t.contains(&format!("  {} ", code)) || t.contains(&format!("  {}  ", code)), "{} missing from the table", code);
    }
    use i7labctl::ClientError as E;
    assert_eq!(E::Usage(String::new()).exit_code(), 2);
    assert_eq!(E::Timeout.exit_code(), 4);
    assert_eq!(E::Auth(String::new()).exit_code(), 5);
    assert_eq!(E::NoHost(String::new()).exit_code(), 6);
    assert_eq!(E::Safety(String::new()).exit_code(), 7);
    assert_eq!(E::Ambiguous(vec![]).exit_code(), 8);
    assert_eq!(E::Unsupported(String::new()).exit_code(), 10);
    assert_eq!(E::Interrupted.exit_code(), 130);
}

#[test]
fn global_options_are_documented() {
    let h = help(&["help"]);
    for o in ["--ether", "--cmd", "--http", "--iface", "--vlan", "--role", "--key", "--timeout", "--json", "--registry", "--yes", "--link", "--transport", "--no-registry", "--retries"] {
        assert!(h.contains(o), "{} missing from the global option list", o);
    }
}
