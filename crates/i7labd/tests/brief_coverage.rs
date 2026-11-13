//! Brief coverage (docs/BRIEF-CHECKLIST.md): which catalogue commands the agent really serves.
//!
//! A command whose `since` is the current release is advertised by `i7labctl help`, the SPA and the TUI as available.
//! If it has no handler in `i7labd::cmds`, the registry answers UNSUPPORTED "not implemented in this build", which is
//! a help text that lies. The known gaps are pinned here so the list cannot silently grow, and so whoever implements
//! one of them is told to update the checklist (and this list) at the same time.

use labproto::catalog::{CATALOG, CURRENT_RELEASE};

/// Current-release commands without a handler on 2026-11-12 (BRIEF-CHECKLIST items 8 and 12; EXPANSION.md G2).
const KNOWN_UNSERVED: &[&str] = &["identify", "msg", "tui", "tui.dump"];

#[test]
fn current_release_commands_have_handlers_except_the_pinned_gaps() {
    let mut unserved: Vec<&str> = CATALOG
        .iter()
        .filter(|c| !c.planned())
        .filter(|c| i7labd::cmds::handler_for(c.name).is_none())
        .map(|c| c.name)
        .collect();
    unserved.sort_unstable();
    let mut known = KNOWN_UNSERVED.to_vec();
    known.sort_unstable();
    assert_eq!(
        unserved, known,
        "the set of {CURRENT_RELEASE} catalogue commands without an i7labd handler changed: update KNOWN_UNSERVED, \
         docs/BRIEF-CHECKLIST.md and docs/EXPANSION.md (or mark the command planned via its `since`)"
    );
}

#[test]
fn planned_commands_have_no_handler_yet_or_are_listed() {
    // A planned command answers UNSUPPORTED before its handler runs (registry dispatch order), so a handler for it is
    // dead code until `since` is moved to the current release. Flag that so the catalogue and the code stay in step.
    let served_but_planned: Vec<&str> =
        CATALOG.iter().filter(|c| c.planned()).filter(|c| i7labd::cmds::handler_for(c.name).is_some()).map(|c| c.name).collect();
    assert!(served_but_planned.is_empty(), "planned commands with a handler (move `since`?): {served_but_planned:?}");
}

#[test]
fn the_brief_core_commands_are_served() {
    // Brief: PCIe probing, block enumeration with read and write tests, system probing, remote exec, files, reboot.
    for name in [
        "ping", "id", "inv", "pcie", "usb", "thermal", "blk.ls", "blk.read", "blk.write", "blk.verify", "blk.smart",
        "net.ls", "exec", "shell", "put", "get", "fs.ls", "logs", "reboot", "poweroff",
    ] {
        let spec = labproto::catalog::by_name(name).unwrap_or_else(|| panic!("{name} missing from the catalogue"));
        assert!(!spec.planned(), "{name} is planned, the brief needs it now");
        assert!(i7labd::cmds::handler_for(name).is_some(), "{name} has no i7labd handler");
    }
}
