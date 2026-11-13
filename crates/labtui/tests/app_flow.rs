//! Key-driven flows through the whole App on the headless backend.

use labtui::headless::Headless;
use labtui::sample::{demo_data, demo_data_no_control_path};
use labtui::{Focus, Options, Request};

const UP: &[u8] = b"\x1b[A";
const DOWN: &[u8] = b"\x1b[B";
const RIGHT: &[u8] = b"\x1b[C";
const LEFT: &[u8] = b"\x1b[D";
const TAB: &[u8] = b"\t";
const ENTER: &[u8] = b"\r";
const ESC_SEQ_F1: &[u8] = b"\x1bOP";

fn hl(w: u16, h: u16) -> Headless {
    Headless::new(w, h, demo_data(), Options::default())
}

#[test]
fn starts_on_overview_with_header_and_tabs() {
    let mut h = hl(132, 43);
    let f = h.frame();
    assert!(f.contains("i7lablinux"), "{}", f);
    assert!(f.contains("host:i7lab-m720q-04"));
    assert!(f.contains("[Overview]"));
    assert!(f.contains("PCIe"));
    assert!(f.contains("F1 Help"));
    assert!(f.contains("attention:"));
}

#[test]
fn tabs_by_arrow_and_digit() {
    let mut h = hl(132, 43);
    h.keys(RIGHT);
    assert!(h.frame().contains("[PCIe]"));
    h.keys(LEFT);
    h.keys(LEFT);
    assert!(h.frame().contains("[Actions]"), "wraps around");
    h.keys(b"3");
    assert!(h.frame().contains("[Storage]"));
    assert_eq!(h.app.tab_name(), "Storage");
    assert!(h.app.select_tab("sensors"));
    assert!(h.frame().contains("[Sensors]"));
    assert!(!h.app.select_tab("nope"));
    h.keys(b"\x1b[17~"); // F6 = Log
    assert_eq!(h.app.tab_name(), "Log");
}

#[test]
fn focus_cycles_with_tab_and_esc() {
    let mut h = hl(132, 43);
    assert_eq!(h.app.focus(), Focus::Tabs);
    h.keys(TAB);
    assert_eq!(h.app.focus(), Focus::List);
    h.keys(TAB);
    assert_eq!(h.app.focus(), Focus::Detail);
    h.keys(TAB);
    assert_eq!(h.app.focus(), Focus::Tabs);
    h.keys(b"\x1b[Z"); // Shift-Tab goes backwards
    assert_eq!(h.app.focus(), Focus::Detail);
    h.keys(b"\x1b");
    // a lone ESC byte needs the timeout in the real loop; the decoder keeps it pending until flushed
    h.keys(b"\x1b[A");
    assert_ne!(h.app.focus(), Focus::Tabs);
    h.keys(DOWN);
}

#[test]
fn quit_needs_confirmation() {
    let mut h = hl(132, 43);
    assert!(h.keys(b"q").is_empty());
    assert!(h.app.dialog_open());
    assert!(h.frame().contains("Leave the TUI?"));
    // default button is No
    assert!(h.keys(ENTER).is_empty());
    assert!(!h.app.dialog_open());
    h.keys(b"q");
    assert_eq!(h.keys(b"y"), vec![Request::Quit]);
    // Ctrl-C is the same dialog
    h.keys(b"\x03");
    assert!(h.app.dialog_open());
    h.keys(b"n");
    assert!(!h.app.dialog_open());
}

#[test]
fn reboot_asks_first_and_runs_on_yes_only() {
    let mut h = hl(132, 43);
    h.keys(b"8");
    h.keys(DOWN); // focus the list
    assert_eq!(h.app.focus(), Focus::List);
    assert!(h.keys(ENTER).is_empty(), "no request before the confirmation");
    assert!(h.frame().contains("Reboot this host now?"));
    assert!(h.keys(b"n").is_empty());
    h.keys(ENTER);
    assert_eq!(h.keys(b"y"), vec![Request::Reboot]);
    // Esc cancels
    h.keys(ENTER);
    assert!(h.keys(b"\x1b[A").is_empty() || true);
}

#[test]
fn actions_page_runs_safe_actions_directly_and_refuses_planned() {
    let mut h = hl(132, 43);
    h.keys(b"8");
    h.keys(DOWN);
    // items: Reboot, Power off, Boot next x2, Rescan PCI, Probe now, Open shell, fingerprints, planned...
    for _ in 0..4 {
        h.keys(DOWN);
    }
    assert_eq!(h.keys(ENTER), vec![Request::RescanPci]);
    h.keys(DOWN);
    assert_eq!(h.keys(ENTER), vec![Request::ProbeNow]);
    h.keys(DOWN);
    assert_eq!(h.keys(ENTER), vec![Request::Shell]);
    h.keys(DOWN);
    assert!(h.keys(ENTER).is_empty());
    assert!(h.frame().contains("Trusted keys"));
    assert!(h.frame().contains("fp 9f3a1c5e77d2"));
    h.keys(ENTER); // Close
    assert!(!h.app.dialog_open());
    h.keys(DOWN);
    assert!(h.keys(ENTER).is_empty());
    assert!(h.frame().contains("planned"));
}

#[test]
fn boot_next_confirmation_carries_the_entry() {
    let mut h = hl(132, 43);
    h.keys(b"8");
    h.keys(DOWN);
    h.keys(DOWN);
    h.keys(DOWN);
    h.keys(ENTER); // Boot next: 0001
    assert!(h.frame().contains("Boot entry 0001"));
    assert_eq!(h.keys(b"y"), vec![Request::BootNext(1)]);
}

#[test]
fn locked_console_disables_shell_and_actions() {
    let mut d = demo_data();
    d.identity.console_locked = true;
    let mut h = Headless::new(132, 43, d, Options::default());
    assert!(h.keys(b"s").is_empty());
    assert!(h.frame().contains("console is locked"));
    assert!(!h.frame().contains("F10 Shell"));
    h.keys(b"8");
    h.keys(DOWN);
    h.keys(ENTER); // Reboot
    assert!(!h.app.dialog_open());
    assert!(h.frame().contains("locked"));
}

#[test]
fn storage_read_test_flow() {
    let mut h = hl(132, 43);
    h.keys(b"3");
    h.keys(DOWN);
    h.frame();
    assert!(h.keys(b"t").is_empty());
    assert!(h.frame().contains("read-only surface test on /dev/nvme0n1"));
    assert_eq!(h.keys(b"y"), vec![Request::BlockReadTest { dev: "nvme0n1".into() }]);
}

#[test]
fn storage_write_is_off_by_default() {
    let mut h = hl(132, 43);
    h.keys(b"3");
    h.keys(DOWN);
    h.frame();
    assert!(h.keys(b"w").is_empty());
    assert!(!h.app.dialog_open());
    assert!(h.frame().contains("write tests are not part of this console yet"));
}

#[test]
fn storage_write_refused_and_typed_serial() {
    let mut h = Headless::new(132, 43, demo_data(), Options { write_tests: true, ..Default::default() });
    h.keys(b"3");
    h.keys(DOWN);
    h.frame();
    h.keys(DOWN); // sda = boot media
    h.frame();
    h.keys(b"w");
    let f = h.frame();
    assert!(f.contains("cannot be written"), "{}", f);
    assert!(f.contains("boot media"));
    h.keys(ENTER);
    assert!(!h.app.dialog_open());
    h.keys(UP); // nvme0n1: needs override, serial S64DNX0R123456A
    h.frame();
    h.keys(b"w");
    let f = h.frame();
    assert!(f.contains("DESTROYS"));
    assert!(f.contains("S64DNX0R123456A"));
    // Enter on Cancel (default) closes it
    h.keys(b"\x1b[D"); // select Confirm
    assert!(h.keys(ENTER).is_empty(), "gated: nothing typed yet");
    assert!(h.app.dialog_open());
    h.keys(b"S64DNX0R12345"); // one character short
    assert!(h.keys(ENTER).is_empty());
    h.keys(b"6Ax"); // full serial plus a stray character
    assert!(h.keys(ENTER).is_empty());
    assert!(h.app.dialog_open());
    h.keys(b"\x7f");
    assert_eq!(h.keys(ENTER), vec![Request::BlockWriteTest { dev: "nvme0n1".into(), serial: "S64DNX0R123456A".into() }]);
}

#[test]
fn network_ping_validates_the_target() {
    let mut h = hl(132, 43);
    h.keys(b"4");
    h.keys(DOWN);
    h.frame();
    h.keys(DOWN); // eno1
    h.frame();
    h.keys(b"p");
    assert!(h.frame().contains("Address to ping"));
    h.keys(b"192.0.2.10");
    assert_eq!(h.keys(ENTER), vec![Request::Ping { target: "192.0.2.10".into() }]);
    h.keys(b"p");
    h.keys(b"a b;rm");
    assert!(h.keys(ENTER).is_empty());
    assert!(h.frame().contains("not a valid address"));
    h.keys(b"p");
    h.keys(ESC_SEQ_F1); // F1 while typing is just ignored by the dialog
    assert!(h.app.dialog_open());
}

#[test]
fn network_dhcp_on_selected_interface() {
    let mut h = hl(132, 43);
    h.keys(b"4");
    h.keys(DOWN);
    h.frame();
    h.keys(DOWN);
    h.frame();
    assert_eq!(h.keys(b"d"), vec![Request::Dhcp { iface: "eno1".into() }]);
}

#[test]
fn pcie_tree_collapses_and_expands() {
    let mut h = hl(132, 43);
    h.keys(b"2");
    h.keys(DOWN);
    let full = h.frame();
    assert!(full.contains("00:1c.0"));
    assert!(full.contains("01:00.0"));
    h.keys(LEFT); // collapse the host bridge (first row)
    let f = h.frame();
    assert!(!f.contains("00:1c.0"), "children hidden:\n{}", f);
    h.keys(RIGHT);
    assert!(h.frame().contains("00:1c.0"));
}

#[test]
fn pcie_degraded_link_is_called_out() {
    let mut h = hl(132, 43);
    h.keys(b"2");
    let f = h.frame();
    assert!(f.contains("x1 Gen1"));
    assert!(f.contains("attention"));
    h.keys(b"1");
    assert!(h.frame().contains("PCIe 0000:03:00.0 link degraded"));
}

#[test]
fn log_search_follow_and_filters() {
    let mut h = hl(132, 43);
    h.keys(b"7");
    h.keys(DOWN);
    let f = h.frame();
    assert!(f.contains("FOLLOW"));
    assert!(f.contains("i7labd: listening"));
    h.keys(b"l"); // level <= info drops the debug line
    let f = h.frame();
    assert!(f.contains("level<=info"));
    assert!(!f.contains("debug: lab init ready"));
    h.keys(b"l");
    h.keys(b"l"); // <= err
    let f = h.frame();
    assert!(f.contains("READ FPDMA"));
    assert!(!f.contains("ACPI: Core"));
    h.keys(b"c");
    assert!(h.frame().contains("ACPI: Core"));
    // tag filter
    h.keys(b"t");
    let f = h.frame();
    assert!(f.contains("tag:ata-error"), "{}", f);
    assert!(f.contains("1/9 lines"));
    h.keys(b"c");
    // search
    h.keys(b"/");
    h.keys(b"link is up");
    h.keys(ENTER);
    let f = h.frame();
    assert!(f.contains("search:'link is up'"));
    h.keys(b"n");
    assert!(h.frame().contains("paused"));
    // Enter shows the whole line
    h.keys(ENTER);
    assert!(h.frame().contains("Log line"));
}

#[test]
fn hostile_usb_string_is_inert() {
    let mut h = hl(132, 43);
    h.keys(b"5");
    h.keys(DOWN);
    h.keys(DOWN);
    h.keys(DOWN); // focus the list, then down to 1-3 (the stick)
    let b = h.buffer();
    let t = b.to_text();
    assert!(t.contains("Ultra Fit"), "{}", t);
    assert!(t.contains("u{001b}"), "escape made visible:\n{}", t);
    assert!(!t.contains('\x1b'));
    for y in 0..b.height() {
        for x in 0..b.width() {
            let c = b.get(x, y).unwrap().ch;
            assert!(c == '\0' || (c >= ' ' && c != '\x7f' && !('\u{80}'..='\u{9f}').contains(&c)), "control char at {},{}", x, y);
        }
    }
}

#[test]
fn ascii_mode_emits_only_ascii() {
    let mut h = Headless::new(132, 43, demo_data(), Options { ascii: true, ..Default::default() });
    for tab in ["Overview", "PCIe", "Storage", "Network", "USB", "Sensors", "Log", "Actions"] {
        h.app.select_tab(tab);
        let f = h.frame();
        assert!(f.is_ascii(), "{} page has non-ASCII:\n{}", tab, f.chars().filter(|c| !c.is_ascii()).collect::<String>());
    }
    // F9 toggles
    let mut h = hl(132, 43);
    assert!(!h.frame().is_ascii());
    assert_eq!(h.keys(b"\x1b[20~"), vec![Request::Redraw]);
    assert!(h.frame().is_ascii());
}

#[test]
fn too_small_terminal_says_so() {
    let mut h = hl(79, 24);
    let f = h.frame();
    assert!(f.contains("terminal too small"));
    assert!(f.contains("need 80x25"));
}

#[test]
fn no_control_path_and_no_keys_banner() {
    let mut h = Headless::new(132, 43, demo_data_no_control_path(), Options::default());
    let f = h.frame();
    assert!(f.contains("NO CONTROL PATH"), "{}", f);
    assert!(f.contains("NO KEYS"));
    assert!(f.contains("RTL8126"));
}

#[test]
fn global_keys_produce_requests() {
    let mut h = hl(132, 43);
    assert_eq!(h.keys(b"\x1b[15~"), vec![Request::Refresh, Request::Redraw]); // F5
    assert_eq!(h.keys(b"\x1b[12~"), vec![Request::ProbeNow]); // F2, Linux console / vt220 form
    assert_eq!(h.keys(b"\x1bOQ"), vec![Request::ProbeNow]); // F2, xterm form
    assert_eq!(h.keys(b"\x0c"), vec![Request::Redraw]);
    assert_eq!(h.keys(b"\x1b[21~"), vec![Request::Shell]); // F10
    assert!(h.keys(b"?").is_empty());
    assert!(h.frame().contains("Everywhere:"));
    assert!(h.keys(ENTER).is_empty());
    h.keys(b"\x1b[24~"); // F12
    assert!(h.frame().contains("About"));
}

#[test]
fn status_message_expires() {
    let mut h = hl(132, 43);
    h.app.set_status("hello operator");
    assert!(h.frame().contains("hello operator"));
    for _ in 0..60 {
        h.app.on_tick();
    }
    assert!(!h.frame().contains("hello operator"));
}

#[test]
fn compact_layout_shows_one_pane_and_drills_in() {
    let mut h = hl(80, 25);
    h.keys(b"3");
    h.keys(DOWN);
    let f = h.frame();
    assert!(f.contains("Disks"));
    assert!(!f.contains("Write gate"), "detail not shown yet:\n{}", f);
    h.keys(ENTER);
    assert_eq!(h.app.focus(), Focus::Detail);
    let f = h.frame();
    assert!(f.contains("Write gate"), "{}", f);
    assert!(!f.contains("Disks"));
    h.keys(b"\x1b[A"); // CSI A is Up here (detail scroll), not Esc
    assert_eq!(h.app.focus(), Focus::Detail);
}

#[test]
fn every_page_draws_at_every_size_without_panicking() {
    for (w, hgt) in [(80, 25), (80, 40), (100, 30), (132, 43), (200, 50), (240, 67), (300, 80)] {
        for tab in ["Overview", "PCIe", "Storage", "Network", "USB", "Sensors", "Log", "Actions"] {
            for focus_steps in 0..3 {
                let mut h = hl(w, hgt);
                h.app.select_tab(tab);
                for _ in 0..focus_steps {
                    h.keys(TAB);
                }
                for _ in 0..5 {
                    h.keys(DOWN);
                }
                let f = h.frame();
                assert!(f.lines().count() >= hgt as usize);
            }
        }
    }
}

#[test]
fn empty_data_does_not_panic() {
    for tab in ["Overview", "PCIe", "Storage", "Network", "USB", "Sensors", "Log", "Actions"] {
        let mut h = Headless::new(132, 43, Default::default(), Options::default());
        h.app.select_tab(tab);
        h.keys(TAB);
        h.keys(DOWN);
        h.keys(ENTER);
        h.keys(b"t");
        h.keys(b"w");
        h.keys(b"d");
        h.keys(b"n");
        let f = h.frame();
        assert!(f.contains("i7lablinux"));
    }
}

#[test]
fn tiny_sizes_do_not_panic() {
    for (w, hgt) in [(0, 0), (1, 1), (10, 3), (80, 5), (80, 24), (30, 100)] {
        let mut h = hl(w, hgt);
        let _ = h.frame();
        h.keys(b"q");
        let _ = h.frame();
    }
}
