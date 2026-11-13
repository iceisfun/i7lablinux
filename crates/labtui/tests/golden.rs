//! Golden frames: every page at 80x25, 132x43 and 240x67 on the demo host.
//! Regenerate with `UPDATE_GOLDEN=1 cargo test -p labtui --test golden` and review the diff.

use std::path::PathBuf;

use labtui::headless::Headless;
use labtui::sample::{demo_data_no_control_path, demo_data_with_test};
use labtui::Options;

fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden").join(format!("{}.txt", name))
}

fn check(name: &str, frame: &str) {
    let p = path(name);
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        std::fs::write(&p, frame).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("missing golden file {} (run with UPDATE_GOLDEN=1)", p.display()));
    if want != frame {
        // show the first differing row, the whole frame is in the failure output below
        let (w, g): (Vec<&str>, Vec<&str>) = (want.lines().collect(), frame.lines().collect());
        let row = (0..w.len().max(g.len())).find(|i| w.get(*i) != g.get(*i)).unwrap_or(0);
        panic!("golden {} differs at row {}:\n want: {:?}\n got:  {:?}\n--- frame ---\n{}", name, row, w.get(row), g.get(row), frame);
    }
}

const SIZES: [(u16, u16); 3] = [(80, 25), (132, 43), (240, 67)];
const TABS: [&str; 8] = ["Overview", "PCIe", "Storage", "Network", "USB", "Sensors", "Log", "Actions"];

#[test]
fn pages_at_three_sizes() {
    for tab in TABS {
        for (w, h) in SIZES {
            let mut hl = Headless::new(w, h, demo_data_with_test(), Options::default());
            hl.app.select_tab(tab);
            let frame = hl.frame();
            check(&format!("{}_{}x{}", tab.to_lowercase(), w, h), &frame);
        }
    }
}

#[test]
fn ascii_frame() {
    let mut hl = Headless::new(132, 43, demo_data_with_test(), Options { ascii: true, ..Default::default() });
    hl.app.select_tab("Storage");
    hl.keys(b"\x1b[B");
    check("storage_ascii_132x43", &hl.frame());
}

#[test]
fn storage_with_running_test_and_dialog() {
    let mut hl = Headless::new(132, 43, demo_data_with_test(), Options::default());
    hl.app.select_tab("Storage");
    hl.keys(b"\x1b[B\x1b[B\x1b[B");
    check("storage_test_132x43", &hl.frame());
    hl.keys(b"t");
    check("storage_dialog_132x43", &hl.frame());
}

#[test]
fn banners_frame() {
    let mut hl = Headless::new(132, 43, demo_data_no_control_path(), Options::default());
    check("overview_banners_132x43", &hl.frame());
}
