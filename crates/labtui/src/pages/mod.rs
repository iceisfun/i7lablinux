//! The page set from docs/TUI.md: Overview, PCIe, Storage, Network, USB, Sensors, Log, Actions. Owner: P5.

mod actions;
mod log;
mod network;
mod overview;
mod pci;
mod sensors;
mod storage;
mod usb;

pub use actions::ActionsPage;
pub use log::LogPage;
pub use network::NetworkPage;
pub use overview::OverviewPage;
pub use pci::PciPage;
pub use sensors::SensorsPage;
pub use storage::StoragePage;
pub use usb::UsbPage;

use crate::buffer::Style;
use crate::page::Page;
use crate::theme::Theme;
use crate::widgets::{line, Line};

/// Tab order. `TABS` in i7labd::console must match.
pub const TAB_NAMES: [&str; 8] = ["Overview", "PCIe", "Storage", "Network", "USB", "Sensors", "Log", "Actions"];

pub fn all_pages() -> Vec<Box<dyn Page>> {
    vec![
        Box::new(OverviewPage::default()),
        Box::new(PciPage::default()),
        Box::new(StoragePage::default()),
        Box::new(NetworkPage::default()),
        Box::new(UsbPage::default()),
        Box::new(SensorsPage::default()),
        Box::new(LogPage::default()),
        Box::new(ActionsPage::default()),
    ]
}

/// Blank line.
pub(crate) fn blank() -> Line {
    line("", Style::default())
}

/// Section heading line.
pub(crate) fn heading(t: &Theme, s: &str) -> Line {
    line(s.to_string(), t.title)
}

pub(crate) fn short_bdf(bdf: &str) -> &str {
    bdf.strip_prefix("0000:").unwrap_or(bdf)
}

pub(crate) fn or_dash(s: Option<&str>) -> String {
    s.filter(|v| !v.is_empty()).unwrap_or("-").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn page_order_matches_tab_names() {
        let p = all_pages();
        assert_eq!(p.len(), TAB_NAMES.len());
        for (page, name) in p.iter().zip(TAB_NAMES) {
            assert_eq!(page.title(), name);
            assert_eq!(page.short().len(), 3);
        }
    }
}
