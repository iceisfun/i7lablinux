//! Kernel command line flags relevant to PID 1 (labproto::cmdline tokenizer, last wins). Owner: P2.
//! Flags that only i7labd reads (`i7lab.http`, `i7lab.ether`, `i7lab.http_bind`, ...) are ignored here.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Console {
    Open,
    Locked,
    Off,
}

/// Optional data partition: `i7lab.data=LABEL[,rw]` (default label I7LABDATA, read-only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataSpec {
    pub label: String,
    pub rw: bool,
}

pub const DEFAULT_DATA_LABEL: &str = "I7LABDATA";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flags {
    pub console: Console,
    pub tui: bool,
    pub watchdog: bool,
    pub serial: Option<String>,
    pub debug: bool,
    pub ascii: bool,
    pub hostname: Option<String>,
    /// None = `i7lab.data=off`
    pub data: Option<DataSpec>,
    /// ttys named by `console=` (kernel flags, not i7lab.*), in order, without the baud suffix
    pub consoles: Vec<String>,
}

impl Flags {
    pub fn parse(cmdline: &str) -> Flags {
        let mut f = Flags {
            console: Console::Open,
            tui: true,
            watchdog: true,
            serial: None,
            debug: false,
            ascii: false,
            hostname: None,
            data: Some(DataSpec { label: DEFAULT_DATA_LABEL.into(), rw: false }),
            consoles: Vec::new(),
        };
        for (k, v) in labproto::cmdline::i7lab_args(cmdline) {
            let v = v.as_str();
            match k.as_str() {
                "console" => f.console = match v { "locked" => Console::Locked, "off" => Console::Off, _ => Console::Open },
                "tui" => f.tui = v != "off" && v != "0",
                "watchdog" => f.watchdog = v != "0",
                "serial" => f.serial = Some(v.to_string()),
                "debug" => f.debug = v == "1",
                "ascii" => f.ascii = v == "1",
                "hostname" => f.hostname = Some(v.to_string()),
                "data" => f.data = parse_data(v),
                _ => {}
            }
        }
        f.consoles = kernel_consoles(cmdline);
        f
    }
}

fn parse_data(v: &str) -> Option<DataSpec> {
    if v == "off" || v == "0" {
        return None;
    }
    let (label, rw) = match v.split_once(',') {
        Some((l, opt)) => (l, opt == "rw"),
        None => (v, false),
    };
    let label = if label.is_empty() || label == "1" { DEFAULT_DATA_LABEL } else { label };
    Some(DataSpec { label: label.to_string(), rw })
}

/// `console=ttyS0,115200n8 console=tty0` -> ["ttyS0", "tty0"]. Bare `console=` and non-tty values are skipped.
pub fn kernel_consoles(cmdline: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for w in labproto::cmdline::tokenize(cmdline) {
        if let Some(v) = w.strip_prefix("console=") {
            let name = v.split(',').next().unwrap_or("");
            let ok = !name.is_empty() && name.len() <= 16 && name.bytes().all(|b| b.is_ascii_alphanumeric());
            if ok && !out.iter().any(|o| o == name) {
                out.push(name.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_and_overrides() {
        let f = Flags::parse("ro i7lab.console=locked i7lab.watchdog=0 i7lab.console=open");
        assert_eq!(f.console, Console::Open);
        assert!(!f.watchdog && f.tui);
        assert_eq!(f.data, Some(DataSpec { label: "I7LABDATA".into(), rw: false }));
    }
    #[test]
    fn data_forms() {
        assert_eq!(Flags::parse("i7lab.data=off").data, None);
        assert_eq!(Flags::parse("i7lab.data=SCRATCH,rw").data, Some(DataSpec { label: "SCRATCH".into(), rw: true }));
        assert_eq!(Flags::parse("i7lab.data=SCRATCH").data.unwrap().rw, false);
    }
    #[test]
    fn consoles_from_kernel_cmdline() {
        let f = Flags::parse("console=tty0 console=ttyS0,115200n8 console=ttyS0 i7lab.tui=off i7lab.ascii=1 i7lab.hostname=lab1");
        assert_eq!(f.consoles, vec!["tty0", "ttyS0"]);
        assert!(!f.tui && f.ascii);
        assert_eq!(f.hostname.as_deref(), Some("lab1"));
        assert!(kernel_consoles("console=,115200 console=../x").is_empty());
    }
}
