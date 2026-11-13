//! Baked config (/etc/i7lab/i7lab.conf, `key = value` lines) overridden by `i7lab.*` kernel args. Owner: P6a.

use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleMode {
    /// TUI with actions; quitting it starts i7labsh (default)
    Open,
    /// read-only TUI, no shell
    Locked,
    /// nothing on the console
    Off,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub http_port: Option<u16>,
    pub beacon_compat: bool,
    /// unauthenticated I7LR1 address hints: OFF by default (review security F6); I7LR2 (HMAC) always accepted
    pub accept_v1_hint: bool,
    /// interfaces the ether server listens on; empty = every Ethernet NIC with carrier (default, PLAN.md C23)
    pub ether_allow: Vec<String>,
    pub ether_deny: Vec<String>,
    /// HTTP bind: None = all addresses; Some(iface name or IPv4 address) restricts it (`i7lab.http_bind=`)
    pub http_bind: Option<String>,
    pub console: ConsoleMode,
    pub tui: bool,
    pub serial_tty: Option<String>,
    pub ascii: bool,
    pub boot_partuuid: Option<String>,
    pub image_build: String,
    pub hostname: String,
    pub key_dir: PathBuf,
    pub audit_log: PathBuf,
    /// runtime directory (ctl.sock, jobs/, tui.up); a temp dir in tests
    pub run_dir: PathBuf,
    /// built-in DHCP client on NICs without an address (`i7lab.dhcp=0` turns it off)
    pub dhcp: bool,
    /// reboot/poweroff only log and set the state (tests)
    pub power_dry_run: bool,
    pub resolv_conf: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            http_port: Some(8080),
            beacon_compat: true,
            accept_v1_hint: false,
            ether_allow: vec![],
            ether_deny: vec![],
            http_bind: None,
            console: ConsoleMode::Open,
            tui: true,
            serial_tty: None,
            ascii: false,
            boot_partuuid: None,
            image_build: "dev".into(),
            hostname: "i7lab".into(),
            key_dir: PathBuf::from("/etc/i7lab/keys"),
            audit_log: PathBuf::from("/run/i7lab/audit.log"),
            run_dir: PathBuf::from("/run/i7lab"),
            dhcp: true,
            power_dry_run: false,
            resolv_conf: PathBuf::from("/etc/resolv.conf"),
        }
    }
}

impl Config {
    pub fn load(etc: &Path, cmdline: &str) -> Config {
        let mut c = Config { key_dir: etc.join("keys"), ..Config::default() };
        if let Ok(t) = std::fs::read_to_string(etc.join("i7lab.conf")) {
            for l in t.lines() {
                if let Some((k, v)) = l.split_once('=') {
                    c.apply(k.trim(), v.trim());
                }
            }
        }
        if let Ok(b) = std::fs::read_to_string(etc.join("BUILD")) {
            c.image_build = b.lines().next().unwrap_or("dev").to_string();
        }
        for (k, v) in labproto::cmdline::i7lab_args(cmdline) {
            c.apply(&k, &v);
        }
        c
    }

    /// One setting; unknown keys ignored. Shared by the conf file and the cmdline (cmdline wins: applied last).
    pub fn apply(&mut self, k: &str, v: &str) {
        let on = matches!(v, "1" | "on" | "yes" | "true");
        match k {
            "http" => self.http_port = if v == "off" { None } else { v.parse().ok().or(self.http_port) },
            "beacon_compat" => self.beacon_compat = on,
            "accept_v1_hint" => self.accept_v1_hint = on,
            "ether_deny" => self.ether_deny = v.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect(),
            "ether" => self.ether_allow = if v == "all" { vec![] } else { v.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect() },
            "http_bind" => self.http_bind = if v.is_empty() || v == "all" { None } else { Some(v.to_string()) },
            "console" => {
                self.console = match v {
                    "locked" => ConsoleMode::Locked,
                    "off" => ConsoleMode::Off,
                    _ => ConsoleMode::Open,
                }
            }
            "tui" => self.tui = v != "off" && v != "0",
            "serial" => self.serial_tty = Some(v.to_string()),
            "ascii" => self.ascii = on,
            "boot" => self.boot_partuuid = v.strip_prefix("PARTUUID=").map(str::to_string),
            "hostname" => self.hostname = v.to_string(),
            "dhcp" => self.dhcp = v != "0" && v != "off",
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cmdline_overrides() {
        let c = Config::load(Path::new("/nonexistent"), "quiet i7lab.http=off i7lab.console=locked i7lab.boot=PARTUUID=abc");
        assert_eq!(c.http_port, None);
        assert_eq!(c.console, ConsoleMode::Locked);
        assert_eq!(c.boot_partuuid.as_deref(), Some("abc"));
        assert!(!c.accept_v1_hint, "v1 hints are off unless enabled");
        let c = Config::load(Path::new("/nonexistent"), "i7lab.ether=eno1,eno2 i7lab.http_bind=eno1");
        assert_eq!(c.ether_allow, vec!["eno1", "eno2"]);
        assert_eq!(c.http_bind.as_deref(), Some("eno1"));
    }
}
