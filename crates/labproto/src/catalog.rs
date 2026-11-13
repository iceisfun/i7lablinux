//! The command catalogue: single source of truth for ids, names, roles and usage strings.
//! Feeds the i7labd registry, `i7labctl help`, the TUI Actions menu, the SPA and openapi.json.
//! Table = PROTOCOL.md section 7 (ids are never reused). Owner: P1.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// read-only key is enough
    Ro,
    /// admin key only
    Admin,
    /// ro key allowed within the read-only path allow-list (get, fs.ls, fs.stat); admin anywhere
    RoLimitedPaths,
}

#[derive(Debug)]
pub struct CmdSpec {
    pub id: u16,
    pub name: &'static str,
    /// caps bit number (0 core, 1 probes, 2 net, 3 exec, 4 files, 5 power, 6 services, 7 logs, 8 console, 9 keys)
    pub group: u8,
    pub access: Access,
    /// sends DATA on chan 1/2/4 or NDJSON events over HTTP
    pub streams: bool,
    pub usage: &'static str,
    pub summary: &'static str,
    /// first release that serves the command (PLAN.md section 15). Entries with `since != CURRENT_RELEASE` are
    /// listed by help/SPA as "(planned vX.Y)", hidden from the TUI Actions menu, and answer UNSUPPORTED.
    pub since: &'static str,
}

/// The release this tree builds. Commands whose `since` differs are planned, not served (review F30).
pub const CURRENT_RELEASE: &str = "v0.1";

impl CmdSpec {
    pub fn planned(&self) -> bool {
        self.since != CURRENT_RELEASE
    }
    /// Commands that take a path as their FIRST word and go through the i7labd path policy.
    pub fn path_op(&self) -> Option<PathOp> {
        match self.name {
            "get" | "fs.ls" | "fs.stat" => Some(PathOp::Read),
            "put" | "fs.rm" => Some(PathOp::Write),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathOp {
    Read,
    Write,
}

macro_rules! c {
    ($id:expr, $name:expr, $g:expr, $a:ident, $s:expr, $usage:expr, $sum:expr) => {
        c!($id, $name, $g, $a, $s, $usage, $sum, "v0.1")
    };
    ($id:expr, $name:expr, $g:expr, $a:ident, $s:expr, $usage:expr, $sum:expr, $since:expr) => {
        CmdSpec { id: $id, name: $name, group: $g, access: Access::$a, streams: $s, usage: $usage, summary: $sum, since: $since }
    };
}

pub static CATALOG: &[CmdSpec] = &[
    c!(0x0001, "ping", 0, Ro, false, "[ECHO]", "round trip, uptime, boot id"),
    c!(0x0002, "id", 0, Ro, false, "", "identity, versions, key fingerprints, build id"),
    c!(0x0003, "cmds", 0, Ro, false, "", "list supported commands"),
    c!(0x0004, "stats", 0, Ro, false, "", "protocol counters"),
    c!(0x0005, "time.set", 0, Admin, false, "UNIX_SECONDS", "set the host clock (audit timestamps before SNTP)"),
    c!(0x0010, "inv", 1, Ro, false, "[--section S,S..]", "system inventory (sections = probe names)"),
    c!(0x0011, "pcie", 1, Ro, false, "[--tree] [--id VVVV:DDDD] [--class CC] [--verbose]", "PCIe devices"),
    c!(0x0012, "usb", 1, Ro, false, "[--tree]", "USB devices"),
    c!(0x0013, "blk.ls", 1, Ro, false, "[--all]", "block devices with write-safety verdict"),
    c!(0x0014, "blk.smart", 1, Ro, false, "DEV [--attrs]", "SMART / NVMe health"),
    c!(0x0015, "blk.read", 1, Ro, true, "DEV [--mb N] [--regions start,mid,end | --offset B --len B] [--bs 1m] [--direct]", "read test (never writes)"),
    c!(0x0016, "blk.write", 1, Admin, true, "DEV --destructive --serial S [--mb N] [--regions ..] [--offset B --len B] [--seed N]", "destructive write+verify test behind the safety gate"),
    c!(0x0017, "blk.verify", 1, Ro, true, "DEV --seed N [--mb N] [--regions ..]", "re-read and compare a seeded pattern"),
    c!(0x0018, "net.ls", 2, Ro, false, "[IFACE]", "network interfaces"),
    c!(0x0019, "thermal", 1, Ro, true, "[--follow]", "temperatures, fans"),
    c!(0x0020, "exec", 3, Admin, true, "[--timeout S] [--env K=V].. [--cwd D] [--tty CxR] [--detach] [--stdin] -- ARGV..", "run a program (no shell)"),
    c!(0x0021, "shell", 3, Admin, true, "[--cols N --rows N] [--term T]", "i7labsh on a pty"),
    c!(0x0030, "put", 4, Admin, true, "PATH --size N --sha256 HEX [--mode 0644] [--offset N] [--mkdirs]", "upload a file (PATH must be the first word)"),
    c!(0x0031, "get", 4, RoLimitedPaths, true, "PATH [--offset N] [--len N]", "download a file (PATH must be the first word)"),
    c!(0x0032, "fs.ls", 4, RoLimitedPaths, false, "PATH [--long]", "list a directory"),
    c!(0x0033, "fs.stat", 4, RoLimitedPaths, false, "PATH", "stat a path"),
    c!(0x0034, "fs.rm", 4, Admin, false, "PATH [--recursive]", "remove a path"),
    c!(0x0040, "reboot", 5, Admin, false, "[--force] [--delay S] [--uefi] [--to-os]", "reboot (firmware setup, or installed OS once; --to-os UEFI only in v0.1)"),
    c!(0x0041, "poweroff", 5, Admin, false, "[--delay S]", "power off"),
    c!(0x0042, "kexec", 5, Admin, false, "--kernel PATH [--initrd PATH] [--cmdline STR]", "load and exec another kernel", "v0.4"),
    c!(0x0050, "net.set", 2, Admin, false, "IFACE (--dhcp | --ip A.B.C.D/N [--gw A.B.C.D] [--dns A,..]) [--mtu N] [--confirm S]", "configure an interface"),
    c!(0x0051, "net.vlan", 2, Admin, false, "add IFACE VID [--ip ..] | del IFACE VID", "802.1Q sub-interfaces"),
    c!(0x0052, "net.confirm", 2, Admin, false, "", "keep a net.set made with --confirm"),
    c!(0x0053, "net.link", 2, Admin, false, "IFACE up|down", "link up/down"),
    c!(0x0060, "svc", 6, Admin, false, "http|beacon|ether start|stop|status [--port N] [--force]", "agent services", "v0.2"),
    c!(0x0070, "logs", 7, Ro, true, "[--dmesg|--init|--daemon|--http|--audit] [-n LINES] [-f]", "logs"),
    c!(0x0080, "identify", 8, Admin, false, "[--seconds N] [--stop]", "blink LEDs, banner on the console"),
    c!(0x0081, "msg", 8, Admin, false, "TEXT..", "show a message on the console TUI"),
    c!(0x0082, "tui", 8, Admin, false, "tab NAME | reset", "switch the console TUI tab"),
    c!(0x0083, "tui.dump", 8, Ro, false, "", "text screenshot of the console TUI frame"),
    c!(0x0090, "key.set", 9, Admin, false, "ROLE --wrapped HEX [--persist]", "add/replace a role key (key-wrapped; planned)", "v0.3"),
    c!(0x00A0, "jobs", 3, Admin, true, "[ls | kill ID | out ID]", "detached jobs"),
];

pub fn by_name(name: &str) -> Option<&'static CmdSpec> {
    CATALOG.iter().find(|c| c.name == name)
}

pub fn by_id(id: u16) -> Option<&'static CmdSpec> {
    CATALOG.iter().find(|c| c.id == id)
}

/// Bit set of command groups present in the catalogue.
pub fn caps_bits() -> u32 {
    CATALOG.iter().fold(0, |acc, c| acc | (1u32 << c.group))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unique_ids_and_names() {
        for (i, a) in CATALOG.iter().enumerate() {
            for b in &CATALOG[i + 1..] {
                assert_ne!(a.id, b.id, "{} {}", a.name, b.name);
                assert_ne!(a.name, b.name);
            }
            assert!(a.id < 0x8000, "0x8xxx is reserved for private experiments");
        }
        assert_eq!(by_name("blk.write").unwrap().access, Access::Admin);
        assert_eq!(by_id(1).unwrap().name, "ping");
        assert!(by_name("key.set").unwrap().planned() && by_name("kexec").unwrap().planned());
        assert!(!by_name("tui.dump").unwrap().planned());
        assert_eq!(by_name("get").unwrap().path_op(), Some(PathOp::Read));
        assert_eq!(by_name("fs.rm").unwrap().path_op(), Some(PathOp::Write));
    }
}
