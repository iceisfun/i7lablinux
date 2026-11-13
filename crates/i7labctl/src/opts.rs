//! Global option split: the options of I7LABCTL.md 2.2 are recognised anywhere before a `--` and removed;
//! what is left (subcommand, its options and positionals, and everything after `--`) is returned verbatim.

use std::path::PathBuf;

use labproto::keys::Role;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportPref {
    Auto,
    Ether,
    Http,
    Ssh,
}

#[derive(Clone, Debug)]
pub struct Global {
    pub host: Option<String>,
    pub ether: Option<String>,
    pub cmd: Option<String>,
    pub http: Option<String>,
    pub ssh: Option<String>,
    pub transport: TransportPref,
    pub ifaces: Vec<String>,
    pub vlans: Vec<u16>,
    pub role: Option<Role>,
    pub key: Option<PathBuf>,
    pub timeout: Option<f64>,
    pub retries: u32,
    pub json: bool,
    pub quiet: bool,
    pub verbose: u8,
    pub no_color: bool,
    pub registry: Option<PathBuf>,
    pub no_registry: bool,
    pub yes: bool,
    pub link: Option<String>,
    pub help: bool,
    pub version: bool,
}

impl Default for Global {
    fn default() -> Self {
        Global {
            host: None,
            ether: None,
            cmd: None,
            http: None,
            ssh: None,
            transport: TransportPref::Auto,
            ifaces: Vec::new(),
            vlans: Vec::new(),
            role: None,
            key: None,
            timeout: None,
            retries: 0,
            json: false,
            quiet: false,
            verbose: 0,
            no_color: false,
            registry: None,
            no_registry: false,
            yes: false,
            link: None,
            help: false,
            version: false,
        }
    }
}

impl Global {
    /// True when the host was named by an option (so positionals do not start with a host).
    pub fn host_by_flag(&self) -> bool {
        self.host.is_some() || self.ether.is_some() || self.http.is_some() || self.ssh.is_some()
    }
}

/// `13`, `13,20`, `1-200`, `1-200,-5`? Only plain ids and ranges: `a,b,c-d`. Returns sorted unique ids 1..=4094.
pub fn parse_vlans(s: &str) -> Result<Vec<u16>, String> {
    let mut v = Vec::new();
    for part in s.split(',').filter(|p| !p.is_empty()) {
        let (a, b) = match part.split_once('-') {
            Some((a, b)) => (a.parse::<u16>().map_err(|_| bad_vlan(part))?, b.parse::<u16>().map_err(|_| bad_vlan(part))?),
            None => {
                let x = part.parse::<u16>().map_err(|_| bad_vlan(part))?;
                (x, x)
            }
        };
        if a == 0 || b > 4094 || a > b {
            return Err(bad_vlan(part));
        }
        v.extend(a..=b);
    }
    if v.is_empty() {
        return Err(bad_vlan(s));
    }
    v.sort_unstable();
    v.dedup();
    Ok(v)
}

fn bad_vlan(s: &str) -> String {
    format!("bad VLAN id or range '{}' (use 1-4094, ranges like 1-200, lists with commas)", s)
}

const VALUED: &[(&str, &str)] = &[
    ("-H", "host"),
    ("--host", "host"),
    ("--ether", "ether"),
    ("--cmd", "cmd"),
    ("--http", "http"),
    ("--ssh", "ssh"),
    ("--transport", "transport"),
    ("-i", "iface"),
    ("--iface", "iface"),
    ("--vlan", "vlan"),
    ("--role", "role"),
    ("--key", "key"),
    ("--timeout", "timeout"),
    ("--retries", "retries"),
    ("--registry", "registry"),
    ("--link", "link"),
];

/// Split global options out of `args` (the arguments after argv[0]).
pub fn split_global(args: &[String]) -> Result<(Global, Vec<String>), String> {
    let mut g = Global::default();
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            rest.extend(args[i..].iter().cloned());
            break;
        }
        // flags
        match a.as_str() {
            "--json" => g.json = true,
            "-q" | "--quiet" => g.quiet = true,
            "-v" => g.verbose = g.verbose.max(1),
            "-vv" => g.verbose = 2,
            "--no-color" => g.no_color = true,
            "--no-registry" => g.no_registry = true,
            "-y" | "--yes" => g.yes = true,
            "-h" | "--help" => g.help = true,
            "-V" | "--version" => g.version = true,
            _ => {
                // valued: `--opt value` or `--opt=value`
                let (name, inline) = match a.split_once('=') {
                    Some((n, v)) if n.starts_with("--") => (n, Some(v.to_string())),
                    _ => (a.as_str(), None),
                };
                if let Some((_, key)) = VALUED.iter().find(|(n, _)| *n == name) {
                    let v = match inline {
                        Some(v) => v,
                        None => {
                            i += 1;
                            args.get(i).cloned().ok_or_else(|| format!("option {} needs a value", name))?
                        }
                    };
                    apply(&mut g, key, &v)?;
                } else {
                    rest.push(a.clone());
                }
            }
        }
        i += 1;
    }
    if std::env::var_os("NO_COLOR").is_some() {
        g.no_color = true;
    }
    Ok((g, rest))
}

fn apply(g: &mut Global, key: &str, v: &str) -> Result<(), String> {
    match key {
        "host" => g.host = Some(v.to_string()),
        "ether" => {
            if labproto::Mac::parse(v).is_none() {
                return Err(format!("--ether needs a MAC address, got '{}'", v));
            }
            g.ether = Some(v.to_ascii_lowercase())
        }
        "cmd" => g.cmd = Some(v.to_string()),
        "http" => g.http = Some(v.to_string()),
        "ssh" => g.ssh = Some(v.to_string()),
        "transport" => {
            g.transport = match v {
                "auto" => TransportPref::Auto,
                "ether" => TransportPref::Ether,
                "http" => TransportPref::Http,
                "ssh" => TransportPref::Ssh,
                _ => return Err(format!("--transport must be auto, ether, http or ssh, got '{}'", v)),
            }
        }
        "iface" => g.ifaces.extend(v.split(',').filter(|s| !s.is_empty()).map(String::from)),
        "vlan" => g.vlans.extend(parse_vlans(v)?),
        "role" => g.role = Some(Role::parse(v).ok_or_else(|| format!("--role must be admin or ro, got '{}'", v))?),
        "key" => g.key = Some(PathBuf::from(v)),
        "timeout" => {
            let t: f64 = v.parse().map_err(|_| format!("--timeout needs seconds, got '{}'", v))?;
            if !(0.0..=86400.0).contains(&t) {
                return Err("--timeout out of range".into());
            }
            g.timeout = Some(t)
        }
        "retries" => g.retries = v.parse().map_err(|_| format!("--retries needs a number, got '{}'", v))?,
        "registry" => g.registry = Some(PathBuf::from(v)),
        "link" => g.link = Some(v.to_string()),
        _ => unreachable!(),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn globals_anywhere() {
        let (g, rest) = split_global(&v(&["inv", "--json", "h1", "-i", "eth0", "--vlan", "13", "--timeout=5", "-v"])).unwrap();
        assert!(g.json);
        assert_eq!(g.ifaces, vec!["eth0"]);
        assert_eq!(g.vlans, vec![13]);
        assert_eq!(g.timeout, Some(5.0));
        assert_eq!(g.verbose, 1);
        assert_eq!(rest, v(&["inv", "h1"]));
    }

    #[test]
    fn double_dash_stops() {
        let (g, rest) = split_global(&v(&["exec", "h", "--json", "--", "ls", "--json", "-v"])).unwrap();
        assert!(g.json);
        assert_eq!(rest, v(&["exec", "h", "--", "ls", "--json", "-v"]));
    }

    #[test]
    fn raw_form() {
        let (g, rest) = split_global(&v(&["--ether", "02:00:00:9D:01:57", "--cmd", "blk.read", "sda", "--mb", "8"])).unwrap();
        assert_eq!(g.ether.as_deref(), Some("02:00:00:9d:01:57"));
        assert_eq!(g.cmd.as_deref(), Some("blk.read"));
        assert_eq!(rest, v(&["sda", "--mb", "8"]));
        assert!(g.host_by_flag());
    }

    #[test]
    fn long_verbose_belongs_to_pcie() {
        let (g, rest) = split_global(&v(&["pcie", "h", "--verbose"])).unwrap();
        assert_eq!(g.verbose, 0);
        assert_eq!(rest, v(&["pcie", "h", "--verbose"]));
    }

    #[test]
    fn errors() {
        assert!(split_global(&v(&["--ether", "nope"])).is_err());
        assert!(split_global(&v(&["--timeout"])).is_err());
        assert!(split_global(&v(&["--role", "root"])).is_err());
        assert!(split_global(&v(&["--transport", "carrier-pigeon"])).is_err());
        assert!(split_global(&v(&["--vlan", "0"])).is_err());
        assert!(split_global(&v(&["--vlan", "5000"])).is_err());
    }

    #[test]
    fn vlan_ranges() {
        assert_eq!(parse_vlans("1-3,10,2").unwrap(), vec![1, 2, 3, 10]);
        assert!(parse_vlans("3-1").is_err());
        assert!(parse_vlans("").is_err());
    }
}
