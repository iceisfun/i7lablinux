//! Configuration: built-in defaults, overridden by `<data>\config.json` and command-line flags.
//! Everything is optional. Directories default to C:\oracle (results, probes, event log) and C:\ProgramData\i7oracled.

use std::path::{Path, PathBuf};

use crate::json::{self, Limits, Value};

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// C:\oracle: probes\, results\, power-events.jsonl, agent spool, markers.
    pub oracle_dir: PathBuf,
    /// C:\ProgramData\i7oracled: keys\, config.json.
    pub data_dir: PathBuf,
    pub keys_dir: PathBuf,
    pub port: u16,
    pub bind: String,
    pub beacon_port: u16,
    pub beacon_interval_s: u64,
    /// Loopback port where the interactive agent forwards window-only events to the service.
    pub agent_port: u16,
    /// `host:port` of an optional collector that receives POST /oracle-hello after the first-boot sweep.
    pub collector: Option<String>,
    pub sweep_on_first_boot: bool,
    pub sweep_timeout_s: u64,
    pub sweep_delay_s: u64,
    /// Unchanged power samples are still written every this many seconds (changes are written at once).
    pub heartbeat_s: u64,
    pub beacon: bool,
}

impl Config {
    pub fn defaults() -> Config {
        Config::with_dirs(PathBuf::from("C:\\oracle"), PathBuf::from("C:\\ProgramData\\i7oracled"))
    }

    pub fn with_dirs(oracle: PathBuf, data: PathBuf) -> Config {
        Config {
            keys_dir: data.join("keys"),
            oracle_dir: oracle,
            data_dir: data,
            port: 8765,
            bind: "0.0.0.0".into(),
            beacon_port: 8766,
            beacon_interval_s: 5,
            agent_port: 8767,
            collector: None,
            sweep_on_first_boot: true,
            sweep_timeout_s: 120,
            sweep_delay_s: 30,
            heartbeat_s: 10,
            beacon: true,
        }
    }

    pub fn probes_dir(&self) -> PathBuf {
        self.oracle_dir.join("probes")
    }
    pub fn results_dir(&self) -> PathBuf {
        self.oracle_dir.join("results")
    }
    pub fn events_path(&self) -> PathBuf {
        crate::evlog::path_in(&self.oracle_dir)
    }
    pub fn spool_path(&self) -> PathBuf {
        self.oracle_dir.join("agent-spool.jsonl")
    }
    pub fn sweep_marker(&self) -> PathBuf {
        self.oracle_dir.join("first-boot-sweep.done")
    }
    pub fn config_path(&self) -> PathBuf {
        self.data_dir.join("config.json")
    }

    /// Apply the keys present in a config.json text. Unknown keys are ignored (forward compatible), wrong types are errors.
    pub fn apply_json(&mut self, text: &str) -> Result<(), String> {
        let v = json::parse(text, &Limits::default()).map_err(|e| format!("config.json: {} at {}", e.msg, e.offset))?;
        if !matches!(v, Value::Obj(_)) {
            return Err("config.json: not an object".into());
        }
        let s = |k: &str| -> Result<Option<String>, String> {
            match v.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::Str(x)) => Ok(Some(x.clone())),
                Some(_) => Err(format!("config.json: {} must be a string", k)),
            }
        };
        let n = |k: &str| -> Result<Option<u64>, String> {
            match v.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(x) => x.as_u64().map(Some).ok_or_else(|| format!("config.json: {} must be a non-negative integer", k)),
            }
        };
        let b = |k: &str| -> Result<Option<bool>, String> {
            match v.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::Bool(x)) => Ok(Some(*x)),
                Some(_) => Err(format!("config.json: {} must be true or false", k)),
            }
        };
        let port = |k: &str, cur: &mut u16| -> Result<(), String> {
            if let Some(x) = n(k)? {
                *cur = u16::try_from(x).ok().filter(|p| *p != 0).ok_or_else(|| format!("config.json: {} out of range", k))?;
            }
            Ok(())
        };
        port("port", &mut self.port)?;
        port("beacon_port", &mut self.beacon_port)?;
        port("agent_port", &mut self.agent_port)?;
        if let Some(x) = s("bind")? {
            self.bind = x;
        }
        if let Some(x) = s("oracle_dir")? {
            self.oracle_dir = PathBuf::from(x);
        }
        if let Some(x) = s("collector")? {
            self.collector = if x.is_empty() { None } else { Some(normalise_collector(&x)?) };
        }
        if let Some(x) = n("beacon_interval_s")? {
            self.beacon_interval_s = x.clamp(1, 3600);
        }
        if let Some(x) = n("sweep_timeout_s")? {
            self.sweep_timeout_s = x.clamp(1, 86_400);
        }
        if let Some(x) = n("sweep_delay_s")? {
            self.sweep_delay_s = x.min(3600);
        }
        if let Some(x) = n("heartbeat_s")? {
            self.heartbeat_s = x.clamp(1, 3600);
        }
        if let Some(x) = b("sweep_on_first_boot")? {
            self.sweep_on_first_boot = x;
        }
        if let Some(x) = b("beacon")? {
            self.beacon = x;
        }
        Ok(())
    }

    pub fn load_file(&mut self, path: &Path) -> Result<bool, String> {
        match std::fs::read_to_string(path) {
            Ok(t) => self.apply_json(t.trim_start_matches('\u{feff}')).map(|_| true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("{}: {}", path.display(), e)),
        }
    }
}

/// Accepts `host:port`, `http://host:port` and `http://host:port/`. Returns `host:port`.
pub fn normalise_collector(s: &str) -> Result<String, String> {
    let t = s.trim().trim_start_matches("http://").trim_end_matches('/');
    let (host, port) = t.rsplit_once(':').ok_or("collector must be host:port")?;
    if host.is_empty() || host.contains('/') || host.contains(' ') || port.parse::<u16>().is_err() {
        return Err(format!("bad collector {:?}", s));
    }
    Ok(t.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_overrides() {
        let mut c = Config::defaults();
        assert_eq!(c.port, 8765);
        assert_eq!(c.keys_dir, PathBuf::from("C:\\ProgramData\\i7oracled").join("keys"));
        c.apply_json(r#"{"port":9000,"collector":"http://192.0.2.7:8080/","sweep_on_first_boot":false,"heartbeat_s":0,"unknown":1}"#).unwrap();
        assert_eq!(c.port, 9000);
        assert_eq!(c.collector.as_deref(), Some("192.0.2.7:8080"));
        assert!(!c.sweep_on_first_boot);
        assert_eq!(c.heartbeat_s, 1);
    }

    #[test]
    fn bad_values_refused() {
        let mut c = Config::defaults();
        assert!(c.apply_json(r#"{"port":"x"}"#).is_err());
        assert!(c.apply_json(r#"{"port":70000}"#).is_err());
        assert!(c.apply_json(r#"{"collector":"nohost"}"#).is_err());
        assert!(c.apply_json("[1]").is_err());
        assert!(c.apply_json("{").is_err());
    }
}
