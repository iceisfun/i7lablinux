//! argv codec (PROTOCOL.md 3.1) and a small option parser shared by i7labd handlers and i7labsh. Owner: P1.

#[derive(Debug, PartialEq)]
pub enum ArgsError {
    Truncated,
    TooLong,
    NotUtf8,
    UnknownOption(String),
    MissingValue(String),
}

impl std::fmt::Display for ArgsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArgsError::Truncated => write!(f, "truncated argument list"),
            ArgsError::TooLong => write!(f, "argument list too long"),
            ArgsError::NotUtf8 => write!(f, "argument is not UTF-8"),
            ArgsError::UnknownOption(o) => write!(f, "unknown option {}", o),
            ArgsError::MissingValue(o) => write!(f, "option {} needs a value", o),
        }
    }
}

pub const MAX_BODY: usize = 64 * 1024;

/// `u16 count`, then per word `u16 len` + bytes.
pub fn encode_argv<S: AsRef<[u8]>>(argv: &[S]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(argv.len() as u16).to_be_bytes());
    for a in argv {
        let a = a.as_ref();
        out.extend_from_slice(&(a.len() as u16).to_be_bytes());
        out.extend_from_slice(a);
    }
    out
}

pub fn decode_argv(body: &[u8]) -> Result<Vec<String>, ArgsError> {
    if body.len() > MAX_BODY {
        return Err(ArgsError::TooLong);
    }
    let rd = |i: usize| -> Result<usize, ArgsError> {
        body.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]]) as usize).ok_or(ArgsError::Truncated)
    };
    let n = rd(0)?;
    let mut pos = 2;
    let mut out = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        let len = rd(pos)?;
        pos += 2;
        let w = body.get(pos..pos + len).ok_or(ArgsError::Truncated)?;
        out.push(String::from_utf8(w.to_vec()).map_err(|_| ArgsError::NotUtf8)?);
        pos += len;
    }
    Ok(out)
}

/// Parsed options: `--flag`, `--key value` (or `--key=value`), positionals; `--` ends options.
#[derive(Debug, Default)]
pub struct Opts {
    flags: Vec<String>,
    values: Vec<(String, String)>,
    positional: Vec<String>,
}

impl Opts {
    /// `flags` and `valued` list option names without the leading `--` (single-letter names take `-x`).
    pub fn parse(argv: &[String], flags: &[&str], valued: &[&str]) -> Result<Opts, ArgsError> {
        let mut o = Opts::default();
        let mut it = argv.iter();
        while let Some(a) = it.next() {
            if a == "--" {
                o.positional.extend(it.by_ref().cloned());
                break;
            }
            let name = a.strip_prefix("--").or_else(|| a.strip_prefix('-').filter(|n| n.len() == 1));
            match name {
                Some(n) if !n.is_empty() => {
                    let (n, inline) = match n.split_once('=') {
                        Some((k, v)) => (k, Some(v.to_string())),
                        None => (n, None),
                    };
                    if flags.contains(&n) && inline.is_none() {
                        o.flags.push(n.to_string());
                    } else if valued.contains(&n) {
                        let v = match inline {
                            Some(v) => v,
                            None => it.next().cloned().ok_or_else(|| ArgsError::MissingValue(a.clone()))?,
                        };
                        o.values.push((n.to_string(), v));
                    } else {
                        return Err(ArgsError::UnknownOption(a.clone()));
                    }
                }
                _ => o.positional.push(a.clone()),
            }
        }
        Ok(o)
    }
    pub fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }
    /// Last occurrence wins.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.values.iter().rev().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    pub fn values(&self, name: &str) -> Vec<&str> {
        self.values.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str()).collect()
    }
    pub fn positional(&self) -> &[String] {
        &self.positional
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }
    #[test]
    fn argv_roundtrip() {
        let a = v(&["blk.read", "sda", "--mb", "256", ""]);
        assert_eq!(decode_argv(&encode_argv(&a)).unwrap(), a);
        assert_eq!(decode_argv(&[0, 1, 0]), Err(ArgsError::Truncated));
    }
    #[test]
    fn opts() {
        let o = Opts::parse(&v(&["sda", "--mb=8", "--direct", "--", "--x"]), &["direct"], &["mb"]).unwrap();
        assert!(o.flag("direct"));
        assert_eq!(o.value("mb"), Some("8"));
        assert_eq!(o.positional(), &v(&["sda", "--x"])[..]);
        assert!(Opts::parse(&v(&["--nope"]), &[], &[]).is_err());
    }
}
