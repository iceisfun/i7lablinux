//! Typed request / response views over the wire bodies of PROTOCOL.md sections 3.1 and 7. Owner: P1.
//!
//! The catalogue (`catalog::CATALOG`) is the table of every command; this module is the typed layer both ends
//! use around it: validate a received REQ (known id, served in this release, role allowed) and turn it into
//! argv words, build a REQ from a command name, and the few fixed binary layouts (`exec` result, channel 5
//! control messages, `put`/`get` option sets).

use crate::args::{decode_argv, encode_argv, ArgsError, Opts};
use crate::catalog::{self, Access, CmdSpec};
use crate::keys::Role;
use crate::status::Status;

#[derive(Debug, PartialEq)]
pub enum RequestError {
    /// no command with this id
    UnknownCommand(u16),
    /// in the catalogue but not served by this release (planned)
    Planned(&'static str),
    /// the key's role may not run it
    Forbidden(&'static str),
    BadArgs(ArgsError),
    /// the CLI named a command the catalogue does not have
    UnknownName(String),
}

impl RequestError {
    /// The wire status for this error (PROTOCOL.md 3.1). Dispatch order of the daemon is: key policy, planned,
    /// role, path policy, handler, which `Request::parse` follows for the middle steps.
    pub fn status(&self) -> Status {
        match self {
            RequestError::UnknownCommand(_) | RequestError::Planned(_) | RequestError::UnknownName(_) => Status::Unsupported,
            RequestError::Forbidden(_) => Status::Eperm,
            RequestError::BadArgs(_) => Status::BadArgs,
        }
    }
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestError::UnknownCommand(id) => write!(f, "unknown command 0x{:04x}", id),
            RequestError::Planned(n) => write!(f, "{} is planned, not served by this release", n),
            RequestError::Forbidden(n) => write!(f, "{} needs the admin key", n),
            RequestError::BadArgs(e) => write!(f, "bad arguments: {}", e),
            RequestError::UnknownName(n) => write!(f, "unknown command {}", n),
        }
    }
}

/// A validated request.
#[derive(Debug)]
pub struct Request {
    pub spec: &'static CmdSpec,
    pub argv: Vec<String>,
}

/// May `role` run `spec`? `RoLimitedPaths` commands are allowed here; the path allow-list is the daemon's.
pub fn role_allows(spec: &CmdSpec, role: Role) -> bool {
    match (spec.access, role) {
        (Access::Admin, Role::Ro) => false,
        _ => true,
    }
}

impl Request {
    /// Validate a received REQ: id known, not planned, role allowed, argv decodes.
    pub fn parse(cmd: u16, body: &[u8], role: Role) -> Result<Request, RequestError> {
        let spec = catalog::by_id(cmd).ok_or(RequestError::UnknownCommand(cmd))?;
        if spec.planned() {
            return Err(RequestError::Planned(spec.name));
        }
        if !role_allows(spec, role) {
            return Err(RequestError::Forbidden(spec.name));
        }
        let argv = decode_argv(body).map_err(RequestError::BadArgs)?;
        Ok(Request { spec, argv })
    }

    /// Build the (cmd id, body) of a REQ from a CLI command name and its argv words.
    pub fn encode(name: &str, argv: &[String]) -> Result<(u16, Vec<u8>), RequestError> {
        let spec = catalog::by_name(name).ok_or_else(|| RequestError::UnknownName(name.to_string()))?;
        let body = encode_argv(argv);
        if body.len() > crate::args::MAX_BODY {
            return Err(RequestError::BadArgs(ArgsError::TooLong));
        }
        Ok((spec.id, body))
    }
}

/// A final response as the client sees it.
#[derive(Clone, Debug, PartialEq)]
pub struct Response {
    pub status: Status,
    pub body: Vec<u8>,
}

impl Response {
    pub fn ok(body: impl Into<Vec<u8>>) -> Response {
        Response { status: Status::Ok, body: body.into() }
    }
    pub fn err(status: Status, message: &str) -> Response {
        Response { status, body: message.as_bytes().to_vec() }
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// RESP body of `exec`: `i32 exit_code` (big endian) followed by JSON `{signal,duration_ms}`.
#[derive(Clone, Debug, PartialEq)]
pub struct ExecResult {
    pub exit_code: i32,
    pub info_json: String,
}

impl ExecResult {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.exit_code.to_be_bytes().to_vec();
        b.extend_from_slice(self.info_json.as_bytes());
        b
    }
    pub fn decode(body: &[u8]) -> Option<ExecResult> {
        if body.len() < 4 {
            return None;
        }
        Some(ExecResult { exit_code: i32::from_be_bytes(body[..4].try_into().ok()?), info_json: String::from_utf8_lossy(&body[4..]).into_owned() })
    }
}

/// Channel 5 (CTL) messages: `'S' signo(1)` and `'W' cols(2) rows(2)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtlMsg {
    Signal(u8),
    Resize { cols: u16, rows: u16 },
}

impl CtlMsg {
    pub fn encode(&self) -> Vec<u8> {
        match *self {
            CtlMsg::Signal(s) => vec![b'S', s],
            CtlMsg::Resize { cols, rows } => {
                let mut v = vec![b'W'];
                v.extend_from_slice(&cols.to_be_bytes());
                v.extend_from_slice(&rows.to_be_bytes());
                v
            }
        }
    }
    /// Decode one message from the front of `b`; returns it and the bytes consumed.
    pub fn decode(b: &[u8]) -> Option<(CtlMsg, usize)> {
        match *b.first()? {
            b'S' => Some((CtlMsg::Signal(*b.get(1)?), 2)),
            b'W' if b.len() >= 5 => Some((CtlMsg::Resize { cols: u16::from_be_bytes([b[1], b[2]]), rows: u16::from_be_bytes([b[3], b[4]]) }, 5)),
            _ => None,
        }
    }
}

/// Options of `put` (PATH must be the first word).
#[derive(Clone, Debug, PartialEq)]
pub struct PutArgs {
    pub path: String,
    pub size: u64,
    pub sha256: [u8; 32],
    pub mode: u32,
    pub offset: u64,
    pub mkdirs: bool,
}

fn num(v: Option<&str>, what: &'static str) -> Result<Option<u64>, ArgsError> {
    match v {
        None => Ok(None),
        Some(s) => s.parse::<u64>().map(Some).map_err(|_| ArgsError::UnknownOption(format!("{}={}", what, s))),
    }
}

impl PutArgs {
    pub fn parse(argv: &[String]) -> Result<PutArgs, ArgsError> {
        let o = Opts::parse(argv, &["mkdirs"], &["size", "sha256", "mode", "offset"])?;
        let path = match (argv.first(), o.positional()) {
            (Some(first), [p]) if first == p && !first.starts_with('-') => p.clone(),
            _ => return Err(ArgsError::MissingValue("PATH (must be the first word)".into())),
        };
        let size = num(o.value("size"), "--size")?.ok_or_else(|| ArgsError::MissingValue("--size".into()))?;
        let sha = o.value("sha256").and_then(crate::crypto::unhex).ok_or_else(|| ArgsError::MissingValue("--sha256".into()))?;
        let sha256: [u8; 32] = sha.try_into().map_err(|_| ArgsError::MissingValue("--sha256 (64 hex digits)".into()))?;
        let mode = match o.value("mode") {
            None => 0o644,
            Some(m) => u32::from_str_radix(m, 8).map_err(|_| ArgsError::UnknownOption(format!("--mode={}", m)))?,
        };
        if mode > 0o7777 {
            return Err(ArgsError::UnknownOption(format!("--mode={:o}", mode)));
        }
        Ok(PutArgs { path, size, sha256, mode, offset: num(o.value("offset"), "--offset")?.unwrap_or(0), mkdirs: o.flag("mkdirs") })
    }

    pub fn to_argv(&self) -> Vec<String> {
        let mut v = vec![self.path.clone(), "--size".into(), self.size.to_string(), "--sha256".into(), crate::crypto::hex(&self.sha256), "--mode".into(), format!("{:04o}", self.mode)];
        if self.offset != 0 {
            v.extend(["--offset".into(), self.offset.to_string()]);
        }
        if self.mkdirs {
            v.push("--mkdirs".into());
        }
        v
    }
}

/// Options of `get` (PATH must be the first word).
#[derive(Clone, Debug, PartialEq)]
pub struct GetArgs {
    pub path: String,
    pub offset: u64,
    pub len: Option<u64>,
}

impl GetArgs {
    pub fn parse(argv: &[String]) -> Result<GetArgs, ArgsError> {
        let o = Opts::parse(argv, &[], &["offset", "len"])?;
        let path = match (argv.first(), o.positional()) {
            (Some(first), [p]) if first == p && !first.starts_with('-') => p.clone(),
            _ => return Err(ArgsError::MissingValue("PATH (must be the first word)".into())),
        };
        Ok(GetArgs { path, offset: num(o.value("offset"), "--offset")?.unwrap_or(0), len: num(o.value("len"), "--len")? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn request_validation_order() {
        let body = encode_argv(&["x"]);
        let r = Request::parse(0x0001, &body, Role::Ro).unwrap();
        assert_eq!((r.spec.name, r.argv), ("ping", v(&["x"])));
        assert_eq!(Request::parse(0xbeef, &body, Role::Admin).unwrap_err().status(), Status::Unsupported);
        // planned wins over role: a ro key asking for planned `kexec` learns UNSUPPORTED, not EPERM
        assert_eq!(Request::parse(0x0042, &body, Role::Ro).unwrap_err(), RequestError::Planned("kexec"));
        assert_eq!(Request::parse(0x0016, &body, Role::Ro).unwrap_err().status(), Status::Eperm);
        assert!(Request::parse(0x0016, &body, Role::Admin).is_ok());
        assert_eq!(Request::parse(0x0001, &[0, 5], Role::Admin).unwrap_err().status(), Status::BadArgs);
        // path commands are allowed for ro here (the daemon's path policy narrows them)
        assert!(Request::parse(0x0031, &body, Role::Ro).is_ok());
    }

    #[test]
    fn every_catalogue_command_can_be_encoded_by_name() {
        for c in catalog::CATALOG {
            let (id, body) = Request::encode(c.name, &v(&["a", "--b", "c"])).unwrap();
            assert_eq!(id, c.id);
            assert_eq!(decode_argv(&body).unwrap(), v(&["a", "--b", "c"]));
        }
        assert!(Request::encode("nope", &[]).is_err());
    }

    #[test]
    fn every_command_is_role_checked_consistently() {
        for c in catalog::CATALOG.iter().filter(|c| !c.planned()) {
            let body = encode_argv::<&str>(&[]);
            assert!(Request::parse(c.id, &body, Role::Admin).is_ok(), "{}", c.name);
            assert_eq!(Request::parse(c.id, &body, Role::Ro).is_ok(), c.access != Access::Admin, "{}", c.name);
        }
    }

    #[test]
    fn exec_result_and_ctl() {
        let e = ExecResult { exit_code: -9, info_json: "{\"signal\":9}".into() };
        assert_eq!(ExecResult::decode(&e.encode()).unwrap(), e);
        assert!(ExecResult::decode(&[1, 2]).is_none());
        for m in [CtlMsg::Signal(2), CtlMsg::Resize { cols: 132, rows: 43 }] {
            let b = m.encode();
            assert_eq!(CtlMsg::decode(&b), Some((m, b.len())));
        }
        assert_eq!(CtlMsg::decode(b"X"), None);
        assert_eq!(CtlMsg::decode(b"W\0"), None);
        // two messages back to back
        let mut two = CtlMsg::Signal(15).encode();
        two.extend(CtlMsg::Resize { cols: 1, rows: 2 }.encode());
        let (a, n) = CtlMsg::decode(&two).unwrap();
        assert_eq!(a, CtlMsg::Signal(15));
        assert_eq!(CtlMsg::decode(&two[n..]).unwrap().0, CtlMsg::Resize { cols: 1, rows: 2 });
    }

    #[test]
    fn put_and_get_args() {
        let sha = crate::crypto::hex(&crate::crypto::sha256(b"x"));
        let a = PutArgs::parse(&v(&["/tmp/f", "--size", "1", "--sha256", &sha, "--mode", "0755", "--mkdirs"])).unwrap();
        assert_eq!((a.size, a.mode, a.mkdirs, a.offset), (1, 0o755, true, 0));
        assert_eq!(PutArgs::parse(&a.to_argv()).unwrap(), a);
        // PATH must be first, even if another word looks like a path
        assert!(PutArgs::parse(&v(&["--size", "1", "/tmp/f", "--sha256", &sha])).is_err());
        assert!(PutArgs::parse(&v(&["/tmp/f", "--size", "1"])).is_err());
        assert!(PutArgs::parse(&v(&["/tmp/f", "--size", "1", "--sha256", "zz"])).is_err());
        assert!(PutArgs::parse(&v(&["/tmp/f", "--size", "1", "--sha256", &sha, "--bogus"])).is_err());
        let g = GetArgs::parse(&v(&["/etc/os-release", "--offset", "5", "--len", "10"])).unwrap();
        assert_eq!(g, GetArgs { path: "/etc/os-release".into(), offset: 5, len: Some(10) });
        // the old check took the first word not starting with '-': "get --offset 0 /etc/shadow" must not parse
        assert!(GetArgs::parse(&v(&["--offset", "0", "/etc/shadow"])).is_err());
    }
}
