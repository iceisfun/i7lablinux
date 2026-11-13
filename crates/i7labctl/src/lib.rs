//! i7labctl: operator CLI (docs/I7LABCTL.md, PLAN.md section 4.7). Owner: P9.
//!
//! Layout: `cli` (subcommand table, help, dispatch) -> `opts` (global option split) -> `cmds` (one handler per
//! subcommand) -> `Transport` (`ether` over `labproto::session`, `http`, `ssh` via the system ssh) with `hosts`
//! (registry, aliases, selectors), `keys`, `discover`, `render` (human tables) and `output` (JSON envelope).
//! Everything that touches the outside world goes through `Env` and `Connect` so tests can inject fakes.

pub mod blkimage;
pub mod cli;
pub mod cmds;
pub mod complete;
pub mod discover;
pub mod ether;
pub mod ffi;
pub mod help;
pub mod hosts;
pub mod http;
pub mod jv;
pub mod keys;
pub mod labboot;
pub mod local;
pub mod opts;
pub mod output;
pub mod render;
pub mod stream;
pub mod wrap;

use std::io::Write;
use std::path::PathBuf;

use labproto::catalog::CmdSpec;
use labproto::frame::Chan;
use labproto::keys::{Key, Role};
use labproto::Status;

/// Data the client hands to the server while a streaming request runs.
#[derive(Debug)]
pub enum Input {
    /// Nothing to send now (the transport asks again soon).
    Pending,
    /// Bytes for the server on `Chan::Stdin`, `Chan::File` or `Chan::Ctl`.
    Data(Chan, Vec<u8>),
    /// End of that channel (FIN). The transport never asks about a channel again.
    End(Chan),
    /// No input source at all (the default).
    None,
}

/// Callbacks for streamed output during a call and the source of client-to-server stream data.
pub trait ClientIo {
    fn stdout(&mut self, bytes: &[u8]);
    fn stderr(&mut self, bytes: &[u8]);
    /// One NDJSON event object (progress, ...), without trailing newline.
    fn event(&mut self, json: &str);
    /// Server to client file data (`get`).
    fn file(&mut self, _bytes: &[u8]) {}
    /// Client to server stream data (`exec --stdin`, `put`, `shell`). Must not block for long.
    fn input(&mut self) -> Input {
        Input::None
    }
}

/// An io that discards everything (buffered commands).
pub struct NullIo;
impl ClientIo for NullIo {
    fn stdout(&mut self, _: &[u8]) {}
    fn stderr(&mut self, _: &[u8]) {}
    fn event(&mut self, _: &str) {}
}

#[derive(Clone, Debug)]
pub struct CallResult {
    pub status: Status,
    pub body: Vec<u8>,
    pub exit_code: Option<i32>,
    pub rtt_ms: f64,
}

#[derive(Debug)]
pub enum ClientError {
    Usage(String),
    Transport(String),
    Timeout,
    Auth(String),
    NoHost(String),
    Ambiguous(Vec<String>),
    Safety(String),
    /// planned command, protocol/version mismatch (exit 10)
    Unsupported(String),
    /// the command ran locally and failed (exit 1)
    Failed(String),
    Interrupted,
}

impl ClientError {
    /// I7LABCTL.md section 5
    pub fn exit_code(&self) -> i32 {
        match self {
            ClientError::Failed(_) => 1,
            ClientError::Usage(_) => 2,
            ClientError::Transport(_) | ClientError::Timeout => 4,
            ClientError::Auth(_) => 5,
            ClientError::NoHost(_) => 6,
            ClientError::Safety(_) => 7,
            ClientError::Ambiguous(_) => 8,
            ClientError::Unsupported(_) => 10,
            ClientError::Interrupted => 130,
        }
    }
    /// JSON envelope code
    pub fn code(&self) -> &'static str {
        match self {
            ClientError::Usage(_) => "E_USAGE",
            ClientError::Transport(_) => "E_TRANSPORT",
            ClientError::Timeout => "E_TIMEOUT",
            ClientError::Auth(_) => "E_AUTH",
            ClientError::NoHost(_) => "E_NOHOST",
            ClientError::Ambiguous(_) => "E_AMBIGUOUS",
            ClientError::Safety(_) => "E_SAFETY",
            ClientError::Unsupported(_) => "UNSUPPORTED",
            ClientError::Failed(_) => "E_FAILED",
            ClientError::Interrupted => "E_INTERRUPTED",
        }
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Usage(s) => write!(f, "usage: {}", s),
            ClientError::Transport(s) => write!(f, "transport: {}", s),
            ClientError::Timeout => write!(f, "no response (timeout)"),
            ClientError::Auth(s) => write!(f, "authentication: {}", s),
            ClientError::NoHost(s) => write!(f, "host not found: {}", s),
            ClientError::Ambiguous(c) => write!(f, "ambiguous host selector, candidates: {}", c.join(", ")),
            ClientError::Safety(s) => write!(f, "refused: {}", s),
            ClientError::Unsupported(s) => write!(f, "unsupported: {}", s),
            ClientError::Failed(s) => write!(f, "{}", s),
            ClientError::Interrupted => write!(f, "interrupted"),
        }
    }
}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Failed(e.to_string())
    }
}

/// One way of reaching a host (ether session, http).
pub trait Transport {
    fn call(&mut self, cmd: &CmdSpec, args: &[String], io: &mut dyn ClientIo) -> Result<CallResult, ClientError>;
    /// Short name for envelopes: "ether" or "http".
    fn name(&self) -> &'static str;
    /// Role granted by the host, when the transport learned it (ether: OPEN_OK).
    fn role(&self) -> Option<Role> {
        None
    }
    /// Raw authenticated request (http only): (HTTP status, body).
    fn raw(&mut self, _method: &str, _target: &str, _body: &[u8]) -> Result<(u16, Vec<u8>), ClientError> {
        Err(ClientError::Unsupported("this transport has no raw requests (use --http)".into()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Ether,
    Http,
}

/// Where a host is, as far as the client knows.
#[derive(Clone, Debug, Default)]
pub struct Target {
    pub entry: Option<hosts::HostEntry>,
    pub mac: Option<labproto::Mac>,
    pub ip: Option<String>,
    pub http_port: Option<u16>,
    pub vlan: Option<u16>,
    pub iface: Option<String>,
    /// transports to try, in order
    pub plan: Vec<Kind>,
}

/// Factory for transports; the real one opens sockets, tests inject in-process fakes.
pub trait Connect {
    fn connect(&self, kind: Kind, target: &Target, g: &opts::Global, key: &Key) -> Result<Box<dyn Transport>, ClientError>;
    /// Raw Ethernet link(s) for discover/wait/probe: (link, [(iface name, ifindex)]).
    fn open_link(&self, g: &opts::Global) -> Result<discover::LinkSet, ClientError>;
}

/// Everything outside the process: streams, files, clock, connectors.
pub struct Env {
    pub out: Box<dyn Write>,
    pub err: Box<dyn Write>,
    pub keyenv: keys::KeyEnv,
    pub home: PathBuf,
    pub cwd: PathBuf,
    pub connector: Box<dyn Connect>,
    pub out_tty: bool,
    pub in_tty: bool,
    pub color: bool,
    /// directory holding scripts/ (build tree), for the image wrappers
    pub scripts_dir: Option<PathBuf>,
    /// fixed "now" (unix seconds) for tests; None = system clock
    pub fake_now: Option<u64>,
    /// answers to confirmation questions in tests (None = ask on the tty)
    pub fake_answer: Option<bool>,
    /// ssh program (default `ssh`) and hwlab CLI words (default from $HWLAB, else `hwlabctl`)
    pub ssh_bin: Option<PathBuf>,
    pub hwlab: Option<String>,
}

impl Env {
    pub fn now(&self) -> u64 {
        self.fake_now.unwrap_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0))
    }
}

/// Entry point used by main and by tests. Returns the process exit status.
pub fn main_with_args(args: Vec<String>) -> i32 {
    let mut env = cli::real_env();
    cli::run_with(args, &mut env)
}
