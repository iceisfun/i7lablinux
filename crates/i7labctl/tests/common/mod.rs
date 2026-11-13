//! Test kit: an `Env` with in-memory output, a temp HOME with real key files, a registry builder, and a mock
//! `Connect` that records every transport call and answers from a closure.
#![allow(dead_code)]

pub mod fake_http;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use i7labctl::discover::LinkSet;
use i7labctl::hosts::{ObserveMeta, Registry};
use i7labctl::keys::KeyEnv;
use i7labctl::opts::Global;
use i7labctl::{CallResult, ClientError, ClientIo, Connect, Env, Input, Kind, Target, Transport};
use labproto::beacon::Beacon;
use labproto::catalog::CmdSpec;
use labproto::keys::{Key, Role};
use labproto::{Mac, Status};

#[derive(Clone, Default)]
pub struct Buf(pub Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buf {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

#[derive(Clone, Debug)]
pub struct Call {
    pub kind: &'static str,
    pub cmd: String,
    pub args: Vec<String>,
    /// bytes the client pushed on its input channels (put, exec --stdin)
    pub uploaded: Vec<u8>,
}

#[derive(Clone, Default)]
pub struct MockOut {
    pub status: Option<Status>,
    pub body: String,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub events: Vec<String>,
    pub file: Vec<u8>,
}

impl MockOut {
    pub fn ok(body: &str) -> MockOut {
        MockOut { body: body.into(), ..Default::default() }
    }
    pub fn status(s: Status, body: &str) -> MockOut {
        MockOut { status: Some(s), body: body.into(), ..Default::default() }
    }
}

pub type Reply = Arc<dyn Fn(&CmdSpec, &[String]) -> Result<MockOut, ClientError> + Send + Sync>;

pub struct MockConnect {
    pub calls: Arc<Mutex<Vec<Call>>>,
    pub connects: Arc<Mutex<Vec<(Kind, Target)>>>,
    pub keys_used: Arc<Mutex<Vec<(Role, String)>>>,
    pub reply: Arc<Mutex<Reply>>,
    /// transports of this kind fail every call with a Transport error
    pub fail_kind: Arc<Mutex<Option<Kind>>>,
    pub link: Arc<Mutex<Option<LinkSet>>>,
    pub role: Role,
}

struct MockTransport {
    kind: Kind,
    calls: Arc<Mutex<Vec<Call>>>,
    reply: Arc<Mutex<Reply>>,
    fail: bool,
    role: Role,
}

impl Transport for MockTransport {
    fn call(&mut self, cmd: &CmdSpec, args: &[String], io: &mut dyn ClientIo) -> Result<CallResult, ClientError> {
        let name = if self.kind == Kind::Ether { "ether" } else { "http" };
        let mut uploaded = Vec::new();
        for _ in 0..10_000 {
            match io.input() {
                Input::Data(_, d) => uploaded.extend(d),
                Input::End(_) | Input::None => break,
                Input::Pending => std::thread::sleep(std::time::Duration::from_millis(1)),
            }
        }
        self.calls.lock().unwrap().push(Call { kind: name, cmd: cmd.name.to_string(), args: args.to_vec(), uploaded });
        if self.fail {
            return Err(ClientError::Transport(format!("mock {} is down", name)));
        }
        let f = self.reply.lock().unwrap().clone();
        let out = f(cmd, args)?;
        io.stdout(&out.stdout);
        io.stderr(&out.stderr);
        for e in &out.events {
            io.event(e);
        }
        io.file(&out.file);
        Ok(CallResult { status: out.status.unwrap_or(Status::Ok), body: out.body.into_bytes(), exit_code: out.exit_code, rtt_ms: 0.5 })
    }
    fn name(&self) -> &'static str {
        if self.kind == Kind::Ether {
            "ether"
        } else {
            "http"
        }
    }
    fn role(&self) -> Option<Role> {
        Some(self.role)
    }
}

impl Connect for MockConnect {
    fn connect(&self, kind: Kind, target: &Target, _g: &Global, key: &Key) -> Result<Box<dyn Transport>, ClientError> {
        self.connects.lock().unwrap().push((kind, target.clone()));
        self.keys_used.lock().unwrap().push((key.role, key.fingerprint()));
        let fail = *self.fail_kind.lock().unwrap() == Some(kind);
        Ok(Box::new(MockTransport { kind, calls: self.calls.clone(), reply: self.reply.clone(), fail, role: self.role }))
    }
    fn open_link(&self, _g: &Global) -> Result<LinkSet, ClientError> {
        self.link.lock().unwrap().take().ok_or_else(|| ClientError::Transport("no link in this test".into()))
    }
}

pub struct T {
    pub dir: PathBuf,
    pub home: PathBuf,
    pub out: Buf,
    pub err: Buf,
    pub calls: Arc<Mutex<Vec<Call>>>,
    pub connects: Arc<Mutex<Vec<(Kind, Target)>>>,
    pub keys_used: Arc<Mutex<Vec<(Role, String)>>>,
    pub reply: Arc<Mutex<Reply>>,
    pub fail_kind: Arc<Mutex<Option<Kind>>>,
    pub link: Arc<Mutex<Option<LinkSet>>>,
    pub answer: Option<bool>,
    pub now: u64,
    pub scripts: Option<PathBuf>,
    pub ssh_bin: Option<PathBuf>,
    pub hwlab: Option<String>,
    pub tty_out: bool,
}

pub const MAC: &str = "52:54:00:17:00:01";

impl T {
    pub fn new(tag: &str) -> T {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("i7ctl-it-{}-{}-{}", std::process::id(), tag, n));
        let _ = std::fs::remove_dir_all(&dir);
        let home = dir.join("home");
        std::fs::create_dir_all(&home).unwrap();
        i7labctl::keys::init_dir(&i7labctl::keys::default_key_dir(&home), false, false, 1_794_000_000).unwrap();
        let reply: Reply = Arc::new(|_, _| Ok(MockOut::ok("{}")));
        T {
            dir,
            home,
            out: Buf::default(),
            err: Buf::default(),
            calls: Default::default(),
            connects: Default::default(),
            keys_used: Default::default(),
            reply: Arc::new(Mutex::new(reply)),
            fail_kind: Default::default(),
            link: Default::default(),
            answer: None,
            now: 1_794_000_100,
            scripts: None,
            ssh_bin: None,
            hwlab: None,
            tty_out: false,
        }
    }

    pub fn reply(&self, f: impl Fn(&CmdSpec, &[String]) -> Result<MockOut, ClientError> + Send + Sync + 'static) {
        *self.reply.lock().unwrap() = Arc::new(f);
    }

    pub fn registry_path(&self) -> PathBuf {
        i7labctl::hosts::default_path(&self.home)
    }

    /// Put a host into the registry. `extra` are beacon fields; `last_seen` is `self.now - age`.
    pub fn add_host(&self, mac: &str, age: u64, extra: &[(&str, &str)]) {
        let path = self.registry_path();
        let mut reg = Registry::load(&path);
        let mut b = Beacon { version: 2, fields: vec![] };
        b.set("mac", mac);
        b.set("host", "lab-1");
        b.set("board", "Q35");
        b.set("board_serial", "SER1");
        b.set("boot", "9f3c");
        b.set("state", "ready");
        for (k, v) in extra {
            b.set(k, v);
        }
        let m = ObserveMeta { iface: "eth0".into(), src_mac: Mac::parse(mac), vlan: None, tag_ok: Some(true) };
        reg.observe(&b, &m, self.now - age);
        reg.save(&path).unwrap();
    }

    pub fn env(&self) -> Env {
        Env {
            out: Box::new(self.out.clone()),
            err: Box::new(self.err.clone()),
            keyenv: KeyEnv { home: Some(self.home.clone()), cwd: Some(self.dir.clone()), ..Default::default() },
            home: self.home.clone(),
            cwd: self.dir.clone(),
            connector: Box::new(MockConnect {
                calls: self.calls.clone(),
                connects: self.connects.clone(),
                keys_used: self.keys_used.clone(),
                reply: self.reply.clone(),
                fail_kind: self.fail_kind.clone(),
                link: self.link.clone(),
                role: Role::Admin,
            }),
            out_tty: self.tty_out,
            in_tty: false,
            color: false,
            scripts_dir: self.scripts.clone(),
            fake_now: Some(self.now),
            fake_answer: self.answer,
            ssh_bin: self.ssh_bin.clone(),
            hwlab: self.hwlab.clone(),
        }
    }

    /// Run i7labctl; returns (exit status, stdout, stderr).
    pub fn run(&self, args: &[&str]) -> (i32, String, String) {
        let mut env = self.env();
        let code = i7labctl::cli::run_with(args.iter().map(|s| s.to_string()).collect(), &mut env);
        (code, self.out.text(), self.err.text())
    }

    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    pub fn last(&self) -> Call {
        self.calls().last().cloned().expect("no call was made")
    }
}

impl Drop for T {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// true when `labproto::json::parse` is a real parser (P1 landed); tests that need it skip loudly otherwise.
pub fn json_parser_ready() -> bool {
    labproto::json::parse("{\"a\":[1]}", &labproto::json::Limits::default()).is_ok()
}

#[macro_export]
macro_rules! need_json {
    () => {
        if !common::json_parser_ready() {
            eprintln!("SKIPPED: labproto::json::parse is still a stub (P1)");
            return;
        }
    };
}

pub fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{}\n", body)).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}
