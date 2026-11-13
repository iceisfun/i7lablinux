//! Command core: host/target/key resolution, transport selection with fallback, output helpers, the real
//! `Connect`, and the buffered (request/response) subcommands. Streaming commands are in `stream`, local ones in
//! `local`. Owner: P9.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use labproto::args::Opts;
use labproto::catalog::{self, CmdSpec};
use labproto::keys::{Key, Role};
use labproto::link::UdpLink;
use labproto::packet::PacketLink;
use labproto::Mac;

use crate::cli::{self, Sub};
use crate::discover::LinkSet;
use crate::ether::{self, EtherOpts, EtherTransport};
use crate::hosts::{self, HostEntry, Registry, Resolution};
use crate::http::{self, HttpTransport};
use crate::opts::{Global, TransportPref};
use crate::output::{self, ok_envelope, remote_error_text, HostInfo, Paint};
use crate::{render, CallResult, ClientError, ClientIo, Connect, Env, Kind, NullIo, Target, Transport};

// ---------------------------------------------------------------- real connector

pub struct RealConnect;

fn test_mac() -> Mac {
    let p = std::process::id();
    Mac([0x02, 0x49, 0x37, (p >> 16) as u8, (p >> 8) as u8, p as u8])
}

fn secs(t: Option<f64>) -> Option<Duration> {
    t.filter(|t| *t > 0.0).map(Duration::from_secs_f64)
}

/// `udp:LOCAL:REMOTE` (each `ip:port`, or just a port meaning 127.0.0.1) or `mcast:GROUP:PORT`.
pub fn parse_link(spec: &str) -> Result<LinkSpec, ClientError> {
    let bad = || ClientError::Usage(format!("bad --link '{}' (use udp:LOCALPORT:REMOTEPORT, udp:IP:PORT:IP:PORT or mcast:GROUP:PORT)", spec));
    let (kind, rest) = spec.split_once(':').ok_or_else(bad)?;
    let parts: Vec<&str> = rest.split(':').collect();
    match (kind, parts.len()) {
        ("udp", 2) => {
            let l: u16 = parts[0].parse().map_err(|_| bad())?;
            let r: u16 = parts[1].parse().map_err(|_| bad())?;
            Ok(LinkSpec::Udp(SocketAddr::from(([127, 0, 0, 1], l)), SocketAddr::from(([127, 0, 0, 1], r))))
        }
        ("udp", 4) => {
            let l = format!("{}:{}", parts[0], parts[1]).parse().map_err(|_| bad())?;
            let r = format!("{}:{}", parts[2], parts[3]).parse().map_err(|_| bad())?;
            Ok(LinkSpec::Udp(l, r))
        }
        ("mcast", 2) => Ok(LinkSpec::Mcast(parts[0].parse::<Ipv4Addr>().map_err(|_| bad())?, parts[1].parse().map_err(|_| bad())?)),
        _ => Err(bad()),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LinkSpec {
    Udp(SocketAddr, SocketAddr),
    Mcast(Ipv4Addr, u16),
}

fn open_set(g: &Global) -> Result<LinkSet, ClientError> {
    if let Some(spec) = &g.link {
        let link: Box<dyn labproto::link::Link> = match parse_link(spec)? {
            LinkSpec::Udp(l, r) => Box::new(UdpLink::new(l, r, test_mac()).map_err(|e| ClientError::Transport(format!("--link: {}", e)))?),
            LinkSpec::Mcast(grp, port) => Box::new(UdpLink::multicast(grp, port, test_mac()).map_err(|e| ClientError::Transport(format!("--link mcast: {}", e)))?),
        };
        return Ok(LinkSet { link, ifaces: vec![("link".into(), 1)] });
    }
    let pl = PacketLink::open(&g.ifaces).map_err(|e| {
        let hint = if e.kind() == std::io::ErrorKind::PermissionDenied { "; raw Ethernet needs CAP_NET_RAW: run once `sudo setcap cap_net_raw+ep $(command -v i7labctl)`, or use sudo, or --http, or --link for a test segment" } else { "" };
        ClientError::Transport(format!("cannot open the Ethernet interface(s): {}{}", e, hint))
    })?;
    let ifaces = pl.ifaces().to_vec();
    Ok(LinkSet { link: Box::new(pl), ifaces })
}

impl Connect for RealConnect {
    fn connect(&self, kind: Kind, t: &Target, g: &Global, key: &Key) -> Result<Box<dyn Transport>, ClientError> {
        let timeout = secs(g.timeout);
        match kind {
            Kind::Http => {
                let ip = t.ip.clone().ok_or_else(|| ClientError::NoHost("the host has no known IP address for http (use ether, or --http IP)".into()))?;
                let port = t.http_port.unwrap_or(http::DEFAULT_PORT);
                let mut h = HttpTransport::new(http::host_port(&ip, port), key.clone(), timeout);
                h.verbose = g.verbose;
                if g.verbose > 0 {
                    h.trace = Some(Box::new(|s| eprintln!("i7labctl: http: {}", s)));
                }
                Ok(Box::new(h))
            }
            Kind::Ether => {
                let mac = t.mac.ok_or_else(|| ClientError::NoHost("the ether transport needs the host's MAC address".into()))?;
                let set = open_set(g)?;
                let ifindex = pick_ifindex(&set, t.iface.as_deref())?;
                let replay = std::env::var_os("I7LABCTL_TEST_REPLAY").is_some_and(|v| v == "1");
                let mut e = EtherTransport::open(set.link, ifindex, mac, t.vlan, key, EtherOpts { timeout, retries: g.retries, replay, verbose: g.verbose })?;
                if g.verbose > 0 {
                    e.set_trace(Box::new(|s| eprintln!("i7labctl: ether: {}", s)));
                }
                Ok(Box::new(e))
            }
        }
    }

    fn open_link(&self, g: &Global) -> Result<LinkSet, ClientError> {
        open_set(g)
    }
}

pub fn pick_ifindex(set: &LinkSet, want: Option<&str>) -> Result<i32, ClientError> {
    if let Some(w) = want {
        if let Some((_, i)) = set.ifaces.iter().find(|(n, _)| n == w) {
            return Ok(*i);
        }
    }
    match set.ifaces.len() {
        0 => Err(ClientError::Transport("no Ethernet interface available".into())),
        1 => Ok(set.ifaces[0].1),
        _ => Err(ClientError::Usage(format!("several interfaces ({}): say which one the host is on with -i IF, or run `i7labctl discover` first so the registry knows", set.ifaces.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", ")))),
    }
}

// ---------------------------------------------------------------- run context

pub struct Run<'a> {
    pub env: &'a mut Env,
    pub g: Global,
    pub paint: Paint,
}

/// Declarative argument shape of one subcommand (verb).
pub struct Spec {
    pub usage: &'static str,
    pub flags: &'static [&'static str],
    pub valued: &'static [&'static str],
    /// `--wait [S]`: option with an optional number
    pub optnum: &'static [&'static str],
    /// first positional is the host (unless a host option was given)
    pub host: bool,
    pub pos_min: usize,
    pub pos_max: usize,
}

impl Spec {
    pub const fn new(usage: &'static str) -> Spec {
        Spec { usage, flags: &[], valued: &[], optnum: &[], host: true, pos_min: 0, pos_max: 0 }
    }
    pub const fn flags(mut self, f: &'static [&'static str]) -> Spec {
        self.flags = f;
        self
    }
    pub const fn valued(mut self, v: &'static [&'static str]) -> Spec {
        self.valued = v;
        self
    }
    pub const fn optnum(mut self, v: &'static [&'static str]) -> Spec {
        self.optnum = v;
        self
    }
    pub const fn pos(mut self, min: usize, max: usize) -> Spec {
        self.pos_min = min;
        self.pos_max = max;
        self
    }
    pub const fn no_host(mut self) -> Spec {
        self.host = false;
        self
    }
}

pub struct Parsed {
    pub host: Option<String>,
    pub opts: Opts,
    pub pos: Vec<String>,
}

impl Parsed {
    pub fn num(&self, name: &str) -> Result<Option<f64>, ClientError> {
        match self.opts.value(name) {
            None => Ok(None),
            Some(v) => v.parse().map(Some).map_err(|_| ClientError::Usage(format!("--{} needs a number, got '{}'", name, v))),
        }
    }
    pub fn uint(&self, name: &str) -> Result<Option<u64>, ClientError> {
        match self.opts.value(name) {
            None => Ok(None),
            Some(v) => v.parse().map(Some).map_err(|_| ClientError::Usage(format!("--{} needs a whole number, got '{}'", name, v))),
        }
    }
}

pub struct Prepared {
    pub transport: Box<dyn Transport>,
    pub info: HostInfo,
    pub entry: Option<HostEntry>,
}

pub struct Done {
    pub res: CallResult,
    pub transport: &'static str,
    pub role: Option<Role>,
}

/// Several transports in preference order; the next is tried only after a transport error that happened
/// before anything was delivered to the caller (so output is never duplicated).
struct Fallback {
    list: Vec<Box<dyn Transport>>,
    errors: Vec<ClientError>,
    used: usize,
}

struct CountIo<'a> {
    inner: &'a mut dyn ClientIo,
    touched: bool,
}

impl ClientIo for CountIo<'_> {
    fn stdout(&mut self, b: &[u8]) {
        self.touched = true;
        self.inner.stdout(b)
    }
    fn stderr(&mut self, b: &[u8]) {
        self.touched = true;
        self.inner.stderr(b)
    }
    fn event(&mut self, j: &str) {
        self.touched = true;
        self.inner.event(j)
    }
    fn file(&mut self, b: &[u8]) {
        self.touched = true;
        self.inner.file(b)
    }
    fn input(&mut self) -> crate::Input {
        let i = self.inner.input();
        if matches!(i, crate::Input::Data(..) | crate::Input::End(_)) {
            self.touched = true;
        }
        i
    }
}

impl Transport for Fallback {
    fn call(&mut self, cmd: &CmdSpec, args: &[String], io: &mut dyn ClientIo) -> Result<CallResult, ClientError> {
        let n = self.list.len();
        for i in 0..n {
            let mut c = CountIo { inner: io, touched: false };
            match self.list[i].call(cmd, args, &mut c) {
                Err(ClientError::Transport(m)) if !c.touched && i + 1 < n => {
                    self.errors.push(ClientError::Transport(m));
                    continue;
                }
                other => {
                    self.used = i;
                    return other;
                }
            }
        }
        unreachable!("Fallback has at least one transport")
    }
    fn name(&self) -> &'static str {
        self.list[self.used.min(self.list.len() - 1)].name()
    }
    fn role(&self) -> Option<Role> {
        self.list[self.used.min(self.list.len() - 1)].role()
    }
    fn raw(&mut self, method: &str, target: &str, body: &[u8]) -> Result<(u16, Vec<u8>), ClientError> {
        for t in self.list.iter_mut() {
            if let r @ Ok(_) = t.raw(method, target, body) {
                return r;
            }
        }
        Err(ClientError::Unsupported("no http transport for this host".into()))
    }
}

impl<'a> Run<'a> {
    pub fn new(env: &'a mut Env, g: &Global, paint: Paint) -> Run<'a> {
        Run { env, g: g.clone(), paint }
    }

    // ---- output
    pub fn out(&mut self, s: &str) {
        let _ = self.env.out.write_all(s.as_bytes());
    }
    pub fn outln(&mut self, s: &str) {
        let _ = writeln!(self.env.out, "{}", s);
    }
    pub fn err(&mut self, s: &str) {
        let _ = writeln!(self.env.err, "{}", s);
    }
    pub fn note(&mut self, s: &str) {
        if !self.g.quiet {
            self.err(s);
        }
    }

    /// Ask a yes/no question on the terminal. `--yes` and non-terminals answer yes (scripts opt in by running).
    pub fn confirm(&mut self, question: &str) -> bool {
        if self.g.yes {
            return true;
        }
        if let Some(a) = self.env.fake_answer {
            return a;
        }
        if !self.env.in_tty {
            return true;
        }
        let _ = write!(self.env.err, "{} [y/N] ", question);
        let _ = self.env.err.flush();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).is_ok() && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    }

    pub fn fail(&mut self, cmd: &str, e: &ClientError) -> i32 {
        cli::emit_error(self.env, &self.g, cmd, e, e.exit_code())
    }

    /// Own errors of exec/sh/shell/ssh exit 255 (the remote command's status uses 0-254).
    pub fn fail255(&mut self, cmd: &str, e: &ClientError) -> i32 {
        let exit = if matches!(e, ClientError::Usage(_)) { 2 } else { 255 };
        cli::emit_error(self.env, &self.g, cmd, e, exit)
    }

    // ---- registry, aliases, keys
    pub fn registry_path(&self) -> PathBuf {
        self.g.registry.clone().unwrap_or_else(|| hosts::default_path(&self.env.home))
    }

    pub fn registry(&self) -> Registry {
        if self.g.no_registry {
            Registry::default()
        } else {
            Registry::load(&self.registry_path())
        }
    }

    pub fn aliases(&self) -> Vec<(String, String)> {
        hosts::load_aliases(&hosts::aliases_path(&self.env.home))
    }

    pub fn keyenv(&self) -> crate::keys::KeyEnv {
        let mut k = self.env.keyenv.clone();
        if self.g.key.is_some() {
            k.flag_key = self.g.key.clone();
        }
        k
    }

    // ---- argument parsing
    pub fn parse(&self, args: &[String], spec: &Spec) -> Result<Parsed, ClientError> {
        let usage = |m: String| ClientError::Usage(format!("{}\nusage: i7labctl {}", m, spec.usage));
        // `--wait [S]`: rewrite to `--wait=S` / `--wait=` so the generic parser can take it
        let mut a: Vec<String> = Vec::with_capacity(args.len());
        let mut i = 0;
        while i < args.len() {
            if args[i] == "--" {
                a.extend(args[i..].iter().cloned());
                break;
            }
            if spec.optnum.iter().any(|n| args[i] == format!("--{}", n)) {
                match args.get(i + 1) {
                    Some(n) if n.parse::<f64>().is_ok() => {
                        a.push(format!("{}={}", args[i], n));
                        i += 2;
                        continue;
                    }
                    _ => {
                        a.push(format!("{}=", args[i]));
                        i += 1;
                        continue;
                    }
                }
            }
            a.push(args[i].clone());
            i += 1;
        }
        let valued: Vec<&str> = spec.valued.iter().chain(spec.optnum.iter()).copied().collect();
        let opts = Opts::parse(&a, spec.flags, &valued).map_err(|e| usage(e.to_string()))?;
        let mut pos: Vec<String> = opts.positional().to_vec();
        let mut host = None;
        if spec.host {
            let by_flag = self.g.host_by_flag();
            if !by_flag || pos.len() > spec.pos_max {
                if pos.is_empty() {
                    return Err(usage("missing <host>".into()));
                }
                host = Some(pos.remove(0));
            } else {
                host = self.flag_host();
            }
        }
        if pos.len() < spec.pos_min {
            return Err(usage(format!("missing argument ({} given, {} needed)", pos.len(), spec.pos_min)));
        }
        if pos.len() > spec.pos_max {
            return Err(usage(format!("unexpected argument '{}'", pos[spec.pos_max])));
        }
        Ok(Parsed { host, opts, pos })
    }

    /// The host named by `-H`, `--ether`, `--http` or `--ssh`.
    pub fn flag_host(&self) -> Option<String> {
        self.g.host.clone().or_else(|| self.g.ether.clone()).or_else(|| self.g.http.as_ref().map(|h| h.split(':').next().unwrap_or(h).to_string())).or_else(|| self.g.ssh.as_ref().map(|h| h.rsplit('@').next().unwrap_or(h).to_string()))
    }

    /// Group commands (`net ls <host> ..`): split a leading host off the positionals unless a host option is set.
    pub fn take_host(&self, pos: &[String], pos_max_without_host: usize) -> Result<(String, Vec<String>), ClientError> {
        if self.g.host_by_flag() && pos.len() <= pos_max_without_host {
            return Ok((self.flag_host().unwrap_or_default(), pos.to_vec()));
        }
        match pos.split_first() {
            Some((h, rest)) => Ok((h.clone(), rest.to_vec())),
            None => Err(ClientError::Usage("missing <host>".into())),
        }
    }

    // ---- target, key, transport
    pub fn target(&self, sel: Option<&str>) -> Result<Target, ClientError> {
        let sel = sel.map(String::from).or_else(|| self.flag_host()).ok_or_else(|| ClientError::Usage("no host given: name one (MAC, IP, hostname, alias) or use --ether MAC / --http IP".into()))?;
        let reg = self.registry();
        let res = hosts::resolve(&sel, &reg, &self.aliases())?;
        let now = self.env.now();
        let mut t = Target::default();
        let mut v1 = false;
        match res {
            Resolution::Entry(e) => {
                t.mac = Mac::parse(&e.mac);
                t.ip = e.addr().map(String::from);
                t.http_port = e.http_port();
                t.vlan = e.vlan;
                t.iface = Some(e.iface.clone()).filter(|s| !s.is_empty());
                v1 = e.proto_ver == 1;
                t.entry = Some(e);
            }
            Resolution::Mac(m) => {
                t.mac = Some(m);
                if let Some(e) = reg.hosts.get(&m.to_string()) {
                    t.entry = Some(e.clone());
                    t.vlan = e.vlan;
                    t.iface = Some(e.iface.clone()).filter(|s| !s.is_empty());
                }
            }
            Resolution::Ip(ip) => t.ip = Some(ip),
        }
        if let Some(h) = &self.g.http {
            let (ip, port) = match h.rsplit_once(':') {
                Some((ip, p)) => (ip.to_string(), p.parse::<u16>().ok()),
                None => (h.clone(), None),
            };
            t.ip = Some(ip);
            t.http_port = port.or(t.http_port);
        }
        if let Some(v) = self.g.vlans.first() {
            t.vlan = Some(*v);
        }
        if let Some(i) = self.g.ifaces.first() {
            t.iface = Some(i.clone());
        }
        let http_fresh = t.ip.is_some() && t.entry.as_ref().is_some_and(|e| e.live(now) && e.http_port().is_some());
        t.plan = match self.g.transport {
            TransportPref::Ether => vec![Kind::Ether],
            TransportPref::Http => vec![Kind::Http],
            TransportPref::Ssh => return Err(ClientError::Usage("--transport ssh applies to exec, sh, shell and ssh only".into())),
            TransportPref::Auto => {
                if self.g.http.is_some() {
                    vec![Kind::Http]
                } else if self.g.ether.is_some() || self.g.link.is_some() && t.mac.is_some() {
                    vec![Kind::Ether]
                } else if t.entry.is_some() {
                    if v1 {
                        vec![Kind::Http]
                    } else if http_fresh {
                        vec![Kind::Http, Kind::Ether]
                    } else {
                        vec![Kind::Ether]
                    }
                } else if t.mac.is_some() {
                    vec![Kind::Ether]
                } else {
                    vec![Kind::Http]
                }
            }
        };
        if t.plan.contains(&Kind::Ether) && t.mac.is_none() {
            t.plan.retain(|k| *k != Kind::Ether);
        }
        if t.plan.contains(&Kind::Http) && t.ip.is_none() {
            t.plan.retain(|k| *k != Kind::Http);
        }
        if t.plan.is_empty() {
            return Err(ClientError::NoHost(format!("'{}' cannot be reached with the chosen transport (no {})", sel, if self.g.transport == TransportPref::Http { "IP address" } else { "MAC address" })));
        }
        Ok(t)
    }

    pub fn key_for(&mut self, t: &Target) -> Result<Key, ClientError> {
        let kid = if self.g.no_registry { None } else { t.entry.as_ref().map(|e| e.kid_pair()) };
        let (k, _path) = crate::keys::select(&self.keyenv(), self.g.role, kid)?;
        Ok(k)
    }

    /// Resolve host, key and transport. `timeout`: local whole-call timeout in seconds, 0 = none.
    pub fn prepare(&mut self, host: Option<&str>, timeout: f64) -> Result<Prepared, ClientError> {
        self.prepare_plan(host, timeout, None)
    }

    /// Like `prepare`, but with the transports forced (`api` = http only, `ether hello` = ether only).
    pub fn prepare_plan(&mut self, host: Option<&str>, timeout: f64, plan: Option<Vec<Kind>>) -> Result<Prepared, ClientError> {
        let mut t = self.target(host)?;
        if let Some(pl) = plan {
            t.plan = pl.into_iter().filter(|k| match k {
                Kind::Ether => t.mac.is_some(),
                Kind::Http => t.ip.is_some(),
            }).collect();
            if t.plan.is_empty() {
                return Err(ClientError::NoHost("the host has no address for the transport this command needs (ether: MAC, http: IP)".into()));
            }
        }
        let key = self.key_for(&t)?;
        let mut g2 = self.g.clone();
        g2.timeout = Some(timeout);
        let mut list = Vec::new();
        let mut first_err = None;
        for k in &t.plan {
            match self.env.connector.connect(*k, &t, &g2, &key) {
                Ok(tr) => list.push(tr),
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        if list.is_empty() {
            return Err(first_err.unwrap_or_else(|| ClientError::NoHost("no transport".into())));
        }
        let info = HostInfo {
            mac: t.mac.map(|m| m.to_string()),
            ip: t.ip.clone(),
            vlan: t.vlan,
            serial: t.entry.as_ref().map(|e| e.board_serial.clone()).filter(|s| !s.is_empty()),
            boot: t.entry.as_ref().map(|e| e.boot.clone()).filter(|s| !s.is_empty()),
        };
        let transport: Box<dyn Transport> = if list.len() == 1 { list.pop().unwrap() } else { Box::new(Fallback { list, errors: Vec::new(), used: 0 }) };
        Ok(Prepared { transport, info, entry: t.entry })
    }

    /// Buffered call: prepare, call, return.
    pub fn simple_call(&mut self, host: Option<&str>, wire: &str, argv: &[String]) -> Result<(Done, HostInfo), ClientError> {
        let spec = catalog::by_name(wire).ok_or_else(|| ClientError::Usage(format!("unknown wire command {}", wire)))?;
        let timeout = self.g.timeout.unwrap_or(30.0);
        let mut p = self.prepare(host, timeout)?;
        let res = p.transport.call(spec, argv, &mut NullIo)?;
        Ok((Done { transport: p.transport.name(), role: p.transport.role(), res }, p.info))
    }

    /// Print the outcome of a buffered call and return the exit status.
    pub fn finish(&mut self, wire: &str, done: &Done, info: &HostInfo, render_fn: &dyn Fn(&str, Paint) -> String) -> i32 {
        self.finish_with(wire, done, info, render_fn, 0)
    }

    /// `ok_exit`: exit status when the call succeeded (3 for a failed SMART verdict etc. is passed by callers).
    pub fn finish_with(&mut self, wire: &str, done: &Done, info: &HostInfo, render_fn: &dyn Fn(&str, Paint) -> String, ok_exit: i32) -> i32 {
        let body = String::from_utf8_lossy(&done.res.body).into_owned();
        let st = done.res.status;
        if st == labproto::Status::Ok {
            if self.g.json {
                let e = ok_envelope(done.transport, Some(info), wire, Some(done.res.rtt_ms), &body);
                self.outln(&e);
            } else {
                let text = render_fn(&body, self.paint);
                self.out(&text);
                if !text.ends_with('\n') {
                    self.out("\n");
                }
            }
            return ok_exit;
        }
        self.remote_failure(wire, done, info, &body)
    }

    pub fn remote_failure(&mut self, wire: &str, done: &Done, info: &HostInfo, body: &str) -> i32 {
        let st = done.res.status;
        let (mut text, reasons) = remote_error_text(st.name(), body);
        if st == labproto::Status::Eperm && done.role == Some(Role::Ro) {
            text.push_str(" (your key is read-only; this needs the admin key: --role admin)");
        }
        let exit = st.cli_exit();
        if self.g.json {
            let e = output::err_envelope(Some(done.transport), Some(info), wire, &output::ErrInfo { code: st.name(), status: Some(st as u16), exit, message: &text, reasons: &reasons });
            self.outln(&e);
        } else {
            self.err(&format!("i7labctl: {}: {}", wire, text));
            for r in &reasons {
                self.err(&format!("  reason: {}", labproto::text::sanitize(r)));
            }
        }
        exit
    }
}

// ---------------------------------------------------------------- dispatch

pub fn dispatch(env: &mut Env, g: &Global, sub: &Sub, args: &[String], paint: Paint) -> i32 {
    // hidden helper for shell completion
    let mut run = Run::new(env, g, paint);
    let r = match sub.name {
        "help" => Ok(crate::help::run_help(run.env, args, paint)),
        "version" => {
            run.outln(&crate::help::version_text());
            Ok(0)
        }
        "completions" => crate::local::completions(&mut run, args),
        "ls" => crate::local::ls(&mut run, args),
        "discover" => crate::local::discover(&mut run, args),
        "wait" => crate::local::wait(&mut run, args),
        "key" => crate::local::key(&mut run, args),
        "ether" => crate::local::ether(&mut run, args),
        "image" => crate::local::image(&mut run, args),
        "ssh" => crate::local::ssh(&mut run, args),
        "lab-boot" => crate::local::lab_boot(&mut run, args),
        "api" => crate::local::api(&mut run, args),
        "exec" | "sh" | "shell" | "put" | "get" | "logs" => crate::stream::dispatch(&mut run, sub.name, args),
        "blk" => crate::stream::blk(&mut run, args),
        _ => wire_command(&mut run, sub.name, args),
    };
    match r {
        Ok(code) => code,
        Err(e) => {
            let own255 = matches!(sub.name, "exec" | "sh" | "shell" | "ssh");
            if own255 {
                run.fail255(sub.name, &e)
            } else {
                run.fail(sub.name, &e)
            }
        }
    }
}

/// May `s` be printed for a completion script? Hostnames and serials come from (possibly unauthenticated) L2
/// beacons, and bash `compgen -W` expands `$(..)`, backquotes and `${..}` in its word list, so anything outside
/// a plain selector charset would run as code in the operator's shell on TAB.
pub fn completion_safe(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// The hidden `__hosts` helper: one selector per line for completion scripts (only `completion_safe` words).
pub fn hosts_for_completion(env: &mut Env, g: &Global) -> i32 {
    let run = Run::new(env, g, Paint { on: false });
    let reg = run.registry();
    let mut v: Vec<String> = Vec::new();
    for h in reg.hosts.values() {
        for s in [&h.mac, &h.host, &h.board_serial] {
            if completion_safe(s) {
                v.push(s.clone());
            }
        }
        if let Some(ip) = h.addr() {
            v.push(ip.to_string());
        }
    }
    v.extend(run.aliases().into_iter().map(|(k, _)| k).filter(|k| completion_safe(k)));
    v.sort();
    v.dedup();
    let mut run = run;
    for s in v {
        run.outln(&s);
    }
    0
}

/// Raw form: `--ether MAC --cmd NAME [params..]`. No pre-validation: the server's gate is what is being tested.
pub fn run_raw(env: &mut Env, g: &Global, rest: &[String], paint: Paint) -> i32 {
    let mut run = Run::new(env, g, paint);
    let cmd_word = g.cmd.clone().unwrap_or_default();
    let r = (|| -> Result<i32, ClientError> {
        let spec = ether::raw_spec(&cmd_word)?;
        if !run.g.host_by_flag() {
            return Err(ClientError::Usage("the raw form needs a host: i7labctl --ether MAC --cmd NAME [params..] (or --http IP / -H HOST)".into()));
        }
        let timeout = run.g.timeout.unwrap_or(if spec.streams { 0.0 } else { 30.0 });
        let prep = run.prepare(None, timeout)?;
        if spec.streams {
            let o = crate::stream::run_stream(&mut run, prep, spec, rest, None, None, true)?;
            let exit = o.done.res.exit_code.map(|n| n.clamp(0, 254)).unwrap_or(0);
            let text = |b: &str, _: Paint| labproto::text::sanitize(b.trim_end()).into_owned();
            return Ok(crate::stream::end_stream(&mut run, spec.name, &o, Some(&text), exit));
        }
        let mut prep = prep;
        let res = prep.transport.call(spec, rest, &mut NullIo)?;
        let done = Done { transport: prep.transport.name(), role: prep.transport.role(), res };
        let body = String::from_utf8_lossy(&done.res.body).into_owned();
        if done.res.status != labproto::Status::Ok {
            return Ok(run.remote_failure(spec.name, &done, &prep.info, &body));
        }
        if run.g.json {
            let e = ok_envelope(done.transport, Some(&prep.info), spec.name, Some(done.res.rtt_ms), &body);
            run.outln(&e);
        } else if !body.trim().is_empty() {
            run.outln(&labproto::text::sanitize(body.trim_end()));
        }
        Ok(done.res.exit_code.map(|n| n.clamp(0, 254)).unwrap_or(0))
    })();
    match r {
        Ok(c) => c,
        Err(e) => run.fail(&cmd_word, &e),
    }
}

// ---------------------------------------------------------------- buffered wire commands

fn wire_command(run: &mut Run, name: &str, args: &[String]) -> Result<i32, ClientError> {
    match name {
        "ping" => ping(run, args),
        "id" => {
            let p = run.parse(args, &Spec::new("id <host>"))?;
            let (d, info) = run.simple_call(p.host.as_deref(), "id", &[])?;
            let role = d.role.map(|r| r.name());
            Ok(run.finish("id", &d, &info, &|b, pt| render::id(b, role, pt)))
        }
        "inv" => {
            let p = run.parse(args, &Spec::new("inv <host> [--section S,..] [--raw]").flags(&["raw"]).valued(&["section"]))?;
            let mut argv = Vec::new();
            if let Some(s) = p.opts.value("section") {
                argv.extend(["--section".to_string(), s.to_string()]);
            }
            let (d, info) = run.simple_call(p.host.as_deref(), "inv", &argv)?;
            if p.opts.flag("raw") && d.res.status == labproto::Status::Ok {
                run.outln(String::from_utf8_lossy(&d.res.body).trim_end());
                return Ok(0);
            }
            Ok(run.finish("inv", &d, &info, &render::inv))
        }
        "pcie" => {
            let p = run.parse(args, &Spec::new("pcie <host> [--tree] [--id VVVV:DDDD] [--class CC] [--verbose]").flags(&["tree", "verbose", "aer"]).valued(&["id", "class"]))?;
            let mut argv = Vec::new();
            for f in ["tree", "verbose", "aer"] {
                if p.opts.flag(f) && f != "aer" {
                    argv.push(format!("--{}", f));
                }
            }
            for v in ["id", "class"] {
                if let Some(x) = p.opts.value(v) {
                    argv.extend([format!("--{}", v), x.to_string()]);
                }
            }
            let (tree, verbose) = (p.opts.flag("tree"), p.opts.flag("verbose"));
            let (d, info) = run.simple_call(p.host.as_deref(), "pcie", &argv)?;
            Ok(run.finish("pcie", &d, &info, &move |b, pt| render::pcie(b, tree, verbose, pt)))
        }
        "usb" => {
            let p = run.parse(args, &Spec::new("usb <host> [--tree] [--id VVVV:PPPP]").flags(&["tree"]).valued(&["id"]))?;
            let mut argv = Vec::new();
            if p.opts.flag("tree") {
                argv.push("--tree".to_string());
            }
            if let Some(x) = p.opts.value("id") {
                // the wire usage has no --id: filter on the client
                let _ = x;
            }
            let id = p.opts.value("id").map(|s| s.to_ascii_lowercase());
            let (d, info) = run.simple_call(p.host.as_deref(), "usb", &argv)?;
            Ok(run.finish("usb", &d, &info, &move |b, pt| match &id {
                Some(f) => render::usb(&filter_usb(b, f), pt),
                None => render::usb(b, pt),
            }))
        }
        "thermal" => thermal(run, args),
        "net" => net(run, args),
        "fs" => fs(run, args),
        "jobs" => jobs(run, args),
        "reboot" => reboot(run, args),
        "poweroff" => {
            let p = run.parse(args, &Spec::new("poweroff <host> [--delay S]").valued(&["delay"]))?;
            let mut argv = Vec::new();
            if let Some(d) = p.uint("delay")? {
                argv.extend(["--delay".to_string(), d.to_string()]);
            }
            let host = p.host.clone().unwrap_or_default();
            if !run.confirm(&format!("Power OFF {}?", host)) {
                return Err(ClientError::Safety("not confirmed".into()));
            }
            let (d, info) = run.simple_call(p.host.as_deref(), "poweroff", &argv)?;
            Ok(run.finish("poweroff", &d, &info, &|_, _| "power off requested\n".to_string()))
        }
        "identify" => {
            let p = run.parse(args, &Spec::new("identify <host> [--seconds N] [--stop]").flags(&["stop"]).valued(&["seconds"]))?;
            let mut argv = Vec::new();
            if let Some(s) = p.uint("seconds")? {
                argv.extend(["--seconds".to_string(), s.to_string()]);
            }
            if p.opts.flag("stop") {
                argv.push("--stop".into());
            }
            let (d, info) = run.simple_call(p.host.as_deref(), "identify", &argv)?;
            Ok(run.finish("identify", &d, &info, &|_, _| "identify requested\n".to_string()))
        }
        "msg" => {
            let p = run.parse(args, &Spec::new("msg <host> <text..>").pos(1, 4096))?;
            let text = p.pos.join(" ");
            let (d, info) = run.simple_call(p.host.as_deref(), "msg", &[text])?;
            Ok(run.finish("msg", &d, &info, &|_, _| "message shown\n".to_string()))
        }
        "time-set" => {
            let p = run.parse(args, &Spec::new("time-set <host> [UNIX_SECONDS|now]").pos(0, 1))?;
            let when = match p.pos.first().map(String::as_str) {
                None | Some("now") => run.env.now(),
                Some(n) => n.parse().map_err(|_| ClientError::Usage(format!("time-set needs UNIX_SECONDS or 'now', got '{}'", n)))?,
            };
            let (d, info) = run.simple_call(p.host.as_deref(), "time.set", &[when.to_string()])?;
            Ok(run.finish("time.set", &d, &info, &|_, _| "clock set\n".to_string()))
        }
        "tui" => tui(run, args),
        _ => Err(ClientError::Usage(format!("no handler for '{}'", name))),
    }
}

fn filter_usb(body: &str, id: &str) -> String {
    // keep the original JSON shape; drop devices that do not match vid:pid (decimal ids in the JSON)
    let Some(v) = crate::jv::parse(body) else { return body.to_string() };
    let Some((vid, pid)) = id.split_once(':').and_then(|(a, b)| Some((u64::from_str_radix(a, 16).ok()?, u64::from_str_radix(b, 16).ok()?))) else { return body.to_string() };
    let devs: Vec<labproto::json::Value> = crate::jv::arr(&v, "devices").iter().filter(|d| crate::jv::u(d, "vid") == Some(vid) && crate::jv::u(d, "pid") == Some(pid)).cloned().collect();
    format!("{{\"devices\":{}}}", crate::jv::to_json(&labproto::json::Value::Arr(devs)))
}

fn ping(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let p = run.parse(args, &Spec::new("ping <host> [-c N] [-W S] [ECHO]").valued(&["c", "W"]).pos(0, 1))?;
    let count = p.uint("c")?.unwrap_or(4).clamp(1, 1000);
    let per = p.num("W")?.unwrap_or(3.0);
    let spec = catalog::by_name("ping").unwrap();
    let mut prep = run.prepare(p.host.as_deref(), per)?;
    let argv: Vec<String> = p.pos.clone();
    let (mut ok, mut rtts, mut last): (u64, Vec<f64>, Option<Vec<u8>>) = (0, Vec::new(), None);
    let mut last_err: Option<ClientError> = None;
    for i in 0..count {
        match prep.transport.call(spec, &argv, &mut NullIo) {
            Ok(r) if r.status == labproto::Status::Ok => {
                ok += 1;
                rtts.push(r.rtt_ms);
                if !run.g.json {
                    let line = format!("reply from {} via {}: seq={} rtt={:.2} ms", prep.info.mac.clone().or(prep.info.ip.clone()).unwrap_or_default(), prep.transport.name(), i + 1, r.rtt_ms);
                    run.outln(&line);
                }
                last = Some(r.body);
            }
            Ok(r) => {
                let done = Done { transport: prep.transport.name(), role: prep.transport.role(), res: r };
                let body = String::from_utf8_lossy(&done.res.body).into_owned();
                return Ok(run.remote_failure("ping", &done, &prep.info, &body));
            }
            Err(e @ ClientError::Auth(_)) => return Err(e),
            Err(e) => {
                if !run.g.json {
                    run.err(&format!("no reply (seq={}): {}", i + 1, e));
                }
                last_err = Some(e);
            }
        }
        if i + 1 < count {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    if ok == 0 {
        return Err(last_err.unwrap_or(ClientError::Timeout));
    }
    let (min, max) = rtts.iter().fold((f64::MAX, 0.0f64), |(a, b), x| (a.min(*x), b.max(*x)));
    let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
    let body = String::from_utf8_lossy(&last.unwrap_or_default()).into_owned();
    if run.g.json {
        let data = format!("{{\"sent\":{},\"received\":{},\"rtt_ms\":{{\"min\":{:.2},\"avg\":{:.2},\"max\":{:.2}}},\"last\":{}}}", count, ok, min, avg, max, if output::looks_like_json(&body) { body.trim().to_string() } else { "null".to_string() });
        let e = ok_envelope(prep.transport.name(), Some(&prep.info), "ping", Some(avg), &data);
        run.outln(&e);
    } else {
        run.outln(&format!("{} sent, {} received, rtt min/avg/max = {:.2}/{:.2}/{:.2} ms", count, ok, min, avg, max));
        let t = render::ping(&body, run.paint);
        run.out(&t);
    }
    Ok(0)
}

fn thermal(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let p = run.parse(args, &Spec::new("thermal <host> [--follow] [--interval S]").flags(&["follow"]).valued(&["interval"]))?;
    if p.opts.flag("follow") {
        return crate::stream::stream_wire(run, p.host.as_deref(), "thermal", vec!["--follow".into()], &|b, pt| render::thermal(b, pt));
    }
    let interval = p.num("interval")?;
    loop {
        let (d, info) = run.simple_call(p.host.as_deref(), "thermal", &[])?;
        let code = run.finish("thermal", &d, &info, &render::thermal);
        match interval {
            Some(s) if s > 0.0 && code == 0 => std::thread::sleep(Duration::from_secs_f64(s)),
            _ => return Ok(code),
        }
    }
}

const NET_VERBS: &str = "net ls|set|vlan|link|confirm <host> ...";

fn net(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let (verb, rest) = args.split_first().ok_or_else(|| ClientError::Usage(format!("net needs a verb\nusage: i7labctl {}", NET_VERBS)))?;
    let rest = rest.to_vec();
    match verb.as_str() {
        "ls" => {
            let p = run.parse(&rest, &Spec::new("net ls <host> [IFACE]").pos(0, 1))?;
            let (d, info) = run.simple_call(p.host.as_deref(), "net.ls", &p.pos)?;
            Ok(run.finish("net.ls", &d, &info, &render::net_ls))
        }
        "set" => {
            let p = run.parse(&rest, &Spec::new("net set <host> IFACE (--dhcp | --ip A.B.C.D/N [--gw A.B.C.D] [--dns A,B]) [--mtu N] [--confirm SEC]").flags(&["dhcp"]).valued(&["ip", "gw", "dns", "mtu", "confirm"]).pos(1, 1))?;
            if p.opts.flag("dhcp") == p.opts.value("ip").is_some() {
                return Err(ClientError::Usage("net set needs exactly one of --dhcp or --ip A.B.C.D/N\nusage: i7labctl net set <host> IFACE (--dhcp | --ip A.B.C.D/N [--gw A.B.C.D] [--dns A,B]) [--mtu N] [--confirm SEC]".into()));
            }
            let mut argv = vec![p.pos[0].clone()];
            if p.opts.flag("dhcp") {
                argv.push("--dhcp".into());
            }
            for v in ["ip", "gw", "dns", "mtu"] {
                if let Some(x) = p.opts.value(v) {
                    argv.extend([format!("--{}", v), x.to_string()]);
                }
            }
            // over http a wrong address would cut us off: default to a 30 s auto-revert unless told otherwise
            let confirm = match p.uint("confirm")? {
                Some(c) => Some(c),
                None => {
                    let t = run.target(p.host.as_deref())?;
                    (t.plan.first() == Some(&Kind::Http)).then_some(30)
                }
            };
            if let Some(c) = confirm {
                argv.extend(["--confirm".to_string(), c.to_string()]);
            }
            let (d, info) = run.simple_call(p.host.as_deref(), "net.set", &argv)?;
            let note = confirm.map(|c| format!("applied; reverts in {} s unless confirmed: i7labctl net confirm <host>\n", c)).unwrap_or_else(|| "applied\n".to_string());
            Ok(run.finish("net.set", &d, &info, &move |_, _| note.clone()))
        }
        "vlan" => {
            let (action, rest2) = rest.split_first().ok_or_else(|| ClientError::Usage("net vlan needs add|del\nusage: i7labctl net vlan add <host> IFACE VID [--ip A.B.C.D/N] | net vlan del <host> IFACE VID".into()))?;
            if action != "add" && action != "del" {
                return Err(ClientError::Usage(format!("net vlan: unknown action '{}' (add|del)", action)));
            }
            let p = run.parse(rest2, &Spec::new("net vlan add|del <host> IFACE VID [--ip A.B.C.D/N]").valued(&["ip"]).pos(2, 2))?;
            let vid: u16 = p.pos[1].parse().ok().filter(|v| (1..=4094).contains(v)).ok_or_else(|| ClientError::Usage(format!("bad VLAN id '{}'", p.pos[1])))?;
            let mut argv = vec![action.clone(), p.pos[0].clone(), vid.to_string()];
            if let Some(ip) = p.opts.value("ip") {
                argv.extend(["--ip".to_string(), ip.to_string()]);
            }
            let (d, info) = run.simple_call(p.host.as_deref(), "net.vlan", &argv)?;
            Ok(run.finish("net.vlan", &d, &info, &|_, _| "done\n".to_string()))
        }
        "link" => {
            let p = run.parse(&rest, &Spec::new("net link <host> IFACE up|down").pos(2, 2))?;
            if p.pos[1] != "up" && p.pos[1] != "down" {
                return Err(ClientError::Usage(format!("net link: '{}' is not up or down", p.pos[1])));
            }
            let (d, info) = run.simple_call(p.host.as_deref(), "net.link", &p.pos)?;
            Ok(run.finish("net.link", &d, &info, &|_, _| "done\n".to_string()))
        }
        "confirm" => {
            let p = run.parse(&rest, &Spec::new("net confirm <host>"))?;
            let (d, info) = run.simple_call(p.host.as_deref(), "net.confirm", &[])?;
            Ok(run.finish("net.confirm", &d, &info, &|_, _| "confirmed\n".to_string()))
        }
        other => Err(ClientError::Usage(format!("net: unknown verb '{}'\nusage: i7labctl {}", other, NET_VERBS))),
    }
}

fn fs(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let (verb, rest) = args.split_first().ok_or_else(|| ClientError::Usage("fs needs a verb\nusage: i7labctl fs ls|stat|rm <host> <path> ...".into()))?;
    let rest = rest.to_vec();
    match verb.as_str() {
        "ls" => {
            let p = run.parse(&rest, &Spec::new("fs ls <host> PATH [-l]").flags(&["l", "long"]).pos(1, 1))?;
            let mut argv = vec![p.pos[0].clone()];
            if p.opts.flag("l") || p.opts.flag("long") {
                argv.push("--long".into());
            }
            let (d, info) = run.simple_call(p.host.as_deref(), "fs.ls", &argv)?;
            Ok(run.finish("fs.ls", &d, &info, &|b, pt| render::generic(b, pt)))
        }
        "stat" => {
            let p = run.parse(&rest, &Spec::new("fs stat <host> PATH").pos(1, 1))?;
            let (d, info) = run.simple_call(p.host.as_deref(), "fs.stat", &p.pos)?;
            Ok(run.finish("fs.stat", &d, &info, &|b, pt| render::generic(b, pt)))
        }
        "rm" => {
            let p = run.parse(&rest, &Spec::new("fs rm <host> PATH [-r]").flags(&["r", "recursive"]).pos(1, 1))?;
            let mut argv = vec![p.pos[0].clone()];
            if p.opts.flag("r") || p.opts.flag("recursive") {
                argv.push("--recursive".into());
            }
            if !run.confirm(&format!("Remove {} on the host?", p.pos[0])) {
                return Err(ClientError::Safety("not confirmed".into()));
            }
            let (d, info) = run.simple_call(p.host.as_deref(), "fs.rm", &argv)?;
            Ok(run.finish("fs.rm", &d, &info, &|_, _| "removed\n".to_string()))
        }
        other => Err(ClientError::Usage(format!("fs: unknown verb '{}'\nusage: i7labctl fs ls|stat|rm <host> <path> ...", other))),
    }
}

fn jobs(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    // jobs <host> [ls] | kill ID | out ID [-f]  (host first, as everywhere else)
    let p = run.parse(args, &Spec::new("jobs <host> [ls] | kill ID | out ID [-f]").flags(&["f"]).pos(0, 2))?;
    let verb = p.pos.first().map(String::as_str).unwrap_or("ls");
    match verb {
        "ls" if p.pos.len() <= 1 => {
            let (d, info) = run.simple_call(p.host.as_deref(), "jobs", &["ls".to_string()])?;
            Ok(run.finish("jobs", &d, &info, &|b, pt| render::generic(b, pt)))
        }
        "kill" if p.pos.len() == 2 => {
            let (d, info) = run.simple_call(p.host.as_deref(), "jobs", &["kill".to_string(), p.pos[1].clone()])?;
            Ok(run.finish("jobs", &d, &info, &|_, _| "killed\n".to_string()))
        }
        "out" if p.pos.len() == 2 => {
            let mut argv = vec!["out".to_string(), p.pos[1].clone()];
            if p.opts.flag("f") {
                argv.push("-f".into());
            }
            crate::stream::stream_wire(run, p.host.as_deref(), "jobs", argv, &|b, pt| render::generic(b, pt))
        }
        _ => Err(ClientError::Usage("usage: i7labctl jobs <host> [ls] | kill ID | out ID [-f]".into())),
    }
}

fn tui(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let (verb, rest) = args.split_first().ok_or_else(|| ClientError::Usage("tui needs a verb\nusage: i7labctl tui tab|reset|dump <host> ...".into()))?;
    let rest = rest.to_vec();
    match verb.as_str() {
        "tab" => {
            let p = run.parse(&rest, &Spec::new("tui tab <host> NAME").pos(1, 1))?;
            let (d, info) = run.simple_call(p.host.as_deref(), "tui", &["tab".to_string(), p.pos[0].clone()])?;
            Ok(run.finish("tui", &d, &info, &|_, _| "tab switched\n".to_string()))
        }
        "reset" => {
            let p = run.parse(&rest, &Spec::new("tui reset <host>"))?;
            let (d, info) = run.simple_call(p.host.as_deref(), "tui", &["reset".to_string()])?;
            Ok(run.finish("tui", &d, &info, &|_, _| "tui reset\n".to_string()))
        }
        "dump" => {
            let p = run.parse(&rest, &Spec::new("tui dump <host>"))?;
            let (d, info) = run.simple_call(p.host.as_deref(), "tui.dump", &[])?;
            Ok(run.finish("tui.dump", &d, &info, &|b, _| {
                let text = crate::jv::parse(b).and_then(|v| crate::jv::s_any(&v, &["frame", "text", "dump"]).map(String::from)).unwrap_or_else(|| b.to_string());
                text.lines().map(|l| format!("{}\n", labproto::text::sanitize(l))).collect()
            }))
        }
        other => Err(ClientError::Usage(format!("tui: unknown verb '{}' (tab|reset|dump)", other))),
    }
}

fn reboot(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let p = run.parse(args, &Spec::new("reboot <host> [--force] [--delay S] [--uefi] [--to-os] [--wait [S]]").flags(&["force", "uefi", "to-os"]).valued(&["delay"]).optnum(&["wait"]))?;
    let mut argv = Vec::new();
    for f in ["force", "uefi", "to-os"] {
        if p.opts.flag(f) {
            argv.push(format!("--{}", f));
        }
    }
    if p.opts.flag("uefi") && p.opts.flag("to-os") {
        return Err(ClientError::Usage("--uefi and --to-os exclude each other".into()));
    }
    if let Some(d) = p.uint("delay")? {
        argv.extend(["--delay".to_string(), d.to_string()]);
    }
    let wait: Option<f64> = match p.opts.value("wait") {
        None => None,
        Some("") => Some(300.0),
        Some(v) => Some(v.parse().map_err(|_| ClientError::Usage("--wait needs seconds".into()))?),
    };
    let host = p.host.clone().unwrap_or_default();
    if !run.confirm(&format!("Reboot {}?", host)) {
        return Err(ClientError::Safety("not confirmed".into()));
    }
    // baseline boot id for --wait, taken before the reboot is requested
    let (entry, macs) = match wait {
        Some(_) => {
            let t = run.target(p.host.as_deref())?;
            let reg = run.registry();
            let macs = t.entry.as_ref().map(|e| crate::discover::sibling_macs(e, &reg)).or_else(|| t.mac.map(|m| vec![m.to_string()])).unwrap_or_default();
            (t.entry, macs)
        }
        None => (None, Vec::new()),
    };
    let (d, info) = run.simple_call(p.host.as_deref(), "reboot", &argv)?;
    let code = run.finish("reboot", &d, &info, &|_, _| "reboot requested\n".to_string());
    if code != 0 || run.g.json {
        return Ok(code);
    }
    if let Some(secs) = wait {
        let boot = entry.as_ref().map(|e| e.boot.clone()).filter(|b| !b.is_empty());
        run.note(&format!("waiting up to {:.0} s for the host to come back with a new boot id ...", secs));
        return crate::local::wait_core(run, macs, crate::discover::WaitKind::Reboot, boot, secs, "reboot");
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_words_are_inert() {
        for ok in ["m900", "02:00:00:9d:01:57", "192.0.2.195", "BTKY000000XX", "rack3-m720q_a.lab"] {
            assert!(completion_safe(ok), "{}", ok);
        }
        for bad in ["$(id)", "`id`", "${HOME}", "a;b", "a|b", "a b", "", "x'y", "x\"y", "~root", "{a,b}", "a\nb"] {
            assert!(!completion_safe(bad), "{:?}", bad);
        }
    }

    #[test]
    fn link_specs() {
        assert_eq!(parse_link("udp:7001:7002").unwrap(), LinkSpec::Udp("127.0.0.1:7001".parse().unwrap(), "127.0.0.1:7002".parse().unwrap()));
        assert_eq!(parse_link("udp:10.0.0.1:5000:10.0.0.2:5001").unwrap(), LinkSpec::Udp("10.0.0.1:5000".parse().unwrap(), "10.0.0.2:5001".parse().unwrap()));
        assert_eq!(parse_link("mcast:239.255.71.1:4711").unwrap(), LinkSpec::Mcast("239.255.71.1".parse().unwrap(), 4711));
        assert!(parse_link("tap:eth0").is_err());
        assert!(parse_link("udp:1").is_err());
        assert!(parse_link("mcast:notip:1").is_err());
    }
}
