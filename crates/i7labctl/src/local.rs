//! Commands that run on this machine or listen on the wire instead of calling one wire command:
//! completions, ls, discover, wait, key, ether, image, ssh, lab-boot, api. Owner: P9.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use labproto::beacon::Hint;
use labproto::catalog;
use labproto::frame::{self, FrameType};
use labproto::json::JsonWriter;
use labproto::keys::{Key, KeySet, Role};
use labproto::text::sanitize;
use labproto::Mac;

use crate::cmds::{Run, Spec};
use crate::discover::{self, LinkSet, Listener, Sighting, WaitKind, Waiter};
use crate::hosts::{self, Change, HostEntry, STALE_SECS};
use crate::output::{self, fmt_age, ok_envelope, Table};
use crate::{keys, labboot, wrap, ClientError, Kind};

pub fn completions(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let p = run.parse(args, &Spec::new("completions bash|zsh|fish").no_host().pos(1, 1))?;
    match crate::complete::script(&p.pos[0]) {
        Some(s) => {
            run.out(&s);
            Ok(0)
        }
        None => Err(ClientError::Usage(format!("no completions for '{}' (bash, zsh or fish)", p.pos[0]))),
    }
}

// ---------------------------------------------------------------- ls

/// One registry entry as JSON (fields of hosts.json plus the computed `state`, `age_s` and `flags`).
pub fn entry_json(h: &HostEntry, now: u64, fps: &[String]) -> String {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_str("mac", &h.mac);
    w.field_str("ip", &h.ip);
    w.field_str("host", &h.host);
    w.field_str("board", &h.board);
    w.field_str("board_serial", &h.board_serial);
    w.field_str("product", &h.product);
    w.field_str("vendor", &h.vendor);
    w.field_str("kernel", &h.kernel);
    w.field_str("build", &h.build);
    w.field_str("state", &h.state);
    w.field_str("proto", if h.proto_ver == 1 { "-" } else { &h.proto });
    w.field_str("boot", &h.boot);
    w.field_str("kid", &h.kid);
    w.field_str("http", &h.http);
    w.field_str("iface", &h.iface);
    w.field_opt_u64("vlan", h.vlan.map(u64::from));
    w.field_u64("proto_ver", u64::from(h.proto_ver));
    w.key("tag_ok");
    match h.tag_ok {
        Some(b) => w.bool(b),
        None => w.null(),
    }
    w.field_u64("first_seen", h.first_seen);
    w.field_u64("last_seen", h.last_seen);
    w.field_u64("age_s", h.age(now));
    w.field_str("liveness", h.state_word(now));
    w.key("flags");
    w.begin_array();
    for f in h.flags(fps) {
        w.str(f);
    }
    w.end_array();
    w.end_object();
    w.finish()
}

fn hosts_table(list: &[&HostEntry], now: u64, fps: &[String]) -> Table {
    let mut t = Table::new(&["MAC", "IP", "BOARD", "SERIAL", "HOST", "BUILD", "STATE", "VLAN", "PROTO", "KERNEL", "AGE", "NOTE"]).right(10);
    for h in list {
        let st = if h.state.is_empty() { h.state_word(now).to_string() } else if h.live(now) { h.state.clone() } else { format!("{} (stale)", h.state) };
        t.row(&[
            h.mac.clone(),
            h.ip.clone(),
            h.board.clone(),
            h.board_serial.clone(),
            h.host.clone(),
            h.build.clone(),
            st,
            h.vlan.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
            if h.proto_ver == 1 { "-".to_string() } else { h.proto.clone() },
            h.kernel.clone(),
            fmt_age(h.age(now)),
            h.flags(fps).join(","),
        ]);
    }
    t
}

fn hosts_json(list: &[&HostEntry], now: u64, fps: &[String]) -> String {
    let items: Vec<String> = list.iter().map(|h| entry_json(h, now, fps)).collect();
    format!("{{\"hosts\":[{}]}}", items.join(","))
}

pub fn ls(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let p = run.parse(args, &Spec::new("ls [--all] [--sort mac|ip|age|board] [--state live|stale|any]").flags(&["all"]).valued(&["sort", "state"]).no_host())?;
    let now = run.env.now();
    let reg = run.registry();
    let fps = keys::local_fingerprints(&run.keyenv());
    let state = p.opts.value("state").unwrap_or("any");
    if !["live", "stale", "any"].contains(&state) {
        return Err(ClientError::Usage(format!("--state must be live, stale or any, got '{}'", state)));
    }
    let all = p.opts.flag("all");
    let mut list: Vec<&HostEntry> = reg
        .hosts
        .values()
        .filter(|h| all || h.age(now) <= hosts::AGE_OUT_SECS)
        .filter(|h| match state {
            "live" => h.live(now),
            "stale" => !h.live(now),
            _ => true,
        })
        .collect();
    match p.opts.value("sort").unwrap_or("age") {
        "mac" => list.sort_by(|a, b| a.mac.cmp(&b.mac)),
        "ip" => list.sort_by_key(|h| ip_key(h.addr())),
        "age" => list.sort_by_key(|h| (h.age(now), h.mac.clone())),
        "board" => list.sort_by(|a, b| (a.board.to_lowercase(), &a.mac).cmp(&(b.board.to_lowercase(), &b.mac))),
        other => return Err(ClientError::Usage(format!("--sort must be mac, ip, age or board, got '{}'", other))),
    }
    emit_hosts(run, "ls", &list, now, &fps);
    Ok(0)
}

fn ip_key(ip: Option<&str>) -> (u8, [u8; 4]) {
    match ip.and_then(|s| s.parse::<std::net::Ipv4Addr>().ok()) {
        Some(a) => (0, a.octets()),
        None => (1, [0; 4]),
    }
}

fn emit_hosts(run: &mut Run, cmd: &str, list: &[&HostEntry], now: u64, fps: &[String]) {
    if run.g.json {
        let e = ok_envelope("registry", None, cmd, None, &hosts_json(list, now, fps));
        run.outln(&e);
    } else if list.is_empty() {
        run.outln("no hosts known (run: i7labctl discover)");
    } else {
        let t = hosts_table(list, now, fps).render(run.paint);
        run.out(&t);
    }
}

// ---------------------------------------------------------------- discover

#[derive(Default)]
pub struct DiscoverOpts {
    pub listen: Option<f64>,
    pub active: bool,
    pub watch: bool,
    pub all: bool,
    pub assigns: Vec<Hint>,
    /// write the registry (false for `ether probe`)
    pub save: bool,
    pub daemon: bool,
}

pub fn discover(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let p = run.parse(args, &Spec::new("discover [--listen S] [--active] [--watch] [--all] [--assign MAC=IP/PFX[/GW]].. [-i IF].. [--vlan IDS]").flags(&["active", "watch", "all", "daemon"]).valued(&["listen", "assign"]).no_host())?;
    let mut assigns = Vec::new();
    for a in p.opts.values("assign") {
        assigns.push(discover::parse_assign(a).map_err(ClientError::Usage)?);
    }
    let o = DiscoverOpts { listen: p.num("listen")?, active: p.opts.flag("active"), watch: p.opts.flag("watch"), all: p.opts.flag("all"), assigns, save: !run.g.no_registry, daemon: p.opts.flag("daemon") };
    discover_core(run, o)
}

fn event_line(kind: &str, h: &HostEntry) -> String {
    format!("{:<7} {}  {}  {}  {}{}", kind, h.mac, if h.ip.is_empty() { "-" } else { &h.ip }, if h.host.is_empty() { "-" } else { &h.host }, if h.board.is_empty() { "-" } else { &h.board }, h.vlan.map(|v| format!("  vlan {}", v)).unwrap_or_default())
}

pub fn discover_core(run: &mut Run, o: DiscoverOpts) -> Result<i32, ClientError> {
    let set = run.env.connector.open_link(&run.g)?;
    let kenv = run.keyenv();
    let ro = keys::find_key(&kenv, Role::Ro).ok().map(|(k, _)| k);
    let admin = keys::find_key(&kenv, Role::Admin).ok().map(|(k, _)| k);
    let beacon_key = KeySet { admin: None, ro }.beacon_key();
    let fps = keys::local_fingerprints(&kenv);
    let mut reg = run.registry();
    let reg_path = run.registry_path();
    let mut l = Listener::new(set, beacon_key);

    let continuous = o.watch || o.daemon;
    let listen = o.listen.unwrap_or(if continuous { f64::INFINITY } else { 4.0 });
    let t0 = Instant::now();
    let deadline = (listen.is_finite()).then(|| t0 + Duration::from_secs_f64(listen));
    let wall0 = run.env.now();

    // active probes: at most 1 per second per NIC, 5 per run, VLAN ids at most 20 per second
    let vlans: Vec<Option<u16>> = if run.g.vlans.is_empty() { vec![None] } else { run.g.vlans.iter().map(|v| Some(*v)).collect() };
    let mut probes_sent = 0u32;
    let mut next_probe = t0;
    let mut seen: BTreeMap<String, u64> = BTreeMap::new(); // mac -> last_seen (this run)
    let mut lost: Vec<String> = Vec::new();
    let mut hinted: HashMap<String, Instant> = HashMap::new();
    let mut last_save = t0;
    let mut dirty = false;
    let mut events: Vec<(String, HostEntry)> = Vec::new();

    loop {
        let now_i = Instant::now();
        if o.active && probes_sent < 5 && now_i >= next_probe {
            let ifaces = l.set.ifaces.clone();
            let mut nonce = [0u8; 8];
            labproto::crypto::random_bytes(&mut nonce)?;
            for (_, idx) in &ifaces {
                let src = l.set.link.local_mac(*idx).unwrap_or(Mac([2, 0, 0, 0, 0, 1]));
                let mut sent_this = 0;
                for v in &vlans {
                    if sent_this >= 20 {
                        break;
                    }
                    let f = discover::probe_frame(src, *v, nonce);
                    let _ = l.set.link.send(*idx, &f);
                    sent_this += 1;
                }
            }
            probes_sent += 1;
            next_probe = now_i + Duration::from_secs(1);
        }
        let wait = Duration::from_millis(100);
        let regs = &reg;
        let sighting = l.poll(wait, &|m| regs.hosts.contains_key(&m.to_string()))?;
        let now = wall0 + t0.elapsed().as_secs();
        if let Some(s) = sighting {
            let before = s.beacon.get("mac").and_then(|m| Mac::parse(m)).and_then(|m| reg.hosts.get(&m.to_string()).cloned());
            let ch = reg.observe(&s.beacon, &s.meta, now);
            if ch != Change::Rejected {
                dirty = true;
                if let Some(mac) = s.beacon.get("mac").and_then(Mac::parse) {
                    let key = mac.to_string();
                    seen.insert(key.clone(), now);
                    lost.retain(|m| *m != key);
                    if let Some(after) = reg.hosts.get(&key).cloned() {
                        if o.watch {
                            if let Some(kind) = classify(ch, before.as_ref(), &after) {
                                events.push((kind.to_string(), after.clone()));
                            }
                        }
                        maybe_hint(&mut l, &o.assigns, &s, &mut hinted, admin.as_ref());
                    }
                }
            }
        }
        // silence detection for watch
        if o.watch {
            for (mac, last) in &seen {
                if now.saturating_sub(*last) > STALE_SECS && !lost.contains(mac) {
                    lost.push(mac.clone());
                    if let Some(h) = reg.hosts.get(mac) {
                        events.push(("lost".into(), h.clone()));
                    }
                }
            }
        }
        for (kind, h) in events.drain(..) {
            if run.g.json {
                let line = format!("{{\"event\":\"host\",\"state\":{},\"host\":{}}}", crate::jv::quote(&kind), entry_json(&h, now, &fps));
                run.outln(&line);
            } else {
                let line = event_line(&kind, &h);
                run.outln(&line);
            }
        }
        if o.save && dirty && continuous && last_save.elapsed() >= Duration::from_secs(1) {
            let _ = reg.save(&reg_path);
            last_save = Instant::now();
            dirty = false;
        }
        if let Some(d) = deadline {
            if Instant::now() >= d {
                break;
            }
        }
    }
    let now = wall0 + t0.elapsed().as_secs();
    reg.purge(now);
    if o.save {
        if let Err(e) = reg.save(&reg_path) {
            run.note(&format!("i7labctl: warning: cannot write the registry {}: {}", reg_path.display(), e));
        }
    }
    if o.watch {
        return Ok(0);
    }
    let list: Vec<&HostEntry> = reg.hosts.values().filter(|h| o.all || seen.contains_key(&h.mac)).collect();
    let mut sorted = list;
    sorted.sort_by_key(|h| (h.age(now), h.mac.clone()));
    if sorted.is_empty() {
        if run.g.json {
            let e = ok_envelope("ether", None, "discover", None, "{\"hosts\":[]}");
            run.outln(&e);
        } else {
            run.outln("no hosts seen in this window (is the host booted and on this segment? try --listen 10, -i IF, --vlan ID)");
        }
        return Ok(0);
    }
    emit_hosts(run, "discover", &sorted, now, &fps);
    Ok(0)
}

fn classify(ch: Change, before: Option<&HostEntry>, after: &HostEntry) -> Option<&'static str> {
    match (ch, before) {
        (Change::New, _) | (_, None) => Some("new"),
        (Change::Same, _) | (Change::Rejected, _) => None,
        (Change::Changed, Some(b)) => {
            if !b.boot.is_empty() && !after.boot.is_empty() && b.boot != after.boot {
                Some("reboot")
            } else if b.ip != after.ip {
                Some("ip")
            } else if b.state != after.state {
                Some("state")
            } else if !b.live(after.last_seen) {
                Some("back")
            } else {
                None
            }
        }
    }
}

fn maybe_hint(l: &mut Listener, assigns: &[Hint], s: &Sighting, hinted: &mut HashMap<String, Instant>, admin: Option<&Key>) {
    let Some(mac) = s.beacon.get("mac").and_then(Mac::parse) else { return };
    let Some(h) = assigns.iter().find(|h| h.target == mac) else { return };
    if !s.beacon.get("ip").unwrap_or("").is_empty() {
        return;
    }
    let key = mac.to_string();
    if hinted.get(&key).is_some_and(|t| t.elapsed() < Duration::from_secs(10)) {
        return;
    }
    let src = l.set.link.local_mac(s.ifindex).unwrap_or(Mac([2, 0, 0, 0, 0, 1]));
    if let Some(f) = discover::hint_frame(h, s, src, admin.map(|k| &k.bytes)) {
        if l.set.link.send(s.ifindex, &f).is_ok() {
            hinted.insert(key, Instant::now());
        }
    }
}

// ---------------------------------------------------------------- wait

pub fn wait(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let p = run.parse(args, &Spec::new("wait <host> [--timeout S] [--state up|down|ready|reboot] [--boot-id ID]").valued(&["state", "boot-id"]))?;
    let kind = match p.opts.value("state") {
        None => WaitKind::Up,
        Some(s) => WaitKind::parse(s).ok_or_else(|| ClientError::Usage(format!("--state must be up, down, ready or reboot, got '{}'", s)))?,
    };
    let sel = p.host.clone().or_else(|| run.flag_host()).ok_or_else(|| ClientError::Usage("no host given".into()))?;
    let reg = run.registry();
    let (macs, boot) = match hosts::resolve(&sel, &reg, &run.aliases())? {
        hosts::Resolution::Entry(e) => (discover::sibling_macs(&e, &reg), Some(e.boot.clone()).filter(|b| !b.is_empty())),
        hosts::Resolution::Mac(m) => (vec![m.to_string()], None),
        hosts::Resolution::Ip(_) => return Err(ClientError::NoHost(format!("wait listens for beacons and needs a MAC or a host the registry knows, not the address {}", sel))),
    };
    let boot = p.opts.value("boot-id").map(String::from).or(boot);
    let secs = run.g.timeout.unwrap_or(300.0);
    wait_core(run, macs, kind, boot, if secs == 0.0 { f64::INFINITY } else { secs }, "wait")
}

pub fn wait_core(run: &mut Run, macs: Vec<String>, kind: WaitKind, boot: Option<String>, secs: f64, cmd: &str) -> Result<i32, ClientError> {
    let set = run.env.connector.open_link(&run.g)?;
    let ro = keys::find_key(&run.keyenv(), Role::Ro).ok().map(|(k, _)| k);
    let mut l = Listener::new(set, KeySet { admin: None, ro }.beacon_key());
    let t0 = Instant::now();
    let mut w = Waiter::new(kind, macs.clone(), if kind == WaitKind::Reboot { boot } else { None }, 0);
    let mut reg = run.registry();
    let reg_path = run.registry_path();
    let wall0 = run.env.now();
    loop {
        let elapsed = t0.elapsed();
        if secs.is_finite() && elapsed.as_secs_f64() >= secs {
            return Err(ClientError::Timeout);
        }
        let regs = &reg;
        let s = l.poll(Duration::from_millis(100), &|m| regs.hosts.contains_key(&m.to_string()))?;
        let now_s = elapsed.as_secs();
        let mut done = false;
        if let Some(s) = s {
            reg.observe(&s.beacon, &s.meta, wall0 + now_s);
            done = w.feed(&s.beacon, now_s).is_some();
        }
        if !done {
            done = w.tick(now_s).is_some();
        }
        if done {
            if !run.g.no_registry {
                let _ = reg.save(&reg_path);
            }
            let b = w.last_beacon.clone();
            let boot = b.as_ref().and_then(|b| b.get("boot")).unwrap_or("").to_string();
            let state = b.as_ref().and_then(|b| b.get("state")).unwrap_or("").to_string();
            let word = match kind {
                WaitKind::Up => "is up",
                WaitKind::Down => "is down",
                WaitKind::Ready => "is ready",
                WaitKind::Reboot => "rebooted",
            };
            if run.g.json {
                let data = format!("{{\"state\":{},\"boot\":{},\"waited_s\":{:.1}}}", crate::jv::quote(&state), crate::jv::quote(&boot), t0.elapsed().as_secs_f64());
                let e = ok_envelope("ether", None, cmd, None, &data);
                run.outln(&e);
            } else {
                run.outln(&format!("{} {} after {:.0} s{}", macs.first().cloned().unwrap_or_default(), word, t0.elapsed().as_secs_f64(), if boot.is_empty() { String::new() } else { format!(" (boot {})", boot) }));
            }
            return Ok(0);
        }
    }
}

// ---------------------------------------------------------------- key

fn default_key_dir(run: &Run) -> Result<PathBuf, ClientError> {
    run.keyenv().home.map(|h| keys::default_key_dir(&h)).ok_or_else(|| ClientError::Failed("no home directory (set HOME)".into()))
}

pub fn key(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let (verb, rest) = args.split_first().ok_or_else(|| ClientError::Usage("key needs a verb\nusage: i7labctl key init|show|verify|import|export ...".into()))?;
    let rest = rest.to_vec();
    match verb.as_str() {
        "init" => key_init(run, &rest),
        "show" => key_show(run, &rest),
        "verify" => {
            let p = run.parse(&rest, &Spec::new("key verify <host>"))?;
            let (d, info) = run.simple_call(p.host.as_deref(), "id", &[])?;
            if d.res.status != labproto::Status::Ok {
                let body = String::from_utf8_lossy(&d.res.body).into_owned();
                return Ok(run.remote_failure("key verify", &d, &info, &body));
            }
            let role = d.role.map(|r| r.name()).or_else(|| crate::jv::parse(&String::from_utf8_lossy(&d.res.body)).and_then(|v| crate::jv::s(&v, "role").map(|_| "see id")));
            let role = role.unwrap_or("unknown");
            if run.g.json {
                let data = format!("{{\"authenticated\":true,\"role\":{}}}", crate::jv::quote(role));
                let e = ok_envelope(d.transport, Some(&info), "key.verify", Some(d.res.rtt_ms), &data);
                run.outln(&e);
            } else {
                run.outln(&format!("key authenticates: the host granted role {} over {}", role, d.transport));
            }
            Ok(0)
        }
        "import" => {
            let p = run.parse(&rest, &Spec::new("key import <file> [--force]").flags(&["force"]).no_host().pos(1, 1))?;
            let line = std::fs::read_to_string(&p.pos[0]).map_err(|e| ClientError::Usage(format!("cannot read {}: {}", p.pos[0], e)))?;
            let c = keys::import_into(&default_key_dir(run)?, &line, p.opts.flag("force"))?;
            run.outln(&format!("installed the {} key {} as {}", c.role.name(), c.fingerprint, c.path.display()));
            Ok(0)
        }
        "export" => {
            let p = run.parse(&rest, &Spec::new("key export [--role ro] [--file F] [-y]").valued(&["file"]).no_host())?;
            let role = run.g.role.unwrap_or(Role::Ro);
            let (k, _) = keys::find_key(&run.keyenv(), role).map_err(|e| ClientError::Auth(format!("{:?}", e)))?;
            if role == Role::Admin && !run.g.yes {
                return Err(ClientError::Safety("the admin key is root on every host of this key set; exporting it needs --yes".into()));
            }
            let line = format!("{}\n", k.to_line());
            match p.opts.value("file") {
                Some(f) => {
                    keys::write_private(std::path::Path::new(f), &line, false).map_err(|e| ClientError::Failed(format!("cannot write {}: {}", f, e)))?;
                    run.outln(&format!("wrote the {} key {} to {} (mode 0600)", role.name(), k.fingerprint(), f));
                }
                None => run.out(&line),
            }
            Ok(0)
        }
        "rotate" => Err(ClientError::Unsupported("key rotate is not in v1 (key.set is planned for v0.3): run scripts/gen-keys --force, then scripts/bake-keys for each stick".into())),
        other => Err(ClientError::Usage(format!("key: unknown verb '{}'\nusage: i7labctl key init|show|verify|import|export ...", other))),
    }
}

fn key_init(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let p = run.parse(args, &Spec::new("key init [--dir DIR] [--force]").flags(&["force"]).valued(&["dir"]).no_host())?;
    let force = p.opts.flag("force");
    let now = run.env.now();
    let mut dirs: Vec<PathBuf> = Vec::new();
    match p.opts.value("dir") {
        Some(d) => dirs.push(PathBuf::from(d)),
        None => {
            dirs.push(default_key_dir(run)?);
            // the build tree's gitignored ./keys is where scripts/bake-keys looks
            let cwd = run.env.cwd.clone();
            if cwd.join("scripts/bake-keys").exists() || cwd.join("scripts/gen-keys").exists() {
                dirs.push(cwd.join("keys"));
            }
        }
    }
    if !force {
        if let Some(d) = dirs.iter().find(|d| keys::has_keys(d)) {
            return Err(ClientError::Safety(format!("{} already holds keys; use --force to replace them (the old set is kept in old/)", d.display())));
        }
    }
    let (a, r) = keys::generate_set()?;
    let mut made = Vec::new();
    for d in &dirs {
        made.extend(keys::write_set(d, &a, &r, force, now)?);
    }
    if run.g.json {
        let items: Vec<String> = made.iter().map(|c| format!("{{\"role\":\"{}\",\"fingerprint\":\"{}\",\"path\":{}}}", c.role.name(), c.fingerprint, crate::jv::quote(&c.path.display().to_string()))).collect();
        let e = ok_envelope("local", None, "key.init", None, &format!("{{\"keys\":[{}]}}", items.join(",")));
        run.outln(&e);
    } else {
        for c in &made {
            run.outln(&format!("{:<6} {}  {}", c.role.name(), c.fingerprint, c.path.display()));
        }
        run.outln("keys are found automatically from now on (see: i7labctl help key). Next: scripts/build-usb-drive, then i7labctl discover");
    }
    Ok(0)
}

fn key_show(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let p = run.parse(args, &Spec::new("key show [--role admin|ro] [--secret]").flags(&["secret"]).no_host())?;
    let roles: Vec<Role> = match run.g.role {
        Some(r) => vec![r],
        None => vec![Role::Admin, Role::Ro],
    };
    let secret = p.opts.flag("secret");
    if secret && !run.confirm("Print the SECRET key line to the terminal?") {
        return Err(ClientError::Safety("not confirmed".into()));
    }
    let mut found = 0;
    let kenv = run.keyenv();
    for r in roles {
        match keys::find_key(&kenv, r) {
            Ok((k, path)) => {
                found += 1;
                run.outln(&format!("{:<6} {}  {}", r.name(), k.fingerprint(), path.display()));
                if secret {
                    run.outln(&format!("       {}", k.to_line()));
                }
            }
            Err(e) => run.outln(&format!("{:<6} none ({})", r.name(), key_error_text(&e))),
        }
    }
    Ok(if found == 0 { 5 } else { 0 })
}

fn key_error_text(e: &labproto::keys::KeyError) -> String {
    match e {
        labproto::keys::KeyError::Format(m) => m.clone(),
        labproto::keys::KeyError::Permissions(p) => format!("{} is readable by group/other: chmod 600 it", p.display()),
        labproto::keys::KeyError::Io(e) => e.to_string(),
    }
}

// ---------------------------------------------------------------- ether tools

pub fn ether(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let (verb, rest) = args.split_first().ok_or_else(|| ClientError::Usage("ether needs a verb\nusage: i7labctl ether cmds|probe|hello|sniff|frame|replay ...".into()))?;
    let rest = rest.to_vec();
    match verb.as_str() {
        "cmds" => {
            let p = run.parse(&rest, &Spec::new("ether cmds <mac>"))?;
            let (d, info) = run.simple_call(p.host.as_deref(), "cmds", &[])?;
            Ok(run.finish("cmds", &d, &info, &|b, pt| crate::render::generic(b, pt)))
        }
        "probe" => {
            let p = run.parse(&rest, &Spec::new("ether probe [--vlan IDS] [-i IF]").no_host())?;
            let _ = p;
            discover_core(run, DiscoverOpts { listen: Some(run.g.timeout.unwrap_or(2.0)), active: true, save: false, ..Default::default() })
        }
        "hello" => {
            let p = run.parse(&rest, &Spec::new("ether hello <mac>"))?;
            let spec = catalog::by_name("ping").unwrap();
            let t0 = Instant::now();
            let mut prep = run.prepare_plan(p.host.as_deref(), run.g.timeout.unwrap_or(10.0), Some(vec![Kind::Ether]))?;
            let r = prep.transport.call(spec, &[], &mut crate::NullIo)?;
            let role = prep.transport.role().map(|r| r.name()).unwrap_or("unknown");
            if run.g.json {
                let data = format!("{{\"role\":{},\"handshake_and_ping_ms\":{:.2},\"ping_ms\":{:.2}}}", crate::jv::quote(role), t0.elapsed().as_secs_f64() * 1000.0, r.rtt_ms);
                let e = ok_envelope("ether", Some(&prep.info), "ether.hello", Some(r.rtt_ms), &data);
                run.outln(&e);
            } else {
                run.outln(&format!("session open: role {}, handshake + first request {:.2} ms (request alone {:.2} ms)", role, t0.elapsed().as_secs_f64() * 1000.0, r.rtt_ms));
            }
            Ok(0)
        }
        "sniff" => ether_sniff(run, &rest),
        "frame" => {
            let p = run.parse(&rest, &Spec::new("ether frame <hex>").no_host().pos(1, 1))?;
            let bytes = labproto::crypto::unhex(&p.pos[0].replace([':', ' '], "")).ok_or_else(|| ClientError::Usage("not a hex string".into()))?;
            let text = decode_frame(&bytes, true).unwrap_or_else(|| "not a lab frame (ethertype 0x88B5/0x88B6)".to_string());
            run.outln(&text);
            Ok(0)
        }
        "replay" => {
            let p = run.parse(&rest, &Spec::new("ether replay <mac> NAME [args..]").pos(1, usize::MAX))?;
            std::env::set_var("I7LABCTL_TEST_REPLAY", "1");
            let name = p.pos[0].clone();
            let spec = crate::ether::raw_spec(&name)?;
            let timeout = run.g.timeout.unwrap_or(30.0);
            let mut prep = run.prepare_plan(p.host.as_deref(), timeout, Some(vec![Kind::Ether]))?;
            let r = prep.transport.call(spec, &p.pos[1..], &mut crate::NullIo)?;
            std::env::remove_var("I7LABCTL_TEST_REPLAY");
            let body = String::from_utf8_lossy(&r.body).into_owned();
            run.outln(&format!("replayed the captured REQ frames; status {}{}", r.status.name(), if body.trim().is_empty() { String::new() } else { format!(": {}", sanitize(body.trim())) }));
            Ok(r.status.cli_exit())
        }
        other => Err(ClientError::Usage(format!("ether: unknown verb '{}'\nusage: i7labctl ether cmds|probe|hello|sniff|frame|replay ...", other))),
    }
}

/// One-line (or detailed) description of a lab frame. Bodies are never shown.
pub fn decode_frame(buf: &[u8], detail: bool) -> Option<String> {
    let (eth, payload) = frame::eth_parse(buf)?;
    let tags: String = eth.tags.iter().map(|(tp, tci)| format!(" vlan {} (tpid {:04x}, prio {})", tci & 0x0fff, tp, tci >> 13)).collect();
    let head = format!("{} -> {}{} ethertype {:04x}", eth.src, eth.dst, tags, eth.ethertype);
    match eth.ethertype {
        frame::ETHERTYPE_BEACON => {
            let magic = String::from_utf8_lossy(&payload[..payload.len().min(5)]).into_owned();
            let mac = labproto::beacon::Beacon::parse(payload).ok().and_then(|b| b.get("mac").map(String::from)).unwrap_or_default();
            Some(format!("{} beacon {} mac={}", head, sanitize(&magic), sanitize(&mac)))
        }
        frame::ETHERTYPE_CTL => {
            let f = frame::open(payload).ok()?;
            let ty = FrameType::from_u8(f.hdr.ftype).map(|t| format!("{:?}", t)).unwrap_or_else(|| format!("type {}", f.hdr.ftype));
            let mut s = format!("{} ctl {} session {:08x} req {} ctr {} plen {}", head, ty, f.hdr.session, f.hdr.req_id, f.hdr.ctr, f.hdr.plen);
            if detail {
                s.push_str(&format!("\n    ver {} flags {:02x} chan {} cmd 0x{:04x} msg_len {} off {} win {} status {}", f.hdr.ver, f.hdr.flags, f.hdr.chan, f.hdr.cmd, f.hdr.msg_len, f.hdr.off, f.hdr.win, f.hdr.status));
            }
            Some(s)
        }
        _ => None,
    }
}

fn ether_sniff(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let p = run.parse(args, &Spec::new("ether sniff [--decode] [--count N] [-i IF] [--vlan N]").flags(&["decode"]).valued(&["count"]).no_host())?;
    let count = p.uint("count")?;
    let detail = p.opts.flag("decode");
    let mut set: LinkSet = run.env.connector.open_link(&run.g)?;
    let t0 = Instant::now();
    let limit = run.g.timeout.filter(|t| *t > 0.0).map(Duration::from_secs_f64);
    let mut buf = vec![0u8; 4096];
    let mut n = 0u64;
    loop {
        if limit.is_some_and(|l| t0.elapsed() >= l) || count.is_some_and(|c| n >= c) {
            break;
        }
        let Some(m) = set.link.recv(&mut buf, Duration::from_millis(100)).map_err(|e| ClientError::Transport(e.to_string()))? else { continue };
        let mut frame_bytes = buf[..m.len].to_vec();
        if let Some((tp, tci)) = m.aux_tag {
            // re-insert the kernel-stripped outer tag so the decode shows it
            if frame_bytes.len() >= 12 {
                let mut v = frame_bytes[..12].to_vec();
                v.extend_from_slice(&tp.to_be_bytes());
                v.extend_from_slice(&tci.to_be_bytes());
                v.extend_from_slice(&frame_bytes[12..]);
                frame_bytes = v;
            }
        }
        if let Some(line) = decode_frame(&frame_bytes, detail) {
            n += 1;
            if run.g.json {
                let e = format!("{{\"event\":\"frame\",\"iface\":{},\"text\":{}}}", crate::jv::quote(&set.iface_name(m.ifindex)), crate::jv::quote(&line));
                run.outln(&e);
            } else {
                let l = format!("{:>8.3} {} {}", t0.elapsed().as_secs_f64(), set.iface_name(m.ifindex), line);
                run.outln(&l);
            }
        }
    }
    Ok(0)
}

// ---------------------------------------------------------------- image, ssh, lab-boot, api

pub fn image(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let (verb, rest) = args.split_first().ok_or_else(|| ClientError::Usage("image needs a verb\nusage: i7labctl image build|write|bake|keys|test|info|verify ...".into()))?;
    if matches!(verb.as_str(), "info" | "verify") {
        return Err(ClientError::Unsupported(format!("image {} is planned (v0.2); check an image by booting it in scripts/qemu-test", verb)));
    }
    let script = wrap::image_script(verb).ok_or_else(|| ClientError::Usage(format!("image: unknown verb '{}' (build|write|bake|keys|test|info|verify)", verb)))?;
    let dir = run.env.scripts_dir.clone().ok_or_else(|| ClientError::Failed("cannot find the build scripts: run from the i7lablinux tree or set I7LABCTL_SCRIPTS=/path/to/scripts".into()))?;
    let path = dir.join(script);
    if !path.is_file() {
        return Err(ClientError::Failed(format!("{} does not exist", path.display())));
    }
    if verb == "write" && rest.first().is_none_or(|a| a.starts_with('-')) {
        return Err(ClientError::Usage("image write needs the target device first: i7labctl image write /dev/sdX [--serial SERIAL] ...".into()));
    }
    let status = Command::new(&path).args(rest).status().map_err(|e| ClientError::Failed(format!("cannot run {}: {}", path.display(), e)))?;
    Ok(status.code().unwrap_or(255))
}

pub fn ssh(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    // ssh [--user U] [--no-start] <host> [command..] [-- ssh-args..]: our options come first, everything after the
    // host belongs to ssh (so `ssh m900 uname -a` works) and is never parsed here.
    let usage = || ClientError::Usage("usage: i7labctl ssh <host> [--user U] [--no-start] [command..] [-- ssh-args..]".into());
    let mut extra: Vec<String> = Vec::new();
    let mut i = 0;
    // our options are recognised before the host and right after it, never inside the command
    let take_opts = |i: &mut usize, extra: &mut Vec<String>| -> Result<(), ClientError> {
        while *i < args.len() {
            match args[*i].as_str() {
                "--user" => {
                    let u = args.get(*i + 1).ok_or_else(usage)?;
                    extra.extend(["-l".to_string(), u.clone()]);
                    *i += 2;
                }
                "--no-start" => *i += 1,
                _ => break,
            }
        }
        Ok(())
    };
    take_opts(&mut i, &mut extra)?;
    let host = if run.g.host_by_flag() {
        None
    } else {
        let h = args.get(i).filter(|h| !h.starts_with('-')).ok_or_else(usage)?;
        i += 1;
        Some(h.clone())
    };
    take_opts(&mut i, &mut extra)?;
    let rest = &args[i.min(args.len())..];
    let (cmd, theirs): (&[String], &[String]) = match rest.iter().position(|a| a == "--") {
        Some(p) => (&rest[..p], &rest[p + 1..]),
        None => (rest, &[]),
    };
    // ssh's own options (after --) go before the destination, the command words after it
    extra.extend(theirs.iter().cloned());
    extra.extend(cmd.iter().cloned());
    ssh_exec(run, host.as_deref(), &extra, false)
}

/// Run the system ssh to the host's IP with pinned host keys; the exit status is ssh's.
pub fn ssh_exec(run: &mut Run, host: Option<&str>, extra: &[String], _interactive: bool) -> Result<i32, ClientError> {
    let mut g2 = run.g.clone();
    g2.transport = crate::opts::TransportPref::Auto;
    let t = {
        let saved = std::mem::replace(&mut run.g, g2);
        let r = run.target(host);
        run.g = saved;
        r?
    };
    if t.entry.as_ref().is_some_and(|e| e.mac_mismatch) {
        return Err(ClientError::Safety("the registry flags this host src-mac-mismatch (its beacon claims another MAC than it came from); not connecting".into()));
    }
    let ip = t.ip.clone().ok_or_else(|| ClientError::NoHost("ssh needs the host's IP address (set one with: i7labctl net set <host> IFACE --ip A.B.C.D/N)".into()))?;
    let home = run.env.home.clone();
    let known = home.join(".cache/i7labctl/known_hosts");
    if let Some(d) = known.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let ident = home.join(".config/i7labctl/ssh/operator_ed25519");
    let mut args = wrap::ssh_base_args(&known, ident.exists().then_some(ident.as_path()));
    let user_given = extra.iter().any(|a| a == "-l");
    if !user_given {
        let user = run.g.ssh.as_deref().and_then(|s| s.split_once('@')).map(|(u, _)| u.to_string()).filter(|u| !u.is_empty()).unwrap_or_else(|| "root".to_string());
        args.extend(["-l".to_string(), user]);
    }
    // options of the user's own (after --) precede the destination; the first non-option word and what follows is the command
    let mut opts_part: Vec<String> = Vec::new();
    let mut cmd_part: Vec<String> = Vec::new();
    let mut it = extra.iter().peekable();
    while let Some(a) = it.next() {
        if cmd_part.is_empty() && a.starts_with('-') {
            opts_part.push(a.clone());
            if matches!(a.as_str(), "-l" | "-p" | "-o" | "-i" | "-L" | "-R" | "-D" | "-J" | "-F") {
                if let Some(v) = it.next() {
                    opts_part.push(v.clone());
                }
            }
        } else {
            cmd_part.push(a.clone());
        }
    }
    args.extend(opts_part);
    args.push(ip);
    args.extend(cmd_part);
    let bin = run.env.ssh_bin.clone().unwrap_or_else(|| PathBuf::from("ssh"));
    let status = Command::new(&bin).args(&args).status().map_err(|e| ClientError::Failed(format!("cannot run {}: {}", bin.display(), e)))?;
    Ok(status.code().unwrap_or(255))
}

pub fn lab_boot(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let p = run.parse(args, &Spec::new("lab-boot --jetkvm HOST --image PATH [--mode cdrom|disk] [--wait S] [--mac MAC] [--dry-run]").flags(&["dry-run"]).valued(&["jetkvm", "image", "mode", "wait", "mac"]).no_host())?;
    let host = p.opts.value("jetkvm").ok_or_else(|| ClientError::Usage("lab-boot needs --jetkvm HOST (the hwlab host name)".into()))?.to_string();
    let image = PathBuf::from(p.opts.value("image").ok_or_else(|| ClientError::Usage("lab-boot needs --image PATH".into()))?);
    let mode = match p.opts.value("mode") {
        Some(m) => labboot::MediaMode::parse(m).ok_or_else(|| ClientError::Usage(format!("--mode must be cdrom or disk, got '{}'", m)))?,
        None => labboot::MediaMode::from_extension(&image),
    };
    let dry = p.opts.flag("dry-run");
    if !dry && !image.is_file() {
        return Err(ClientError::Usage(format!("image {} does not exist", image.display())));
    }
    let hw = labboot::hwlab_cmd(run.env.hwlab.as_deref());
    let plan = labboot::plan(&hw, &host, &image, mode)?;
    if dry {
        run.outln(&labboot::render(&plan));
        return Ok(0);
    }
    // which beacon means "it booted"? an explicit --mac, or an alias / registry entry named like the hwlab host
    let reg = run.registry();
    let macs: Vec<String> = match p.opts.value("mac") {
        Some(m) => vec![Mac::parse(m).ok_or_else(|| ClientError::Usage(format!("bad --mac '{}'", m)))?.to_string()],
        None => match hosts::resolve(&host, &reg, &run.aliases()) {
            Ok(hosts::Resolution::Entry(e)) => discover::sibling_macs(&e, &reg),
            Ok(hosts::Resolution::Mac(m)) => vec![m.to_string()],
            _ => return Err(ClientError::Usage(format!("cannot tell which beacon to wait for: add an alias '{} = <MAC>' to ~/.config/i7labctl/aliases or pass --mac MAC (nothing was changed)", host))),
        },
    };
    let secs = p.num("wait")?.unwrap_or(300.0);
    if !run.confirm(&format!("Power cycle hwlab host {} and boot it from {}?", host, image.display())) {
        return Err(ClientError::Safety("not confirmed".into()));
    }
    for c in &plan {
        run.note(&format!("i7labctl: running: {}", labboot::render(std::slice::from_ref(c))));
        let status = Command::new(&c[0]).args(&c[1..]).status().map_err(|e| ClientError::Failed(format!("cannot run {}: {} (set HWLAB to the hwlab CLI)", c[0], e)))?;
        if !status.success() {
            return Err(ClientError::Failed(format!("`{}` failed with {}; stopped before the next step", c.join(" "), status)));
        }
    }
    run.note("i7labctl: waiting for the host's beacon ...");
    wait_core(run, macs, WaitKind::Ready, None, secs, "lab-boot")
}

pub fn api(run: &mut Run, args: &[String]) -> Result<i32, ClientError> {
    let p = run.parse(args, &Spec::new("api <host> METHOD PATH [--data JSON|@file]").valued(&["data"]).pos(2, 2))?;
    let method = p.pos[0].to_ascii_uppercase();
    if !["GET", "POST", "PUT", "DELETE"].contains(&method.as_str()) {
        return Err(ClientError::Usage(format!("METHOD must be GET, POST, PUT or DELETE, got '{}'", p.pos[0])));
    }
    let path = p.pos[1].clone();
    if !path.starts_with('/') {
        return Err(ClientError::Usage(format!("PATH must start with '/', got '{}'", path)));
    }
    let body: Vec<u8> = match p.opts.value("data") {
        None => Vec::new(),
        Some(d) => match d.strip_prefix('@') {
            Some(f) => std::fs::read(f).map_err(|e| ClientError::Usage(format!("cannot read {}: {}", f, e)))?,
            None => d.as_bytes().to_vec(),
        },
    };
    let timeout = run.g.timeout.unwrap_or(30.0);
    let mut prep = run.prepare_plan(p.host.as_deref(), timeout, Some(vec![Kind::Http]))?;
    let (code, rbody) = prep.transport.raw(&method, &path, &body)?;
    let text = String::from_utf8_lossy(&rbody).into_owned();
    if run.g.json {
        let data = format!("{{\"status\":{},\"body\":{}}}", code, if output::looks_like_json(&text) { text.trim().to_string() } else { crate::jv::quote(&text) });
        let e = ok_envelope("http", Some(&prep.info), "api", None, &data);
        run.outln(&e);
    } else {
        run.err(&format!("HTTP {}", code));
        run.outln(&sanitize(text.trim_end()));
    }
    Ok(if (200..300).contains(&code) { 0 } else { 1 })
}
