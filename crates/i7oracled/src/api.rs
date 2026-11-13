//! HTTP API routing and handlers.
//!
//!   open  (no auth):  GET /  GET /health  GET /nonce
//!   ro or admin:      GET /info  GET /sample  GET /events?since=SEQ[&limit=N]  GET /results  GET /results/<file>  GET /probes
//!   admin only:       POST /run  POST /power  POST /powercfg  POST /sweep
//! Paths may also carry the i7labd prefix `/api/v1`.

use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::auth::{self, AuthError, Authed};
use crate::evlog::{self, json_str};
use crate::exec;
use crate::httpd::{Request, Response};
use crate::json::{self, JsonWriter, Limits, Value};
use crate::keys::Role;
use crate::power;
use crate::powercfg;
use crate::stamp::{filetime_compact, Stamp};
use crate::state::{lock, Shared};

pub fn handle(sh: &Arc<Shared>, req: &Request, peer: IpAddr) -> Response {
    let method = if req.method == "HEAD" { "GET" } else { req.method.as_str() };
    let path = req.path.strip_prefix("/api/v1").filter(|p| p.starts_with('/')).unwrap_or(&req.path);
    let path = if path.len() > 1 { path.trim_end_matches('/') } else { path };

    match (method, path) {
        ("GET", "/" | "/health") => return health(sh),
        ("GET", "/nonce") => {
            let n = lock(&sh.nonces).issue(Instant::now());
            return match n {
                Ok(n) => Response::json(200, format!("{{\"nonce\":\"{}\",\"ttl_s\":{}}}", n, auth::NONCE_TTL.as_secs())),
                Err(_) => Response::error(500, "no randomness"),
            };
        }
        _ => {}
    }

    let authed = {
        let hdr = |k: &str| req.header(k);
        let r = auth::authenticate(&sh.keys, &mut lock(&sh.nonces), &mut lock(&sh.guard), peer, &req.method, &req.target, &req.body, &hdr, Instant::now());
        match r {
            Ok(a) => a,
            Err(e) => {
                return match e {
                    AuthError::Locked => Response::error(429, "too many failed attempts: address locked for up to 60 s"),
                    AuthError::Missing => Response::error(401, "authentication required (X-Lab-Key, X-Lab-Nonce, X-Lab-Auth)"),
                    AuthError::BadKey => Response::error(401, "unknown key id"),
                    AuthError::BadNonce => Response::error(401, "nonce unknown, expired or already used"),
                    AuthError::BadMac => Response::error(401, "bad request signature"),
                }
            }
        }
    };
    let mut resp = route(sh, req, method, path, &authed);
    resp.proof = Some(auth::proof(&authed, resp.status, &resp.body));
    resp
}

fn route(sh: &Arc<Shared>, req: &Request, method: &str, path: &str, a: &Authed) -> Response {
    let need_admin = |f: &dyn Fn() -> Response| if a.role == Role::Admin { f() } else { Response::error(403, "admin key required") };
    match (method, path) {
        ("GET", "/info") => Response::json(200, info(sh)),
        ("GET", "/sample") => Response::json(200, format!("{{\"ok\":true,\"sample\":{}}}", crate::plat::sample_json())),
        ("GET", "/events") => events(sh, req),
        ("GET", "/results") => list_results(sh),
        ("GET", "/probes") => list_probes(sh),
        ("GET", p) if p.starts_with("/results/") => get_result(sh, &p["/results/".len()..]),
        ("POST", "/run") => need_admin(&|| run(sh, req)),
        ("POST", "/power") => need_admin(&|| power_req(sh, req)),
        ("POST", "/powercfg") => need_admin(&|| powercfg_req(sh, req)),
        ("POST", "/sweep") => need_admin(&|| sweep_req(sh)),
        (_, "/info" | "/sample" | "/events" | "/results" | "/probes" | "/run" | "/power" | "/powercfg" | "/sweep") => Response::error(405, "method not allowed"),
        _ => Response::error(404, "no such route"),
    }
}

fn health(sh: &Arc<Shared>) -> Response {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_bool("ok", true);
    w.field_str("service", "i7oracled");
    w.field_str("version", env!("CARGO_PKG_VERSION"));
    w.field_str("mode", sh.mode.name());
    w.field_str("host", &crate::plat::hostname());
    w.field_str("boot", &sh.boot_id);
    w.field_u64("up_s", sh.started.elapsed().as_secs());
    w.field_u64("seq", sh.last_seq());
    w.field_str("kid", &sh.keys.kid_summary());
    w.end_object();
    Response::json(200, w.finish())
}

fn info(sh: &Arc<Shared>) -> String {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_bool("ok", true);
    w.field_str("version", env!("CARGO_PKG_VERSION"));
    w.field_str("mode", sh.mode.name());
    w.field_str("boot", &sh.boot_id);
    w.field_u64("seq", sh.last_seq());
    w.field_u64("suspends_seen", sh.counters.suspends.load(Ordering::Relaxed));
    w.field_u64("resumes_seen", sh.counters.resumes.load(Ordering::Relaxed));
    w.field_u64("runs", sh.counters.runs.load(Ordering::Relaxed));
    w.key("machine");
    w.raw(&crate::plat::info_json());
    w.end_object();
    w.finish()
}

fn num(req: &Request, key: &str, default: u64, max: u64) -> Result<u64, String> {
    match req.q(key) {
        None | Some("") => Ok(default),
        Some(s) => s.parse::<u64>().map(|n| n.min(max)).map_err(|_| format!("{} must be a non-negative integer", key)),
    }
}

fn events(sh: &Arc<Shared>, req: &Request) -> Response {
    let (since, limit) = match (num(req, "since", 0, u64::MAX), num(req, "limit", 500, 5000)) {
        (Ok(s), Ok(l)) => (s, l as usize),
        (Err(e), _) | (_, Err(e)) => return Response::error(400, &e),
    };
    match evlog::read_since(&sh.cfg.events_path(), since, limit, 4 << 20) {
        Ok((lines, last)) => {
            let body = format!(
                "{{\"ok\":true,\"boot\":{},\"mode\":{},\"last_seq\":{},\"count\":{},\"next\":{},\"events\":[{}]}}",
                json_str(&sh.boot_id),
                json_str(sh.mode.name()),
                sh.last_seq(),
                lines.len(),
                last,
                lines.join(",")
            );
            Response::json(200, body)
        }
        Err(e) => Response::error(500, &e.to_string()),
    }
}

fn list_results(sh: &Arc<Shared>) -> Response {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_bool("ok", true);
    w.key("results");
    w.begin_array();
    for (n, s) in exec::list_results(&sh.cfg.results_dir()).into_iter().take(2000) {
        w.begin_object();
        w.field_str("name", &n);
        w.field_u64("size", s);
        w.end_object();
    }
    w.end_array();
    w.end_object();
    Response::json(200, w.finish())
}

fn list_probes(sh: &Arc<Shared>) -> Response {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_bool("ok", true);
    w.key("probes");
    w.begin_array();
    for n in exec::list_probes(&sh.cfg.probes_dir(), false) {
        w.str(&n);
    }
    w.end_array();
    w.end_object();
    Response::json(200, w.finish())
}

fn get_result(sh: &Arc<Shared>, name: &str) -> Response {
    match exec::read_result(&sh.cfg.results_dir(), name) {
        Ok(b) => Response { status: 200, ctype: if name.ends_with(".html") { "text/html; charset=utf-8" } else { "text/plain; charset=utf-8" }, body: b, proof: None },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Response::error(404, "no such result"),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => Response::error(400, "bad file name"),
        Err(e) => Response::error(500, &e.to_string()),
    }
}

fn parse_body(req: &Request) -> Result<Value, Response> {
    let text = std::str::from_utf8(&req.body).map_err(|_| Response::error(400, "body is not utf-8"))?;
    json::parse(text, &Limits::default()).map_err(|e| Response::error(400, &format!("bad json: {} at {}", e.msg, e.offset)))
}

fn run(sh: &Arc<Shared>, req: &Request) -> Response {
    let v = match parse_body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(name) = v.get("name").and_then(Value::as_str) else { return Response::error(400, "name required") };
    let mut args = Vec::new();
    match v.get("args") {
        None | Some(Value::Null) => {}
        Some(Value::Arr(a)) => {
            for x in a {
                match x.as_str() {
                    Some(s) => args.push(s.to_string()),
                    None => return Response::error(400, "args must be strings"),
                }
            }
        }
        Some(_) => return Response::error(400, "args must be an array of strings"),
    }
    let timeout = match v.get("timeout_s") {
        None | Some(Value::Null) => 60,
        Some(x) => match x.as_u64().filter(|n| (1..=7200).contains(n)) {
            Some(n) => n,
            None => return Response::error(400, "timeout_s must be 1..7200"),
        },
    };
    let is_async = matches!(v.get("async"), Some(Value::Bool(true)));
    if is_async {
        // validate synchronously, run in the background; poll /events (run_end) and /results
        if !exec::valid_probe_name(name) || !sh.cfg.probes_dir().join(name).is_file() {
            return Response::error(404, "no such probe");
        }
        let (sh2, name2) = (sh.clone(), name.to_string());
        std::thread::spawn(move || {
            let _ = crate::jobs::run_probe(&sh2, "api", &name2, &args, Duration::from_secs(timeout));
        });
        return Response::json(202, format!("{{\"ok\":true,\"async\":true,\"name\":{},\"note\":\"poll GET /events for run_end, then GET /results\"}}", json_str(name)));
    }
    match crate::jobs::run_probe(sh, "api", name, &args, Duration::from_secs(timeout)) {
        Ok(o) => Response::json(200, o.json(true)),
        Err(e) => Response::error(if e.starts_with("no such") { 404 } else { 400 }, &e),
    }
}

fn power_req(sh: &Arc<Shared>, req: &Request) -> Response {
    let pr = match power::parse_power_req(&req.body) {
        Ok(p) => p,
        Err(e) => return Response::error(400, &e),
    };
    if !crate::plat::power_supported() {
        return Response::error(501, "power actions are only implemented on Windows");
    }
    let detail = format!(
        "{{\"action\":{},\"wake_after_s\":{},\"wake_method\":{},\"delay_s\":{},\"seq_before\":{}}}",
        json_str(pr.action.name()),
        pr.wake_after_s.map(|n| n.to_string()).unwrap_or_else(|| "null".into()),
        json_str(match pr.wake_method {
            power::WakeMethod::Timer => "timer",
            power::WakeMethod::Task => "task",
            power::WakeMethod::Both => "both",
        }),
        pr.delay_s,
        sh.last_seq()
    );
    let seq = sh.emit("api", "power_request", &detail);
    let sh2 = sh.clone();
    let prc = pr.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(prc.delay_s));
        match crate::plat::power_action(&sh2, &prc) {
            Ok(note) => {
                sh2.emit("api", "power_returned", &format!("{{\"action\":{},\"note\":{}}}", json_str(prc.action.name()), json_str(&note)));
            }
            Err(e) => {
                sh2.emit("api", "power_error", &format!("{{\"action\":{},\"error\":{}}}", json_str(prc.action.name()), json_str(&e)));
            }
        }
    });
    Response::json(202, format!("{{\"ok\":true,\"action\":{},\"executes_in_s\":{},\"wake_after_s\":{},\"request_seq\":{},\"note\":\"poll GET /events?since={}; the connection may drop while the machine sleeps\"}}", json_str(pr.action.name()), pr.delay_s, pr.wake_after_s.map(|n| n.to_string()).unwrap_or_else(|| "null".into()), seq, seq.saturating_sub(1)))
}

fn powercfg_req(sh: &Arc<Shared>, req: &Request) -> Response {
    let stamp = filetime_compact(Stamp::now().wall_100ns);
    let results = sh.cfg.results_dir();
    let cmds = match powercfg::plan(&req.body, &results, &stamp) {
        Ok(c) => c,
        Err(e) => return Response::error(400, &e),
    };
    let _ = std::fs::create_dir_all(&results);
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_bool("ok", true);
    w.key("commands");
    w.begin_array();
    for c in &cmds {
        let r = exec::exec_capture(c.program, &c.args, None, Duration::from_secs(600), 1 << 20);
        w.begin_object();
        w.field_str("program", c.program);
        w.key("args");
        w.begin_array();
        for a in &c.args {
            w.str(a);
        }
        w.end_array();
        w.field_opt_str("spawn_error", r.spawn_error.as_deref());
        match r.exit {
            Some(x) => w.field_i64("exit_code", x as i64),
            None => w.field_opt_u64("exit_code", None),
        }
        w.field_bool("timed_out", r.timed_out);
        w.field_str("output", &exec::lossy(&r.stdout));
        w.field_str("stderr", &exec::lossy(&r.stderr));
        w.field_opt_str("saved_as", c.output_file.as_deref());
        w.end_object();
    }
    w.end_array();
    w.end_object();
    let body = w.finish();
    sh.emit("api", "powercfg", &format!("{{\"request\":{},\"commands\":{}}}", json_str(&String::from_utf8_lossy(&req.body)), cmds.len()));
    Response::json(200, body)
}

fn sweep_req(sh: &Arc<Shared>) -> Response {
    let sh2 = sh.clone();
    std::thread::spawn(move || {
        let s = crate::jobs::sweep(&sh2, "api", Duration::from_secs(sh2.cfg.sweep_timeout_s));
        crate::jobs::hello_collector(&sh2, &s);
    });
    Response::json(202, "{\"ok\":true,\"note\":\"sweep started; poll GET /events for sweep_end\"}".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::crypto;
    use crate::httpauth;
    use crate::keys::{Key, KeySet};
    use crate::state::Mode;

    const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));

    fn shared(tag: &str) -> Arc<Shared> {
        let d = std::env::temp_dir().join(format!("i7oracled-api-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("o")).unwrap();
        let cfg = Config::with_dirs(d.join("o"), d.join("d"));
        let keys = KeySet { admin: Some(Key { role: Role::Admin, bytes: [1; 32] }), ro: Some(Key { role: Role::Ro, bytes: [2; 32] }) };
        Arc::new(Shared::new(cfg, keys, Mode::Console).unwrap())
    }

    fn req(method: &str, target: &str, headers: Vec<(String, String)>, body: &[u8]) -> Request {
        let (path, q) = target.split_once('?').unwrap_or((target, ""));
        Request { method: method.into(), target: target.into(), path: path.into(), query: crate::httpd::parse_query(q), headers, body: body.to_vec() }
    }

    fn signed(sh: &Arc<Shared>, key: &Key, method: &str, target: &str, body: &[u8]) -> (Response, String) {
        let nonce = {
            let r = handle(sh, &req("GET", "/nonce", vec![], b""), IP);
            let v = json::parse(std::str::from_utf8(&r.body).unwrap(), &Limits::default()).unwrap();
            v.get("nonce").unwrap().as_str().unwrap().to_string()
        };
        let mac = crypto::hex(&httpauth::request_mac(&key.bytes, &nonce, method, target, body));
        let h = vec![("x-lab-key".to_string(), key.fingerprint()), ("x-lab-nonce".to_string(), nonce.clone()), ("x-lab-auth".to_string(), mac)];
        (handle(sh, &req(method, target, h, body), IP), nonce)
    }

    #[test]
    fn open_endpoints() {
        let sh = shared("open");
        let r = handle(&sh, &req("GET", "/health", vec![], b""), IP);
        assert_eq!(r.status, 200);
        assert!(String::from_utf8_lossy(&r.body).contains("\"service\":\"i7oracled\""));
        assert!(r.proof.is_none());
        assert_eq!(handle(&sh, &req("GET", "/api/v1/health", vec![], b""), IP).status, 200);
        assert_eq!(handle(&sh, &req("GET", "/events", vec![], b""), IP).status, 401);
    }

    #[test]
    fn signed_events_with_proof_and_roles() {
        let sh = shared("events");
        sh.emit("t", "a", "{}");
        sh.emit("t", "b", "{}");
        let ro = sh.keys.ro.clone().unwrap();
        let (r, nonce) = signed(&sh, &ro, "GET", "/events?since=1", b"");
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let v = json::parse(std::str::from_utf8(&r.body).unwrap(), &Limits::default()).unwrap();
        assert_eq!(v.get("count").unwrap().as_u64(), Some(1));
        assert_eq!(v.get("next").unwrap().as_u64(), Some(2));
        assert_eq!(v.get("events").unwrap().as_array().unwrap()[0].get("kind").unwrap().as_str(), Some("b"));
        // the proof is the labproto response MAC over (nonce,status,body)
        let want = crypto::hex(&httpauth::response_mac(&ro.bytes, &nonce, 200, &r.body));
        assert_eq!(r.proof.as_deref(), Some(want.as_str()));
        // ro cannot POST
        let (r, _) = signed(&sh, &ro, "POST", "/power", br#"{"action":"sleep"}"#);
        assert_eq!(r.status, 403);
        // admin can reach validation
        let ad = sh.keys.admin.clone().unwrap();
        let (r, _) = signed(&sh, &ad, "POST", "/power", br#"{"action":"explode"}"#);
        assert_eq!(r.status, 400);
        // path with the i7labd prefix
        let (r, _) = signed(&sh, &ro, "GET", "/api/v1/results", b"");
        assert_eq!(r.status, 200);
        let (r, _) = signed(&sh, &ro, "GET", "/nothing", b"");
        assert_eq!(r.status, 404);
        let (r, _) = signed(&sh, &ro, "GET", "/events?since=x", b"");
        assert_eq!(r.status, 400);
    }

    #[test]
    fn body_tamper_and_replay_rejected() {
        let sh = shared("tamper");
        let ad = sh.keys.admin.clone().unwrap();
        let nonce = {
            let r = handle(&sh, &req("GET", "/nonce", vec![], b""), IP);
            json::parse(std::str::from_utf8(&r.body).unwrap(), &Limits::default()).unwrap().get("nonce").unwrap().as_str().unwrap().to_string()
        };
        let mac = crypto::hex(&httpauth::request_mac(&ad.bytes, &nonce, "POST", "/run", br#"{"name":"a.exe"}"#));
        let h = vec![("x-lab-key".to_string(), ad.fingerprint()), ("x-lab-nonce".to_string(), nonce), ("x-lab-auth".to_string(), mac)];
        let r = handle(&sh, &req("POST", "/run", h.clone(), br#"{"name":"b.exe"}"#), IP);
        assert_eq!(r.status, 401);
        let r = handle(&sh, &req("POST", "/run", h, br#"{"name":"a.exe"}"#), IP);
        assert_eq!(r.status, 401, "nonce was consumed by the failed attempt");
    }

    #[cfg(unix)]
    #[test]
    fn run_and_results_flow() {
        use std::os::unix::fs::PermissionsExt;
        let sh = shared("run");
        std::fs::create_dir_all(sh.cfg.probes_dir()).unwrap();
        let p = sh.cfg.probes_dir().join("hello_probe.exe");
        std::fs::write(&p, "#!/bin/sh\necho hello $1\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        let ad = sh.keys.admin.clone().unwrap();
        let (r, _) = signed(&sh, &ad, "POST", "/run", br#"{"name":"hello_probe.exe","args":["w"],"timeout_s":10}"#);
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let v = json::parse(std::str::from_utf8(&r.body).unwrap(), &Limits::default()).unwrap();
        assert_eq!(v.get("stdout").unwrap().as_str(), Some("hello w\n"));
        let saved = v.get("saved_as").unwrap().as_str().unwrap().to_string();
        let ro = sh.keys.ro.clone().unwrap();
        let (r, _) = signed(&sh, &ro, "GET", &format!("/results/{}", saved), b"");
        assert_eq!(r.status, 200);
        assert!(String::from_utf8_lossy(&r.body).contains("hello w"));
        let (r, _) = signed(&sh, &ro, "GET", "/results/..%2Fsecret", b"");
        assert_eq!(r.status, 400);
        let (r, _) = signed(&sh, &ad, "POST", "/run", br#"{"name":"..\\evil.exe"}"#);
        assert_eq!(r.status, 400);
        let (r, _) = signed(&sh, &ad, "POST", "/run", br#"{"name":"nothere.exe"}"#);
        assert_eq!(r.status, 404);
        // power is refused cleanly off Windows
        let (r, _) = signed(&sh, &ad, "POST", "/power", br#"{"action":"sleep","wake_after_s":20}"#);
        assert_eq!(r.status, 501);
    }
}
