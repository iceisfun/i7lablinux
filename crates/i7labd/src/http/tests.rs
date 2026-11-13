//! HTTP server tests: a real server on a loopback socket, a hand-written client that signs requests exactly as
//! docs/WEB.md says, and checks of every proof, trailer and event MAC.

use super::*;
use crate::registry::tests_support::test_daemon;
use labproto::keys::{Key, KeySet};
use std::io::{Read, Write};

const ADMIN: [u8; 32] = [1; 32];
const RO: [u8; 32] = [2; 32];

struct Server {
    daemon: Arc<Daemon>,
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<io::Result<()>>>,
}

impl Server {
    fn start() -> Server {
        let daemon = test_daemon();
        *daemon.keys.write().unwrap() = KeySet { admin: Some(Key { role: Role::Admin, bytes: ADMIN }), ro: Some(Key { role: Role::Ro, bytes: RO }) };
        daemon.set_state("ready");
        let daemon = Arc::new(daemon);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (d, s) = (daemon.clone(), stop.clone());
        let handle = Some(std::thread::spawn(move || serve_listener(d, l, s)));
        Server { daemon, addr, stop, handle }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let _ = std::fs::remove_dir_all(&self.daemon.config.run_dir);
    }
}

#[derive(Debug)]
struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    trailers: Vec<(String, String)>,
    chunked: bool,
}

impl Resp {
    fn h(&self, n: &str) -> Option<&str> {
        self.headers.iter().chain(self.trailers.iter()).find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.as_str())
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn read_line(r: &mut impl BufRead) -> String {
    let mut s = String::new();
    r.read_line(&mut s).unwrap();
    s.trim_end().to_string()
}

fn read_resp(s: TcpStream) -> Resp {
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut r = BufReader::new(s);
    let status_line = read_line(&mut r);
    let status: u16 = status_line.split(' ').nth(1).unwrap_or("0").parse().unwrap_or(0);
    let mut headers = Vec::new();
    loop {
        let l = read_line(&mut r);
        if l.is_empty() {
            break;
        }
        let (k, v) = l.split_once(':').unwrap();
        headers.push((k.to_string(), v.trim().to_string()));
    }
    let mut resp = Resp { status, headers, body: vec![], trailers: vec![], chunked: false };
    if resp.h("transfer-encoding") == Some("chunked") {
        resp.chunked = true;
        loop {
            let size = read_line(&mut r);
            if size.is_empty() && r.fill_buf().map(|b| b.is_empty()).unwrap_or(true) {
                break; // truncated stream
            }
            let n = usize::from_str_radix(&size, 16).unwrap();
            if n == 0 {
                loop {
                    let l = read_line(&mut r);
                    if l.is_empty() {
                        break;
                    }
                    let (k, v) = l.split_once(':').unwrap();
                    resp.trailers.push((k.to_string(), v.trim().to_string()));
                }
                break;
            }
            let mut buf = vec![0u8; n];
            r.read_exact(&mut buf).unwrap();
            resp.body.extend_from_slice(&buf);
            read_line(&mut r);
        }
    } else if let Some(n) = resp.h("content-length").and_then(|v| v.parse::<usize>().ok()) {
        resp.body = vec![0u8; n];
        r.read_exact(&mut resp.body).unwrap();
    }
    resp
}

fn raw(addr: SocketAddr, bytes: &[u8]) -> Resp {
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(bytes).unwrap();
    read_resp(s)
}

fn get_nonce(addr: SocketAddr) -> String {
    let r = raw(addr, b"GET /api/v1/nonce HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    assert_eq!(r.status, 200);
    let t = r.text();
    t.split('"').nth(3).unwrap().to_string()
}

struct Signed {
    resp: Resp,
    nonce: String,
}

fn kid(key: &[u8; 32], role: Role) -> String {
    hex(&Key { role, bytes: *key }.key_id())
}

fn signed_with(addr: SocketAddr, key: &[u8; 32], role: Role, method: &str, target: &str, body: &[u8], extra: &str) -> Signed {
    let nonce = get_nonce(addr);
    let mac = hex(&httpauth::request_mac(key, &nonce, method, target, body));
    let req = format!(
        "{} {} HTTP/1.1\r\nHost: t\r\nConnection: close\r\nX-Lab-Key: {}\r\nX-Lab-Nonce: {}\r\nX-Lab-Auth: {}\r\nContent-Length: {}\r\n{}\r\n",
        method, target, kid(key, role), nonce, mac, body.len(), extra
    );
    let mut bytes = req.into_bytes();
    bytes.extend_from_slice(body);
    Signed { resp: raw(addr, &bytes), nonce }
}

fn admin(addr: SocketAddr, method: &str, target: &str, body: &[u8]) -> Signed {
    signed_with(addr, &ADMIN, Role::Admin, method, target, body, "")
}

fn ro(addr: SocketAddr, method: &str, target: &str, body: &[u8]) -> Signed {
    signed_with(addr, &RO, Role::Ro, method, target, body, "")
}

fn check_proof(s: &Signed, key: &[u8; 32]) {
    let want = hex(&httpauth::response_mac(key, &s.nonce, s.resp.status, &s.resp.body));
    assert_eq!(s.resp.h("x-lab-proof"), Some(want.as_str()), "response proof ({} {})", s.resp.status, s.resp.text());
}

#[test]
fn open_endpoints_and_spa_csp() {
    let s = Server::start();
    let r = raw(s.addr, b"GET /api/v1/hello HTTP/1.1\r\nConnection: close\r\n\r\n");
    assert_eq!(r.status, 200);
    assert!(r.text().contains("\"name\":\"i7labd\"") && r.text().contains("\"state\":\"ready\""), "{}", r.text());
    assert_eq!(raw(s.addr, b"GET /health HTTP/1.1\r\nConnection: close\r\n\r\n").status, 200);
    let r = raw(s.addr, b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n");
    assert_eq!(r.status, 200);
    let csp = r.h("content-security-policy").unwrap();
    assert!(!r.text().contains(crate::web::NONCE_TOKEN), "every script nonce placeholder is replaced");
    assert!(csp.contains(&format!("'nonce-{}'", r.text().split("nonce=\"").nth(1).unwrap().split('"').next().unwrap())), "scripts carry the nonce of the CSP header");
    assert!(csp.contains("script-src 'nonce-") && csp.contains("default-src 'self'"), "{}", csp);
    assert!(r.text().contains("<title>i7lablinux</title>"));
    assert_eq!(r.h("x-content-type-options"), Some("nosniff"));
    // nonces are single use and unique
    assert_ne!(get_nonce(s.addr), get_nonce(s.addr));
    assert_eq!(raw(s.addr, b"GET /nope HTTP/1.1\r\nConnection: close\r\n\r\n").status, 404);
}

#[test]
fn signed_get_works_and_response_is_proven() {
    let s = Server::start();
    let r = admin(s.addr, "GET", "/api/v1/probe/system", b"");
    assert_eq!(r.resp.status, 200, "{}", r.resp.text());
    assert!(r.resp.text().contains("\"system\""));
    check_proof(&r, &ADMIN);
    let r = raw(s.addr, b"GET /api/v1/openapi.json HTTP/1.1\r\nConnection: close\r\n\r\n");
    assert_eq!(r.status, 200);
    assert!(r.text().contains("/api/v1/cmd/blk.write") && r.text().contains("\"x-planned\":true"));
    let r = ro(s.addr, "GET", "/api/v1/probe", b"");
    assert!(r.resp.text().contains("\"pci\""));
    let r = ro(s.addr, "GET", "/api/v1/overview", b"");
    assert_eq!(r.resp.status, 200);
    assert_eq!(ro(s.addr, "GET", "/api/v1/nothing", b"").resp.status, 404);
    let r = ro(s.addr, "GET", "/api/v1/net?a=nosuchif0", b"");
    assert_eq!(r.resp.status, 404, "alias with argv from ?a=: {}", r.resp.text());
}

#[test]
fn authentication_failures() {
    let s = Server::start();
    // no headers
    assert_eq!(raw(s.addr, b"GET /api/v1/probe HTTP/1.1\r\nConnection: close\r\n\r\n").status, 401);
    // wrong key bytes
    assert_eq!(signed_with(s.addr, &[9; 32], Role::Admin, "GET", "/api/v1/probe", b"", "").resp.status, 401);
    // MAC over another target
    let nonce = get_nonce(s.addr);
    let mac = hex(&httpauth::request_mac(&ADMIN, &nonce, "GET", "/api/v1/probe/cpu", b""));
    let req = format!("GET /api/v1/probe/mem HTTP/1.1\r\nConnection: close\r\nX-Lab-Key: {}\r\nX-Lab-Nonce: {}\r\nX-Lab-Auth: {}\r\n\r\n", kid(&ADMIN, Role::Admin), nonce, mac);
    assert_eq!(raw(s.addr, req.as_bytes()).status, 401, "target is bound");
    // body is bound
    let nonce = get_nonce(s.addr);
    let mac = hex(&httpauth::request_mac(&ADMIN, &nonce, "POST", "/api/v1/cmd/ping", b"{\"args\":[]}"));
    let req = format!("POST /api/v1/cmd/ping HTTP/1.1\r\nConnection: close\r\nX-Lab-Key: {}\r\nX-Lab-Nonce: {}\r\nX-Lab-Auth: {}\r\nContent-Length: 11\r\n\r\n{{\"args\":[]}}", kid(&ADMIN, Role::Admin), nonce, mac);
    assert_eq!(raw(s.addr, req.as_bytes()).status, 200);
    let req2 = req.replace("{\"args\":[]}", "{\"args\":[1]}");
    assert_eq!(raw(s.addr, req2.as_bytes()).status, 401);
    // replay of a captured request with a used nonce
    assert_eq!(raw(s.addr, req.as_bytes()).status, 401, "nonce is single use");
    assert!(s.daemon.stats.http_auth_fail.load(Ordering::Relaxed) >= 4);
}

#[test]
fn failures_lock_the_address() {
    let s = Server::start();
    for _ in 0..FAIL_LIMIT {
        raw(s.addr, b"GET /api/v1/probe HTTP/1.1\r\nConnection: close\r\n\r\n");
    }
    let r = admin(s.addr, "GET", "/api/v1/probe", b"");
    assert_eq!(r.resp.status, 429, "a correct request from the locked address is refused too");
}

#[test]
fn fail_table_window() {
    let mut t = FailTable::default();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    let t0 = Instant::now();
    for _ in 0..FAIL_LIMIT - 1 {
        t.failed(ip, t0);
    }
    assert!(!t.locked(ip, t0));
    t.failed(ip, t0);
    assert!(t.locked(ip, t0 + Duration::from_secs(30)));
    assert!(!t.locked(ip, t0 + FAIL_WINDOW + Duration::from_secs(1)), "lock expires");
    t.failed(ip, t0);
    t.ok(ip);
    assert!(!t.locked(ip, t0));
}

#[test]
fn commands_and_role_enforcement() {
    let s = Server::start();
    let r = ro(s.addr, "POST", "/api/v1/cmd/ping", b"{\"args\":[\"hello\"]}");
    assert_eq!(r.resp.status, 200);
    assert!(r.resp.text().contains("\"echo\":\"hello\""));
    check_proof(&r, &RO);
    let r = ro(s.addr, "POST", "/api/v1/cmd/reboot", b"{}");
    assert_eq!(r.resp.status, 403, "ro key: {}", r.resp.text());
    assert!(r.resp.text().contains("EPERM"));
    assert_eq!(admin(s.addr, "POST", "/api/v1/cmd/nosuchcmd", b"{}").resp.status, 404);
    assert_eq!(admin(s.addr, "POST", "/api/v1/cmd/ping", b"not json").resp.status, 400);
    assert_eq!(admin(s.addr, "POST", "/api/v1/cmd/ping", b"{\"args\":[1]}").resp.status, 400);
    assert_eq!(admin(s.addr, "POST", "/api/v1/cmd/kexec", b"{\"args\":[\"--kernel\",\"/x\"]}").resp.status, 501);
    // path policy through HTTP: key material is denied even to admin
    let r = admin(s.addr, "POST", "/api/v1/cmd/get", b"{\"args\":[\"/etc/i7lab/keys/admin.key\"]}");
    assert_eq!(r.resp.status, 403);
    // admin ran something: audit line exists
    admin(s.addr, "POST", "/api/v1/cmd/time.set", b"{\"args\":[\"1800000000\"]}");
    assert!(s.daemon.audit.recent(5).iter().any(|l| l.contains("cmd=time.set") && l.contains("http 127.0.0.1")));
}

#[test]
fn exec_non_stream_returns_an_envelope() {
    let s = Server::start();
    let r = admin(s.addr, "POST", "/api/v1/cmd/exec", b"{\"args\":[\"--\",\"/bin/sh\",\"-c\",\"echo out; echo err >&2; exit 3\"]}");
    assert_eq!(r.resp.status, 200, "{}", r.resp.text());
    let t = r.resp.text();
    assert!(t.contains("\"exit\":3") && t.contains("\"stdout\":\"out\\n\"") && t.contains("\"stderr\":\"err\\n\""), "{}", t);
    check_proof(&r, &ADMIN);
    let r = admin(s.addr, "POST", "/api/v1/exec", b"{\"args\":[\"--\",\"/bin/echo\",\"alias\"]}");
    assert!(r.resp.text().contains("alias"));
}

#[test]
fn ndjson_stream_events_are_sealed() {
    let s = Server::start();
    let r = admin(s.addr, "POST", "/api/v1/cmd/exec?stream=1", b"{\"args\":[\"--\",\"/bin/sh\",\"-c\",\"echo one; echo two >&2\"]}");
    assert_eq!(r.resp.status, 200);
    assert!(r.resp.chunked);
    let lines: Vec<String> = r.resp.text().lines().map(str::to_string).collect();
    assert!(lines.len() >= 3, "{:?}", lines);
    for (i, l) in lines.iter().enumerate() {
        let (seq, _) = verify_event(&ADMIN, &r.nonce, l).unwrap_or_else(|| panic!("bad event mac: {}", l));
        assert_eq!(seq, i as u64, "no gaps");
    }
    assert!(lines.iter().any(|l| l.contains("\"event\":\"stdout\"") && l.contains("one")));
    assert!(lines.iter().any(|l| l.contains("\"event\":\"stderr\"") && l.contains("two")));
    let last = lines.last().unwrap();
    assert!(last.contains("\"event\":\"result\"") && last.contains("\"exit\":0") && last.contains("\"ok\":true"), "{}", last);
    // a tampered line fails verification
    let one = lines.iter().find(|l| l.contains("one")).unwrap();
    assert!(verify_event(&ADMIN, &r.nonce, &one.replace("one", "uno")).is_none());
}

#[test]
fn file_upload_download_with_proofs() {
    let s = Server::start();
    let dir = s.daemon.config.run_dir.join("web");
    let path = dir.join("x.bin");
    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let sha = labproto::crypto::sha256(&data);
    let target = format!("/api/v1/file?path={}&mode=0640&mkdirs=1", path.display());
    let nonce = get_nonce(s.addr);
    let mac = hex(&httpauth::request_mac_hashed(&ADMIN, &nonce, "PUT", &target, &sha));
    let head = format!("PUT {} HTTP/1.1\r\nConnection: close\r\nX-Lab-Key: {}\r\nX-Lab-Nonce: {}\r\nX-Lab-Auth: {}\r\nX-Lab-Body-Sha256: {}\r\nContent-Length: {}\r\n\r\n", target, kid(&ADMIN, Role::Admin), nonce, mac, hex(&sha), data.len());
    let mut req = head.into_bytes();
    req.extend_from_slice(&data);
    let r = raw(s.addr, &req);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(std::fs::read(&path).unwrap(), data);
    let want = hex(&httpauth::response_mac(&ADMIN, &nonce, 200, &r.body));
    assert_eq!(r.h("x-lab-proof"), Some(want.as_str()));

    // download, verifying the trailer proof over the streamed body hash
    let target = format!("/api/v1/file?path={}", path.display());
    let g = admin(s.addr, "GET", &target, b"");
    assert_eq!(g.resp.status, 200);
    assert!(g.resp.chunked);
    assert_eq!(g.resp.body, data);
    let want = hex(&httpauth::response_mac_hashed(&ADMIN, &g.nonce, 200, &labproto::crypto::sha256(&data)));
    assert_eq!(g.resp.h("x-lab-proof"), Some(want.as_str()), "trailer proof");
    // ranged
    let g = admin(s.addr, "GET", &format!("{}&offset=10&len=5", target), b"");
    assert_eq!(g.resp.body, &data[10..15]);

    // upload whose body does not match the declared digest is rejected and leaves no file
    let bad = dir.join("bad.bin");
    let target = format!("/api/v1/file?path={}", bad.display());
    let nonce = get_nonce(s.addr);
    let mac = hex(&httpauth::request_mac_hashed(&ADMIN, &nonce, "PUT", &target, &sha));
    let body = vec![1u8; 1000];
    let head = format!("PUT {} HTTP/1.1\r\nConnection: close\r\nX-Lab-Key: {}\r\nX-Lab-Nonce: {}\r\nX-Lab-Auth: {}\r\nX-Lab-Body-Sha256: {}\r\nContent-Length: 1000\r\n\r\n", target, kid(&ADMIN, Role::Admin), nonce, mac, hex(&sha));
    let mut req = head.into_bytes();
    req.extend_from_slice(&body);
    let r = raw(s.addr, &req);
    assert_ne!(r.status, 200);
    assert!(!bad.exists() && !dir.join("bad.bin.part").exists());

    // a ro key cannot upload; an upload signed for another digest is not even started
    let nonce = get_nonce(s.addr);
    let mac = hex(&httpauth::request_mac_hashed(&RO, &nonce, "PUT", &target, &sha));
    let head = format!("PUT {} HTTP/1.1\r\nConnection: close\r\nX-Lab-Key: {}\r\nX-Lab-Nonce: {}\r\nX-Lab-Auth: {}\r\nX-Lab-Body-Sha256: {}\r\nContent-Length: 4\r\n\r\nabcd", target, kid(&RO, Role::Ro), nonce, mac, hex(&sha));
    assert_eq!(raw(s.addr, head.as_bytes()).status, 403);
    let r = raw(s.addr, format!("PUT {} HTTP/1.1\r\nConnection: close\r\nContent-Length: 4\r\n\r\nabcd", target).as_bytes());
    assert_eq!(r.status, 400, "declared digest header is mandatory");
}

#[test]
fn download_errors_are_plain_json() {
    let s = Server::start();
    let g = admin(s.addr, "GET", "/api/v1/file?path=/nonexistent/file", b"");
    assert_eq!(g.resp.status, 404);
    check_proof(&g, &ADMIN);
    let g = admin(s.addr, "GET", "/api/v1/file", b"");
    assert_eq!(g.resp.status, 400);
    let empty = s.daemon.config.run_dir.join("empty");
    std::fs::write(&empty, b"").unwrap();
    let g = admin(s.addr, "GET", &format!("/api/v1/file?path={}", empty.display()), b"");
    assert_eq!((g.resp.status, g.resp.body.len()), (200, 0));
    check_proof(&g, &ADMIN);
}

#[test]
fn sse_snapshot_and_events_are_sealed() {
    let s = Server::start();
    let nonce = get_nonce(s.addr);
    let mac = hex(&httpauth::request_mac(&ADMIN, &nonce, "GET", "/api/v1/events", b""));
    let mut sock = TcpStream::connect(s.addr).unwrap();
    write!(sock, "GET /api/v1/events HTTP/1.1\r\nX-Lab-Key: {}\r\nX-Lab-Nonce: {}\r\nX-Lab-Auth: {}\r\n\r\n", kid(&ADMIN, Role::Admin), nonce, mac).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut r = BufReader::new(sock);
    assert!(read_line(&mut r).starts_with("HTTP/1.1 200"));
    loop {
        if read_line(&mut r).is_empty() {
            break;
        }
    }
    // publish an audit event after the stream is up
    let events = loop {
        let l = read_line(&mut r);
        if l.starts_with("event: snapshot") {
            break read_line(&mut r);
        }
    };
    let data = events.strip_prefix("data: ").unwrap();
    assert_eq!(verify_event(&ADMIN, &nonce, data).unwrap().0, 0);
    assert!(data.contains("\"event\":\"snapshot\"") && data.contains("\"state\":\"ready\""));
    s.daemon.events.publish(Event::Link("eth9".into()));
    let ev = loop {
        let l = read_line(&mut r);
        if l.starts_with("data: ") && l.contains("\"event\":\"link\"") {
            break l;
        }
    };
    let (seq, _) = verify_event(&ADMIN, &nonce, ev.strip_prefix("data: ").unwrap()).unwrap();
    assert!(seq >= 1);
    assert!(ev.contains("eth9"));
}

#[test]
fn oversized_and_malformed_requests_are_rejected() {
    let s = Server::start();
    let big = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD));
    assert_eq!(raw(s.addr, big.as_bytes()).status, 431);
    let r = raw(s.addr, format!("POST /api/v1/cmd/ping HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1).as_bytes());
    assert_eq!(r.status, 413);
    assert_eq!(raw(s.addr, b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").status, 501);
    assert_eq!(raw(s.addr, b"BREW / HTTP/1.1\r\n\r\n").status, 404);
    assert_eq!(raw(s.addr, b"nonsense\r\n\r\n").status, 400);
    assert_eq!(raw(s.addr, b"GET / HTTP/3.0\r\n\r\n").status, 505);
    assert!(s.daemon.stats.http_rejected.load(Ordering::Relaxed) >= 5);
}

#[test]
fn slow_client_times_out_without_blocking_others() {
    let s = Server::start();
    let mut slow = TcpStream::connect(s.addr).unwrap();
    slow.write_all(b"GET /api/v1/hel").unwrap(); // never finishes
    let r = raw(s.addr, b"GET /api/v1/hello HTTP/1.1\r\nConnection: close\r\n\r\n");
    assert_eq!(r.status, 200, "other clients are served while one stalls");
    drop(slow);
}

#[test]
fn keep_alive_serves_several_requests() {
    let s = Server::start();
    let mut sock = TcpStream::connect(s.addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut r = BufReader::new(sock.try_clone().unwrap());
    for _ in 0..3 {
        sock.write_all(b"GET /api/v1/hello HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
        assert!(read_line(&mut r).starts_with("HTTP/1.1 200"));
        let mut len = 0;
        loop {
            let l = read_line(&mut r);
            if l.is_empty() {
                break;
            }
            if let Some(v) = l.to_ascii_lowercase().strip_prefix("content-length:") {
                len = v.trim().parse().unwrap();
            }
        }
        let mut b = vec![0u8; len];
        r.read_exact(&mut b).unwrap();
    }
}

#[test]
fn many_connections_beyond_the_cap_get_503() {
    let s = Server::start();
    let mut held = Vec::new();
    for _ in 0..MAX_WORKERS {
        let mut c = TcpStream::connect(s.addr).unwrap();
        c.write_all(b"GET /api/v1/he").unwrap();
        held.push(c);
    }
    std::thread::sleep(Duration::from_millis(300));
    let r = raw(s.addr, b"GET /api/v1/hello HTTP/1.1\r\nConnection: close\r\n\r\n");
    assert_eq!(r.status, 503);
    drop(held);
}

#[test]
fn cmd_body_parser() {
    let ok = |s: &str| parse_cmd_body(s.as_bytes());
    assert_eq!(ok("").unwrap(), Vec::<String>::new());
    assert_eq!(ok("{}").unwrap(), Vec::<String>::new());
    assert_eq!(ok("{\"args\":[]}").unwrap(), Vec::<String>::new());
    assert_eq!(ok(" { \"x\": [1, {\"a\": null}, \"s\"], \"args\" : [ \"a\" , \"b\\n\\u00e9\\ud83d\\ude00\" ] } ").unwrap(), vec!["a", "b\né😀"]);
    for bad in ["[]", "{\"args\":\"x\"}", "{\"args\":[1]}", "{\"args\":[\"a\"", "{\"args\":[\"a\"]} x", "{\"args\":[\"\\ud800\"]}", "{\"args\":[\"a\x01\"]}", "{\"a\":}", "nope"] {
        assert!(ok(bad).is_err(), "{:?}", bad);
    }
    let deep = format!("{{\"x\":{}1{}}}", "[".repeat(20), "]".repeat(20));
    assert!(ok(&deep).is_err(), "nesting is bounded");
}

#[test]
fn bind_resolution() {
    let m = crate::netcfg::mock::MockNet::default();
    assert_eq!(resolve_bind(&None, &m).unwrap(), Ipv4Addr::UNSPECIFIED);
    assert_eq!(resolve_bind(&Some("10.1.2.3".into()), &m).unwrap(), Ipv4Addr::new(10, 1, 2, 3));
    assert!(resolve_bind(&Some("nosuchif0".into()), &m).is_err());
}

#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);
impl Write for Shared {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn ndjson_sink_frames_and_finishes() {
    let buf = Shared::default();
    let mut sink = NdjsonSink::new(buf.clone(), [5; 32], "n".into());
    sink.data(Chan::Stdout, b"hi").unwrap();
    sink.data(Chan::File, &[0xff, 0xfe]).unwrap();
    sink.event("{\"event\":\"progress\",\"done_bytes\":1}").unwrap();
    sink.data(Chan::Stderr, b"e").unwrap();
    sink.finish(&Reply::json("{\"ok\":true}".into())).unwrap();
    let raw = buf.0.lock().unwrap().clone();
    // decode the chunked framing back into lines
    let mut lines = Vec::new();
    let mut i = 0;
    loop {
        let nl = raw[i..].windows(2).position(|w| w == b"\r\n").unwrap();
        let n = usize::from_str_radix(std::str::from_utf8(&raw[i..i + nl]).unwrap(), 16).unwrap();
        i += nl + 2;
        if n == 0 {
            break;
        }
        lines.push(String::from_utf8(raw[i..i + n - 1].to_vec()).unwrap());
        assert_eq!(raw[i + n - 1], b'\n');
        i += n + 2;
    }
    assert_eq!(lines.len(), 5);
    for (k, l) in lines.iter().enumerate() {
        assert_eq!(verify_event(&[5; 32], "n", l).unwrap().0, k as u64);
    }
    assert!(lines[0].contains("\"event\":\"stdout\"") && lines[0].contains("\"data\":\"hi\""));
    assert!(lines[1].contains("\"b64\":\"//4=\""), "binary data is base64: {}", lines[1]);
    assert!(lines[2].contains("\"event\":\"progress\"") && lines[3].contains("\"event\":\"stderr\""));
    assert!(lines[4].contains("\"event\":\"result\"") && lines[4].contains("\"data\":{\"ok\":true}") && lines[4].contains("\"ok\":true,\"status\":0"), "{}", lines[4]);
}

#[test]
fn stream_failure_ends_with_an_error_result() {
    let s = Server::start();
    let r = admin(s.addr, "POST", "/api/v1/cmd/exec?stream=1", b"{\"args\":[\"--\",\"/no/such/prog\"]}");
    let lines: Vec<String> = r.resp.text().lines().map(str::to_string).collect();
    let last = lines.last().unwrap();
    assert!(verify_event(&ADMIN, &r.nonce, last).is_some());
    assert!(last.contains("\"ok\":false") && last.contains("\"status\":6") && last.contains("\"error\":{\"code\":\"NOT_FOUND\""), "{}", last);
    // unknown command: a plain 404 before any stream starts
    assert_eq!(admin(s.addr, "POST", "/api/v1/cmd/nosuch?stream=1", b"{}").resp.status, 404);
}
