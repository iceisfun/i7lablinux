//! A fake i7labd HTTP API on loopback, implemented only with std + labproto::httpauth (the real signing code).
//! It verifies request signatures, issues single-use nonces, signs replies and stream events, and can be told
//! to misbehave (bad proof, tampered events, sequence gaps, truncated streams).
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use labproto::crypto::{hex, sha256, unhex};
use labproto::httpauth::{self, NonceStore};
use labproto::keys::Key;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Evil {
    #[default]
    None,
    /// reply proofs computed with another key
    BadProof,
    /// one stream event carries a wrong mac
    BadEventMac,
    /// an event is skipped (seq gap)
    SeqGap,
    /// the stream ends without a result event
    NoResult,
    /// get: the body differs from what the trailer proof covers
    TamperBody,
    /// never answers
    Hang,
}

#[derive(Default)]
pub struct State {
    pub evil: Evil,
    pub requests: Vec<String>,
    pub files: HashMap<String, Vec<u8>>,
    pub last_nonce_reuse_rejected: bool,
}

pub struct FakeHttp {
    pub addr: String,
    pub state: Arc<Mutex<State>>,
}

impl FakeHttp {
    /// `keys`: the keys the "host" knows (by key id).
    pub fn start(keys: Vec<Key>) -> FakeHttp {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let state = Arc::new(Mutex::new(State::default()));
        let nonces = Arc::new(Mutex::new(NonceStore::new(16, Duration::from_secs(30))));
        let st = state.clone();
        std::thread::spawn(move || {
            for conn in l.incoming() {
                let Ok(conn) = conn else { continue };
                let (st, nonces, keys) = (st.clone(), nonces.clone(), keys.clone());
                std::thread::spawn(move || {
                    let _ = serve(conn, &st, &nonces, &keys);
                });
            }
        });
        FakeHttp { addr, state }
    }

    pub fn set_evil(&self, e: Evil) {
        self.state.lock().unwrap().evil = e;
    }
}

struct Req {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Req {
    fn h(&self, n: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.as_str())
    }
    fn query(&self, k: &str) -> Option<String> {
        let q = self.target.split_once('?')?.1;
        q.split('&').find_map(|kv| kv.split_once('=').filter(|(a, _)| *a == k).map(|(_, v)| unpct(v)))
    }
    fn path(&self) -> &str {
        self.target.split('?').next().unwrap()
    }
}

fn unpct(s: &str) -> String {
    let b = s.as_bytes();
    let mut o = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() + 0 {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                o.push(v);
                i += 3;
                continue;
            }
        }
        o.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&o).into_owned()
}

fn read_req(r: &mut BufReader<TcpStream>) -> std::io::Result<Req> {
    let mut line = String::new();
    r.read_line(&mut line)?;
    let mut it = line.split_whitespace();
    let (method, target) = (it.next().unwrap_or("").to_string(), it.next().unwrap_or("").to_string());
    let mut headers = Vec::new();
    loop {
        let mut l = String::new();
        r.read_line(&mut l)?;
        let l = l.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let len: usize = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Req { method, target, headers, body })
}

fn respond(w: &mut TcpStream, code: u16, extra: &[(String, String)], body: &[u8]) -> std::io::Result<()> {
    let mut s = format!("HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n", code, body.len());
    for (k, v) in extra {
        s.push_str(&format!("{}: {}\r\n", k, v));
    }
    s.push_str("\r\n");
    w.write_all(s.as_bytes())?;
    w.write_all(body)
}

fn serve(conn: TcpStream, st: &Arc<Mutex<State>>, nonces: &Arc<Mutex<NonceStore>>, keys: &[Key]) -> std::io::Result<()> {
    let mut w = conn.try_clone()?;
    let mut r = BufReader::new(conn);
    let req = read_req(&mut r)?;
    st.lock().unwrap().requests.push(format!("{} {}", req.method, req.target));
    let evil = st.lock().unwrap().evil;
    if evil == Evil::Hang {
        std::thread::sleep(Duration::from_secs(5));
        return Ok(());
    }
    if req.path() == "/api/v1/nonce" {
        let n = nonces.lock().unwrap().issue(Instant::now())?;
        return respond(&mut w, 200, &[], n.as_bytes());
    }
    // everything else is signed
    let nonce = req.h("X-Lab-Nonce").unwrap_or("").to_string();
    let kid = req.h("X-Lab-Key").and_then(unhex).unwrap_or_default();
    let key = keys.iter().find(|k| k.key_id().to_vec() == kid);
    let is_put = req.method == "PUT" && req.path() == "/api/v1/file";
    // like i7labd: an upload must declare its digest up front (X-Lab-Body-Sha256); without it the answer is an
    // unsigned 400 (the client used to report that as an authentication failure)
    let declared: Option<[u8; 32]> = req.h("X-Lab-Body-Sha256").and_then(unhex).and_then(|v| <[u8; 32]>::try_from(v).ok());
    if is_put && declared.is_none() {
        return respond(&mut w, 400, &[], b"{\"error\":{\"code\":\"BAD_ARGS\",\"message\":\"PUT file needs Content-Length and X-Lab-Body-Sha256\"}}");
    }
    let mac = |k: &Key| {
        if is_put {
            httpauth::request_mac_hashed(&k.bytes, &nonce, &req.method, &req.target, &declared.unwrap())
        } else {
            httpauth::request_mac(&k.bytes, &nonce, &req.method, &req.target, &req.body)
        }
    };
    let fresh = nonces.lock().unwrap().take(&nonce, Instant::now());
    let ok = fresh && key.is_some_and(|k| httpauth::check_hex_mac(&mac(k), req.h("X-Lab-Auth").unwrap_or("")));
    if !ok {
        return respond(&mut w, 401, &[], b"{\"error\":{\"code\":\"EPERM\",\"message\":\"bad signature\"}}");
    }
    let key = key.unwrap();
    let proof_key: Vec<u8> = if evil == Evil::BadProof { vec![0x42; 32] } else { key.bytes.to_vec() };
    let signed = |w: &mut TcpStream, code: u16, body: &str| -> std::io::Result<()> {
        let p = httpauth::response_mac(&proof_key, &nonce, code, body.as_bytes());
        respond(w, code, &[("X-Lab-Proof".to_string(), hex(&p))], body.as_bytes())
    };

    let path = req.path().to_string();
    if let Some(cmd) = path.strip_prefix("/api/v1/cmd/") {
        let args: Vec<String> = {
            // crude extraction of the args array is enough for the fake
            let b = String::from_utf8_lossy(&req.body).into_owned();
            let inner = b.split_once('[').and_then(|(_, r)| r.rsplit_once(']')).map(|(a, _)| a.to_string()).unwrap_or_default();
            inner.split(',').filter(|s| !s.is_empty()).map(|s| s.trim().trim_matches('"').to_string()).collect()
        };
        if req.query("stream").is_some() {
            return stream(&mut w, cmd, &args, &nonce, &proof_key, evil);
        }
        return match cmd {
            "ping" => signed(&mut w, 200, "{\"uptime_ms\":4242,\"boot_id\":\"9f3c\"}"),
            "id" => signed(&mut w, 200, &format!("{{\"role\":\"{}\",\"kid\":\"{}\"}}", key.role.name(), key.fingerprint())),
            "blk.ls" => signed(&mut w, 200, "{\"v\":1,\"devices\":[]}"),
            "blk.write" => signed(&mut w, 409, "{\"error\":{\"code\":\"REFUSED\",\"message\":\"device mounted: sdb1\",\"reasons\":[\"mounted\"]}}"),
            "reboot" => signed(&mut w, 403, "{\"error\":{\"code\":\"EPERM\",\"message\":\"admin key needed\"}}"),
            _ => signed(&mut w, 501, "{\"error\":{\"code\":\"UNSUPPORTED\",\"message\":\"no such command\"}}"),
        };
    }
    if is_put {
        if declared != Some(sha256(&req.body)) {
            return signed(&mut w, 400, "{\"error\":{\"code\":\"BAD_ARGS\",\"message\":\"body does not match X-Lab-Body-Sha256\"}}");
        }
        let path = req.query("path").unwrap_or_default();
        let n = req.body.len();
        st.lock().unwrap().files.insert(path, req.body.clone());
        return signed(&mut w, 200, &format!("{{\"bytes\":{},\"sha256\":\"{}\"}}", n, hex(&sha256(&req.body))));
    }
    if req.method == "GET" && path == "/api/v1/file" {
        let p = req.query("path").unwrap_or_default();
        let data = st.lock().unwrap().files.get(&p).cloned();
        let Some(data) = data else { return signed(&mut w, 404, "{\"error\":{\"code\":\"NOT_FOUND\",\"message\":\"no such file\"}}") };
        let proof = httpauth::response_mac_hashed(&proof_key, &nonce, 200, &sha256(&data));
        let mut sent = data.clone();
        if evil == Evil::TamperBody {
            sent[0] ^= 0xff;
        }
        w.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nTrailer: X-Lab-Proof\r\nConnection: close\r\n\r\n")?;
        for c in sent.chunks(7000) {
            w.write_all(format!("{:x}\r\n", c.len()).as_bytes())?;
            w.write_all(c)?;
            w.write_all(b"\r\n")?;
        }
        return w.write_all(format!("0\r\nX-Lab-Proof: {}\r\n\r\n", hex(&proof)).as_bytes());
    }
    signed(&mut w, 404, "{\"error\":{\"code\":\"NOT_FOUND\",\"message\":\"no route\"}}")
}

fn chunk(w: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    w.write_all(format!("{:x}\r\n", data.len()).as_bytes())?;
    w.write_all(data)?;
    w.write_all(b"\r\n")
}

fn stream(w: &mut TcpStream, cmd: &str, args: &[String], nonce: &str, key: &[u8], evil: Evil) -> std::io::Result<()> {
    w.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/x-ndjson\r\nConnection: close\r\n\r\n")?;
    let mut events: Vec<String> = Vec::new();
    match cmd {
        "exec" if args.iter().any(|a| a == "--detach") => {
            events.push("{\"event\":\"result\",\"ok\":true,\"status\":0,\"data\":{\"v\":1,\"job\":7}}".into());
        }
        "exec" => {
            events.push("{\"event\":\"stdout\",\"data\":\"hello\\n\"}".into());
            events.push("{\"event\":\"stderr\",\"data\":\"warn\\n\"}".into());
            events.push("{\"event\":\"stdout\",\"b64\":\"Yf9i\"}".into());
            events.push("{\"event\":\"result\",\"ok\":true,\"status\":0,\"exit\":3,\"data\":{\"signal\":0}}".into());
        }
        "blk.read" => {
            events.push("{\"event\":\"progress\",\"region\":\"mid\",\"mib_s\":412.5,\"done\":0.43}".into());
            events.push(format!("{{\"event\":\"result\",\"ok\":true,\"status\":0,\"data\":{{\"v\":1,\"dev\":\"{}\",\"serial\":null,\"mode\":\"Read\",\"seed\":null,\"ok\":true,\"regions\":[]}}}}", args.first().map(String::as_str).unwrap_or("?")));
        }
        "blk.write" => {
            events.push("{\"event\":\"result\",\"ok\":false,\"status\":5,\"error\":{\"code\":\"REFUSED\",\"message\":\"device mounted: sdb1\",\"reasons\":[\"mounted\"]}}".into());
        }
        _ => {
            events.push("{\"event\":\"result\",\"ok\":false,\"status\":3,\"error\":{\"code\":\"UNSUPPORTED\",\"message\":\"no\"}}".into());
        }
    }
    if evil == Evil::NoResult {
        events.pop();
    }
    let mut seq = 0u64;
    for (i, ev) in events.iter().enumerate() {
        if evil == Evil::SeqGap && i == 1 {
            seq += 1;
        }
        let body = format!("{},\"seq\":{}}}", &ev[..ev.len() - 1], seq);
        let mut mac = httpauth::event_mac(key, nonce, seq, &body);
        if evil == Evil::BadEventMac && i == 0 {
            mac[0] ^= 1;
        }
        let line = format!("{},\"mac\":\"{}\"}}\n", &body[..body.len() - 1], hex(&mac));
        chunk(w, line.as_bytes())?;
        seq += 1;
    }
    w.write_all(b"0\r\n\r\n")
}
