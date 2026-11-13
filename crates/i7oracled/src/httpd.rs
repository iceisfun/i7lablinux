//! Minimal HTTP/1.1 server: one request per connection (Connection: close), bounded head and body,
//! thread per connection with read/write timeouts. No TLS (the scheme authenticates and the lab LAN is private).

use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::state::Shared;

pub const MAX_HEAD: usize = 16 << 10;
pub const MAX_BODY: usize = 1 << 20;
const MAX_CONNS: usize = 32;

#[derive(Debug)]
pub struct Request {
    pub method: String,
    /// Request target exactly as sent (path and query): this is what the MAC covers.
    pub target: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    /// Header names lower-cased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
    }
    pub fn q(&self, name: &str) -> Option<&str> {
        self.query.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

pub struct Response {
    pub status: u16,
    pub ctype: &'static str,
    pub body: Vec<u8>,
    pub proof: Option<String>,
}

impl Response {
    pub fn json(status: u16, body: String) -> Response {
        Response { status, ctype: "application/json", body: body.into_bytes(), proof: None }
    }
    pub fn error(status: u16, msg: &str) -> Response {
        Response::json(status, format!("{{\"ok\":false,\"error\":{}}}", crate::evlog::json_str(msg)))
    }
}

#[derive(Debug, PartialEq)]
pub enum ReqError {
    Io,
    Closed,
    TooLarge,
    Malformed(&'static str),
    Unsupported(&'static str),
}

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let h = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|x| u8::from_str_radix(x, 16).ok());
                if let Some(v) = h {
                    out.push(v);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(p), String::new()),
        })
        .collect()
}

/// Read one request. `r` should have a read timeout set by the caller.
pub fn read_request(r: &mut dyn Read) -> Result<Request, ReqError> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let head_end = loop {
        if let Some(p) = find(&buf, b"\r\n\r\n") {
            break p;
        }
        if buf.len() > MAX_HEAD {
            return Err(ReqError::TooLarge);
        }
        match r.read(&mut chunk) {
            Ok(0) => return Err(if buf.is_empty() { ReqError::Closed } else { ReqError::Malformed("truncated head") }),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ReqError::Io),
        }
    };
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| ReqError::Malformed("non-utf8 head"))?;
    let mut lines = head.split("\r\n");
    let first = lines.next().ok_or(ReqError::Malformed("empty"))?;
    let mut parts = first.split(' ');
    let (Some(method), Some(target), Some(ver), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(ReqError::Malformed("request line"));
    };
    if !ver.starts_with("HTTP/1.") || !target.starts_with('/') || method.is_empty() || !method.bytes().all(|c| c.is_ascii_uppercase()) {
        return Err(ReqError::Malformed("request line"));
    }
    let mut headers = Vec::new();
    for l in lines {
        let (k, v) = l.split_once(':').ok_or(ReqError::Malformed("header"))?;
        headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
    }
    if headers.iter().any(|(k, _)| k == "transfer-encoding") {
        return Err(ReqError::Unsupported("chunked request bodies"));
    }
    let clen: usize = match headers.iter().find(|(k, _)| k == "content-length") {
        Some((_, v)) => v.parse().map_err(|_| ReqError::Malformed("content-length"))?,
        None => 0,
    };
    if clen > MAX_BODY {
        return Err(ReqError::TooLarge);
    }
    let mut body: Vec<u8> = buf[head_end + 4..].to_vec();
    if body.len() > clen {
        body.truncate(clen);
    }
    while body.len() < clen {
        match r.read(&mut chunk) {
            Ok(0) => return Err(ReqError::Malformed("truncated body")),
            Ok(n) => body.extend_from_slice(&chunk[..n.min(clen - body.len())]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ReqError::Io),
        }
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (percent_decode(p), parse_query(q)),
        None => (percent_decode(target), Vec::new()),
    };
    Ok(Request { method: method.to_string(), target: target.to_string(), path, query, headers, body })
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

pub fn encode_response(resp: &Response, head_only: bool) -> Vec<u8> {
    let mut h = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n",
        resp.status,
        reason(resp.status),
        resp.ctype,
        resp.body.len()
    );
    if let Some(p) = &resp.proof {
        h.push_str(&format!("X-Lab-Proof: {}\r\n", p));
    }
    h.push_str("\r\n");
    let mut out = h.into_bytes();
    if !head_only {
        out.extend_from_slice(&resp.body);
    }
    out
}

/// Accept loop. Polls so `stop` is honoured; `handler` runs on a worker thread per connection.
pub fn serve<F>(listener: TcpListener, shared: Arc<Shared>, handler: F)
where
    F: Fn(&Arc<Shared>, &Request, IpAddr) -> Response + Send + Sync + 'static,
{
    let _ = listener.set_nonblocking(true);
    let handler = Arc::new(handler);
    let active = Arc::new(AtomicUsize::new(0));
    while !shared.stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, peer)) => {
                if active.load(Ordering::SeqCst) >= MAX_CONNS {
                    drop(stream);
                    continue;
                }
                active.fetch_add(1, Ordering::SeqCst);
                let (sh, h, act) = (shared.clone(), handler.clone(), active.clone());
                std::thread::spawn(move || {
                    let _ = conn(stream, peer.ip(), &sh, &*h);
                    act.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

fn conn<F>(mut s: TcpStream, peer: IpAddr, sh: &Arc<Shared>, handler: &F) -> io::Result<()>
where
    F: Fn(&Arc<Shared>, &Request, IpAddr) -> Response,
{
    let _ = s.set_nonblocking(false);
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(30)))?;
    let resp = match read_request(&mut s) {
        Ok(req) => {
            let head_only = req.method == "HEAD";
            let r = handler(sh, &req, peer);
            let bytes = encode_response(&r, head_only);
            return s.write_all(&bytes);
        }
        Err(ReqError::Closed) | Err(ReqError::Io) => return Ok(()),
        Err(ReqError::TooLarge) => Response::error(413, "request too large"),
        Err(ReqError::Malformed(m)) => Response::error(400, m),
        Err(ReqError::Unsupported(m)) => Response::error(501, m),
    };
    s.write_all(&encode_response(&resp, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_get_with_query() {
        let raw = b"GET /events?since=5&limit=10&x=a%20b HTTP/1.1\r\nHost: h\r\nX-Lab-Key: AB\r\n\r\n";
        let r = read_request(&mut Cursor::new(&raw[..])).unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.target, "/events?since=5&limit=10&x=a%20b");
        assert_eq!(r.path, "/events");
        assert_eq!(r.q("since"), Some("5"));
        assert_eq!(r.q("x"), Some("a b"));
        assert_eq!(r.header("x-lab-key").as_deref(), Some("AB"));
    }

    #[test]
    fn parses_post_body_even_when_split() {
        struct Slow(Vec<u8>, usize);
        impl Read for Slow {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                let n = 7.min(b.len()).min(self.0.len() - self.1);
                b[..n].copy_from_slice(&self.0[self.1..self.1 + n]);
                self.1 += n;
                Ok(n)
            }
        }
        let raw = b"POST /run HTTP/1.1\r\nContent-Length: 17\r\n\r\n{\"name\":\"a.exe\"}X".to_vec();
        let r = read_request(&mut Slow(raw, 0)).unwrap();
        assert_eq!(r.body, br#"{"name":"a.exe"}X"#);
        assert_eq!(r.body.len(), 17);
    }

    #[test]
    fn refuses_bad_input() {
        let bad = |raw: &[u8]| read_request(&mut Cursor::new(raw.to_vec())).err().unwrap();
        assert_eq!(bad(b""), ReqError::Closed);
        assert!(matches!(bad(b"GET / HTTP/1.1\r\n"), ReqError::Malformed(_)));
        assert!(matches!(bad(b"get / HTTP/1.1\r\n\r\n"), ReqError::Malformed(_)));
        assert!(matches!(bad(b"GET x HTTP/1.1\r\n\r\n"), ReqError::Malformed(_)));
        assert!(matches!(bad(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"), ReqError::Unsupported(_)));
        assert_eq!(bad(b"POST / HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n"), ReqError::TooLarge);
        assert!(matches!(bad(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab"), ReqError::Malformed(_)));
        let huge = vec![b'a'; MAX_HEAD + 5000];
        assert_eq!(read_request(&mut Cursor::new(huge)).err().unwrap(), ReqError::TooLarge);
    }

    #[test]
    fn percent_decode_edges() {
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("a+b"), "a b");
    }

    #[test]
    fn response_encoding() {
        let mut r = Response::json(200, "{}".into());
        r.proof = Some("ff".into());
        let s = String::from_utf8(encode_response(&r, false)).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Length: 2\r\n") && s.contains("X-Lab-Proof: ff\r\n") && s.ends_with("\r\n\r\n{}"));
        let h = String::from_utf8(encode_response(&r, true)).unwrap();
        assert!(h.ends_with("\r\n\r\n"));
    }
}
