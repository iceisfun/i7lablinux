//! HTTP/1.1 wire helpers for the agent's server: bounded request-head parser, percent decoding, response and
//! chunked writers, base64, and the NDJSON/SSE event sealing of `labproto::httpauth::event_mac`. Pure code over
//! `Read`/`Write`; the server logic is `http.rs`. Owner: P7.

use std::io::{self, BufRead, Read, Write};

pub const MAX_HEAD: usize = 64 * 1024;
pub const MAX_HEADERS: usize = 64;
pub const MAX_TARGET: usize = 8 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum HttpError {
    /// 400 with a reason
    Bad(&'static str),
    /// 431
    HeadTooLarge,
    /// 414
    TargetTooLong,
    /// 413
    BodyTooLarge,
    /// 501 (chunked request bodies, unknown methods with bodies)
    NotImplemented(&'static str),
    /// 505
    Version,
    /// peer closed before a request line: not an error to log
    Closed,
    Timeout,
    Io(io::ErrorKind),
}

impl From<io::Error> for HttpError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => HttpError::Timeout,
            io::ErrorKind::UnexpectedEof => HttpError::Closed,
            k => HttpError::Io(k),
        }
    }
}

impl HttpError {
    pub fn status(&self) -> (u16, &'static str) {
        match self {
            HttpError::Bad(m) => (400, m),
            HttpError::HeadTooLarge => (431, "request header too large"),
            HttpError::TargetTooLong => (414, "request target too long"),
            HttpError::BodyTooLarge => (413, "request body too large"),
            HttpError::NotImplemented(m) => (501, m),
            HttpError::Version => (505, "HTTP version not supported"),
            HttpError::Timeout => (408, "request timeout"),
            HttpError::Closed | HttpError::Io(_) => (400, "connection error"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub method: String,
    /// raw request target exactly as sent (it is what the request MAC covers)
    pub target: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    /// names lower-cased
    pub headers: Vec<(String, String)>,
    pub content_length: Option<u64>,
    pub http11: bool,
}

impl Head {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    pub fn q(&self, name: &str) -> Option<&str> {
        self.query.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    pub fn q_all(&self, name: &str) -> Vec<&str> {
        self.query.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str()).collect()
    }
    pub fn wants_close(&self) -> bool {
        match self.header("connection") {
            Some(c) => c.to_ascii_lowercase().contains("close") || !self.http11 && !c.to_ascii_lowercase().contains("keep-alive"),
            None => !self.http11,
        }
    }
}

/// `%XX` and `+` (query only) decoding; `None` on a bad escape or invalid UTF-8.
pub fn pct_decode(s: &str, plus_is_space: bool) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(h, 16).ok()?);
                i += 3;
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

pub fn parse_query(q: &str) -> Option<Vec<(String, String)>> {
    let mut out = Vec::new();
    for pair in q.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.push((pct_decode(k, true)?, pct_decode(v, true)?));
    }
    Some(out)
}

/// One line (without CRLF), bounded by `budget` bytes of head left.
fn read_line<R: BufRead>(r: &mut R, budget: &mut usize) -> Result<Option<String>, HttpError> {
    let mut buf = Vec::new();
    let n = r.by_ref().take(*budget as u64 + 1).read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    if n > *budget {
        return Err(HttpError::HeadTooLarge);
    }
    *budget -= n;
    if buf.last() != Some(&b'\n') {
        return Err(HttpError::Bad("truncated request head"));
    }
    buf.pop();
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    if buf.contains(&0) {
        return Err(HttpError::Bad("NUL in request head"));
    }
    String::from_utf8(buf).map(Some).map_err(|_| HttpError::Bad("request head is not UTF-8"))
}

/// Parse a request head. Rejects: oversized head/target, more than 64 headers, folded or malformed header lines,
/// `Transfer-Encoding` (no chunked request bodies), conflicting `Content-Length`, non-1.x versions.
pub fn read_head<R: BufRead>(r: &mut R) -> Result<Head, HttpError> {
    let mut budget = MAX_HEAD;
    // tolerate stray blank lines between pipelined requests (RFC 9112 2.2)
    let line = loop {
        match read_line(r, &mut budget)? {
            None => return Err(HttpError::Closed),
            Some(l) if l.is_empty() => continue,
            Some(l) => break l,
        }
    };
    let mut it = line.split(' ');
    let (method, target, version) = match (it.next(), it.next(), it.next(), it.next()) {
        (Some(m), Some(t), Some(v), None) if !m.is_empty() && !t.is_empty() => (m, t, v),
        _ => return Err(HttpError::Bad("malformed request line")),
    };
    if !method.bytes().all(|b| b.is_ascii_uppercase()) || method.len() > 16 {
        return Err(HttpError::Bad("bad method"));
    }
    let http11 = match version {
        "HTTP/1.1" => true,
        "HTTP/1.0" => false,
        _ => return Err(HttpError::Version),
    };
    if target.len() > MAX_TARGET {
        return Err(HttpError::TargetTooLong);
    }
    if !target.starts_with('/') || target.bytes().any(|b| b < 0x21 || b == 0x7f) {
        return Err(HttpError::Bad("bad request target"));
    }
    let (raw_path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    let path = pct_decode(raw_path, false).ok_or(HttpError::Bad("bad percent escape in path"))?;
    if path.contains('\0') {
        return Err(HttpError::Bad("NUL in path"));
    }
    let query = parse_query(raw_query).ok_or(HttpError::Bad("bad percent escape in query"))?;
    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let Some(l) = read_line(r, &mut budget)? else { return Err(HttpError::Bad("truncated request head")) };
        if l.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(HttpError::HeadTooLarge);
        }
        if l.starts_with([' ', '\t']) {
            return Err(HttpError::Bad("folded header lines are not accepted"));
        }
        let (k, v) = l.split_once(':').ok_or(HttpError::Bad("malformed header line"))?;
        if k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)) {
            return Err(HttpError::Bad("bad header name"));
        }
        headers.push((k.to_ascii_lowercase(), v.trim().to_string()));
    }
    if headers.iter().any(|(k, _)| k == "transfer-encoding") {
        return Err(HttpError::NotImplemented("request bodies must use Content-Length"));
    }
    let mut content_length: Option<u64> = None;
    for (_, v) in headers.iter().filter(|(k, _)| k == "content-length") {
        if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
            return Err(HttpError::Bad("bad Content-Length"));
        }
        let n: u64 = v.parse().map_err(|_| HttpError::Bad("bad Content-Length"))?;
        if content_length.is_some_and(|c| c != n) {
            return Err(HttpError::Bad("conflicting Content-Length"));
        }
        content_length = Some(n);
    }
    Ok(Head { method: method.to_string(), target: target.to_string(), path, query, headers, content_length, http11 })
}

/// Read a body of exactly `len` bytes (`len <= max`, else `BodyTooLarge` before reading anything).
pub fn read_body<R: Read>(r: &mut R, len: u64, max: usize) -> Result<Vec<u8>, HttpError> {
    if len > max as u64 {
        return Err(HttpError::BodyTooLarge);
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    Ok(body)
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        499 => "Client Closed Request",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Status",
    }
}

/// Header values must stay on one line.
fn clean(v: &str) -> String {
    v.chars().filter(|c| !c.is_control()).collect()
}

/// A complete response with a Content-Length body.
pub fn write_response<W: Write>(w: &mut W, status: u16, headers: &[(&str, String)], body: &[u8], keep_alive: bool) -> io::Result<()> {
    let mut h = format!("HTTP/1.1 {} {}\r\n", status, reason(status));
    for (k, v) in headers {
        h.push_str(&format!("{}: {}\r\n", k, clean(v)));
    }
    h.push_str(&format!("Content-Length: {}\r\nConnection: {}\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-cache\r\n\r\n", body.len(), if keep_alive { "keep-alive" } else { "close" }));
    w.write_all(h.as_bytes())?;
    w.write_all(body)?;
    w.flush()
}

/// Start a chunked response (`Connection: close`: a stream ends the connection).
pub fn write_chunked_head<W: Write>(w: &mut W, status: u16, headers: &[(&str, String)]) -> io::Result<()> {
    let mut h = format!("HTTP/1.1 {} {}\r\n", status, reason(status));
    for (k, v) in headers {
        h.push_str(&format!("{}: {}\r\n", k, clean(v)));
    }
    h.push_str("Transfer-Encoding: chunked\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-cache\r\n\r\n");
    w.write_all(h.as_bytes())
}

pub fn write_chunk<W: Write>(w: &mut W, data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(()); // an empty chunk would terminate the body
    }
    write!(w, "{:x}\r\n", data.len())?;
    w.write_all(data)?;
    w.write_all(b"\r\n")?;
    w.flush()
}

/// Last chunk plus optional trailers.
pub fn write_last_chunk<W: Write>(w: &mut W, trailers: &[(&str, String)]) -> io::Result<()> {
    w.write_all(b"0\r\n")?;
    for (k, v) in trailers {
        write!(w, "{}: {}\r\n", k, clean(v))?;
    }
    w.write_all(b"\r\n")?;
    w.flush()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Stamp `seq` into an event object and append the MAC (httpauth.rs): the MAC covers `{"seq":N,<fields>}` and is
/// added as the LAST field `"mac":"<32 hex>"`. A verifier strips `,"mac":"<32 hex>"` and re-checks.
pub struct EventSealer {
    key: [u8; 32],
    nonce: String,
    seq: u64,
}

impl EventSealer {
    pub fn new(key: [u8; 32], nonce: String) -> EventSealer {
        EventSealer { key, nonce, seq: 0 }
    }

    pub fn seal(&mut self, event_json: &str) -> String {
        let body = event_json.trim();
        let stamped = if body == "{}" { format!("{{\"seq\":{}}}", self.seq) } else { format!("{{\"seq\":{},{}", self.seq, &body[1..]) };
        let mac = labproto::httpauth::event_mac(&self.key, &self.nonce, self.seq, &stamped);
        self.seq += 1;
        format!("{},\"mac\":\"{}\"}}", &stamped[..stamped.len() - 1], labproto::crypto::hex(&mac))
    }
}

/// Inverse of `seal` for verifiers and tests: (seq, ok).
pub fn verify_event(key: &[u8; 32], nonce: &str, sealed: &str) -> Option<(u64, String)> {
    let i = sealed.rfind(",\"mac\":\"")?;
    let mac_hex = sealed[i + 8..].strip_suffix("\"}")?;
    let stamped = format!("{}}}", &sealed[..i]);
    let seq: u64 = stamped.strip_prefix("{\"seq\":")?.split([',', '}']).next()?.parse().ok()?;
    let want = labproto::httpauth::event_mac(key, nonce, seq, &stamped);
    labproto::crypto::ct_eq(labproto::crypto::hex(&want).as_bytes(), mac_hex.as_bytes()).then_some((seq, stamped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn head(s: &str) -> Result<Head, HttpError> {
        read_head(&mut Cursor::new(s.as_bytes().to_vec()))
    }

    #[test]
    fn parses_a_normal_request() {
        let h = head("GET /api/v1/file?path=%2Fetc%2Fos-release&a=x+y&a=z HTTP/1.1\r\nHost: x\r\nX-Lab-Key: ab12\r\nContent-Length: 4\r\n\r\n").unwrap();
        assert_eq!((h.method.as_str(), h.path.as_str()), ("GET", "/api/v1/file"));
        assert_eq!(h.q("path"), Some("/etc/os-release"));
        assert_eq!(h.q_all("a"), vec!["x y", "z"]);
        assert_eq!(h.header("x-lab-key"), Some("ab12"));
        assert_eq!(h.content_length, Some(4));
        assert!(h.target.contains("%2Fetc"), "raw target is kept for the MAC");
        assert!(!h.wants_close());
        assert!(head("GET / HTTP/1.0\r\n\r\n").unwrap().wants_close());
        assert!(head("GET / HTTP/1.1\r\nConnection: close\r\n\r\n").unwrap().wants_close());
        assert!(head("\r\n\r\nGET / HTTP/1.1\r\n\r\n").is_ok(), "leading blank lines tolerated");
    }

    #[test]
    fn rejects_malformed_and_hostile_heads() {
        for (req, want) in [
            ("GET /\r\n\r\n", HttpError::Bad("malformed request line")),
            ("get / HTTP/1.1\r\n\r\n", HttpError::Bad("bad method")),
            ("GET / HTTP/2\r\n\r\n", HttpError::Version),
            ("GET x HTTP/1.1\r\n\r\n", HttpError::Bad("bad request target")),
            ("GET /a b HTTP/1.1\r\n\r\n", HttpError::Bad("malformed request line")),
            ("GET /%zz HTTP/1.1\r\n\r\n", HttpError::Bad("bad percent escape in path")),
            ("GET /?a=%ff HTTP/1.1\r\n\r\n", HttpError::Bad("bad percent escape in query")),
            ("GET / HTTP/1.1\r\nBad Header: x\r\n\r\n", HttpError::Bad("bad header name")),
            ("GET / HTTP/1.1\r\nA: b\r\n folded\r\n\r\n", HttpError::Bad("folded header lines are not accepted")),
            ("GET / HTTP/1.1\r\nnocolon\r\n\r\n", HttpError::Bad("malformed header line")),
            ("POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n", HttpError::Bad("conflicting Content-Length")),
            ("POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n", HttpError::Bad("bad Content-Length")),
            ("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", HttpError::NotImplemented("request bodies must use Content-Length")),
            ("GET / HTTP/1.1\r\nHost: x", HttpError::Bad("truncated request head")),
        ] {
            assert_eq!(head(req).unwrap_err(), want, "{:?}", req);
        }
        assert_eq!(head("").unwrap_err(), HttpError::Closed);
        // same Content-Length twice is fine
        assert_eq!(head("POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n").unwrap().content_length, Some(5));
    }

    #[test]
    fn head_limits() {
        let long = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(MAX_TARGET));
        assert_eq!(head(&long).unwrap_err(), HttpError::TargetTooLong);
        let big = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD));
        assert_eq!(head(&big).unwrap_err(), HttpError::HeadTooLarge);
        let many: String = (0..MAX_HEADERS + 1).map(|i| format!("H{}: v\r\n", i)).collect();
        assert_eq!(head(&format!("GET / HTTP/1.1\r\n{}\r\n", many)).unwrap_err(), HttpError::HeadTooLarge);
        let ok: String = (0..MAX_HEADERS).map(|i| format!("H{}: v\r\n", i)).collect();
        assert!(head(&format!("GET / HTTP/1.1\r\n{}\r\n", ok)).is_ok());
        assert_eq!(head("GET /\0 HTTP/1.1\r\n\r\n").unwrap_err(), HttpError::Bad("NUL in request head"));
    }

    #[test]
    fn body_reading() {
        let mut c = Cursor::new(b"abcdef".to_vec());
        assert_eq!(read_body(&mut c, 4, 10).unwrap(), b"abcd");
        assert_eq!(read_body(&mut c, 100, 10).unwrap_err(), HttpError::BodyTooLarge);
        assert_eq!(read_body(&mut c, 5, 10).unwrap_err(), HttpError::Closed, "short body");
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(pct_decode("a%20b%2Fc", false).as_deref(), Some("a b/c"));
        assert_eq!(pct_decode("a+b", false).as_deref(), Some("a+b"));
        assert_eq!(pct_decode("a+b", true).as_deref(), Some("a b"));
        assert_eq!(pct_decode("%4", false), None);
        assert_eq!(pct_decode("%c3%a9", false).as_deref(), Some("é"));
        assert_eq!(pct_decode("%c3", false), None);
    }

    #[test]
    fn response_and_chunk_framing() {
        let mut v = Vec::new();
        write_response(&mut v, 404, &[("Content-Type", "text/plain".into())], b"nope", false).unwrap();
        let s = String::from_utf8(v).unwrap();
        assert!(s.starts_with("HTTP/1.1 404 Not Found\r\n") && s.contains("Content-Length: 4\r\n") && s.ends_with("\r\n\r\nnope") && s.contains("Connection: close"));
        let mut v = Vec::new();
        write_chunked_head(&mut v, 200, &[]).unwrap();
        write_chunk(&mut v, b"hello").unwrap();
        write_chunk(&mut v, b"").unwrap();
        write_last_chunk(&mut v, &[("X-Lab-Proof", "ab\r\nInjected: 1".into())]).unwrap();
        let s = String::from_utf8(v).unwrap();
        assert!(s.contains("\r\n\r\n5\r\nhello\r\n0\r\nX-Lab-Proof: abInjected: 1\r\n\r\n"), "{:?}", s);
    }

    #[test]
    fn base64_vectors() {
        for (i, o) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")] {
            assert_eq!(base64(i.as_bytes()), o);
        }
    }

    #[test]
    fn events_are_sealed_with_growing_seq_and_verify() {
        let key = [7u8; 32];
        let mut s = EventSealer::new(key, "n1".into());
        let e0 = s.seal("{\"event\":\"stdout\",\"data\":\"hi\"}");
        let e1 = s.seal("{}");
        assert!(e0.starts_with("{\"seq\":0,\"event\":\"stdout\"") && e0.contains(",\"mac\":\""));
        assert_eq!(verify_event(&key, "n1", &e0).unwrap().0, 0);
        assert_eq!(verify_event(&key, "n1", &e1).unwrap().0, 1);
        assert!(verify_event(&key, "other", &e0).is_none(), "nonce bound");
        assert!(verify_event(&[8u8; 32], "n1", &e0).is_none(), "key bound");
        assert!(verify_event(&key, "n1", &e0.replace("hi", "ho")).is_none(), "content bound");
        assert!(verify_event(&key, "n1", &e0.replace("\"seq\":0", "\"seq\":5")).is_none(), "seq bound");
        assert!(e0.starts_with('{') && e0.ends_with("\"}"), "{}", e0);
    }
}
