//! Human tables, `--json` envelope, NDJSON events, sanitised output. All remote strings pass
//! `labproto::text::sanitize` before they reach a terminal. Owner: P9.

use labproto::json::JsonWriter;
use labproto::text::sanitize;

use crate::jv;

/// ANSI styling that switches off with `--no-color`, `NO_COLOR` or a non-terminal stdout.
#[derive(Clone, Copy)]
pub struct Paint {
    pub on: bool,
}

impl Paint {
    fn wrap(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("\x1b[{}m{}\x1b[0m", code, s)
        } else {
            s.to_string()
        }
    }
    pub fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    pub fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    pub fn red(&self, s: &str) -> String {
        self.wrap("31", s)
    }
    pub fn green(&self, s: &str) -> String {
        self.wrap("32", s)
    }
    pub fn yellow(&self, s: &str) -> String {
        self.wrap("33", s)
    }
}

/// Sanitise and shorten a remote string for a table cell.
pub fn cell(s: &str, max: usize) -> String {
    let c = sanitize(s);
    if c.chars().count() <= max {
        c.into_owned()
    } else {
        let mut t: String = c.chars().take(max.saturating_sub(1)).collect();
        t.push('~');
        t
    }
}

pub struct Table {
    headers: Vec<String>,
    right: Vec<bool>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new(headers: &[&str]) -> Table {
        Table { headers: headers.iter().map(|h| h.to_string()).collect(), right: vec![false; headers.len()], rows: Vec::new() }
    }
    /// Right-align a column (numbers).
    pub fn right(mut self, col: usize) -> Table {
        if col < self.right.len() {
            self.right[col] = true;
        }
        self
    }
    /// Cells are sanitised and cut to 48 characters here; callers pass raw remote strings.
    pub fn row<S: AsRef<str>>(&mut self, cells: &[S]) {
        let mut r: Vec<String> = cells.iter().map(|c| cell(c.as_ref(), 48)).collect();
        r.resize(self.headers.len(), String::new());
        self.rows.push(r);
    }
    pub fn len(&self) -> usize {
        self.rows.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
    pub fn render(&self, p: Paint) -> String {
        let n = self.headers.len();
        let mut w: Vec<usize> = self.headers.iter().map(|h| h.chars().count()).collect();
        for r in &self.rows {
            for (i, c) in r.iter().enumerate().take(n) {
                w[i] = w[i].max(c.chars().count());
            }
        }
        let line = |cells: &[String], head: bool| -> String {
            let mut s = String::new();
            for (i, c) in cells.iter().enumerate().take(n) {
                let pad = w[i] - c.chars().count();
                let last = i + 1 == n;
                let text = if head { p.bold(c) } else { c.clone() };
                if self.right[i] {
                    s.push_str(&" ".repeat(pad));
                    s.push_str(&text);
                } else {
                    s.push_str(&text);
                    if !last {
                        s.push_str(&" ".repeat(pad));
                    }
                }
                if !last {
                    s.push_str("  ");
                }
            }
            s.push('\n');
            s
        };
        let mut out = line(&self.headers, true);
        for r in &self.rows {
            out.push_str(&line(r, false));
        }
        out
    }
}

/// `key  value` block with aligned values (sanitised).
pub fn kv_block(rows: &[(&str, String)], p: Paint) -> String {
    let w = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let mut s = String::new();
    for (k, v) in rows {
        s.push_str(&format!("{}  {}\n", p.dim(&format!("{:<w$}", k, w = w)), sanitize(v)));
    }
    s
}

pub fn fmt_bytes(b: u64) -> String {
    const U: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < U.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} B", b)
    } else {
        format!("{:.1} {}", v, U[i])
    }
}

pub fn fmt_secs(s: u64) -> String {
    let (d, h, m) = (s / 86400, s % 86400 / 3600, s % 3600 / 60);
    if d > 0 {
        format!("{}d{:02}h", d, h)
    } else if h > 0 {
        format!("{}h{:02}m", h, m)
    } else if m > 0 {
        format!("{}m{:02}s", m, s % 60)
    } else {
        format!("{}s", s)
    }
}

pub fn fmt_age(secs: u64) -> String {
    if secs < 120 {
        format!("{}s", secs)
    } else if secs < 7200 {
        format!("{}m", secs / 60)
    } else if secs < 172_800 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// What the envelope says about the host.
#[derive(Clone, Debug, Default)]
pub struct HostInfo {
    pub mac: Option<String>,
    pub ip: Option<String>,
    pub vlan: Option<u16>,
    pub serial: Option<String>,
    pub boot: Option<String>,
}

fn host_obj(w: &mut JsonWriter, h: &HostInfo) {
    w.key("host");
    w.begin_object();
    w.field_opt_str("mac", h.mac.as_deref());
    w.field_opt_str("ip", h.ip.as_deref());
    w.field_opt_u64("vlan", h.vlan.map(u64::from));
    w.field_opt_str("serial", h.serial.as_deref());
    w.field_opt_str("boot", h.boot.as_deref());
    w.end_object();
}

/// Is `s` plausibly one JSON value (so it can be embedded unquoted)?
pub fn looks_like_json(s: &str) -> bool {
    let t = s.trim();
    let Some(c) = t.chars().next() else { return false };
    match c {
        '{' => t.ends_with('}'),
        '[' => t.ends_with(']'),
        '"' => t.len() >= 2 && t.ends_with('"'),
        't' | 'f' | 'n' | '-' | '0'..='9' => t == "true" || t == "false" || t == "null" || t.parse::<f64>().is_ok(),
        _ => false,
    }
}

/// `{"ok":true,"transport":..,"host":{..},"cmd":..,"rtt_ms":..,"data":<server JSON>}`
pub fn ok_envelope(transport: &str, host: Option<&HostInfo>, cmd: &str, rtt_ms: Option<f64>, data: &str) -> String {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_bool("ok", true);
    w.field_str("transport", transport);
    if let Some(h) = host {
        host_obj(&mut w, h);
    }
    w.field_str("cmd", cmd);
    if let Some(r) = rtt_ms {
        w.field_f64("rtt_ms", (r * 10.0).round() / 10.0);
    }
    w.key("data");
    let d = data.trim();
    if d.is_empty() {
        w.null();
    } else if looks_like_json(d) {
        w.raw(d);
    } else {
        w.str(d);
    }
    w.end_object();
    w.finish()
}

#[derive(Clone, Debug)]
pub struct ErrInfo<'a> {
    pub code: &'a str,
    /// remote status number, if the host answered
    pub status: Option<u16>,
    pub exit: i32,
    pub message: &'a str,
    pub reasons: &'a [String],
}

pub fn err_envelope(transport: Option<&str>, host: Option<&HostInfo>, cmd: &str, e: &ErrInfo) -> String {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_bool("ok", false);
    if let Some(t) = transport {
        w.field_str("transport", t);
    }
    if let Some(h) = host {
        host_obj(&mut w, h);
    }
    w.field_str("cmd", cmd);
    w.key("error");
    w.begin_object();
    w.field_str("code", e.code);
    w.field_opt_u64("status", e.status.map(u64::from));
    w.field_i64("exit", i64::from(e.exit));
    w.field_str("message", e.message);
    w.key("reasons");
    w.begin_array();
    for r in e.reasons {
        w.str(r);
    }
    w.end_array();
    w.end_object();
    w.end_object();
    w.finish()
}

/// NDJSON `{"event":"stdout","data":"..."}` (or `"b64"` for bytes that are not UTF-8).
pub fn data_event(kind: &str, bytes: &[u8]) -> String {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_str("event", kind);
    match std::str::from_utf8(bytes) {
        Ok(s) => w.field_str("data", s),
        Err(_) => w.field_str("b64", &b64(bytes)),
    }
    w.end_object();
    w.finish()
}

/// Final NDJSON line of a streaming command.
pub fn result_event(ok: bool, exit: i32, extra_raw: Option<&str>) -> String {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_str("event", "result");
    w.field_bool("ok", ok);
    w.field_i64("exit", i64::from(exit));
    if let Some(x) = extra_raw.filter(|x| looks_like_json(x)) {
        w.key("data");
        w.raw(x.trim());
    }
    w.end_object();
    w.finish()
}

/// Final NDJSON line of a failed streaming command.
pub fn result_error_event(e: &ErrInfo) -> String {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.field_str("event", "result");
    w.field_bool("ok", false);
    w.field_i64("exit", i64::from(e.exit));
    w.key("error");
    w.begin_object();
    w.field_str("code", e.code);
    w.field_opt_u64("status", e.status.map(u64::from));
    w.field_str("message", e.message);
    w.key("reasons");
    w.begin_array();
    for r in e.reasons {
        w.str(r);
    }
    w.end_array();
    w.end_object();
    w.end_object();
    w.finish()
}

pub fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    s
}

pub fn unb64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = acc << 6 | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Message for a non-OK remote reply: the server's error body if it has one, else the status name.
pub fn remote_error_text(status_name: &str, body: &str) -> (String, Vec<String>) {
    if let Some((code, msg, reasons)) = jv::error_parts(body) {
        let head = if code.is_empty() { status_name.to_string() } else { sanitize(&code).into_owned() };
        let text = if msg.is_empty() { head } else { format!("{}: {}", head, sanitize(&msg)) };
        return (text, reasons);
    }
    let t = body.trim();
    if t.is_empty() {
        (status_name.to_string(), Vec::new())
    } else {
        (format!("{}: {}", status_name, sanitize(t)), Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_aligns_and_sanitises() {
        let mut t = Table::new(&["MAC", "N"]).right(1);
        t.row(&["aa", "1"]);
        t.row(&["b\x1b[2Jb", "100"]);
        let s = t.render(Paint { on: false });
        assert!(!s.contains('\x1b'), "{:?}", s);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[1].ends_with("  1"), "{:?}", lines[1]);
        assert!(lines[2].ends_with("100"));
    }

    #[test]
    fn cell_cuts() {
        assert_eq!(cell("abcdef", 4), "abc~");
        assert_eq!(cell("ab", 4), "ab");
    }

    #[test]
    fn envelopes() {
        let h = HostInfo { mac: Some("02:00:00:9d:01:57".into()), vlan: None, ..Default::default() };
        let e = ok_envelope("ether", Some(&h), "inv", Some(0.84), "{\"a\":1}");
        assert_eq!(e, "{\"ok\":true,\"transport\":\"ether\",\"host\":{\"mac\":\"02:00:00:9d:01:57\",\"ip\":null,\"vlan\":null,\"serial\":null,\"boot\":null},\"cmd\":\"inv\",\"rtt_ms\":0.8,\"data\":{\"a\":1}}");
        let e = ok_envelope("http", None, "ping", None, "not json");
        assert!(e.ends_with("\"data\":\"not json\"}"), "{}", e);
        let e = ok_envelope("http", None, "ping", None, "");
        assert!(e.ends_with("\"data\":null}"));
        let r = vec!["mounted".to_string()];
        let e = err_envelope(Some("ether"), None, "blk.write", &ErrInfo { code: "REFUSED", status: Some(5), exit: 7, message: "device mounted", reasons: &r });
        assert!(e.contains("\"code\":\"REFUSED\"") && e.contains("\"exit\":7") && e.contains("\"reasons\":[\"mounted\"]"), "{}", e);
    }

    #[test]
    fn ndjson_events() {
        assert_eq!(data_event("stdout", b"hi\n"), "{\"event\":\"stdout\",\"data\":\"hi\\n\"}");
        assert_eq!(data_event("stderr", &[0xff, 0x00]), "{\"event\":\"stderr\",\"b64\":\"/wA=\"}");
        assert_eq!(result_event(true, 0, None), "{\"event\":\"result\",\"ok\":true,\"exit\":0}");
        assert_eq!(b64(b"abc"), "YWJj");
        assert_eq!(b64(b"ab"), "YWI=");
        assert_eq!(unb64("YWJj").unwrap(), b"abc");
        assert_eq!(unb64("/wA=").unwrap(), vec![0xff, 0]);
        assert!(unb64("a$b").is_none());
    }

    #[test]
    fn units() {
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1536 * 1024), "1.5 MiB");
        assert_eq!(fmt_secs(3700), "1h01m");
        assert_eq!(fmt_age(30), "30s");
        assert_eq!(fmt_age(86400 * 3), "3d");
    }

    #[test]
    fn json_detection() {
        assert!(looks_like_json("{}") && looks_like_json("[1]") && looks_like_json("12") && looks_like_json("true"));
        assert!(!looks_like_json("hello") && !looks_like_json("{") && !looks_like_json(""));
    }
}
