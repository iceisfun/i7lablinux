//! Small helpers over `labproto::json`: bounded parse, string quoting, field access by dotted path.

use labproto::json::{Limits, Value};

pub fn parse(s: &str) -> Option<Value> {
    labproto::json::parse(s, &Limits::default()).ok()
}

/// A JSON string literal (quotes included).
pub fn quote(s: &str) -> String {
    let mut w = labproto::json::JsonWriter::new();
    w.str(s);
    w.finish()
}

/// `a.b.c` lookup through nested objects.
pub fn path<'a>(v: &'a Value, p: &str) -> Option<&'a Value> {
    let mut cur = v;
    for part in p.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

pub fn s<'a>(v: &'a Value, p: &str) -> Option<&'a str> {
    path(v, p).and_then(Value::as_str)
}

pub fn n(v: &Value, p: &str) -> Option<f64> {
    path(v, p).and_then(Value::as_f64)
}

pub fn u(v: &Value, p: &str) -> Option<u64> {
    path(v, p).and_then(Value::as_u64)
}

/// A PCI/USB id field: the probes write `"8086"` (hex string, optionally 0x-prefixed); older bodies and tests
/// carry plain numbers.
pub fn hex_u(v: &Value, p: &str) -> Option<u64> {
    match path(v, p)? {
        Value::Str(s) => u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok(),
        other => other.as_u64(),
    }
}

/// `vvvv` of `hex_u`, `0000` when absent or unparsable.
pub fn hex4(v: &Value, p: &str) -> String {
    format!("{:04x}", hex_u(v, p).unwrap_or(0))
}

pub fn b(v: &Value, p: &str) -> Option<bool> {
    match path(v, p) {
        Some(Value::Bool(x)) => Some(*x),
        _ => None,
    }
}

pub fn arr<'a>(v: &'a Value, p: &str) -> &'a [Value] {
    path(v, p).and_then(Value::as_array).unwrap_or(&[])
}

/// First of several dotted paths that is a string.
pub fn s_any<'a>(v: &'a Value, ps: &[&str]) -> Option<&'a str> {
    ps.iter().find_map(|p| s(v, p))
}

/// `{"error":{"code":..,"message":..,"reasons":[..]}}` -> (code, message, reasons)
pub fn error_parts(body: &str) -> Option<(String, String, Vec<String>)> {
    let v = parse(body)?;
    let e = v.get("error")?;
    let code = e.get("code").and_then(Value::as_str).unwrap_or("").to_string();
    let msg = e.get("message").and_then(Value::as_str).unwrap_or("").to_string();
    let reasons = e.get("reasons").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    Some((code, msg, reasons))
}

/// Cheap string-field extraction without a parser (used where the input may be a plain token or tiny JSON).
pub fn scan_str_field(text: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\"", key);
    let i = text.find(&pat)? + pat.len();
    let rest = text[i..].trim_start().strip_prefix(':')?.trim_start().strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quoting_and_scan() {
        assert_eq!(quote("a\"b\n"), "\"a\\\"b\\n\"");
        assert_eq!(scan_str_field("{\"nonce\": \"ab12\"}", "nonce").as_deref(), Some("ab12"));
        assert_eq!(scan_str_field("{}", "nonce"), None);
    }
}

/// Serialise a parsed value back to compact JSON (numbers that are integers print without a fraction).
pub fn to_json(v: &Value) -> String {
    let mut w = labproto::json::JsonWriter::new();
    write_value(&mut w, v);
    w.finish()
}

fn write_value(w: &mut labproto::json::JsonWriter, v: &Value) {
    match v {
        Value::Null => w.null(),
        Value::Bool(b) => w.bool(*b),
        Value::Num(n) => {
            if n.fract() == 0.0 && n.abs() < 9.0e15 {
                w.i64(*n as i64)
            } else {
                w.f64(*n)
            }
        }
        Value::Str(s) => w.str(s),
        Value::Arr(a) => {
            w.begin_array();
            for x in a {
                write_value(w, x);
            }
            w.end_array();
        }
        Value::Obj(o) => {
            w.begin_object();
            for (k, x) in o {
                w.key(k);
                write_value(w, x);
            }
            w.end_object();
        }
    }
}
