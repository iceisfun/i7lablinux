//! Hand-written JSON writer and bounded parser. Owner: P1.
//! Port of the earlier lab-proxy prototype (parser).

/// Compact JSON writer. Comma placement is automatic.
pub struct JsonWriter {
    buf: String,
    need_comma: Vec<bool>,
    after_key: bool,
}

pub trait ToJson {
    fn write_json(&self, w: &mut JsonWriter);
}

pub fn to_json<T: ToJson + ?Sized>(v: &T) -> String {
    let mut w = JsonWriter::new();
    v.write_json(&mut w);
    w.finish()
}

impl Default for JsonWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl JsonWriter {
    pub fn new() -> Self {
        JsonWriter { buf: String::new(), need_comma: Vec::new(), after_key: false }
    }
    pub fn finish(self) -> String {
        self.buf
    }

    fn pre(&mut self) {
        if self.after_key {
            self.after_key = false;
            return;
        }
        if let Some(c) = self.need_comma.last_mut() {
            if *c {
                self.buf.push(',');
            }
            *c = true;
        }
    }

    fn escape(&mut self, s: &str) {
        self.buf.push('"');
        for ch in s.chars() {
            match ch {
                '"' => self.buf.push_str("\\\""),
                '\\' => self.buf.push_str("\\\\"),
                '\n' => self.buf.push_str("\\n"),
                '\r' => self.buf.push_str("\\r"),
                '\t' => self.buf.push_str("\\t"),
                c if (c as u32) < 0x20 => self.buf.push_str(&format!("\\u{:04x}", c as u32)),
                c => self.buf.push(c),
            }
        }
        self.buf.push('"');
    }

    pub fn begin_object(&mut self) {
        self.pre();
        self.buf.push('{');
        self.need_comma.push(false);
    }
    pub fn end_object(&mut self) {
        self.need_comma.pop();
        self.buf.push('}');
    }
    pub fn begin_array(&mut self) {
        self.pre();
        self.buf.push('[');
        self.need_comma.push(false);
    }
    pub fn end_array(&mut self) {
        self.need_comma.pop();
        self.buf.push(']');
    }
    pub fn key(&mut self, k: &str) {
        self.pre();
        self.escape(k);
        self.buf.push(':');
        self.after_key = true;
    }
    pub fn str(&mut self, v: &str) {
        self.pre();
        self.escape(v);
    }
    pub fn opt_str(&mut self, v: Option<&str>) {
        match v {
            Some(s) => self.str(s),
            None => self.null(),
        }
    }
    pub fn u64(&mut self, v: u64) {
        self.pre();
        self.buf.push_str(&v.to_string());
    }
    pub fn i64(&mut self, v: i64) {
        self.pre();
        self.buf.push_str(&v.to_string());
    }
    /// NaN and infinities are written as `null`.
    pub fn f64(&mut self, v: f64) {
        self.pre();
        if v.is_finite() {
            self.buf.push_str(&format!("{}", v));
        } else {
            self.buf.push_str("null");
        }
    }
    pub fn bool(&mut self, v: bool) {
        self.pre();
        self.buf.push_str(if v { "true" } else { "false" });
    }
    pub fn null(&mut self) {
        self.pre();
        self.buf.push_str("null");
    }
    /// Insert pre-serialised JSON (must be one valid value).
    pub fn raw(&mut self, json: &str) {
        self.pre();
        self.buf.push_str(json);
    }
    pub fn value<T: ToJson + ?Sized>(&mut self, v: &T) {
        v.write_json(self);
    }

    pub fn field_str(&mut self, k: &str, v: &str) {
        self.key(k);
        self.str(v);
    }
    pub fn field_opt_str(&mut self, k: &str, v: Option<&str>) {
        self.key(k);
        self.opt_str(v);
    }
    pub fn field_u64(&mut self, k: &str, v: u64) {
        self.key(k);
        self.u64(v);
    }
    pub fn field_opt_u64(&mut self, k: &str, v: Option<u64>) {
        self.key(k);
        match v {
            Some(x) => self.u64(x),
            None => self.null(),
        }
    }
    pub fn field_i64(&mut self, k: &str, v: i64) {
        self.key(k);
        self.i64(v);
    }
    pub fn field_f64(&mut self, k: &str, v: f64) {
        self.key(k);
        self.f64(v);
    }
    pub fn field_opt_f64(&mut self, k: &str, v: Option<f64>) {
        self.key(k);
        match v {
            Some(x) => self.f64(x),
            None => self.null(),
        }
    }
    pub fn field_bool(&mut self, k: &str, v: bool) {
        self.key(k);
        self.bool(v);
    }
}

impl ToJson for str {
    fn write_json(&self, w: &mut JsonWriter) {
        w.str(self)
    }
}
impl ToJson for String {
    fn write_json(&self, w: &mut JsonWriter) {
        w.str(self)
    }
}
impl<T: ToJson> ToJson for [T] {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_array();
        for x in self {
            x.write_json(w);
        }
        w.end_array();
    }
}
impl<T: ToJson> ToJson for Vec<T> {
    fn write_json(&self, w: &mut JsonWriter) {
        self.as_slice().write_json(w)
    }
}
impl<T: ToJson> ToJson for Option<T> {
    fn write_json(&self, w: &mut JsonWriter) {
        match self {
            Some(v) => v.write_json(w),
            None => w.null(),
        }
    }
}

/// Parsed JSON value. Object keys keep their order.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(kv) => kv.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Num(n) => Some(*n),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        self.as_f64().filter(|n| *n >= 0.0 && n.fract() == 0.0 && *n <= 9.007_199_254_740_992e15).map(|n| n as u64)
    }
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Arr(a) => Some(a),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_items: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_bytes: 16 << 20, max_depth: 64, max_items: 1 << 20 }
    }
}

#[derive(Debug, PartialEq)]
pub struct JsonError {
    pub offset: usize,
    pub msg: &'static str,
}

/// Bounded recursive-descent parser (RFC 8259): depth, total size and container item counts are capped by `limits`;
/// duplicate keys are kept in order (`Value::get` returns the first); trailing garbage is an error.
pub fn parse(s: &str, limits: &Limits) -> Result<Value, JsonError> {
    if s.len() > limits.max_bytes {
        return Err(JsonError { offset: 0, msg: "input too large" });
    }
    let mut p = Parser { b: s.as_bytes(), i: 0, limits, items: 0 };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.b.len() {
        return Err(p.err("trailing characters"));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    limits: &'a Limits,
    items: usize,
}

impl Parser<'_> {
    fn err(&self, msg: &'static str) -> JsonError {
        JsonError { offset: self.i, msg }
    }
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    fn count(&mut self) -> Result<(), JsonError> {
        self.items += 1;
        if self.items > self.limits.max_items {
            Err(self.err("too many items"))
        } else {
            Ok(())
        }
    }
    fn lit(&mut self, word: &str, v: Value) -> Result<Value, JsonError> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(self.err("bad literal"))
        }
    }
    fn value(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth > self.limits.max_depth {
            return Err(self.err("nesting too deep"));
        }
        self.count()?;
        match self.b.get(self.i) {
            None => Err(self.err("unexpected end")),
            Some(b'n') => self.lit("null", Value::Null),
            Some(b't') => self.lit("true", Value::Bool(true)),
            Some(b'f') => self.lit("false", Value::Bool(false)),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b'[') => {
                self.i += 1;
                let mut v = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(Value::Arr(v));
                }
                loop {
                    self.ws();
                    v.push(self.value(depth + 1)?);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Value::Arr(v));
                        }
                        _ => return Err(self.err("expected , or ]")),
                    }
                }
            }
            Some(b'{') => {
                self.i += 1;
                let mut v = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(Value::Obj(v));
                }
                loop {
                    self.ws();
                    if self.b.get(self.i) != Some(&b'"') {
                        return Err(self.err("expected object key"));
                    }
                    self.count()?;
                    let k = self.string()?;
                    self.ws();
                    if self.b.get(self.i) != Some(&b':') {
                        return Err(self.err("expected :"));
                    }
                    self.i += 1;
                    self.ws();
                    v.push((k, self.value(depth + 1)?));
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Value::Obj(v));
                        }
                        _ => return Err(self.err("expected , or }")),
                    }
                }
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.err("unexpected character")),
        }
    }
    fn number(&mut self) -> Result<Value, JsonError> {
        let st = self.i;
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        match self.b.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err(self.err("bad number")),
        }
        if self.b.get(self.i) == Some(&b'.') {
            self.i += 1;
            if !matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
                return Err(self.err("bad number"));
            }
            while matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        if matches!(self.b.get(self.i), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.b.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
                return Err(self.err("bad number"));
            }
            while matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        // the slice is ASCII digits/sign/./e only
        let t = std::str::from_utf8(&self.b[st..self.i]).map_err(|_| self.err("bad number"))?;
        let n: f64 = t.parse().map_err(|_| self.err("bad number"))?;
        if !n.is_finite() {
            return Err(self.err("number out of range"));
        }
        Ok(Value::Num(n))
    }
    fn hex4(&mut self) -> Result<u32, JsonError> {
        if self.i + 4 > self.b.len() {
            return Err(self.err("bad \\u escape"));
        }
        let mut n = 0u32;
        for k in 0..4 {
            let d = (self.b[self.i + k] as char).to_digit(16).ok_or_else(|| self.err("bad \\u escape"))?;
            n = n * 16 + d;
        }
        self.i += 4;
        Ok(n)
    }
    fn string(&mut self) -> Result<String, JsonError> {
        self.i += 1; // opening quote
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = *self.b.get(self.i).ok_or_else(|| self.err("unterminated string"))?;
            match c {
                b'"' => {
                    self.i += 1;
                    // the input came from a &str and escapes only add valid UTF-8, so this cannot fail
                    return String::from_utf8(out).map_err(|_| self.err("invalid utf-8"));
                }
                b'\\' => {
                    self.i += 1;
                    let e = *self.b.get(self.i).ok_or_else(|| self.err("unterminated string"))?;
                    self.i += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.b.get(self.i) == Some(&b'\\') && self.b.get(self.i + 1) == Some(&b'u') {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..0xE000).contains(&lo) {
                                        return Err(self.err("bad surrogate pair"));
                                    }
                                    0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                                } else {
                                    return Err(self.err("lone surrogate"));
                                }
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(self.err("lone surrogate"));
                            } else {
                                hi
                            };
                            char::from_u32(cp).ok_or_else(|| self.err("bad code point"))?
                        }
                        _ => return Err(self.err("bad escape")),
                    };
                    let mut tmp = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
                }
                0..=0x1f => return Err(self.err("control character in string")),
                _ => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn writer_commas_and_escapes() {
        let mut w = JsonWriter::new();
        w.begin_object();
        w.field_u64("v", 1);
        w.field_str("s", "a\"b\\\n");
        w.key("a");
        w.begin_array();
        w.u64(1);
        w.null();
        w.f64(f64::NAN);
        w.end_array();
        w.end_object();
        assert_eq!(w.finish(), r#"{"v":1,"s":"a\"b\\\n","a":[1,null,null]}"#);
    }

    #[test]
    fn parse_basic_and_roundtrip() {
        let l = Limits::default();
        let v = parse(r#" {"a":[1,2.5,-3e2,true,false,null],"s":"x\n\u00e9\ud83d\ude00","o":{}} "#, &l).unwrap();
        assert_eq!(v.get("a").unwrap().as_array().unwrap().len(), 6);
        assert_eq!(v.get("a").unwrap().as_array().unwrap()[2], Value::Num(-300.0));
        assert_eq!(v.get("s").unwrap().as_str(), Some("x\n\u{e9}\u{1f600}"));
        assert_eq!(v.get("o"), Some(&Value::Obj(vec![])));
        let mut w = JsonWriter::new();
        w.begin_object();
        w.field_str("k", "a\"b\\\n\u{1}");
        w.end_object();
        let back = parse(&w.finish(), &l).unwrap();
        assert_eq!(back.get("k").unwrap().as_str(), Some("a\"b\\\n\u{1}"));
    }

    #[test]
    fn parse_rejects_malformed() {
        let l = Limits::default();
        for bad in ["", "{", "[1,]", "{\"a\"}", "{'a':1}", "01", "1.", "-", "\"a", "\"\\x\"", "\"\\ud800\"", "nul", "[1] x", "\"a\nb\"", "1e999", "{\"a\":1,}", "[,1]"] {
            assert!(parse(bad, &l).is_err(), "{bad:?} should fail");
        }
    }

    #[test]
    fn parse_limits() {
        let deep = "[".repeat(100) + &"]".repeat(100);
        assert!(parse(&deep, &Limits::default()).is_err());
        assert!(parse(&deep, &Limits { max_depth: 200, ..Limits::default() }).is_ok());
        assert!(parse("[1,2,3,4]", &Limits { max_items: 3, ..Limits::default() }).is_err());
        assert!(parse("[1]", &Limits { max_bytes: 2, ..Limits::default() }).is_err());
    }
}
