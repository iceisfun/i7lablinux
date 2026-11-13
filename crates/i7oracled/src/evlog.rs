//! Durable power-event log: one JSON object per line, strictly increasing `seq`, fsync after every record.
//!
//! Line format (all on one line, `seq` always first so a tail scan can find it cheaply):
//! `{"seq":42,"src":"svc-ctl","kind":"pbt","utc":"...","wall_100ns":..,"qpc":..,"qpc_hz":..,"tick_ms":..,
//!   "unb_100ns":..,"int_100ns":..,"data":{...}}`
//! A torn last line (power loss mid-write) is ignored by readers and cut off from the next record by a newline.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::json::JsonWriter;
use crate::stamp::Stamp;

pub struct EventLog {
    file: File,
    next_seq: u64,
}

pub fn json_str(s: &str) -> String {
    let mut w = JsonWriter::new();
    w.str(s);
    w.finish()
}

/// A record body (a JSON object WITHOUT seq). `data_json` must already be one valid JSON value.
pub fn record(src: &str, kind: &str, stamp: &Stamp, data_json: &str) -> String {
    format!("{{\"src\":{},\"kind\":{},{},\"data\":{}}}", json_str(src), json_str(kind), stamp.json_fields(), data_json)
}

/// Pull `seq` out of a complete log line.
pub fn line_seq(line: &str) -> Option<u64> {
    let rest = line.strip_prefix("{\"seq\":")?;
    if !line.ends_with('}') {
        return None;
    }
    let end = rest.find(|c: char| !c.is_ascii_digit())?;
    if end == 0 {
        return None;
    }
    rest[..end].parse().ok()
}

impl EventLog {
    /// Open (creating directories), find the last durable seq, and make sure the next record starts on a new line.
    pub fn open(path: &Path) -> io::Result<EventLog> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let last = last_seq_in(path)?;
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        let len = file.metadata()?.len();
        if len > 0 {
            let mut r = File::open(path)?;
            r.seek(SeekFrom::Start(len - 1))?;
            let mut b = [0u8; 1];
            r.read_exact(&mut b)?;
            if b[0] != b'\n' {
                file.write_all(b"\n")?;
                file.sync_all()?;
            }
        }
        Ok(EventLog { file, next_seq: last + 1 })
    }

    pub fn last_seq(&self) -> u64 {
        self.next_seq - 1
    }

    /// Append `body` (a JSON object without seq), return its seq. The record is on stable storage when this returns.
    pub fn append(&mut self, body: &str) -> io::Result<u64> {
        let rest = body.strip_prefix('{').filter(|r| body.ends_with('}') && !r.contains('\n')).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "record must be a one-line JSON object"))?;
        let seq = self.next_seq;
        let mut line = format!("{{\"seq\":{},", seq);
        line.push_str(rest);
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.sync_all()?;
        self.next_seq += 1;
        Ok(seq)
    }
}

fn last_seq_in(path: &Path) -> io::Result<u64> {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let len = f.metadata()?.len();
    // lines are bounded (a few tens of KiB at most); look back in growing windows until a complete line is found
    let mut window: u64 = 64 << 10;
    loop {
        let start = len.saturating_sub(window);
        f.seek(SeekFrom::Start(start))?;
        let mut buf = Vec::new();
        (&mut f).take(len - start).read_to_end(&mut buf)?;
        let text = String::from_utf8_lossy(&buf);
        let mut lines: Vec<&str> = text.split('\n').collect();
        if start > 0 && !lines.is_empty() {
            lines.remove(0); // possibly cut in the middle
        }
        for l in lines.iter().rev() {
            if let Some(s) = line_seq(l) {
                return Ok(s);
            }
        }
        if start == 0 {
            return Ok(0);
        }
        window *= 4;
    }
}

/// Lines with seq > `since`, at most `limit` lines and `max_bytes` bytes. Returns (lines, last seq returned or `since`).
pub fn read_since(path: &Path, since: u64, limit: usize, max_bytes: usize) -> io::Result<(Vec<String>, u64)> {
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), since)),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    let mut last = since;
    let mut bytes = 0usize;
    for line in BufReader::new(f).lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue, // invalid UTF-8 in a torn line
        };
        let Some(s) = line_seq(&line) else { continue };
        if s <= since {
            continue;
        }
        if out.len() >= limit || bytes + line.len() > max_bytes {
            break;
        }
        bytes += line.len() + 1;
        last = s;
        out.push(line);
    }
    Ok((out, last))
}

pub fn path_in(dir: &Path) -> PathBuf {
    dir.join("power-events.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("i7oracled-evlog-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("power-events.jsonl")
    }

    #[test]
    fn append_and_resume() {
        let p = tmp("resume");
        let st = Stamp::now();
        {
            let mut l = EventLog::open(&p).unwrap();
            assert_eq!(l.last_seq(), 0);
            assert_eq!(l.append(&record("t", "a", &st, "{}")).unwrap(), 1);
            assert_eq!(l.append(&record("t", "b", &st, "{\"x\":1}")).unwrap(), 2);
        }
        let mut l = EventLog::open(&p).unwrap();
        assert_eq!(l.last_seq(), 2);
        assert_eq!(l.append(&record("t", "c", &st, "null")).unwrap(), 3);
        let (lines, last) = read_since(&p, 1, 10, 1 << 20).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(last, 3);
        assert!(lines[0].starts_with("{\"seq\":2,\"src\":\"t\",\"kind\":\"b\","));
        for l in &lines {
            assert!(crate::json::parse(l, &crate::json::Limits::default()).is_ok(), "{}", l);
        }
        let (none, last) = read_since(&p, 3, 10, 1 << 20).unwrap();
        assert!(none.is_empty());
        assert_eq!(last, 3);
        let (lim, _) = read_since(&p, 0, 2, 1 << 20).unwrap();
        assert_eq!(lim.len(), 2);
    }

    #[test]
    fn torn_tail_is_skipped_and_fenced() {
        let p = tmp("torn");
        let st = Stamp::now();
        {
            let mut l = EventLog::open(&p).unwrap();
            l.append(&record("t", "a", &st, "{}")).unwrap();
            l.append(&record("t", "b", &st, "{}")).unwrap();
        }
        // power loss in the middle of record 3
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"{\"seq\":3,\"src\":\"t\",\"kind\":\"c\",\"utc\":\"20").unwrap();
        drop(f);
        let mut l = EventLog::open(&p).unwrap();
        assert_eq!(l.last_seq(), 2, "torn record 3 is not durable");
        assert_eq!(l.append(&record("t", "d", &st, "{}")).unwrap(), 3);
        let (lines, last) = read_since(&p, 0, 100, 1 << 20).unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(last, 3);
        assert!(lines[2].contains("\"kind\":\"d\""));
    }

    #[test]
    fn rejects_bad_bodies() {
        let p = tmp("bad");
        let mut l = EventLog::open(&p).unwrap();
        assert!(l.append("not json").is_err());
        assert!(l.append("{\"a\":\n1}").is_err());
        assert_eq!(l.last_seq(), 0);
    }

    #[test]
    fn big_line_before_tail_window() {
        let p = tmp("big");
        let st = Stamp::now();
        let mut l = EventLog::open(&p).unwrap();
        l.append(&record("t", "small", &st, "{}")).unwrap();
        let big = format!("{{\"t\":{}}}", json_str(&"x".repeat(200_000)));
        l.append(&record("t", "big", &st, &big)).unwrap();
        drop(l);
        assert_eq!(EventLog::open(&p).unwrap().last_seq(), 2);
    }
}
