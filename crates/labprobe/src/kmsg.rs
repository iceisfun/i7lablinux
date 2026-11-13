//! kmsg: /dev/kmsg structured records, classifier tags (pcie-aer, mce, ata-error, nvme-timeout, ...). Owner: P3.

use labproto::json::{JsonWriter, ToJson};

use crate::ctx::{ProbeCtx, ProbeError};

#[derive(Clone, Debug, Default)]
pub struct KmsgOpts {
    /// last N records (default 200)
    pub last: Option<usize>,
    pub since_seq: Option<u64>,
    pub max_level: Option<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct KmsgLine {
    pub seq: u64,
    pub level: u8,
    pub ts_us: u64,
    pub text: String,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct KmsgReport {
    pub lines: Vec<KmsgLine>,
}

/// Parse one /dev/kmsg record: "pri,seq,ts_us,flags[,..];text\n KEY=VALUE\n...". Only the first text line is
/// kept (the continuation lines are the structured dictionary). `ts_us` is the monotonic time in microseconds.
pub fn parse_record(rec: &str) -> Option<KmsgLine> {
    let (head, rest) = rec.split_once(';')?;
    let mut it = head.split(',');
    let pri: u32 = it.next()?.parse().ok()?;
    let seq = it.next()?.parse().ok()?;
    let ts_us = it.next()?.parse().ok()?;
    let text = rest.split('\n').next().unwrap_or("").trim_end().to_string();
    let tags = classify(&text);
    Some(KmsgLine { seq, level: (pri & 7) as u8, ts_us, text, tags })
}

/// Parse a text dump of records (one record per line starting with `pri,seq,ts,flags;`; lines starting with a
/// space are dictionary continuations and are ignored). Used for fixture trees and saved dumps.
pub fn parse_dump(text: &str) -> Vec<KmsgLine> {
    text.lines().filter(|l| !l.starts_with(' ')).filter_map(parse_record).collect()
}

/// Tags for lines worth the operator's attention. A line may carry several tags.
pub fn classify(text: &str) -> Vec<String> {
    let has = |pats: &[&str]| pats.iter().any(|p| text.contains(p));
    let lower = text.to_ascii_lowercase();
    let mut t: Vec<&str> = Vec::new();
    // "AER: enabled with IRQ 24" is the driver announcing itself, not an error report
    if has(&["AER:", "pcieport"]) && (lower.contains("error") || lower.contains("corrected") || lower.contains("fatal")) {
        t.push("pcie-aer");
    }
    if has(&["Machine check", "mce:", "MCE:", "Hardware Error"]) {
        t.push("mce");
    }
    if lower.starts_with("ata") && (lower.contains("error") || lower.contains("failed") || lower.contains("exception") || lower.contains("hard resetting link") || lower.contains("serror")) {
        t.push("ata-error");
    }
    if lower.contains("nvme") && (lower.contains("timeout") || lower.contains("controller is down") || lower.contains("reset")) {
        t.push("nvme-timeout");
    }
    if has(&["Out of memory", "oom-kill", "Killed process"]) {
        t.push("oom");
    }
    if has(&["BUG:", "Oops:", "general protection fault", "kernel BUG", "Call Trace:", "RIP:"]) {
        t.push("oops");
    }
    if has(&["soft lockup", "hard LOCKUP", "NMI watchdog", "rcu_sched self-detected stall", "blocked for more than"]) {
        t.push("lockup");
    }
    if has(&["I/O error", "blk_update_request", "EXT4-fs error", "Buffer I/O error", "critical medium error"]) {
        t.push("io-error");
    }
    // "ata5: SATA link down (SStatus 0 ...)" is an empty port at boot, not a fault
    if (lower.contains("link is down") || lower.contains("link down") || lower.contains("nic link is down")) && !lower.starts_with("ata") {
        t.push("link-down");
    }
    if lower.contains("thermal") && (lower.contains("throttl") || lower.contains("critical") || lower.contains("above threshold")) || lower.contains("temperature above threshold") {
        t.push("thermal");
    }
    if lower.starts_with("usb ") && (lower.contains("disconnect") || lower.contains("error -") || lower.contains("device descriptor read") || lower.contains("unable to enumerate")) {
        t.push("usb-error");
    }
    // regulatory.db is the optional Wi-Fi regulatory database: its absence is expected on this image
    if (lower.contains("direct firmware load for") && lower.contains("failed") || lower.contains("firmware: failed to load")) && !lower.contains("regulatory.db") {
        t.push("fw-missing");
    }
    t.into_iter().map(str::to_string).collect()
}

/// Last records of the kernel log. Live: non-blocking read of /dev/kmsg (one record per read(2); EAGAIN = end;
/// EPIPE = overwritten, retry). Fixture: a text dump in the same file. `since_seq` and `max_level` filter, `last`
/// (default 200) caps the result to the newest records.
pub fn read(ctx: &ProbeCtx, opts: &KmsgOpts) -> Result<KmsgReport, ProbeError> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let path = ctx.path("/dev/kmsg");
    let mut all: Vec<KmsgLine> = Vec::new();
    let md = std::fs::metadata(&path)?;
    if md.is_file() {
        all = parse_dump(&String::from_utf8_lossy(&std::fs::read(&path)?));
    } else {
        let mut f = std::fs::OpenOptions::new().read(true).custom_flags(0o4000 /* O_NONBLOCK */ | 0o2000000).open(&path)?;
        let mut buf = vec![0u8; 8192 + 1];
        let started = std::time::Instant::now();
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Some(l) = parse_record(&String::from_utf8_lossy(&buf[..n])) {
                        all.push(l);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.raw_os_error() == Some(32) => continue, // EPIPE: records overwritten, resume
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
            if started.elapsed() > ctx.budget {
                return Err(ProbeError::Timeout);
            }
        }
    }
    let mut lines: Vec<KmsgLine> = all
        .into_iter()
        .filter(|l| opts.since_seq.map(|s| l.seq > s).unwrap_or(true) && opts.max_level.map(|m| l.level <= m).unwrap_or(true))
        .collect();
    let keep = opts.last.unwrap_or(200);
    if lines.len() > keep {
        lines.drain(..lines.len() - keep);
    }
    Ok(KmsgReport { lines })
}

impl ToJson for KmsgReport {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_u64("v", crate::SCHEMA_V);
        w.key("lines");
        w.begin_array();
        for l in &self.lines {
            w.begin_object();
            w.field_u64("seq", l.seq);
            w.field_u64("level", l.level as u64);
            w.field_u64("ts_us", l.ts_us);
            w.field_str("text", &l.text);
            w.key("tags");
            w.value(&l.tags);
            w.end_object();
        }
        w.end_array();
        w.end_object();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn dictionary_lines_are_dropped_and_tags_set() {
        let l = super::parse_record("3,77,99,-;ata1.00: exception Emask 0x0 SAct 0x0\n SUBSYSTEM=ata\n DEVICE=+ata:1\n").unwrap();
        assert_eq!(l.text, "ata1.00: exception Emask 0x0 SAct 0x0");
        assert_eq!(l.tags, ["ata-error"]);
        assert!(super::parse_record("garbage").is_none());
    }

    #[test]
    fn classifier() {
        let c = super::classify;
        assert_eq!(c("pcieport 0000:00:1c.0: AER: Corrected error received: 0000:03:00.0"), ["pcie-aer"]);
        assert_eq!(c("mce: [Hardware Error]: Machine check events logged"), ["mce"]);
        assert_eq!(c("nvme nvme0: I/O 12 QID 3 timeout, aborting"), ["nvme-timeout"]);
        assert_eq!(c("Out of memory: Killed process 123 (x)"), ["oom"]);
        assert_eq!(c("r8169 0000:03:00.0 eth0: Link is Down"), ["link-down"]);
        assert_eq!(c("usb 1-2: device descriptor read/64, error -71"), ["usb-error"]);
        assert_eq!(c("i915 0000:00:02.0: Direct firmware load for i915/foo.bin failed with error -2"), ["fw-missing"]);
        assert!(c("EXT4-fs (vda1): mounted filesystem").is_empty());
        assert!(c("ata1: SATA link up 6.0 Gbps").is_empty());
        assert!(c("pcieport 0000:00:03.0: AER: enabled with IRQ 24").is_empty());
        assert!(c("ata5: SATA link down (SStatus 0 SControl 300)").is_empty());
        assert!(c("faux_driver regulatory: Direct firmware load for regulatory.db failed with error -2").is_empty());
    }

    #[test]
    fn dump_filters_and_cap() {
        let dir = std::env::temp_dir().join(format!("i7ll-kmsg-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("dev")).unwrap();
        let mut t = String::new();
        for i in 0..10 {
            t.push_str(&format!("{},{},{}00,-;line {}\n SUBSYSTEM=x\n", if i % 2 == 0 { 6 } else { 3 }, i, i, i));
        }
        std::fs::write(dir.join("dev/kmsg"), t).unwrap();
        let ctx = crate::ProbeCtx::fixture(&dir);
        let r = super::read(&ctx, &super::KmsgOpts { last: Some(3), ..Default::default() }).unwrap();
        assert_eq!(r.lines.iter().map(|l| l.seq).collect::<Vec<_>>(), [7, 8, 9]);
        let r = super::read(&ctx, &super::KmsgOpts { max_level: Some(3), since_seq: Some(4), ..Default::default() }).unwrap();
        assert_eq!(r.lines.iter().map(|l| l.seq).collect::<Vec<_>>(), [5, 7, 9]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record() {
        let l = super::parse_record("6,1234,5678900,-;usb 1-2: new device").unwrap();
        assert_eq!((l.level, l.seq, l.ts_us), (6, 1234, 5678900));
        assert_eq!(l.text, "usb 1-2: new device");
    }
}
