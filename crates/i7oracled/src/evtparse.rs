//! `wevtutil qe System ... /f:text` output parser and the "why did the machine last stop" classification.

use crate::evlog::json_str;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct WEvent {
    pub id: u32,
    pub date: String,
    pub source: String,
}

pub const QUERY: &str = "*[System[(EventID=41 or EventID=1074 or EventID=6005 or EventID=6006 or EventID=6008 or EventID=42 or EventID=107 or EventID=109 or EventID=506 or EventID=507 or EventID=1)]]";

pub fn parse(text: &str) -> Vec<WEvent> {
    let mut v = Vec::new();
    let mut cur: Option<WEvent> = None;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("Event[") {
            if let Some(e) = cur.take().filter(|e| e.id != 0) {
                v.push(e);
            }
            cur = Some(WEvent { id: 0, date: String::new(), source: String::new() });
        } else if let Some(e) = cur.as_mut() {
            if let Some(x) = l.strip_prefix("Event ID:") {
                e.id = x.trim().parse().unwrap_or(0);
            } else if let Some(x) = l.strip_prefix("Date:") {
                e.date = x.trim().to_string();
            } else if let Some(x) = l.strip_prefix("Source:") {
                e.source = x.trim().to_string();
            }
        }
    }
    if let Some(e) = cur.filter(|e| e.id != 0) {
        v.push(e);
    }
    v
}

/// Newest-first list in, classification of the most recent boot/shutdown marker out.
pub fn classify(events: &[WEvent]) -> (&'static str, Option<&WEvent>) {
    let mut best: Option<&WEvent> = None;
    for e in events.iter().filter(|e| matches!(e.id, 41 | 1074 | 6005 | 6006 | 6008)) {
        if best.map(|b| e.date > b.date).unwrap_or(true) {
            best = Some(e);
        }
    }
    let class = match best.map(|e| e.id) {
        Some(41) => "kernel-power-41: rebooted without a clean shutdown (power loss, crash or hard reset)",
        Some(6008) => "6008: previous shutdown was unexpected",
        Some(1074) => "1074: planned shutdown or restart initiated by a process or user",
        Some(6006) => "6006: event log service stopped cleanly",
        Some(6005) => "6005: event log service started (a boot with no later stop marker)",
        _ => "no shutdown marker found",
    };
    (class, best)
}

pub fn summary_json(events: &[WEvent], raw_head: &str) -> String {
    let (class, last) = classify(events);
    let list: Vec<String> = events.iter().take(40).map(|e| format!("{{\"id\":{},\"date\":{},\"source\":{}}}", e.id, json_str(&e.date), json_str(&e.source))).collect();
    format!(
        "{{\"classification\":{},\"marker\":{},\"events\":[{}],\"raw_head\":{}}}",
        json_str(class),
        last.map(|e| format!("{{\"id\":{},\"date\":{}}}", e.id, json_str(&e.date))).unwrap_or_else(|| "null".into()),
        list.join(","),
        json_str(raw_head.chars().take(3000).collect::<String>().as_str())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Event[0]:\n  Log Name: System\n  Source: Microsoft-Windows-Kernel-Power\n  Date: 2026-11-12T10:00:00.123\n  Event ID: 41\n  Task: (63)\n\nEvent[1]:\n  Log Name: System\n  Source: EventLog\n  Date: 2026-11-12T10:01:30.500\n  Event ID: 6008\n\nEvent[2]:\n  Source: User32\n  Date: 2026-11-11T22:00:00.000\n  Event ID: 1074\n";

    #[test]
    fn parses_and_classifies() {
        let ev = parse(SAMPLE);
        assert_eq!(ev.len(), 3);
        assert_eq!(ev[0], WEvent { id: 41, date: "2026-11-12T10:00:00.123".into(), source: "Microsoft-Windows-Kernel-Power".into() });
        let (c, m) = classify(&ev);
        assert!(c.starts_with("6008"));
        assert_eq!(m.unwrap().id, 6008);
        let j = summary_json(&ev, SAMPLE);
        assert!(crate::json::parse(&j, &crate::json::Limits::default()).is_ok());
        assert_eq!(classify(&[]).0, "no shutdown marker found");
        assert!(parse("garbage\n").is_empty());
    }
}
