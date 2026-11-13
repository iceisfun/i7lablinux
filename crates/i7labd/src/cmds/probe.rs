//! inv, pcie, usb, net.ls, thermal: thin wrappers over labprobe (always through `Daemon::probe`).

use std::sync::atomic::Ordering;
use std::time::Duration;

use labprobe::{inventory, ProbeError, Section};
use labproto::json::{to_json, ToJson};
use labproto::Status;

use crate::opts_or_bad;
use crate::registry::{Ctx, Handler, Reply};

pub const TABLE: &[(&str, Handler)] = &[("inv", inv), ("pcie", pcie), ("usb", usb), ("net.ls", net_ls), ("thermal", thermal)];

pub fn probe_status(e: &ProbeError) -> Status {
    match e {
        ProbeError::Unsupported => Status::Unsupported,
        ProbeError::NotFound(_) => Status::NotFound,
        ProbeError::Timeout => Status::Timeout,
        _ => Status::Io,
    }
}

pub fn probe_reply<T: ToJson>(r: Result<T, ProbeError>) -> Reply {
    match r {
        Ok(v) => Reply::json(to_json(&v)),
        Err(e) => Reply::error(probe_status(&e), &e.to_string()),
    }
}

/// "all" or a comma list of section names.
pub fn parse_sections(list: &str) -> Result<Vec<Section>, String> {
    if list == "all" {
        return Ok(Section::ALL.to_vec());
    }
    list.split(',').map(|s| Section::parse(s).ok_or_else(|| format!("unknown section {}", labproto::text::sanitize(s)))).collect()
}

fn inv(ctx: &mut Ctx) -> Reply {
    let o = opts_or_bad!(ctx, &[], &["section"]);
    let sections = match o.value("section") {
        None => Section::ALL.to_vec(),
        Some(list) => match parse_sections(list) {
            Ok(v) => v,
            Err(m) => return Reply::error(Status::BadArgs, &m),
        },
    };
    Reply::json(to_json(&inventory(&ctx.daemon.probe, &sections)))
}

/// "10ec:8126"
pub fn parse_id(s: &str) -> Option<(u16, u16)> {
    let (v, d) = s.split_once(':')?;
    Some((u16::from_str_radix(v, 16).ok()?, u16::from_str_radix(d, 16).ok()?))
}

fn pcie(ctx: &mut Ctx) -> Reply {
    let o = opts_or_bad!(ctx, &["tree", "verbose", "aer"], &["id", "class"]);
    let filter_id = match o.value("id").map(parse_id) {
        Some(None) => return Reply::error(Status::BadArgs, "bad --id (VVVV:DDDD hex)"),
        Some(Some(x)) => Some(x),
        None => None,
    };
    let filter_class = match o.value("class").map(|c| u8::from_str_radix(c.trim_start_matches("0x"), 16)) {
        Some(Err(_)) => return Reply::error(Status::BadArgs, "bad --class (hex byte)"),
        Some(Ok(c)) => Some(c),
        None => None,
    };
    let opts = labprobe::pci::PciOpts { verbose: o.flag("verbose"), filter_id, filter_class };
    // --tree / --aer: the report always carries `parent` and the AER counters; clients draw the tree
    probe_reply(labprobe::pci::probe(&ctx.daemon.probe, &opts))
}

fn usb(ctx: &mut Ctx) -> Reply {
    let _o = opts_or_bad!(ctx, &["tree"], &[]);
    probe_reply(labprobe::usb::probe(&ctx.daemon.probe))
}

/// `[IFACE]`
fn net_ls(ctx: &mut Ctx) -> Reply {
    let o = opts_or_bad!(ctx, &[], &[]);
    let mut rep = match labprobe::net::probe(&ctx.daemon.probe) {
        Ok(r) => r,
        Err(e) => return Reply::error(probe_status(&e), &e.to_string()),
    };
    if let Some(name) = o.positional().first() {
        rep.ifaces.retain(|i| &i.name == name);
        if rep.ifaces.is_empty() {
            return Reply::error(Status::NotFound, "no such interface");
        }
    }
    Reply::json(to_json(&rep))
}

/// `[--follow]`: with a streaming transport one JSON object per 2 s as events until cancelled.
fn thermal(ctx: &mut Ctx) -> Reply {
    let o = opts_or_bad!(ctx, &["follow"], &[]);
    let first = labprobe::thermal::probe(&ctx.daemon.probe);
    if !(o.flag("follow") && ctx.sink.streaming()) {
        return probe_reply(first);
    }
    let mut r = first;
    loop {
        match &r {
            Ok(rep) => {
                if ctx.sink.event(&to_json(rep)).is_err() {
                    break;
                }
            }
            Err(e) => return Reply::error(probe_status(e), &e.to_string()),
        }
        for _ in 0..10 {
            if ctx.cancel.load(Ordering::SeqCst) {
                return Reply::ok_empty();
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        r = labprobe::thermal::probe(&ctx.daemon.probe);
    }
    Reply::error(Status::Canceled, "transport closed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests_support::*;
    use labproto::keys::Role;

    #[test]
    fn section_and_id_parsing() {
        assert_eq!(parse_sections("cpu,mem").unwrap().len(), 2);
        assert_eq!(parse_sections("all").unwrap().len(), Section::ALL.len());
        assert!(parse_sections("cpu,bogus").is_err());
        assert_eq!(parse_id("10ec:8126"), Some((0x10ec, 0x8126)));
        assert_eq!(parse_id("10ec"), None);
        assert_eq!(parse_id("zz:1"), None);
    }

    #[test]
    fn probes_answer_json_or_a_status() {
        let d = test_daemon();
        let (r, _) = run_with(&d, Role::Ro, "inv", &["--section", "system,mem"]);
        assert_eq!(r.status, Status::Ok);
        let j = String::from_utf8(r.body).unwrap();
        assert!(j.contains("\"system\"") && j.contains("\"mem\"") && !j.contains("\"cpu\""), "{}", &j[..j.len().min(300)]);
        assert_eq!(run_with(&d, Role::Ro, "inv", &["--section", "x"]).0.status, Status::BadArgs);
        assert_eq!(run_with(&d, Role::Ro, "pcie", &["--id", "nonsense"]).0.status, Status::BadArgs);
        assert_eq!(run_with(&d, Role::Ro, "net.ls", &["nosuchif0"]).0.status, Status::NotFound);
        assert_eq!(run_with(&d, Role::Ro, "usb", &["--bogus"]).0.status, Status::BadArgs);
    }
}
