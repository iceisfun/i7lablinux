//! Human renderers for server JSON. Every function takes the server's JSON text and returns text; strings that
//! came from hardware are sanitised by `output::cell` / `sanitize`. Missing fields print as `-`, so an older or
//! newer server never breaks the display (`--json` shows everything). Owner: P9.

use labproto::json::Value;
use labproto::text::sanitize;

use crate::output::{cell, fmt_bytes, fmt_secs, kv_block, Paint, Table};
use crate::{hosts::HostEntry, jv};

fn dash(o: Option<String>) -> String {
    o.unwrap_or_else(|| "-".into())
}

fn s_of(v: &Value, p: &str) -> String {
    dash(jv::s(v, p).filter(|s| !s.trim().is_empty()).map(String::from))
}

fn n_of(v: &Value, p: &str, prec: usize) -> String {
    dash(jv::n(v, p).map(|n| format!("{:.*}", prec, n)))
}

fn u_of(v: &Value, p: &str) -> String {
    dash(jv::u(v, p).map(|n| n.to_string()))
}

fn bytes_of(v: &Value, p: &str) -> String {
    dash(jv::u(v, p).map(fmt_bytes))
}

/// Strings of an array that holds strings or other values (reasons are strings or small objects).
fn texts(a: &[Value]) -> Vec<String> {
    a.iter()
        .map(|x| match x {
            Value::Str(s) => s.clone(),
            other => jv::to_json(other),
        })
        .collect()
}

pub fn parse_or_raw(body: &str) -> Result<Value, String> {
    jv::parse(body).ok_or_else(|| format!("(not JSON) {}", sanitize(body.trim())))
}

/// Fallback for any JSON: scalars as `key  value` lines (dotted for nested objects), arrays of objects as tables.
pub fn generic(body: &str, p: Paint) -> String {
    match parse_or_raw(body) {
        Err(raw) => format!("{}\n", raw),
        Ok(v) => {
            let mut rows: Vec<(String, String)> = Vec::new();
            let mut tables = String::new();
            flatten("", &v, &mut rows, &mut tables, p);
            let borrowed: Vec<(&str, String)> = rows.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
            let mut s = kv_block(&borrowed, p);
            s.push_str(&tables);
            if s.is_empty() {
                s.push_str("(empty)\n");
            }
            s
        }
    }
}

fn flatten(prefix: &str, v: &Value, rows: &mut Vec<(String, String)>, tables: &mut String, p: Paint) {
    match v {
        Value::Obj(kv) => {
            for (k, x) in kv {
                let key = if prefix.is_empty() { k.clone() } else { format!("{}.{}", prefix, k) };
                flatten(&key, x, rows, tables, p);
            }
        }
        Value::Arr(a) if !a.is_empty() && a.iter().all(|x| matches!(x, Value::Obj(_))) => {
            let cols: Vec<String> = match &a[0] {
                Value::Obj(kv) => kv.iter().filter(|(_, x)| !matches!(x, Value::Obj(_) | Value::Arr(_))).map(|(k, _)| k.clone()).collect(),
                _ => Vec::new(),
            };
            let heads: Vec<&str> = cols.iter().map(String::as_str).collect();
            let mut t = Table::new(&heads);
            for x in a {
                let cells: Vec<String> = cols.iter().map(|c| scalar(x.get(c))).collect();
                t.row(&cells);
            }
            tables.push_str(&format!("\n{}\n{}", p.bold(prefix), t.render(p)));
        }
        Value::Arr(a) => rows.push((prefix.to_string(), texts(a).join(", "))),
        other => rows.push((prefix.to_string(), scalar(Some(other)))),
    }
}

fn scalar(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "-".into(),
        Some(Value::Str(s)) => s.clone(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Num(n)) => {
            if n.fract() == 0.0 && n.abs() < 1e15 {
                format!("{}", *n as i64)
            } else {
                format!("{:.2}", n)
            }
        }
        Some(other) => jv::to_json(other),
    }
}

// ---------------------------------------------------------------- ping / id

pub fn ping(body: &str, p: Paint) -> String {
    let Some(v) = jv::parse(body) else { return generic(body, p) };
    let mut rows = vec![("uptime", dash(jv::u(&v, "uptime_ms").map(|ms| fmt_secs(ms / 1000)))), ("boot_id", s_of(&v, "boot_id"))];
    if let Some(l) = jv::path(&v, "load").and_then(Value::as_array) {
        rows.push(("load", l.iter().map(|x| scalar(Some(x))).collect::<Vec<_>>().join(" ")));
    }
    kv_block(&rows, p)
}

pub fn id(body: &str, role: Option<&str>, p: Paint) -> String {
    let mut s = generic(body, p);
    if let Some(r) = role {
        s.push_str(&format!("{}\n", p.dim(&format!("role granted to your key: {}", r))));
    }
    s
}

// ---------------------------------------------------------------- inv

const SECTIONS: &[&str] = &["system", "cpu", "mem", "dmi", "pci", "usb", "block", "net", "thermal", "firmware", "smart", "kmsg"];

pub fn inv(body: &str, p: Paint) -> String {
    let Ok(v) = parse_or_raw(body) else { return generic(body, p) };
    let root = v.get("sections").unwrap_or(&v);
    let mut out = String::new();
    for name in SECTIONS {
        let Some(sec) = root.get(name) else { continue };
        out.push_str(&format!("{}\n", p.bold(&format!("== {} ==", name))));
        if let Some(e) = sec.get("error") {
            out.push_str(&format!("  {}\n\n", p.yellow(&format!("unavailable: {}", sanitize(&scalar(Some(e)))))));
            continue;
        }
        let text = match *name {
            "system" => system(sec, p),
            "cpu" => cpu(sec, p),
            "mem" => mem(sec, p),
            "dmi" => dmi(sec, p),
            "pci" => format!("{} PCI devices, IOMMU {}\n", jv::arr(sec, "devices").len(), dash(jv::b(sec, "iommu_enabled").map(|b| if b { "on".to_string() } else { "off".to_string() }))),
            "usb" => format!("{} USB devices\n", jv::arr(sec, "devices").len()),
            "block" => blk_ls_value(sec, p),
            "net" => net_value(sec, false, p),
            "thermal" => thermal_value(sec, p),
            "firmware" => kv_block(&[("boot_mode", s_of(sec, "boot_mode")), ("secure_boot", scalar(sec.get("secure_boot"))), ("boot_current", scalar(sec.get("boot_current")))], p),
            "smart" => smart_all(sec, p),
            _ => generic(&jv::to_json(sec), p),
        };
        for l in text.lines() {
            out.push_str(&format!("  {}\n", l));
        }
        out.push('\n');
    }
    if out.is_empty() {
        return generic(body, p);
    }
    out
}

fn system(v: &Value, p: Paint) -> String {
    kv_block(
        &[
            ("hostname", s_of(v, "hostname")),
            ("kernel", s_of(v, "kernel")),
            ("uptime", dash(jv::n(v, "uptime_s").filter(|x| *x >= 0.0).map(|x| fmt_secs(x as u64)))),
            ("boot_mode", s_of(v, "boot_mode")),
            ("image_build", s_of(v, "image_build")),
        ],
        p,
    )
}

fn cpu(v: &Value, p: Paint) -> String {
    kv_block(
        &[
            ("model", s_of(v, "model_name")),
            ("topology", format!("{} socket(s), {} cores, {} threads", u_of(v, "sockets"), u_of(v, "cores"), u_of(v, "threads"))),
            ("microcode", s_of(v, "microcode")),
            ("freq_mhz", n_of(v, "freq_mhz", 0)),
            ("flags", texts(jv::arr(v, "flags_summary")).join(" ")),
        ],
        p,
    )
}

fn mem(v: &Value, p: Paint) -> String {
    let kib = |k: &str| dash(jv::u(v, k).map(|n| fmt_bytes(n * 1024)));
    kv_block(&[("total", kib("total_kib")), ("available", kib("available_kib")), ("dimms", jv::arr(v, "dimms").len().to_string()), ("ecc", s_of(v, "ecc"))], p)
}

fn dmi(v: &Value, p: Paint) -> String {
    kv_block(
        &[
            ("system", format!("{} {}", s_of(v, "sys_vendor"), s_of(v, "product_name"))),
            ("serial", s_of(v, "product_serial")),
            ("board", format!("{} {} (serial {})", s_of(v, "board_vendor"), s_of(v, "board_name"), s_of(v, "board_serial"))),
            ("bios", format!("{} {} {}", s_of(v, "bios_vendor"), s_of(v, "bios_version"), s_of(v, "bios_date"))),
        ],
        p,
    )
}

// ---------------------------------------------------------------- pcie / usb

pub fn pcie(body: &str, tree: bool, verbose: bool, p: Paint) -> String {
    let Ok(v) = parse_or_raw(body) else { return generic(body, p) };
    let devs = jv::arr(&v, "devices");
    let mut out = format!("{} PCI devices, IOMMU {}\n", devs.len(), dash(jv::b(&v, "iommu_enabled").map(|b| if b { "on".to_string() } else { "off".to_string() })));
    let link = |d: &Value| -> String {
        let Some(l) = d.get("link").filter(|l| !matches!(l, Value::Null)) else { return "-".into() };
        let x = |k: &str| jv::u(l, k).map(|n| n.to_string()).unwrap_or_else(|| "?".into());
        let mut s = format!("x{} gen{} (max x{} gen{})", x("cur_width"), x("cur_gen"), x("max_width"), x("max_gen"));
        if jv::b(l, "degraded") == Some(true) {
            s.push_str(" DEGRADED");
        }
        s
    };
    let depth = |d: &Value| -> usize {
        let mut n = 0;
        let mut parent = jv::s(d, "parent");
        while let Some(pb) = parent {
            n += 1;
            parent = devs.iter().find(|x| jv::s(x, "bdf") == Some(pb)).and_then(|x| jv::s(x, "parent"));
            if n > 8 {
                break;
            }
        }
        n
    };
    let mut t = Table::new(&["BDF", "ID", "CLASS", "NAME", "DRIVER", "LINK", "IOMMU"]);
    for d in devs {
        let id = format!("{}:{}", jv::hex4(d, "vendor"), jv::hex4(d, "device"));
        let name = format!("{} {}", jv::s(d, "vendor_name").unwrap_or(""), jv::s(d, "device_name").unwrap_or("")).trim().to_string();
        let bdf = s_of(d, "bdf");
        let bdf = if tree { format!("{}{}", "  ".repeat(depth(d)), bdf) } else { bdf };
        // Wi-Fi and other non-Ethernet network functions say so: "Network controller [wifi]"
        let class = match jv::s(d, "nic_kind") {
            Some(k) if k != "ethernet" => format!("{} [{}]", s_of(d, "class_name"), k),
            _ => s_of(d, "class_name"),
        };
        t.row(&[bdf, id, class, if name.is_empty() { "-".into() } else { name }, s_of(d, "driver"), link(d), u_of(d, "iommu_group")]);
    }
    out.push_str(&t.render(p));
    if verbose {
        for d in devs {
            let bars = jv::arr(d, "bars");
            let hex = jv::s(d, "config_hex");
            if bars.is_empty() && hex.is_none() && jv::hex_u(d, "subsys_vendor").is_none() {
                continue;
            }
            out.push_str(&format!("\n{} {}\n", p.bold(&s_of(d, "bdf")), s_of(d, "class_name")));
            if jv::hex_u(d, "subsys_vendor").is_some() {
                out.push_str(&format!("  subsystem {}:{}\n", jv::hex4(d, "subsys_vendor"), jv::hex4(d, "subsys_device")));
            }
            for b in bars {
                out.push_str(&format!("  BAR {}\n", sanitize(&jv::to_json(b))));
            }
            if let Some(h) = hex {
                for (i, chunk) in h.as_bytes().chunks(32).enumerate() {
                    out.push_str(&format!("  {:03x}: {}\n", i * 16, sanitize(std::str::from_utf8(chunk).unwrap_or(""))));
                }
            }
        }
    }
    out
}

pub fn usb(body: &str, p: Paint) -> String {
    let Ok(v) = parse_or_raw(body) else { return generic(body, p) };
    let devs = jv::arr(&v, "devices");
    let mut t = Table::new(&["PATH", "ID", "CLASS", "MBPS", "MANUFACTURER", "PRODUCT", "SERIAL", "DRIVER"]).right(3);
    for d in devs {
        let id = format!("{}:{}", jv::hex4(d, "vid"), jv::hex4(d, "pid"));
        // the device's own strings win; the embedded id table fills in for devices that carry none
        let pick = |own: &str, table: &str| match jv::s(d, own).filter(|x| !x.is_empty()) {
            Some(x) => x.to_string(),
            None => s_of(d, table),
        };
        t.row(&[s_of(d, "path"), id, u_of(d, "class"), u_of(d, "speed_mbps"), pick("manufacturer", "vendor_name"), pick("product", "product_name"), s_of(d, "serial"), texts(jv::arr(d, "drivers")).join(",")]);
    }
    format!("{} USB devices\n{}", devs.len(), t.render(p))
}

// ---------------------------------------------------------------- block

fn safety_text(d: &Value) -> String {
    let verdict = s_of(d, "write_safety.verdict");
    // i7labd sends reasons as {"code":"mounted","detail":"/mnt",...}; older/test bodies use plain strings
    let reason = |x: &Value| match x {
        Value::Str(s) => s.clone(),
        Value::Obj(_) => match (jv::s(x, "code"), jv::s(x, "detail")) {
            // the RAM-resident boot media: the one reason that names the client flag that lifts it
            (Some("boot_media"), Some(det)) if jv::b(x, "overridable") == Some(true) => format!("boot_media({}: --allow-boot-media)", det),
            (Some(c), Some(det)) => format!("{}({})", c, det),
            (Some(c), None) => c.to_string(),
            _ => jv::to_json(x),
        },
        other => jv::to_json(other),
    };
    let reasons: Vec<String> = jv::arr(d, "write_safety.absolute").iter().chain(jv::arr(d, "write_safety.overridable").iter()).map(reason).collect();
    match verdict.to_ascii_lowercase().as_str() {
        "safe" => "WRITE-SAFE".into(),
        "-" => "-".into(),
        _ if reasons.is_empty() => format!("UNSAFE: {}", verdict),
        _ => format!("UNSAFE: {}", reasons.join(" | ")),
    }
}

/// `blk ls` table, one row per disk, with the write-safety verdict.
pub fn blk_ls(body: &str, p: Paint) -> String {
    match parse_or_raw(body) {
        Ok(v) => blk_ls_value(&v, p),
        Err(r) => r,
    }
}

fn blk_ls_value(v: &Value, p: Paint) -> String {
    let devs = jv::arr(v, "devices");
    let mut t = Table::new(&["NAME", "SIZE", "KIND", "MODEL", "SERIAL", "TABLE", "FS", "MOUNTED", "BOOT", "SMART", "WRITE SAFETY"]).right(1).max_cell(100);
    for d in devs {
        let fs: Vec<String> = jv::arr(d, "signatures").iter().map(|s| match s {
            Value::Str(x) => x.clone(),
            o => jv::s(o, "kind").or_else(|| jv::s(o, "name")).map(String::from).unwrap_or_else(|| jv::to_json(o)),
        }).collect();
        let ptab = match d.get("partition_table") {
            Some(Value::Str(s)) => s.clone(),
            Some(o @ Value::Obj(_)) => jv::s(o, "kind").map(String::from).unwrap_or_else(|| "yes".into()),
            _ => "-".into(),
        };
        let safety = safety_text(d);
        let safety = if safety == "WRITE-SAFE" { p.green(&safety) } else { p.yellow(&cell(&safety, 100)) };
        t.row(&[
            s_of(d, "name"),
            bytes_of(d, "size_bytes"),
            s_of(d, "kind"),
            s_of(d, "model"),
            s_of(d, "serial"),
            ptab,
            if fs.is_empty() { "-".into() } else { fs.join(",") },
            { let m = texts(jv::arr(d, "mounts")); if m.is_empty() { "-".into() } else { m.join(",") } },
            if jv::b(d, "boot_media") == Some(true) { "BOOT".into() } else { "-".into() },
            jv::s(d, "smart").map(|v| smart_word(v, p)).unwrap_or_else(|| "-".into()),
            safety,
        ]);
    }
    if devs.is_empty() {
        "no block devices\n".to_string()
    } else {
        t.render(p)
    }
}

/// Verdict word as printed: PASSED / FAILED / WARNING / UNKNOWN (the JSON says pass / fail / warn / unknown).
pub fn smart_word(verdict: &str, p: Paint) -> String {
    match verdict {
        "pass" | "PASSED" => p.green("PASSED"),
        "fail" | "FAILED" | "failed" => p.red("FAILED"),
        "warn" | "WARNING" => p.yellow("WARNING"),
        "unknown" | "UNKNOWN" | "" => "UNKNOWN".to_string(),
        other => p.yellow(&other.to_ascii_uppercase()),
    }
}

pub fn blk_smart(body: &str, attrs: bool, p: Paint) -> String {
    let Ok(v) = parse_or_raw(body) else { return generic(body, p) };
    let mut rows = vec![("device", s_of(&v, "dev")), ("kind", s_of(&v, "kind")), ("verdict", smart_word(&s_of(&v, "verdict"), p))];
    for (label, key) in [("model", "model"), ("serial", "serial"), ("firmware", "firmware")] {
        if jv::s(&v, key).is_some() {
            rows.push((label, s_of(&v, key)));
        }
    }
    rows.push(("temperature", jv::n(&v, "temperature_c").map(|t| format!("{:.0} C", t)).unwrap_or_else(|| "-".into())));
    rows.push(("power_on_hours", u_of(&v, "power_on_hours")));
    for r in jv::arr(&v, "reasons") {
        if let Some(x) = r.as_str() {
            rows.push(("reason", sanitize(x).into_owned()));
        }
    }
    let mut out = kv_block(&rows, p);
    if let Some(n) = v.get("nvme").filter(|n| matches!(n, Value::Obj(_))) {
        let gb = |k: &str| jv::u(n, k).map(|b| format!("{:.1} GB", b as f64 / 1e9)).unwrap_or_else(|| "-".into());
        out.push_str(&kv_block(
            &[
                ("critical_warning", format!("0x{:02x}", jv::u(n, "critical_warning").unwrap_or(0))),
                ("available_spare", format!("{}% (threshold {}%)", u_of(n, "available_spare"), u_of(n, "spare_threshold"))),
                ("percentage_used", format!("{}%", u_of(n, "percentage_used"))),
                ("data_read", gb("data_read_bytes")),
                ("data_written", gb("data_written_bytes")),
                ("power_cycles", u_of(n, "power_cycles")),
                ("unsafe_shutdowns", u_of(n, "unsafe_shutdowns")),
                ("media_errors", u_of(n, "media_errors")),
                ("error_log_entries", u_of(n, "error_log_entries")),
            ],
            p,
        ));
    }
    let a = jv::arr(&v, "attrs");
    if attrs && !a.is_empty() {
        let mut t = Table::new(&["ID", "ATTRIBUTE", "VALUE", "WORST", "THRESH", "RAW", ""]).right(0).right(2).right(3).right(4).right(5);
        for x in a {
            let fail = if jv::b(x, "failing_now") == Some(true) { p.red("FAILING") } else { String::new() };
            t.row(&[u_of(x, "id"), s_of(x, "name"), u_of(x, "value"), u_of(x, "worst"), u_of(x, "thresh"), u_of(x, "raw"), fail]);
        }
        out.push_str(&t.render(p));
    } else if !a.is_empty() {
        out.push_str(&p.dim("(attribute table: add --attrs)\n"));
    }
    out
}

fn smart_all(v: &Value, p: Paint) -> String {
    let mut t = Table::new(&["DEVICE", "VERDICT", "TEMP C", "POWER-ON H"]).right(2).right(3);
    for d in jv::arr(v, "devices") {
        t.row(&[s_of(d, "dev"), smart_word(&s_of(d, "verdict"), p), n_of(d, "temperature_c", 0), u_of(d, "power_on_hours")]);
    }
    t.render(p)
}

/// True when a SMART report's verdict is a failure (exit 3).
pub fn smart_failed(body: &str) -> bool {
    jv::parse(body).and_then(|v| jv::s(&v, "verdict").map(|s| matches!(s, "fail" | "FAILED" | "failed"))).unwrap_or(false)
}

/// Result of blk read/write/verify. Returns (text, problems found).
pub fn blk_test(body: &str, p: Paint) -> (String, bool) {
    let Ok(v) = parse_or_raw(body) else { return (generic(body, p), false) };
    let mut t = Table::new(&["REGION", "OFFSET", "LEN", "MiB/s", "LAT MAX us", "IO ERR", "MISMATCH"]).right(1).right(2).right(3).right(4).right(5).right(6);
    let mut bad = jv::b(&v, "ok") == Some(false);
    for r in jv::arr(&v, "regions") {
        let errs = jv::u(r, "io_errors").unwrap_or(0) + jv::u(r, "mismatches").unwrap_or(0);
        bad |= errs > 0;
        t.row(&[s_of(r, "name"), bytes_of(r, "offset"), bytes_of(r, "len"), n_of(r, "mib_s", 1), u_of(r, "lat_max_us"), u_of(r, "io_errors"), u_of(r, "mismatches")]);
    }
    let mut out = kv_block(&[("device", s_of(&v, "dev")), ("serial", s_of(&v, "serial")), ("mode", s_of(&v, "mode")), ("seed", u_of(&v, "seed"))], p);
    out.push_str(&t.render(p));
    out.push_str(&if bad { p.red("RESULT: PROBLEMS FOUND\n") } else { p.green("RESULT: ok\n") });
    (out, bad)
}

/// One progress event as a status-line text (`mid  43%  412.5 MiB/s`).
pub fn progress_line(json: &str) -> Option<String> {
    let v = jv::parse(json)?;
    if jv::s(&v, "event") != Some("progress") {
        return None;
    }
    let pct = jv::n(&v, "done").map(|d| if d <= 1.0 { d * 100.0 } else { d }).unwrap_or(0.0);
    Some(format!("{:<8} {:>3.0}%  {} MiB/s", s_of(&v, "region"), pct, n_of(&v, "mib_s", 1)))
}

// ---------------------------------------------------------------- net / thermal

pub fn net_ls(body: &str, p: Paint) -> String {
    net_ls_all(body, false, p)
}

/// `net ls`: kernel-made virtual devices (dummy0, sit0, tunnel base devices: kind `virtual/kernel`) are hidden
/// unless `all`.
pub fn net_ls_all(body: &str, all: bool, p: Paint) -> String {
    match parse_or_raw(body) {
        Ok(v) => net_value(&v, all, p),
        Err(r) => r,
    }
}

/// Kind of an interface as the host reported it; bodies from hosts that predate the `kind` field fall back to a
/// name check for the kernel's own devices.
fn net_kind(i: &Value) -> String {
    if let Some(k) = jv::s(i, "kind").filter(|k| !k.is_empty()) {
        return k.to_string();
    }
    let name = jv::s(i, "name").unwrap_or("");
    let stem = name.trim_end_matches(|c: char| c.is_ascii_digit());
    let digits = &name[stem.len()..];
    let default_dev = !digits.is_empty() && digits.len() <= 2 && ["dummy", "sit", "tunl", "ip6tnl", "ip6gre", "gre", "gretap", "erspan", "ip_vti", "ip6_vti", "ifb", "teql"].contains(&stem);
    if default_dev && jv::s(i, "driver").is_none() { "virtual/kernel".into() } else { "-".into() }
}

fn net_value(v: &Value, all: bool, p: Paint) -> String {
    let ifs = jv::arr(v, "ifaces");
    let mut t = Table::new(&["IFACE", "KIND", "MAC", "STATE", "SPEED", "DRIVER", "ADDRESSES", "VLAN OF"]);
    let mut hidden = 0;
    for i in ifs {
        let kind = net_kind(i);
        if kind == "virtual/kernel" && !all {
            hidden += 1;
            continue;
        }
        let addrs: Vec<String> = texts(jv::arr(i, "ipv4")).into_iter().chain(texts(jv::arr(i, "ipv6"))).collect();
        let state = format!("{}{}", s_of(i, "operstate"), if jv::b(i, "carrier") == Some(true) { "/carrier" } else { "" });
        t.row(&[s_of(i, "name"), kind, s_of(i, "mac"), state, dash(jv::u(i, "speed_mbps").map(|s| format!("{}M", s))), s_of(i, "driver"), if addrs.is_empty() { "-".into() } else { addrs.join(" ") }, s_of(i, "vlan_of")]);
    }
    let mut out = if ifs.is_empty() { "no interfaces\n".to_string() } else if hidden == ifs.len() { String::new() } else { t.render(p) };
    if hidden > 0 {
        out.push_str(&format!("{}\n", p.dim(&format!("{} virtual/kernel interface(s) hidden (dummy0, sit0, ...); show them with: net ls --all", hidden))));
    }
    out
}

pub fn thermal(body: &str, p: Paint) -> String {
    match parse_or_raw(body) {
        Ok(v) => thermal_value(&v, p),
        Err(r) => r,
    }
}

fn thermal_value(v: &Value, p: Paint) -> String {
    let mut t = Table::new(&["SENSOR", "TYPE", "TEMP C", "CRIT C"]).right(2).right(3);
    for z in jv::arr(v, "zones") {
        t.row(&[s_of(z, "name"), s_of(z, "type_"), n_of(z, "temp_c", 1), n_of(z, "crit_c", 0)]);
    }
    for h in jv::arr(v, "hwmon") {
        let name = s_of(h, "name");
        for x in jv::arr(h, "temps") {
            t.row(&[format!("{}/{}", name, s_of(x, "label")), "hwmon".to_string(), n_of(x, "value", 1), n_of(x, "crit", 0)]);
        }
        for f in jv::arr(h, "fans") {
            t.row(&[format!("{}/{}", name, s_of(f, "label")), "fan".to_string(), format!("{} rpm", n_of(f, "value", 0)), "-".to_string()]);
        }
    }
    let mut out = if t.is_empty() { "no temperature sensors\n".to_string() } else { t.render(p) };
    for a in jv::arr(v, "alarms") {
        out.push_str(&p.red(&format!("ALARM: {}\n", sanitize(&scalar(Some(a))))));
    }
    out
}

// ---------------------------------------------------------------- registry rows

pub fn host_line(h: &HostEntry) -> String {
    format!("{} {} {}", h.mac, h.ip, h.host)
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOP: Paint = Paint { on: false };

    fn need_parser() -> bool {
        if jv::parse("{\"a\":1}").is_none() {
            eprintln!("SKIPPED: labproto::json::parse is still a stub (P1)");
            return false;
        }
        true
    }

    #[test]
    fn blk_ls_reasons_as_objects() {
        let ram = r#"{"v":1,"devices":[{"name":"sda","size_bytes":1,"kind":"usb","serial":"X","boot_media":true,"write_safety":{"verdict":"needs_override","absolute":[],"overridable":[{"code":"boot_media","detail":"ram-resident","overridable":true}]}},{"name":"sdb","size_bytes":1,"kind":"usb","serial":"Y","boot_media":true,"write_safety":{"verdict":"refused","absolute":[{"code":"boot_media","detail":null,"overridable":false}],"overridable":[]}}]}"#;
        let s = blk_ls(ram, NOP);
        assert!(s.contains("UNSAFE: boot_media(ram-resident: --allow-boot-media)"), "{s}");
        assert!(s.contains("UNSAFE: boot_media ") || s.contains("UNSAFE: boot_media\n"), "{s}");
        let body = r#"{"v":1,"devices":[{"name":"vdb","size_bytes":134217728,"kind":"virtio","serial":"X","write_safety":{"verdict":"refused","absolute":[{"code":"mounted","detail":"/mnt","overridable":false}],"overridable":[{"code":"partition_table","detail":"gpt","overridable":true},{"code":"boot_media","detail":null,"overridable":false}]}}]}"#;
        let s = blk_ls(body, NOP);
        assert!(s.contains("UNSAFE: mounted(/mnt) | partition_table"), "{}", s);
        assert!(!s.contains('{'), "reasons are rendered, not dumped as JSON: {}", s);
    }

    #[test]
    fn blk_ls_shows_verdicts_and_sanitises() {
        if !need_parser() {
            return;
        }
        let body = r#"{"v":1,"devices":[
          {"name":"nvme0n1","size_bytes":1000204886016,"kind":"Nvme","model":"Evil\u001b[2J Disk","serial":"I7NVME0001","partition_table":null,"signatures":[],"mounts":[],"boot_media":false,"write_safety":{"verdict":"Safe","absolute":[],"overridable":[]}},
          {"name":"sda","size_bytes":64000000000,"kind":"Usb","model":"Stick","serial":"I7STICK0001","partition_table":"gpt","signatures":["vfat"],"mounts":["/boot"],"boot_media":true,"write_safety":{"verdict":"Refused","absolute":["BootMedia"],"overridable":["PartitionTable(gpt)"]}}]}"#;
        let s = blk_ls(body, NOP);
        assert!(s.contains("WRITE-SAFE"), "{}", s);
        assert!(s.contains("UNSAFE: BootMedia | PartitionTable(gpt)"), "{}", s);
        assert!(!s.contains('\x1b'), "{:?}", s);
        assert!(s.contains("931.5 GiB") || s.contains("931."), "{}", s);
        assert!(s.contains("BOOT"));
    }

    #[test]
    fn blk_test_flags_problems() {
        if !need_parser() {
            return;
        }
        let good = r#"{"v":1,"dev":"sdb","serial":"S","mode":"Read","seed":null,"ok":true,"regions":[{"name":"start","offset":0,"len":1048576,"mib_s":410.2,"lat_max_us":900,"io_errors":0,"mismatches":0,"first_mismatch":null}]}"#;
        let (t, bad) = blk_test(good, NOP);
        assert!(!bad && t.contains("RESULT: ok") && t.contains("410.2"), "{}", t);
        let badj = good.replace("\"mismatches\":0", "\"mismatches\":3");
        let (t, bad) = blk_test(&badj, NOP);
        assert!(bad && t.contains("PROBLEMS"), "{}", t);
        assert!(smart_failed("{\"verdict\":\"fail\"}") && !smart_failed("{\"verdict\":\"pass\"}"));
    }

    #[test]
    fn pcie_tree_and_degraded() {
        if !need_parser() {
            return;
        }
        let body = r#"{"v":1,"iommu_enabled":true,"devices":[
         {"bdf":"0000:00:1c.0","parent":null,"vendor":32902,"device":4096,"class_name":"PCI bridge","vendor_name":"Intel","device_name":"Root Port","driver":"pcieport","link":{"cur_gen":3,"cur_width":4,"max_gen":3,"max_width":4,"degraded":false},"iommu_group":1},
         {"bdf":"0000:01:00.0","parent":"0000:00:1c.0","vendor":5549,"device":16,"class_name":"NVMe","vendor_name":"Red Hat","device_name":"NVMe","driver":"nvme","link":{"cur_gen":1,"cur_width":1,"max_gen":3,"max_width":4,"degraded":true},"iommu_group":null}]}"#;
        let s = pcie(body, true, false, NOP);
        assert!(s.contains("  0000:01:00.0"), "{}", s);
        assert!(s.contains("DEGRADED") && s.contains("15ad:0010") || s.contains("15ad"), "{}", s);
        assert!(s.contains("2 PCI devices, IOMMU on"));
    }

    #[test]
    fn inv_sections_render_and_errors_do_not_abort() {
        if !need_parser() {
            return;
        }
        let body = r#"{"v":1,"system":{"hostname":"i7lab-x","kernel":"6.18","uptime_s":4000,"boot_mode":"uefi","image_build":"b1"},"cpu":{"model_name":"Xeon","sockets":1,"cores":4,"threads":8},"thermal":{"error":"no sensors"},"mem":{"total_kib":2097152,"available_kib":1048576,"dimms":[]}}"#;
        let s = inv(body, NOP);
        assert!(s.contains("== system ==") && s.contains("i7lab-x") && s.contains("1 socket(s), 4 cores, 8 threads"), "{}", s);
        assert!(s.contains("unavailable: no sensors"), "{}", s);
        assert!(s.contains("2.0 GiB"), "{}", s);
    }

    #[test]
    fn generic_handles_unknown_shapes() {
        if !need_parser() {
            return;
        }
        let s = generic(r#"{"a":1,"b":{"c":"x"},"rows":[{"k":1,"j":"y"},{"k":2,"j":"z"}],"l":["p","q"]}"#, NOP);
        assert!(s.contains("b.c") && s.contains("p, q") && s.contains("rows"), "{}", s);
        assert!(generic("not json \x1b[2J", NOP).contains("(not JSON)"));
    }

    #[test]
    fn progress_and_ping() {
        if !need_parser() {
            return;
        }
        assert_eq!(progress_line(r#"{"event":"progress","region":"mid","mib_s":412.5,"done":0.43}"#).unwrap(), "mid       43%  412.5 MiB/s");
        assert!(progress_line(r#"{"event":"result"}"#).is_none());
        let s = ping(r#"{"uptime_ms":412000,"boot_id":"9f3c","load":[0.1,0.2,0.3]}"#, NOP);
        assert!(s.contains("6m52s") && s.contains("9f3c"), "{}", s);
    }

    #[test]
    fn net_and_thermal() {
        if !need_parser() {
            return;
        }
        let s = net_ls(r#"{"ifaces":[{"name":"eth0","mac":"aa","operstate":"up","carrier":true,"speed_mbps":1000,"driver":"e1000e","ipv4":["10.0.0.2/24"],"ipv6":[]}]}"#, NOP);
        assert!(s.contains("up/carrier") && s.contains("1000M") && s.contains("10.0.0.2/24"), "{}", s);
        let s = thermal(r#"{"zones":[{"name":"acpitz","type_":"acpi","temp_c":45.5,"crit_c":99}],"hwmon":[],"alarms":["cpu hot"]}"#, NOP);
        assert!(s.contains("45.5") && s.contains("ALARM: cpu hot"), "{}", s);
    }

    // The probes write ids as hex strings ("8086"); these bodies are the live Darter Pro host's JSON (excerpts).
    const LIVE_PCI: &str = r#"{"v":1,"iommu_enabled":true,"devices":[
      {"bdf":"0000:00:00.0","parent":null,"vendor":"8086","device":"4621","subsys_vendor":"1558","subsys_device":"7716","class":"060000","revision":2,"class_name":"Host bridge","nic_kind":null,"vendor_name":"Intel Corporation","device_name":"Alder Lake-P Host Bridge/DRAM Controller","driver":null,"link":null,"iommu_group":1},
      {"bdf":"0000:00:14.3","parent":null,"vendor":"8086","device":"51f0","subsys_vendor":"8086","subsys_device":"0074","class":"028000","class_name":"Network controller","nic_kind":"wifi","vendor_name":"Intel Corporation","device_name":"Alder Lake PCH CNVi WiFi","driver":null,"link":null,"iommu_group":7},
      {"bdf":"0000:2e:00.0","parent":"0000:00:1c.7","vendor":"10ec","device":"8168","subsys_vendor":"0000","subsys_device":"0000","class":"020000","class_name":"Ethernet controller","nic_kind":"ethernet","vendor_name":"Realtek Semiconductor Co., Ltd.","device_name":"RTL8111/8168/8211/8411 PCI Express Gigabit Ethernet Controller","driver":"r8169","link":null,"iommu_group":15},
      {"bdf":"0000:2d:00.0","parent":null,"vendor":"1217","device":"8621","class":"080501","class_name":"system","vendor_name":"O2 Micro, Inc.","device_name":"SD/MMC Card Reader Controller","driver":"sdhci-pci","link":null,"iommu_group":14}]}"#;

    #[test]
    fn pcie_shows_the_hex_ids_the_host_sends() {
        if !need_parser() {
            return;
        }
        let s = pcie(LIVE_PCI, false, false, NOP);
        assert!(!s.contains("0000:0000"), "ids must not collapse to zero:\n{}", s);
        for id in ["8086:4621", "8086:51f0", "10ec:8168", "1217:8621"] {
            assert!(s.contains(id), "{} missing:\n{}", id, s);
        }
        assert!(s.contains("Alder Lake PCH CNVi WiFi") && s.contains("Network controller [wifi]"), "{}", s);
        assert!(!s.contains("Ethernet controller ["), "ethernet is not annotated: {}", s);
        let v = pcie(LIVE_PCI, false, true, NOP);
        assert!(v.contains("subsystem 8086:0074"), "{}", v);
        // older bodies with numeric ids still render
        let old = pcie(r#"{"devices":[{"bdf":"0000:00:1c.0","vendor":32902,"device":4096,"class_name":"x"}]}"#, false, false, NOP);
        assert!(old.contains("8086:1000"), "{}", old);
    }

    #[test]
    fn usb_shows_ids_and_falls_back_to_table_names() {
        if !need_parser() {
            return;
        }
        let body = r#"{"v":1,"devices":[
          {"path":"usb3","vid":"1d6b","pid":"0002","class":9,"speed_mbps":480,"manufacturer":"Linux 6.18.63-i7lab xhci-hcd","product":"xHCI Host Controller","serial":"0000:00:14.0","drivers":["hub"],"vendor_name":"Linux Foundation","product_name":"2.0 root hub"},
          {"path":"3-10","vid":"8087","pid":"0026","class":224,"speed_mbps":12,"manufacturer":null,"product":null,"serial":null,"drivers":[],"vendor_name":"Intel Corp.","product_name":"AX201 Bluetooth"}]}"#;
        let s = usb(body, NOP);
        assert!(s.contains("1d6b:0002") && s.contains("8087:0026") && !s.contains("0000:0000"), "{}", s);
        assert!(s.contains("Intel Corp.") && s.contains("AX201 Bluetooth") && s.contains("xHCI Host Controller") && s.contains("hub"), "{}", s);
        let f = crate::cmds::filter_usb(body, "8087:0026");
        assert!(f.contains("8087") && !f.contains("1d6b"), "{}", f);
    }

    #[test]
    fn inv_prints_uptime_from_the_float_the_host_sends() {
        if !need_parser() {
            return;
        }
        let s = inv(r#"{"v":1,"system":{"hostname":"h","kernel":"6.18","uptime_s":4321.98,"boot_mode":"uefi"}}"#, NOP);
        assert!(s.contains("uptime       1h12m") || s.contains("1h12m"), "{}", s);
        assert!(!s.contains("uptime       -"), "{}", s);
        // a host that reports no uptime still shows a dash
        assert!(inv(r#"{"v":1,"system":{"hostname":"h"}}"#, NOP).contains("uptime       -"));
    }

    #[test]
    fn net_hides_kernel_virtual_devices_unless_all() {
        if !need_parser() {
            return;
        }
        let body = r#"{"ifaces":[
          {"name":"dummy0","kind":"virtual/kernel","mac":"b6:1c:81:32:57:d5","operstate":"unknown","carrier":true},
          {"name":"eth0","kind":"ethernet","mac":"02:00:00:00:00:60","operstate":"up","carrier":true,"speed_mbps":1000,"driver":"r8169","ipv4":["192.0.2.60/24"],"ipv6":[]},
          {"name":"sit0","kind":"virtual/kernel","operstate":"down","carrier":false},
          {"name":"wg0","kind":"virtual","operstate":"unknown"}]}"#;
        let s = net_ls(body, NOP);
        assert!(s.contains("eth0") && s.contains("ethernet") && s.contains("wg0") && s.contains("KIND"), "{}", s);
        assert!(!s.contains("\ndummy0") && !s.contains("\nsit0") && s.contains("2 virtual/kernel interface(s) hidden"), "{}", s);
        let a = net_ls_all(body, true, NOP);
        assert!(a.contains("dummy0") && a.contains("sit0") && a.contains("virtual/kernel") && !a.contains("hidden"), "{}", a);
        // hosts that predate `kind`: the kernel's own device names are still recognised
        let old = net_ls(r#"{"ifaces":[{"name":"dummy0","operstate":"unknown"},{"name":"sit0","operstate":"down"},{"name":"eth0","operstate":"up","driver":"e1000e"}]}"#, NOP);
        assert!(old.contains("eth0") && !old.contains("sit0 ") && old.contains("2 virtual/kernel"), "{}", old);
    }

    #[test]
    fn smart_verdict_words_and_nvme_details() {
        if !need_parser() {
            return;
        }
        let body = r#"{"dev":"nvme0n1","kind":"nvme","verdict":"pass","reasons":[],"temperature_c":38,"power_on_hours":1034,"model":"WD Green SN3000 500GB","serial":"TESTSER00001","firmware":"X","attrs":[],
          "nvme":{"critical_warning":0,"temperature_c":38,"available_spare":100,"spare_threshold":10,"percentage_used":1,"data_units_read":1234567,"data_units_written":2345678,"power_cycles":312,"power_on_hours":1034,"unsafe_shutdowns":21,"media_errors":0,"error_log_entries":0,"data_read_bytes":632098304000,"data_written_bytes":1200000000000}}"#;
        let s = blk_smart(body, false, NOP);
        for want in ["PASSED", "WD Green SN3000 500GB", "38 C", "1034", "available_spare", "100% (threshold 10%)", "unsafe_shutdowns   21", "632.1 GB"] {
            assert!(s.contains(want), "{} missing:\n{}", want, s);
        }
        let bad = body.replace("\"verdict\":\"pass\"", "\"verdict\":\"fail\"").replace("\"reasons\":[]", "\"reasons\":[\"available spare below threshold\"]");
        let s = blk_smart(&bad, false, NOP);
        assert!(s.contains("FAILED") && s.contains("reason") && s.contains("available spare below threshold"), "{}", s);
        assert!(smart_failed(&bad) && !smart_failed(body));
        assert!(blk_smart(&body.replace("pass", "warn"), false, NOP).contains("WARNING"));
        assert!(blk_smart(r#"{"dev":"vda","kind":"unsupported","verdict":"unknown","reasons":["no SMART on this kind of device"],"attrs":[]}"#, false, NOP).contains("UNKNOWN"));
        let ata = r#"{"dev":"sda","kind":"ata","verdict":"fail","reasons":["x"],"temperature_c":36,"power_on_hours":20000,"attrs":[{"id":5,"name":"Reallocated_Sector_Ct","value":2,"worst":2,"thresh":36,"raw":812,"failing_now":true}],"nvme":null}"#;
        let t = blk_smart(ata, true, NOP);
        assert!(t.contains("Reallocated_Sector_Ct") && t.contains("FAILING") && t.contains("812"), "{}", t);
        assert!(blk_smart(ata, false, NOP).contains("--attrs"));
    }

    #[test]
    fn blk_ls_has_a_smart_column() {
        if !need_parser() {
            return;
        }
        let body = r#"{"devices":[{"name":"nvme0n1","size_bytes":500107862016,"kind":"nvme","model":"WD Green SN3000 500GB","serial":"TESTSER00001","boot_media":true,"smart":"pass","write_safety":{"verdict":"unsafe"}},{"name":"sda","size_bytes":1,"kind":"usb","write_safety":{"verdict":"safe"}}]}"#;
        let s = blk_ls(body, NOP);
        assert!(s.contains("SMART") && s.contains("PASSED"), "{}", s);
        let row = s.lines().find(|l| l.starts_with("sda")).unwrap();
        assert!(row.contains(" - "), "no verdict for a disk that was not asked: {}", row);
    }
}
