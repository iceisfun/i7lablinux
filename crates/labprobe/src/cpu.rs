//! cpu: /proc/cpuinfo + /sys/devices/system/cpu. Owner: P3.

use labproto::json::{JsonWriter, ToJson};

use crate::ctx::{ProbeCtx, ProbeError};

#[derive(Clone, Debug, Default)]
pub struct Cache {
    pub level: u8,
    /// "Data" | "Instruction" | "Unified"
    pub kind: String,
    pub size_kib: u64,
}

#[derive(Clone, Debug, Default)]
pub struct CpuInfo {
    pub vendor: String,
    pub model_name: String,
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    pub microcode: Option<String>,
    pub codename: Option<String>,
    pub sockets: u32,
    pub cores: u32,
    pub threads: u32,
    /// decoded subset: avx2 avx512f aes sha_ni vmx svm smep smap pdpe1gb ...
    pub flags_summary: Vec<String>,
    pub freq_mhz: Option<f64>,
    pub caches: Vec<Cache>,
    /// (name, status) from /sys/devices/system/cpu/vulnerabilities
    pub vulnerabilities: Vec<(String, String)>,
}

/// Flags worth showing (the full list is hundreds of entries); order is the display order.
pub const INTERESTING_FLAGS: &[&str] = &[
    "lm", "nx", "pdpe1gb", "sse4_2", "avx", "avx2", "avx512f", "avx512bw", "avx512vl", "avx512_vnni", "avx_vnni", "amx_tile", "aes", "vaes",
    "pclmulqdq", "sha_ni", "gfni", "bmi2", "adx", "rdrand", "rdseed", "fma", "f16c", "vmx", "svm", "ept", "npt", "hypervisor", "smep", "smap",
    "sgx", "tme", "x2apic", "invpcid", "la57", "constant_tsc", "nonstop_tsc", "tsc_adjust", "ibrs", "ibpb", "stibp", "ssbd", "arch_capabilities",
];

pub fn probe(ctx: &ProbeCtx) -> Result<CpuInfo, ProbeError> {
    let text = ctx.read_trim("/proc/cpuinfo")?;
    let mut c = parse_cpuinfo(&text);
    // topology from sysfs wins (cpuinfo "physical id"/"core id" are missing on some kernels / VMs)
    let (mut pkgs, mut cores): (Vec<String>, Vec<(String, String)>) = (vec![], vec![]);
    let mut online = 0;
    for e in ctx.list_dir("/sys/devices/system/cpu").unwrap_or_default() {
        let Some(n) = e.strip_prefix("cpu").filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())) else { continue };
        let _ = n;
        let t = |f: &str| ctx.read_opt(&format!("/sys/devices/system/cpu/{}/topology/{}", e, f));
        if let (Some(p), Some(core)) = (t("physical_package_id"), t("core_id")) {
            online += 1;
            if !pkgs.contains(&p) {
                pkgs.push(p.clone());
            }
            if !cores.contains(&(p.clone(), core.clone())) {
                cores.push((p, core));
            }
        }
    }
    if online > 0 {
        c.sockets = pkgs.len() as u32;
        c.cores = cores.len() as u32;
        c.threads = online;
    }
    c.freq_mhz = c.freq_mhz.or_else(|| {
        ctx.read_opt("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq").and_then(|v| v.parse::<f64>().ok()).map(|k| k / 1000.0)
    });
    for i in 0..8 {
        let base = format!("/sys/devices/system/cpu/cpu0/cache/index{}", i);
        let (Some(level), Some(kind), Some(size)) = (ctx.read_opt(&format!("{}/level", base)), ctx.read_opt(&format!("{}/type", base)), ctx.read_opt(&format!("{}/size", base))) else { continue };
        if let (Ok(level), Some(size_kib)) = (level.parse(), parse_cache_size(&size)) {
            c.caches.push(Cache { level, kind, size_kib });
        }
    }
    let vdir = "/sys/devices/system/cpu/vulnerabilities";
    for v in ctx.list_dir(vdir).unwrap_or_default() {
        if let Some(status) = ctx.read_opt(&format!("{}/{}", vdir, v)) {
            c.vulnerabilities.push((v, status.lines().next().unwrap_or("").to_string()));
        }
    }
    c.codename = codename(&c.vendor, c.family, c.model).map(str::to_string);
    Ok(c)
}

/// "32K" -> 32, "8192K" -> 8192, "16M" -> 16384.
pub fn parse_cache_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('K') {
        n.parse().ok()
    } else if let Some(n) = s.strip_suffix('M') {
        n.parse::<u64>().ok().map(|m| m * 1024)
    } else {
        s.parse::<u64>().ok().map(|b| b / 1024)
    }
}

/// Microarchitecture names for the families met in the lab. `None` = not in the table (never guessed).
pub fn codename(vendor: &str, family: u32, model: u32) -> Option<&'static str> {
    Some(match (vendor, family, model) {
        ("GenuineIntel", 6, 0x2a) => "Sandy Bridge",
        ("GenuineIntel", 6, 0x2d) => "Sandy Bridge-EP",
        ("GenuineIntel", 6, 0x3a) => "Ivy Bridge",
        ("GenuineIntel", 6, 0x3e) => "Ivy Bridge-EP",
        ("GenuineIntel", 6, 0x3c) | ("GenuineIntel", 6, 0x45) | ("GenuineIntel", 6, 0x46) => "Haswell",
        ("GenuineIntel", 6, 0x3f) => "Haswell-EP",
        ("GenuineIntel", 6, 0x3d) | ("GenuineIntel", 6, 0x47) => "Broadwell",
        ("GenuineIntel", 6, 0x4f) | ("GenuineIntel", 6, 0x56) => "Broadwell-EP/DE",
        ("GenuineIntel", 6, 0x4e) | ("GenuineIntel", 6, 0x5e) => "Skylake",
        ("GenuineIntel", 6, 0x55) => "Skylake-SP/Cascade Lake",
        ("GenuineIntel", 6, 0x8e) | ("GenuineIntel", 6, 0x9e) => "Kaby Lake/Coffee Lake",
        ("GenuineIntel", 6, 0xa5) | ("GenuineIntel", 6, 0xa6) => "Comet Lake",
        ("GenuineIntel", 6, 0xa7) => "Rocket Lake",
        ("GenuineIntel", 6, 0x6a) | ("GenuineIntel", 6, 0x6c) => "Ice Lake-SP/D",
        ("GenuineIntel", 6, 0x7d) | ("GenuineIntel", 6, 0x7e) => "Ice Lake",
        ("GenuineIntel", 6, 0x8c) | ("GenuineIntel", 6, 0x8d) => "Tiger Lake",
        ("GenuineIntel", 6, 0x8f) => "Sapphire Rapids",
        ("GenuineIntel", 6, 0x97) | ("GenuineIntel", 6, 0x9a) => "Alder Lake",
        ("GenuineIntel", 6, 0xbe) => "Alder Lake-N",
        ("GenuineIntel", 6, 0xb7) | ("GenuineIntel", 6, 0xba) | ("GenuineIntel", 6, 0xbf) => "Raptor Lake",
        ("GenuineIntel", 6, 0xaa) | ("GenuineIntel", 6, 0xac) => "Meteor Lake",
        ("GenuineIntel", 6, 0xcf) => "Emerald Rapids",
        ("GenuineIntel", 6, 0x5c) => "Goldmont",
        ("GenuineIntel", 6, 0x7a) => "Goldmont Plus",
        ("GenuineIntel", 6, 0x9c) => "Jasper Lake",
        ("AuthenticAMD", 0x15, 0x70) => "Stoney Ridge",
        ("AuthenticAMD", 0x17, 0x01) => "Zen (Summit Ridge)",
        ("AuthenticAMD", 0x17, 0x08) => "Zen+ (Pinnacle Ridge)",
        ("AuthenticAMD", 0x17, 0x11) | ("AuthenticAMD", 0x17, 0x18) => "Zen (Raven Ridge)",
        ("AuthenticAMD", 0x17, 0x31) => "Zen 2 (Rome)",
        ("AuthenticAMD", 0x17, 0x60) => "Zen 2 (Renoir)",
        ("AuthenticAMD", 0x17, 0x71) => "Zen 2 (Matisse)",
        ("AuthenticAMD", 0x19, 0x01) => "Zen 3 (Milan)",
        ("AuthenticAMD", 0x19, 0x21) => "Zen 3 (Vermeer)",
        ("AuthenticAMD", 0x19, 0x50) => "Zen 3 (Cezanne)",
        ("AuthenticAMD", 0x19, 0x44) | ("AuthenticAMD", 0x19, 0x40) => "Zen 3+ (Rembrandt)",
        ("AuthenticAMD", 0x19, 0x10) | ("AuthenticAMD", 0x19, 0x11) => "Zen 4 (Genoa)",
        ("AuthenticAMD", 0x19, 0x61) => "Zen 4 (Raphael / Dragon Range)",
        _ => return None,
    })
}

/// Pure parser over /proc/cpuinfo text (first logical CPU's identity and flags; thread count = number of
/// `processor` stanzas; sockets/cores from `physical id` / `core id` when present).
pub fn parse_cpuinfo(text: &str) -> CpuInfo {
    let mut c = CpuInfo::default();
    let mut first_flags: Option<Vec<&str>> = None;
    let mut seen_cpu = 0;
    let mut pkgs: Vec<&str> = vec![];
    let mut cores: Vec<(&str, &str)> = vec![];
    let (mut cur_pkg, mut cur_core) = ("", "");
    for line in text.lines().chain(std::iter::once("")) {
        if line.trim().is_empty() {
            // end of a stanza
            if !cur_pkg.is_empty() && !cur_core.is_empty() {
                if !pkgs.contains(&cur_pkg) {
                    pkgs.push(cur_pkg);
                }
                if !cores.contains(&(cur_pkg, cur_core)) {
                    cores.push((cur_pkg, cur_core));
                }
            }
            cur_pkg = "";
            cur_core = "";
            continue;
        }
        let Some((k, v)) = line.split_once(':') else { continue };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "processor" => {
                c.threads += 1;
                seen_cpu += 1;
            }
            "vendor_id" if c.vendor.is_empty() => c.vendor = v.into(),
            "model name" if c.model_name.is_empty() => c.model_name = v.into(),
            "cpu family" if seen_cpu <= 1 => c.family = v.parse().unwrap_or(0),
            "model" if seen_cpu <= 1 => c.model = v.parse().unwrap_or(0),
            "stepping" if seen_cpu <= 1 => c.stepping = v.parse().unwrap_or(0),
            "microcode" if c.microcode.is_none() => c.microcode = Some(v.into()),
            "cpu MHz" if c.freq_mhz.is_none() => c.freq_mhz = v.parse().ok(),
            "flags" if first_flags.is_none() => first_flags = Some(v.split_whitespace().collect()),
            "physical id" => cur_pkg = v,
            "core id" => cur_core = v,
            _ => {}
        }
    }
    if let Some(flags) = first_flags {
        c.flags_summary = INTERESTING_FLAGS.iter().filter(|f| flags.contains(f)).map(|f| f.to_string()).collect();
    }
    c.sockets = pkgs.len() as u32;
    c.cores = cores.len() as u32;
    c
}

impl ToJson for CpuInfo {
    fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.field_u64("v", crate::SCHEMA_V);
        w.field_str("vendor", &self.vendor);
        w.field_str("model_name", &self.model_name);
        w.field_u64("family", self.family as u64);
        w.field_u64("model", self.model as u64);
        w.field_u64("stepping", self.stepping as u64);
        w.field_opt_str("microcode", self.microcode.as_deref());
        w.field_opt_str("codename", self.codename.as_deref());
        w.field_u64("sockets", self.sockets as u64);
        w.field_u64("cores", self.cores as u64);
        w.field_u64("threads", self.threads as u64);
        w.key("flags_summary");
        w.value(&self.flags_summary);
        w.field_opt_f64("freq_mhz", self.freq_mhz);
        w.key("caches");
        w.begin_array();
        for k in &self.caches {
            w.begin_object();
            w.field_u64("level", k.level as u64);
            w.field_str("kind", &k.kind);
            w.field_u64("size_kib", k.size_kib);
            w.end_object();
        }
        w.end_array();
        w.key("vulnerabilities");
        w.begin_object();
        for (k, v) in &self.vulnerabilities {
            w.field_str(k, v);
        }
        w.end_object();
        w.end_object();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWO_SOCKET: &str = "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 85\nmodel name\t: Intel(R) Xeon(R) Gold 6130\nstepping\t: 4\nmicrocode\t: 0x2007006\ncpu MHz\t\t: 2100.000\nphysical id\t: 0\nflags\t\t: fpu vme sse4_2 avx avx2 avx512f aes vmx lm nx\ncore id\t\t: 0\n\n\
processor\t: 1\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 85\nmodel name\t: Intel(R) Xeon(R) Gold 6130\nphysical id\t: 0\ncore id\t\t: 0\nflags\t\t: fpu\n\n\
processor\t: 2\nvendor_id\t: GenuineIntel\nphysical id\t: 1\ncore id\t\t: 0\n\n\
processor\t: 3\nvendor_id\t: GenuineIntel\nphysical id\t: 1\ncore id\t\t: 1\n";

    #[test]
    fn parses_basic_fields() {
        let c = parse_cpuinfo("processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 158\nmodel name\t: Intel(R) Core(TM) i7-8700T\nprocessor\t: 1\n");
        assert_eq!(c.vendor, "GenuineIntel");
        assert_eq!((c.family, c.model, c.threads), (6, 158, 2));
    }

    #[test]
    fn topology_flags_and_first_cpu_wins() {
        let c = parse_cpuinfo(TWO_SOCKET);
        assert_eq!((c.sockets, c.cores, c.threads), (2, 3, 4)); // socket 0 has 1 core (2 threads listed with same core id), socket 1 has 2
        assert_eq!(c.microcode.as_deref(), Some("0x2007006"));
        assert_eq!(c.freq_mhz, Some(2100.0));
        assert_eq!(c.flags_summary, ["lm", "nx", "sse4_2", "avx", "avx2", "avx512f", "aes", "vmx"]);
        assert_eq!(c.model, 85);
    }

    #[test]
    fn caches_and_codenames() {
        assert_eq!(parse_cache_size("32K"), Some(32));
        assert_eq!(parse_cache_size("16M"), Some(16384));
        assert_eq!(parse_cache_size("8192K"), Some(8192));
        assert_eq!(codename("GenuineIntel", 6, 158), Some("Kaby Lake/Coffee Lake"));
        assert_eq!(codename("AuthenticAMD", 0x19, 0x61), Some("Zen 4 (Raphael / Dragon Range)"));
        assert_eq!(codename("GenuineIntel", 6, 0x01), None);
    }
}
