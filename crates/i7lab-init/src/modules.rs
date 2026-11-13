//! Kernel module loading by modalias scan, no udev, no modprobe.
//!
//! Inputs: the modalias strings of every device the kernel knows (`/sys/bus/*/devices/*/modalias`), the
//! `modules.alias` and `modules.dep` files of `/lib/modules/<release>/` (depmod output of the image build).
//! Pure part (host-tested): alias glob matching, alias/dep parsing, load planning (dependencies first, each module
//! once, already-loaded skipped). Impure part: the sysfs walk and finit_module(2).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------- pure

/// Shell-style glob as used by modules.alias: `*`, `?`, `[abc]`, `[a-f]`, `[!x]`. Case sensitive.
pub fn glob_match(pat: &str, text: &str) -> bool {
    fn go(p: &[u8], t: &[u8]) -> bool {
        let (mut pi, mut ti) = (0usize, 0usize);
        let (mut star_p, mut star_t) = (usize::MAX, 0usize);
        while ti < t.len() {
            if pi < p.len() {
                match p[pi] {
                    b'*' => {
                        star_p = pi;
                        star_t = ti;
                        pi += 1;
                        continue;
                    }
                    b'?' => {
                        pi += 1;
                        ti += 1;
                        continue;
                    }
                    b'[' => {
                        if let Some((ok, next)) = class(&p[pi..], t[ti]) {
                            if ok {
                                pi += next;
                                ti += 1;
                                continue;
                            }
                        } else if t[ti] == b'[' {
                            // unterminated class: literal '['
                            pi += 1;
                            ti += 1;
                            continue;
                        }
                    }
                    c => {
                        if c == t[ti] {
                            pi += 1;
                            ti += 1;
                            continue;
                        }
                    }
                }
            }
            if star_p != usize::MAX {
                star_t += 1;
                ti = star_t;
                pi = star_p + 1;
                continue;
            }
            return false;
        }
        while pi < p.len() && p[pi] == b'*' {
            pi += 1;
        }
        pi == p.len()
    }
    go(pat.as_bytes(), text.as_bytes())
}

/// Match one byte against a `[...]` class at the start of `p`. Returns (matched, bytes consumed) or None when the
/// class is not terminated.
fn class(p: &[u8], c: u8) -> Option<(bool, usize)> {
    let mut i = 1;
    let neg = matches!(p.get(i), Some(b'!') | Some(b'^'));
    if neg {
        i += 1;
    }
    let mut matched = false;
    let mut first = true;
    loop {
        let &b = p.get(i)?;
        if b == b']' && !first {
            return Some((matched != neg, i + 1));
        }
        first = false;
        if p.get(i + 1) == Some(&b'-') && p.get(i + 2).map(|&e| e != b']').unwrap_or(false) {
            let hi = p[i + 2];
            if b <= c && c <= hi {
                matched = true;
            }
            i += 3;
        } else {
            if b == c {
                matched = true;
            }
            i += 1;
        }
    }
}

/// Normalised module name: basename without `.ko[.zst|.xz|.gz]`, `-` -> `_` (what /sys/module uses).
pub fn module_name(path_or_name: &str) -> String {
    let base = path_or_name.rsplit('/').next().unwrap_or(path_or_name);
    let mut b = base;
    for ext in [".zst", ".xz", ".gz"] {
        if let Some(s) = b.strip_suffix(ext) {
            b = s;
        }
    }
    b.strip_suffix(".ko").unwrap_or(b).replace('-', "_")
}

#[derive(Default, Debug)]
pub struct AliasDb {
    /// (pattern, module name), file order
    pub entries: Vec<(String, String)>,
}

pub fn parse_aliases(text: &str) -> AliasDb {
    let mut db = AliasDb::default();
    for l in text.lines() {
        let mut it = l.split_whitespace();
        if it.next() == Some("alias") {
            if let (Some(p), Some(m)) = (it.next(), it.next()) {
                db.entries.push((p.to_string(), module_name(m)));
            }
        }
    }
    db
}

impl AliasDb {
    /// Distinct module names (first-seen order) matching any of the device modaliases.
    pub fn modules_for(&self, modaliases: &[String]) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for ma in modaliases {
            for (pat, m) in &self.entries {
                if glob_match(pat, ma) && seen.insert(m.clone()) {
                    out.push(m.clone());
                }
            }
        }
        out
    }
}

#[derive(Default, Debug)]
pub struct DepDb {
    /// module name -> (relative path, dependency module names in load order)
    pub map: HashMap<String, (String, Vec<String>)>,
    /// file order, for the no-alias fallback
    pub order: Vec<String>,
}

/// `modules.dep` lines: `kernel/x/foo.ko.zst: kernel/lib/bar.ko.zst kernel/lib/baz.ko.zst`. depmod lists the
/// dependencies in the order they must be loaded after their own dependencies, closest last, so the kernel docs
/// say to load them in REVERSE of the listed order. We rely on the plan below instead (recursion), which does not
/// depend on that ordering.
pub fn parse_deps(text: &str) -> DepDb {
    let mut db = DepDb::default();
    for l in text.lines() {
        let Some((m, d)) = l.split_once(':') else { continue };
        let name = module_name(m.trim());
        let deps = d.split_whitespace().map(module_name).collect();
        db.order.push(name.clone());
        db.map.insert(name, (m.trim().to_string(), deps));
    }
    db
}

impl DepDb {
    /// Load order for `wanted`: every dependency before its dependant, each module once, skipping `loaded`.
    /// Cycle-safe. Modules absent from the db are returned in `missing`.
    pub fn plan(&self, wanted: &[String], loaded: &dyn Fn(&str) -> bool) -> Plan {
        let mut p = Plan::default();
        let mut visiting = HashSet::new();
        let mut done = HashSet::new();
        for w in wanted {
            self.visit(w, loaded, &mut visiting, &mut done, &mut p);
        }
        p
    }

    fn visit(&self, name: &str, loaded: &dyn Fn(&str) -> bool, visiting: &mut HashSet<String>, done: &mut HashSet<String>, p: &mut Plan) {
        if done.contains(name) || visiting.contains(name) || loaded(name) {
            return;
        }
        let Some((path, deps)) = self.map.get(name) else {
            if !p.missing.iter().any(|m| m == name) {
                p.missing.push(name.to_string());
            }
            return;
        };
        visiting.insert(name.to_string());
        for d in deps {
            self.visit(d, loaded, visiting, done, p);
        }
        visiting.remove(name);
        if done.insert(name.to_string()) {
            p.load.push((name.to_string(), path.clone()));
        }
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Plan {
    /// (module name, path relative to /lib/modules/<release>)
    pub load: Vec<(String, String)>,
    pub missing: Vec<String>,
}

/// Wait until a counter stops changing: `observe` returns true once the value has been stable for `quiet_ms`, or
/// after `max_ms` in total.
pub struct Settle {
    start: u64,
    quiet_ms: u64,
    max_ms: u64,
    last: Option<usize>,
    since: u64,
}

impl Settle {
    pub fn new(now: u64, quiet_ms: u64, max_ms: u64) -> Settle {
        Settle { start: now, quiet_ms, max_ms, last: None, since: now }
    }
    pub fn observe(&mut self, now: u64, value: usize) -> bool {
        if self.last != Some(value) {
            self.last = Some(value);
            self.since = now;
        }
        now.saturating_sub(self.since) >= self.quiet_ms || now.saturating_sub(self.start) >= self.max_ms
    }
}

// ---------------------------------------------------------------- impure

pub fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease").map(|s| s.trim().to_string()).unwrap_or_default()
}

/// Every device modalias in sysfs: `/sys/bus/*/devices/*/modalias` (PCI, USB, platform, ACPI, cpu features, ...).
pub fn device_modaliases() -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let Ok(buses) = std::fs::read_dir("/sys/bus") else { return out };
    for bus in buses.flatten() {
        let Ok(devs) = std::fs::read_dir(bus.path().join("devices")) else { continue };
        for d in devs.flatten() {
            if let Ok(s) = std::fs::read_to_string(d.path().join("modalias")) {
                let s = s.trim().to_string();
                if !s.is_empty() && seen.insert(s.clone()) {
                    out.push(s);
                }
            }
        }
    }
    out
}

fn is_loaded(name: &str) -> bool {
    Path::new("/sys/module").join(name).exists()
}

/// Count of things that appear as drivers bind: NICs, disks, USB devices.
pub fn device_count() -> usize {
    let n = |p: &str| std::fs::read_dir(p).map(|d| d.count()).unwrap_or(0);
    n("/sys/class/net") + n("/sys/block") + n("/sys/bus/usb/devices")
}

pub struct LoadStats {
    pub loaded: usize,
    pub failed: usize,
    pub rounds: u32,
}

/// Scan, load, settle, and repeat while new modalias strings keep appearing (a USB hub driver exposes new
/// devices). At most 4 rounds; each round ends with a settle of at most 3 s.
pub fn load_by_modalias(now_ms: &dyn Fn() -> u64) -> Option<LoadStats> {
    let rel = kernel_release();
    let dir = PathBuf::from("/lib/modules").join(&rel);
    let alias_text = std::fs::read_to_string(dir.join("modules.alias")).ok();
    let dep_text = std::fs::read_to_string(dir.join("modules.dep")).ok()?;
    let deps = parse_deps(&dep_text);
    let mut stats = LoadStats { loaded: 0, failed: 0, rounds: 0 };
    let mut tried: HashSet<String> = HashSet::new();

    let Some(alias_text) = alias_text else {
        // No alias database: load everything listed in modules.dep (the image only carries the wanted modules).
        let all: Vec<String> = deps.order.clone();
        apply(&deps.plan(&all, &is_loaded), &dir, &mut tried, &mut stats);
        return Some(stats);
    };
    let aliases = parse_aliases(&alias_text);
    let mut seen_aliases: HashSet<String> = HashSet::new();
    for _ in 0..4 {
        stats.rounds += 1;
        let new: Vec<String> = device_modaliases().into_iter().filter(|a| seen_aliases.insert(a.clone())).collect();
        if new.is_empty() && stats.rounds > 1 {
            break;
        }
        let wanted = aliases.modules_for(&new);
        let plan = deps.plan(&wanted, &is_loaded);
        let before = stats.loaded;
        apply(&plan, &dir, &mut tried, &mut stats);
        if stats.loaded == before && stats.rounds > 1 {
            break;
        }
        let mut s = Settle::new(now_ms(), 500, 3000);
        while !s.observe(now_ms(), device_count()) {
            crate::ffi::sleep_ms(100);
        }
    }
    Some(stats)
}

fn apply(plan: &Plan, dir: &Path, tried: &mut HashSet<String>, stats: &mut LoadStats) {
    for (name, rel) in &plan.load {
        if !tried.insert(name.clone()) {
            continue;
        }
        match crate::ffi::finit_module(&dir.join(rel)) {
            Ok(()) => stats.loaded += 1,
            Err(17) => {} // EEXIST: loaded meanwhile (built-in or a dependency of another)
            Err(e) => {
                stats.failed += 1;
                crate::logf!("finit_module {name}: errno {e}");
            }
        }
    }
    for m in &plan.missing {
        crate::logf!("module {m}: matched by an alias but absent from modules.dep");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_basics() {
        assert!(glob_match("pci:v00008086d000015F3sv*sd*bc*sc*i*", "pci:v00008086d000015F3sv00001043sd0000866Fbc02sc00i00"));
        assert!(!glob_match("pci:v00008086d000015F3*", "pci:v00008086d000015F2sv0"));
        assert!(glob_match("usb:v0BDAp8153d*dc*dsc*dp*ic*isc*ip*in*", "usb:v0BDAp8153d3000dc00dsc00dp00ic09isc00ip00in00"));
        assert!(glob_match("a?c", "abc") && !glob_match("a?c", "ac"));
        assert!(glob_match("*", "") && glob_match("**x", "x") && !glob_match("*x", "xy"));
    }

    #[test]
    fn glob_classes() {
        assert!(glob_match("x[0-9]y", "x5y") && !glob_match("x[0-9]y", "xay"));
        assert!(glob_match("x[!0-9]y", "xay") && !glob_match("x[!0-9]y", "x5y"));
        assert!(glob_match("[abc]*", "cat") && !glob_match("[abc]*", "dog"));
        assert!(glob_match("x[]]y", "x]y")); // leading ] is literal
        assert!(glob_match("a[b", "a[b")); // unterminated class is literal
    }

    #[test]
    fn module_names() {
        assert_eq!(module_name("kernel/drivers/net/ethernet/intel/e1000e/e1000e.ko.zst"), "e1000e");
        assert_eq!(module_name("kernel/x/snd-hda-intel.ko"), "snd_hda_intel");
        assert_eq!(module_name("r8152"), "r8152");
    }

    const ALIAS: &str = "# comment\nalias pci:v00008086d000015F3sv*sd*bc*sc*i* igc\nalias usb:v0BDAp8153d*dc*dsc*dp*ic*isc*ip*in* r8152\nalias pci:v00008086d*sv*sd*bc02sc*i* e1000e\nalias cpu:type:x86,ven*fam*mod*:feature:*0099* aesni_intel\n";
    const DEP: &str = "kernel/net/a.ko.zst:\nkernel/drivers/igc.ko.zst: kernel/lib/ptp.ko.zst kernel/lib/phy.ko.zst\nkernel/lib/ptp.ko.zst: kernel/lib/phy.ko.zst\nkernel/lib/phy.ko.zst:\nkernel/drivers/r8152.ko.zst: kernel/lib/mii.ko.zst\nkernel/lib/mii.ko.zst:\nkernel/drivers/loop1.ko: kernel/drivers/loop2.ko\nkernel/drivers/loop2.ko: kernel/drivers/loop1.ko\n";

    #[test]
    fn alias_matching_is_deduplicated_and_ordered() {
        let db = parse_aliases(ALIAS);
        let mods = db.modules_for(&[
            "pci:v00008086d000015F3sv00001043sd0000866Fbc02sc00i00".to_string(),
            "usb:v0BDAp8153d3000dc00dsc00dp00ic09isc00ip00in00".to_string(),
            "usb:v0BDAp8153d3000dc00dsc00dp00ic09isc00ip00in01".to_string(),
        ]);
        // igc and e1000e both match the PCI NIC (e1000e's alias is a class wildcard), r8152 once
        assert_eq!(mods, vec!["igc", "e1000e", "r8152"]);
    }

    #[test]
    fn plan_loads_dependencies_first_once() {
        let deps = parse_deps(DEP);
        let p = deps.plan(&["igc".into(), "r8152".into()], &|_| false);
        let names: Vec<&str> = p.load.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["phy", "ptp", "igc", "mii", "r8152"]);
        assert_eq!(p.load[0].1, "kernel/lib/phy.ko.zst");
        assert!(p.missing.is_empty());
    }

    #[test]
    fn plan_skips_loaded_and_reports_missing() {
        let deps = parse_deps(DEP);
        let p = deps.plan(&["igc".into(), "nonesuch".into()], &|n| n == "phy");
        let names: Vec<&str> = p.load.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["ptp", "igc"]);
        assert_eq!(p.missing, vec!["nonesuch"]);
    }

    #[test]
    fn plan_survives_dependency_cycles() {
        let deps = parse_deps(DEP);
        let p = deps.plan(&["loop1".into()], &|_| false);
        assert_eq!(p.load.len(), 2);
    }

    #[test]
    fn settle_waits_for_quiet_or_deadline() {
        let mut s = Settle::new(0, 1000, 5000);
        assert!(!s.observe(0, 3));
        assert!(!s.observe(500, 4)); // changed: quiet period restarts
        assert!(!s.observe(1400, 4));
        assert!(s.observe(1500, 4));
        let mut s = Settle::new(0, 1000, 5000);
        for t in 0..5 {
            assert!(!s.observe(t * 900, t as usize));
        }
        assert!(s.observe(5000, 99)); // deadline
    }
}
