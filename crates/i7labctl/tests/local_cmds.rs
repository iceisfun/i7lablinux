//! Commands that run locally or listen on the wire: ls, discover, wait, key, image, ssh, lab-boot, completions.
mod common;

use std::time::Duration;

use common::*;
use i7labctl::discover::LinkSet;
use labproto::beacon::Beacon;
use labproto::frame::{self, FrameType};
use labproto::keys::KeySet;
use labproto::link::{Link, MemLink};
use labproto::Mac;

fn beacon(mac: &str, extra: &[(&str, &str)]) -> Beacon {
    let mut b = Beacon { version: 2, fields: vec![] };
    b.set("mac", mac);
    b.set("iface", "eth0");
    b.set("host", "lab-1");
    b.set("board", "Q35");
    b.set("board_serial", "SER1");
    b.set("boot", "9f3c");
    b.set("state", "ready");
    b.set("ip", "10.0.0.5/24");
    for (k, v) in extra {
        b.set(k, v);
    }
    b
}

fn beacon_frame(b: &Beacon, key: Option<&[u8; 32]>, tags: Vec<(u16, u16)>) -> Vec<u8> {
    let src = Mac::parse(b.get("mac").unwrap()).unwrap();
    let eth = frame::EthHeader { dst: Mac::BROADCAST, src, tags, ethertype: frame::ETHERTYPE_BEACON };
    frame::eth_build(&eth, &b.encode_v2(key, &src))
}

fn memlink() -> (LinkSet, MemLink) {
    let (a, b) = MemLink::pair(Mac([2, 0, 0, 0, 0, 1]), Mac([2, 0, 0, 0, 0, 2]));
    (LinkSet { link: Box::new(a), ifaces: vec![("eth0".into(), 1)] }, b)
}

fn ro_beacon_key(t: &T) -> [u8; 32] {
    let ks = KeySet::load_dir(&i7labctl::keys::default_key_dir(&t.home)).unwrap();
    KeySet { admin: None, ro: ks.ro }.beacon_key().unwrap()
}

// ---------------------------------------------------------------- ls

#[test]
fn ls_table_json_filters_and_sorting() {
    need_json!();
    let t = T::new("ls");
    t.add_host("52:54:00:17:00:01", 3, &[("ip", "10.0.0.9/24"), ("host", "bravo")]);
    t.add_host("52:54:00:17:00:02", 100, &[("ip", "10.0.0.2/24"), ("host", "alpha"), ("board_serial", "SER2")]);
    t.add_host("52:54:00:17:00:03", 5000, &[("host", "ancient"), ("board_serial", "SER3")]);
    let (code, o, _) = t.run(&["ls"]);
    assert_eq!(code, 0);
    assert!(o.contains("bravo") && o.contains("alpha") && !o.contains("ancient"), "{}", o);
    assert!(o.lines().next().unwrap().starts_with("MAC"), "{}", o);
    // most recently seen first
    assert!(o.find("bravo").unwrap() < o.find("alpha").unwrap());
    // --all shows the ancient one
    assert!(t.run(&["ls", "--all"]).1.contains("ancient"));
    // sort by ip
    let o = { t.out.0.lock().unwrap().clear(); t.run(&["ls", "--sort", "ip"]).1 };
    assert!(o.find("alpha").unwrap() < o.find("bravo").unwrap(), "{}", o);
    // state filters
    t.out.0.lock().unwrap().clear();
    let o = t.run(&["ls", "--state", "live"]).1;
    assert!(o.contains("bravo") && !o.contains("alpha"), "{}", o);
    t.out.0.lock().unwrap().clear();
    let o = t.run(&["ls", "--state", "stale"]).1;
    assert!(!o.contains("bravo") && o.contains("alpha"), "{}", o);
    // json
    t.out.0.lock().unwrap().clear();
    let (code, o, _) = t.run(&["ls", "--json"]);
    assert_eq!(code, 0);
    assert!(o.starts_with("{\"ok\":true,\"transport\":\"registry\",\"cmd\":\"ls\",\"data\":{\"hosts\":[{\"mac\":\"52:54:00:17:00:01\""), "{}", o);
    assert!(o.contains("\"liveness\":\"live\"") && o.contains("\"liveness\":\"stale\""), "{}", o);
    assert_eq!(o.lines().count(), 1);
}

#[test]
fn ls_flags_other_keyset_and_untrusted_beacons() {
    need_json!();
    let t = T::new("lsflags");
    t.add_host("52:54:00:17:00:01", 3, &[("kid", "a:deadbeef,r:cafef00d")]);
    let (_, o, _) = t.run(&["ls"]);
    assert!(o.contains("other-keyset"), "{}", o);
    t.out.0.lock().unwrap().clear();
    let (_, o, _) = t.run(&["ls", "--json"]);
    assert!(o.contains("\"flags\":[\"other-keyset\"]") || o.contains("other-keyset"), "{}", o);
}

#[test]
fn ls_is_empty_politely() {
    let t = T::new("lsempty");
    let (code, o, _) = t.run(&["ls"]);
    assert_eq!(code, 0);
    assert!(o.contains("run: i7labctl discover"), "{}", o);
    let (code, o, _) = t.run(&["ls", "--json"]);
    assert_eq!(code, 0);
    assert!(o.contains("\"hosts\":[]"), "{}", o);
}

// ---------------------------------------------------------------- discover

#[test]
fn discover_records_hosts_and_reports_them() {
    need_json!();
    let t = T::new("disc");
    let (set, mut peer) = memlink();
    *t.link.lock().unwrap() = Some(set);
    let key = ro_beacon_key(&t);
    peer.send(1, &beacon_frame(&beacon("52:54:00:17:00:01", &[("kid", "a:11111111,r:22222222")]), Some(&key), vec![])).unwrap();
    peer.send(1, &beacon_frame(&beacon("52:54:00:17:00:02", &[("host", "lab-2"), ("vlan", "13")]), None, vec![(0x8100, 13)])).unwrap();
    let (code, o, e) = t.run(&["discover", "--listen", "1"]);
    assert_eq!(code, 0, "{}", e);
    assert!(o.contains("52:54:00:17:00:01") && o.contains("52:54:00:17:00:02") && o.contains("lab-2"), "{}", o);
    // tag verified for the first, not for the second; the VLAN is decoded
    let lines: Vec<&str> = o.lines().collect();
    let l1 = lines.iter().find(|l| l.starts_with("52:54:00:17:00:01")).unwrap();
    let l2 = lines.iter().find(|l| l.starts_with("52:54:00:17:00:02")).unwrap();
    assert!(!l1.contains("unverified-tag") && l1.contains("other-keyset"), "{}", l1);
    assert!(l2.contains("unverified-tag") && l2.contains(" 13 "), "{}", l2);
    // the registry was written (mode 0600) and is what `ls` shows now
    let md = std::fs::metadata(t.registry_path()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(md.permissions().mode() & 0o777, 0o600);
    let (_, o, _) = t.run(&["ls", "--json"]);
    assert!(o.contains("52:54:00:17:00:02") && o.contains("\"vlan\":13"), "{}", o);
}

#[test]
fn discover_json_and_no_registry_and_empty() {
    need_json!();
    let t = T::new("disc2");
    let (set, mut peer) = memlink();
    *t.link.lock().unwrap() = Some(set);
    peer.send(1, &beacon_frame(&beacon("52:54:00:17:00:01", &[]), None, vec![])).unwrap();
    let (code, o, _) = t.run(&["discover", "--listen", "1", "--json", "--no-registry"]);
    assert_eq!(code, 0);
    assert!(o.contains("\"cmd\":\"discover\"") && o.contains("\"hosts\":[{\"mac\":\"52:54:00:17:00:01\""), "{}", o);
    assert!(!t.registry_path().exists(), "--no-registry must not write");
    // nothing on the wire
    t.out.0.lock().unwrap().clear();
    let (set, _peer2) = memlink();
    *t.link.lock().unwrap() = Some(set);
    let (code, o, _) = t.run(&["discover", "--listen", "0.3"]);
    assert_eq!(code, 0);
    assert!(o.contains("no hosts seen"), "{}", o);
}

#[test]
fn discover_drops_forged_beacons() {
    need_json!();
    let t = T::new("disc3");
    let (set, mut peer) = memlink();
    *t.link.lock().unwrap() = Some(set);
    // mac= differs from the Ethernet source: kept but flagged
    let mut b = beacon("52:54:00:17:00:09", &[]);
    b.set("mac", "52:54:00:17:00:09");
    let eth = frame::EthHeader { dst: Mac::BROADCAST, src: Mac([2, 9, 9, 9, 9, 9]), tags: vec![], ethertype: frame::ETHERTYPE_BEACON };
    peer.send(1, &frame::eth_build(&eth, &b.encode_v2(None, &Mac([2, 9, 9, 9, 9, 9])))).unwrap();
    // a broadcast MAC in mac=, and a non-IPv4 ip: dropped
    let mut bad = beacon("52:54:00:17:00:0a", &[("ip", "javascript:1")]);
    bad.set("mac", "52:54:00:17:00:0a");
    peer.send(1, &beacon_frame(&bad, None, vec![])).unwrap();
    let mut bc = beacon("52:54:00:17:00:0b", &[]);
    bc.set("mac", "ff:ff:ff:ff:ff:ff");
    let eth = frame::EthHeader { dst: Mac::BROADCAST, src: Mac([2, 1, 1, 1, 1, 1]), tags: vec![], ethertype: frame::ETHERTYPE_BEACON };
    peer.send(1, &frame::eth_build(&eth, &bc.encode_v2(None, &Mac([2, 1, 1, 1, 1, 1])))).unwrap();
    let (_, o, _) = t.run(&["discover", "--listen", "1"]);
    assert!(o.contains("52:54:00:17:00:09") && o.contains("src-mac-mismatch"), "{}", o);
    assert!(!o.contains("52:54:00:17:00:0a") && !o.contains("ff:ff:ff:ff:ff:ff"), "{}", o);
}

#[test]
fn discover_active_sends_probes_with_vlan_tags() {
    let t = T::new("probe");
    let (set, mut peer) = memlink();
    *t.link.lock().unwrap() = Some(set);
    let (code, _, _) = t.run(&["discover", "--active", "--listen", "0.4", "--vlan", "13,20", "--no-registry"]);
    assert_eq!(code, 0);
    let mut buf = vec![0u8; 2048];
    let mut vlans = Vec::new();
    while let Some(m) = peer.recv(&mut buf, Duration::from_millis(50)).unwrap() {
        let (eth, payload) = frame::eth_parse(&buf[..m.len]).unwrap();
        assert_eq!(eth.dst, Mac::BROADCAST);
        assert_eq!(eth.ethertype, frame::ETHERTYPE_CTL);
        let f = frame::open(payload).unwrap();
        assert_eq!(f.hdr.ftype, FrameType::Probe as u8);
        vlans.push(eth.tags[0].1);
    }
    assert_eq!(vlans, vec![13, 20], "one probe per VLAN id, at most 20 per second per NIC");
}

#[test]
fn discover_watch_reports_new_and_reboot_events() {
    need_json!();
    let t = T::new("watch");
    let (set, mut peer) = memlink();
    *t.link.lock().unwrap() = Some(set);
    let h = std::thread::spawn(move || {
        peer.send(1, &beacon_frame(&beacon("52:54:00:17:00:01", &[]), None, vec![])).unwrap();
        std::thread::sleep(Duration::from_millis(650));
        peer.send(1, &beacon_frame(&beacon("52:54:00:17:00:01", &[("boot", "aaaa")]), None, vec![])).unwrap();
        std::thread::sleep(Duration::from_millis(650));
        peer.send(1, &beacon_frame(&beacon("52:54:00:17:00:01", &[("boot", "aaaa"), ("state", "busy")]), None, vec![])).unwrap();
        peer
    });
    let (code, o, _) = t.run(&["discover", "--watch", "--listen", "2", "--json", "--no-registry"]);
    let _peer = h.join().unwrap();
    assert_eq!(code, 0);
    let events: Vec<&str> = o.lines().collect();
    assert!(events[0].starts_with("{\"event\":\"host\",\"state\":\"new\""), "{}", o);
    assert!(events.iter().any(|l| l.contains("\"state\":\"reboot\"")), "{}", o);
    assert!(events.iter().any(|l| l.contains("\"state\":\"state\"")), "{}", o);
}

// ---------------------------------------------------------------- wait

#[test]
fn wait_for_ready_and_timeout() {
    need_json!();
    let t = T::new("wait");
    t.add_host("52:54:00:17:00:01", 30, &[]);
    let (set, mut peer) = memlink();
    *t.link.lock().unwrap() = Some(set);
    let h = std::thread::spawn(move || {
        peer.send(1, &beacon_frame(&beacon("52:54:00:17:00:01", &[("state", "booting")]), None, vec![])).unwrap();
        std::thread::sleep(Duration::from_millis(650));
        peer.send(1, &beacon_frame(&beacon("52:54:00:17:00:01", &[("state", "ready")]), None, vec![])).unwrap();
        peer
    });
    let (code, o, e) = t.run(&["wait", "lab-1", "--state", "ready", "--timeout", "5"]);
    let _p = h.join().unwrap();
    assert_eq!(code, 0, "{}", e);
    assert!(o.contains("is ready"), "{}", o);

    // nothing arrives: exit 4
    let (set, _peer) = memlink();
    *t.link.lock().unwrap() = Some(set);
    let (code, _, e) = t.run(&["wait", "52:54:00:17:00:01", "--timeout", "1"]);
    assert_eq!(code, 4, "{}", e);
    // an unknown name or a bare IP cannot be waited for
    assert_eq!(t.run(&["wait", "nonesuch", "--timeout", "1"]).0, 6);
    assert_eq!(t.run(&["wait", "10.9.9.9", "--timeout", "1"]).0, 6);
}

#[test]
fn wait_for_reboot_uses_the_registry_boot_id() {
    need_json!();
    let t = T::new("waitboot");
    t.add_host("52:54:00:17:00:01", 30, &[("boot", "old1")]);
    let (set, mut peer) = memlink();
    *t.link.lock().unwrap() = Some(set);
    let h = std::thread::spawn(move || {
        peer.send(1, &beacon_frame(&beacon("52:54:00:17:00:01", &[("boot", "old1")]), None, vec![])).unwrap();
        std::thread::sleep(Duration::from_millis(650));
        peer.send(1, &beacon_frame(&beacon("52:54:00:17:00:01", &[("boot", "new2")]), None, vec![])).unwrap();
        peer
    });
    let (code, o, _) = t.run(&["wait", "lab-1", "--state", "reboot", "--timeout", "5", "--json"]);
    let _p = h.join().unwrap();
    assert_eq!(code, 0);
    assert!(o.contains("\"boot\":\"new2\""), "{}", o);
}

#[test]
fn reboot_wait_flag_sends_then_waits() {
    need_json!();
    let t = T::new("rebootwait");
    t.add_host("52:54:00:17:00:01", 30, &[("boot", "old1")]);
    let (set, mut peer) = memlink();
    *t.link.lock().unwrap() = Some(set);
    let h = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        peer.send(1, &beacon_frame(&beacon("52:54:00:17:00:01", &[("boot", "new2")]), None, vec![])).unwrap();
        peer
    });
    let (code, o, e) = t.run(&["reboot", "lab-1", "-y", "--wait", "5"]);
    let _p = h.join().unwrap();
    assert_eq!(code, 0, "{}", e);
    assert_eq!(t.last().cmd, "reboot");
    assert!(o.contains("rebooted"), "{}", o);
}

// ---------------------------------------------------------------- keys

fn fresh_home(t: &T) {
    std::fs::remove_dir_all(t.home.join(".config")).unwrap();
}

#[test]
fn key_init_show_export_import_flow() {
    let t = T::new("keyflow");
    fresh_home(&t);
    let (code, o, e) = t.run(&["key", "init"]);
    assert_eq!(code, 0, "{}", e);
    assert!(o.contains("admin") && o.contains("ro"), "{}", o);
    let dir = t.home.join(".config/i7labctl/keys");
    use std::os::unix::fs::PermissionsExt;
    for f in ["admin.key", "ro.key", "KEYSET-ID"] {
        assert_eq!(std::fs::metadata(dir.join(f)).unwrap().permissions().mode() & 0o777, 0o600, "{}", f);
    }
    assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
    // no secret in init's output
    let admin_line = std::fs::read_to_string(dir.join("admin.key")).unwrap();
    let hex = admin_line.trim().rsplit(':').next().unwrap().to_string();
    assert!(!o.contains(&hex));
    // a second init refuses; --force keeps the old set
    let (code, _, e) = t.run(&["key", "init"]);
    assert_eq!(code, 7, "{}", e);
    assert_eq!(std::fs::read_to_string(dir.join("admin.key")).unwrap(), admin_line);
    assert_eq!(t.run(&["key", "init", "--force"]).0, 0);
    assert_ne!(std::fs::read_to_string(dir.join("admin.key")).unwrap(), admin_line);
    assert_eq!(std::fs::read_dir(dir.join("old")).unwrap().count(), 1);

    // show: fingerprints, never the secret unless asked
    t.out.0.lock().unwrap().clear();
    let (code, o, _) = t.run(&["key", "show"]);
    assert_eq!(code, 0);
    let now_hex = std::fs::read_to_string(dir.join("admin.key")).unwrap().trim().rsplit(':').next().unwrap().to_string();
    assert!(o.contains("admin") && !o.contains(&now_hex) && !o.contains("i7k1"), "{}", o);
    t.out.0.lock().unwrap().clear();
    let (_, o, _) = t.run(&["key", "show", "--secret", "--yes", "--role", "ro"]);
    assert!(o.contains("i7k1:ro:"), "{}", o);

    // export: ro freely, admin only with --yes
    t.out.0.lock().unwrap().clear();
    let (code, o, _) = t.run(&["key", "export"]);
    assert_eq!(code, 0);
    assert!(o.starts_with("i7k1:ro:"), "{}", o);
    let (code, _, e) = t.run(&["key", "export", "--role", "admin"]);
    assert_eq!(code, 7, "{}", e);
    let out_file = t.dir.join("ro-copy.key");
    assert_eq!(t.run(&["key", "export", "--file", out_file.to_str().unwrap()]).0, 0);
    assert_eq!(std::fs::metadata(&out_file).unwrap().permissions().mode() & 0o777, 0o600);

    // import into another home
    let t2 = T::new("keyflow2");
    fresh_home(&t2);
    assert_eq!(t2.run(&["key", "import", out_file.to_str().unwrap()]).0, 0);
    assert!(t2.home.join(".config/i7labctl/keys/ro.key").exists());
    assert_eq!(t2.run(&["key", "import", out_file.to_str().unwrap()]).0, 7);
    assert_eq!(t2.run(&["key", "import", "/nonexistent"]).0, 2);
}

#[test]
fn key_init_also_fills_the_build_tree_keys_dir() {
    let t = T::new("keytree");
    fresh_home(&t);
    std::fs::create_dir_all(t.dir.join("scripts")).unwrap();
    std::fs::write(t.dir.join("scripts/gen-keys"), "#!/bin/sh\n").unwrap();
    assert_eq!(t.run(&["key", "init"]).0, 0);
    let a = std::fs::read_to_string(t.home.join(".config/i7labctl/keys/admin.key")).unwrap();
    let b = std::fs::read_to_string(t.dir.join("keys/admin.key")).unwrap();
    assert_eq!(a, b, "the same key set in both places");
    // an explicit --dir writes only there
    let d = t.dir.join("elsewhere");
    assert_eq!(t.run(&["key", "init", "--dir", d.to_str().unwrap()]).0, 0);
    assert!(d.join("ro.key").exists());
}

#[test]
fn key_verify_reports_the_granted_role() {
    need_json!();
    let t = T::new("keyverify");
    t.add_host(MAC, 3, &[]);
    let (code, o, _) = t.run(&["key", "verify", MAC]);
    assert_eq!(code, 0);
    assert!(o.contains("role admin"), "{}", o);
    assert_eq!(t.last().cmd, "id");
}

// ---------------------------------------------------------------- image, ssh, lab-boot, completions

#[test]
fn image_wrappers_run_the_scripts_and_pass_the_status_through() {
    let mut t = T::new("image");
    let scripts = t.dir.join("scripts");
    write_script(&scripts, "build-image", &format!("echo \"$@\" > {}/args-build; exit 0", t.dir.display()));
    write_script(&scripts, "build-usb-drive", &format!("echo \"$@\" > {}/args-write; exit 3", t.dir.display()));
    write_script(&scripts, "bake-keys", "exit 0");
    t.scripts = Some(scripts.clone());
    assert_eq!(t.run(&["image", "build", "--no-iso"]).0, 0);
    assert_eq!(std::fs::read_to_string(t.dir.join("args-build")).unwrap().trim(), "--no-iso");
    assert_eq!(t.run(&["image", "write", "/dev/sdz", "--serial", "S1"]).0, 3);
    assert_eq!(std::fs::read_to_string(t.dir.join("args-write")).unwrap().trim(), "/dev/sdz --serial S1");
    // write without a device is a usage error and runs nothing
    std::fs::remove_file(t.dir.join("args-write")).unwrap();
    assert_eq!(t.run(&["image", "write", "--serial", "S1"]).0, 2);
    assert!(!t.dir.join("args-write").exists());
    assert_eq!(t.run(&["image", "frob"]).0, 2);
    // missing script and missing scripts dir
    assert_eq!(t.run(&["image", "test"]).0, 1);
    t.scripts = None;
    assert_eq!(t.run(&["image", "build"]).0, 1);
}

#[test]
fn ssh_uses_pinned_host_keys_and_the_hosts_ip() {
    need_json!();
    let mut t = T::new("ssh");
    t.add_host(MAC, 3, &[("ip", "10.0.0.5/24")]);
    t.ssh_bin = Some(write_script(&t.dir.join("bin"), "fakessh", &format!("echo \"$@\" > {}/ssh-args; exit 7", t.dir.display())));
    let (code, _, e) = t.run(&["ssh", MAC, "uname", "-a"]);
    assert_eq!(code, 7, "ssh's status is passed through: {}", e);
    let a = std::fs::read_to_string(t.dir.join("ssh-args")).unwrap();
    for must in ["BatchMode=yes", "StrictHostKeyChecking=yes", "ForwardAgent=no", "ClearAllForwardings=yes", "known_hosts", "-l root", "10.0.0.5 uname -a"] {
        assert!(a.contains(must), "{} missing in {}", must, a);
    }
    let (code, _, _) = t.run(&["ssh", MAC, "--user", "bob", "--", "-p", "2222", "id"]);
    assert_eq!(code, 7);
    let a = std::fs::read_to_string(t.dir.join("ssh-args")).unwrap();
    assert!(a.contains("-l bob") && a.contains("-p 2222") && a.trim_end().ends_with("10.0.0.5 id"), "{}", a);
    // flagged host / no IP
    let t2 = {
        let t2 = T::new("ssh2");
        t2.add_host(MAC, 3, &[("ip", "10.0.0.5/24")]);
        t2
    };
    let mut reg = i7labctl::hosts::Registry::load(&t2.registry_path());
    reg.hosts.values_mut().for_each(|h| h.mac_mismatch = true);
    reg.save(&t2.registry_path()).unwrap();
    // ssh's own errors exit 255 (1..254 are the remote command's), the reason is on stderr
    let (code, _, e) = t2.run(&["ssh", MAC]);
    assert_eq!(code, 255);
    assert!(e.contains("src-mac-mismatch"), "{}", e);
    let t3 = T::new("ssh3");
    t3.add_host(MAC, 3, &[("ip", "")]);
    let (code, _, e) = t3.run(&["ssh", MAC]);
    assert_eq!(code, 255);
    assert!(e.contains("IP address"), "{}", e);
}

#[test]
fn lab_boot_dry_run_prints_the_hwlab_plan() {
    let mut t = T::new("labboot");
    t.hwlab = Some("hwlabctl".into());
    let (code, o, _) = t.run(&["lab-boot", "--jetkvm", "nova", "--image", "out/i7lablinux.iso", "--dry-run"]);
    assert_eq!(code, 0);
    assert!(o.contains("hwlabctl power nova off") && o.contains("hwlabctl media mount nova --file out/i7lablinux.iso --mode CDROM") && o.contains("hwlabctl power nova on"), "{}", o);
    let (_, o, _) = t.run(&["lab-boot", "--jetkvm", "nova", "--image", "x.img", "--dry-run"]);
    assert!(o.contains("--mode Disk"), "{}", o);
    assert_eq!(t.run(&["lab-boot", "--image", "x.img"]).0, 2);
    assert_eq!(t.run(&["lab-boot", "--jetkvm", "nova"]).0, 2);
    assert_eq!(t.run(&["lab-boot", "--jetkvm", "nova", "--image", "x.img", "--mode", "floppy", "--dry-run"]).0, 2);
}

#[test]
fn lab_boot_runs_the_plan_then_waits_for_the_beacon() {
    need_json!();
    let mut t = T::new("labboot2");
    let img = t.dir.join("i.iso");
    std::fs::write(&img, "x").unwrap();
    // the "hwlab CLI" is a script that logs its arguments
    let hw = write_script(&t.dir.join("bin"), "hw", &format!("echo \"$@\" >> {}/hw-log", t.dir.display()));
    t.hwlab = Some(hw.display().to_string());
    // without --mac or an alias nothing is run
    let (code, _, e) = t.run(&["lab-boot", "--jetkvm", "nova", "--image", img.to_str().unwrap(), "-y"]);
    assert_eq!(code, 2, "{}", e);
    assert!(!t.dir.join("hw-log").exists());
    // with --mac: the three steps run, then the ready beacon ends the wait
    let (set, mut peer) = memlink();
    *t.link.lock().unwrap() = Some(set);
    let h = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        peer.send(1, &beacon_frame(&beacon("52:54:00:17:00:01", &[]), None, vec![])).unwrap();
        peer
    });
    let (code, o, e) = t.run(&["lab-boot", "--jetkvm", "nova", "--image", img.to_str().unwrap(), "--mac", "52:54:00:17:00:01", "--wait", "5", "-y"]);
    let _p = h.join().unwrap();
    assert_eq!(code, 0, "{}", e);
    assert!(o.contains("is ready"), "{}", o);
    let log = std::fs::read_to_string(t.dir.join("hw-log")).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 3, "{}", log);
    assert!(lines[0].starts_with("power nova off") && lines[1].starts_with("media mount nova") && lines[2].starts_with("power nova on"), "{}", log);
    // a failing step stops the sequence
    std::fs::remove_file(t.dir.join("hw-log")).unwrap();
    t.hwlab = Some("false".into());
    let (code, _, e) = t.run(&["lab-boot", "--jetkvm", "nova", "--image", img.to_str().unwrap(), "--mac", "52:54:00:17:00:01", "-y"]);
    assert_eq!(code, 1, "{}", e);
    assert!(e.contains("stopped before the next step"), "{}", e);
}

#[test]
fn completions_and_the_hidden_host_list() {
    need_json!();
    let t = T::new("compl");
    t.add_host(MAC, 3, &[("ip", "10.0.0.5/24")]);
    std::fs::create_dir_all(t.home.join(".config/i7labctl")).unwrap();
    std::fs::write(t.home.join(".config/i7labctl/aliases"), "m900 = lab-1\n").unwrap();
    for sh in ["bash", "zsh", "fish"] {
        let (code, o, _) = t.run(&["completions", sh]);
        assert_eq!(code, 0);
        assert!(o.contains("discover") && o.contains("__hosts"), "{}", sh);
        t.out.0.lock().unwrap().clear();
    }
    assert_eq!(t.run(&["completions", "powershell"]).0, 2);
    t.out.0.lock().unwrap().clear();
    let (code, o, _) = t.run(&["__hosts"]);
    assert_eq!(code, 0);
    let l: Vec<&str> = o.lines().collect();
    for w in [MAC, "lab-1", "SER1", "10.0.0.5", "m900"] {
        assert!(l.contains(&w), "{} not in {:?}", w, l);
    }
}

#[test]
fn ether_frame_decoder_and_probe() {
    let t = T::new("etherf");
    let b = beacon("52:54:00:17:00:01", &[]);
    let f = beacon_frame(&b, None, vec![(0x8100, 13)]);
    let hex = labproto::crypto::hex(&f);
    let (code, o, _) = t.run(&["ether", "frame", &hex]);
    assert_eq!(code, 0);
    assert!(o.contains("vlan 13") && o.contains("beacon") && o.contains("52:54:00:17:00:01"), "{}", o);
    assert_eq!(t.run(&["ether", "frame", "zz"]).0, 2);
    let (set, mut peer) = memlink();
    *t.link.lock().unwrap() = Some(set);
    t.out.0.lock().unwrap().clear();
    peer.send(1, &f).unwrap();
    peer.send(1, b"short").unwrap();
    let (code, o, _) = t.run(&["ether", "sniff", "--count", "1", "--timeout", "2"]);
    assert_eq!(code, 0);
    assert!(o.contains("beacon") && o.contains("vlan 13"), "{}", o);
}

#[test]
fn ether_hello_and_cmds_and_replay_go_to_ether() {
    need_json!();
    let t = T::new("etherh");
    t.add_host(MAC, 3, &[("ip", "10.0.0.5/24"), ("http", "8080")]);
    let (code, o, _) = t.run(&["ether", "hello", MAC]);
    assert_eq!(code, 0);
    assert!(o.contains("role admin"), "{}", o);
    assert_eq!(t.last().kind, "ether");
    let (code, _, _) = t.run(&["ether", "replay", MAC, "ping"]);
    assert_eq!(code, 0);
    assert_eq!(t.last().kind, "ether");
    std::env::remove_var("I7LABCTL_TEST_REPLAY");
}
