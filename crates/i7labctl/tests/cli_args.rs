//! Argument parsing and command-to-wire mapping, with a recording mock transport (no sockets).
mod common;

use common::*;
use labproto::Status;

fn argv(c: &Call) -> Vec<&str> {
    c.args.iter().map(String::as_str).collect()
}

#[test]
fn host_selectors_and_global_options_anywhere() {
    need_json!();
    let t = T::new("sel");
    t.add_host(MAC, 3, &[]);
    for args in [
        vec!["inv", MAC, "--section", "dmi"],
        vec!["inv", "lab-1", "--section", "dmi"],
        vec!["inv", "--ether", MAC, "--section", "dmi"],
        vec!["inv", "ser1", "--section=dmi"],
        vec!["inv", "-H", "Q35", "--section", "dmi"],
        vec!["inv", "52:54:00:17", "--section", "dmi"],
    ] {
        let (code, _o, e) = t.run(&args);
        assert_eq!(code, 0, "{:?}: {}", args, e);
        let c = t.last();
        assert_eq!(c.cmd, "inv");
        assert_eq!(argv(&c), ["--section", "dmi"], "{:?}", args);
    }
    assert_eq!(t.connects.lock().unwrap().last().unwrap().1.mac.unwrap().to_string(), MAC);
}

#[test]
fn aliases_resolve() {
    need_json!();
    let t = T::new("alias");
    t.add_host(MAC, 3, &[]);
    std::fs::create_dir_all(t.home.join(".config/i7labctl")).unwrap();
    std::fs::write(t.home.join(".config/i7labctl/aliases"), "m900 = lab-1\n").unwrap();
    assert_eq!(t.run(&["id", "m900"]).0, 0);
    assert_eq!(t.last().cmd, "id");
}

#[test]
fn unknown_and_ambiguous_hosts() {
    need_json!();
    let t = T::new("amb");
    t.add_host(MAC, 3, &[("board_serial", "A")]);
    t.add_host("52:54:00:17:00:02", 3, &[("board_serial", "B"), ("host", "lab-2")]);
    let (code, _, e) = t.run(&["id", "nonesuch"]);
    assert_eq!(code, 6, "{}", e);
    assert!(t.calls().is_empty());
    // both entries have board Q35
    let (code, _, e) = t.run(&["id", "q35"]);
    assert_eq!(code, 8, "{}", e);
    assert!(e.contains("52:54:00:17:00:01") && e.contains("52:54:00:17:00:02"), "{}", e);
    assert!(t.calls().is_empty());
}

#[test]
fn usage_errors_exit_2_and_send_nothing() {
    need_json!();
    let t = T::new("usage");
    t.add_host(MAC, 3, &[]);
    for args in [
        vec!["inv"],                                  // no host
        vec!["inv", MAC, "--nope"],                   // unknown option
        vec!["inv", MAC, "extra"],                    // stray positional
        vec!["blk"],                                  // no verb
        vec!["blk", "frob", MAC],                     // unknown verb
        vec!["blk", "read", MAC],                     // no device
        vec!["blk", "read", MAC, "/dev/sda"],         // a path, not a name
        vec!["blk", "read", MAC, "sda", "--regions", "start", "--offset", "0", "--len", "512"],
        vec!["blk", "read", MAC, "sda", "--offset", "5"],
        vec!["blk", "verify", MAC, "sda"],            // no seed
        vec!["net", "set", MAC, "eth0"],              // neither --dhcp nor --ip
        vec!["net", "set", MAC, "eth0", "--dhcp", "--ip", "1.2.3.4/24"],
        vec!["net", "vlan", "add", MAC, "eth0", "5000"],
        vec!["net", "link", MAC, "eth0", "sideways"],
        vec!["exec", MAC, "ls"],                      // needs --
        vec!["put", MAC, "onlyone"],
        vec!["get", MAC, "a", "b", "c"],
        vec!["ping", MAC, "-c", "many"],
        vec!["discover", "--assign", "garbage"],
        vec!["wait", MAC, "--state", "sleepy"],
        vec!["ls", "--sort", "colour"],
        vec!["ls", "--state", "maybe"],
        vec!["reboot", MAC, "--uefi", "--to-os"],
        vec!["time-set", MAC, "tomorrow"],
        vec!["api", MAC, "FETCH", "/x"],
        vec!["api", MAC, "GET", "x"],
        vec!["frobnicate"],
        vec!["--transport", "pigeon", "id", MAC],
        vec!["--role", "root", "id", MAC],
        vec!["--ether", "not-a-mac", "id"],
        vec!["--vlan", "9999", "id", MAC],
    ] {
        let (code, _o, e) = t.run(&args);
        assert_eq!(code, 2, "{:?} -> {} / {}", args, code, e);
        assert!(!e.is_empty(), "{:?} gave no message", args);
    }
    assert!(t.calls().is_empty(), "something was sent: {:?}", t.calls());
}

#[test]
fn usage_error_in_json_mode_is_an_envelope() {
    let t = T::new("usagejson");
    let (code, o, _) = t.run(&["frobnicate", "--json"]);
    assert_eq!(code, 2);
    assert!(o.contains("\"ok\":false") && o.contains("\"code\":\"E_USAGE\"") && o.contains("\"exit\":2"), "{}", o);
    assert_eq!(o.lines().count(), 1);
}

#[test]
fn unknown_command_suggests() {
    let t = T::new("sugg");
    let (code, _, e) = t.run(&["discove"]);
    assert_eq!(code, 2);
    assert!(e.contains("did you mean 'discover'"), "{}", e);
}

#[test]
fn simple_commands_map_to_wire_commands() {
    need_json!();
    let t = T::new("map");
    t.add_host(MAC, 3, &[]);
    let cases: Vec<(Vec<&str>, &str, Vec<&str>)> = vec![
        (vec!["ping", MAC, "-c", "1"], "ping", vec![]),
        (vec!["ping", MAC, "-c", "1", "hello"], "ping", vec!["hello"]),
        (vec!["id", MAC], "id", vec![]),
        (vec!["inv", MAC], "inv", vec![]),
        (vec!["pcie", MAC, "--tree", "--id", "8086:1237", "--class", "06", "--verbose"], "pcie", vec!["--tree", "--verbose", "--id", "8086:1237", "--class", "06"]),
        (vec!["usb", MAC, "--tree"], "usb", vec!["--tree"]),
        (vec!["thermal", MAC], "thermal", vec![]),
        (vec!["net", "ls", MAC], "net.ls", vec![]),
        (vec!["net", "ls", MAC, "eth0"], "net.ls", vec!["eth0"]),
        (vec!["net", "set", MAC, "eth0", "--ip", "10.0.0.5/24", "--gw", "10.0.0.1", "--dns", "9.9.9.9", "--mtu", "1400", "--confirm", "20"], "net.set", vec!["eth0", "--ip", "10.0.0.5/24", "--gw", "10.0.0.1", "--dns", "9.9.9.9", "--mtu", "1400", "--confirm", "20"]),
        (vec!["net", "set", MAC, "eth0", "--dhcp"], "net.set", vec!["eth0", "--dhcp"]),
        (vec!["net", "vlan", "add", MAC, "eth0", "13", "--ip", "10.13.0.5/24"], "net.vlan", vec!["add", "eth0", "13", "--ip", "10.13.0.5/24"]),
        (vec!["net", "vlan", "del", MAC, "eth0", "13"], "net.vlan", vec!["del", "eth0", "13"]),
        (vec!["net", "link", MAC, "eth0", "down"], "net.link", vec!["eth0", "down"]),
        (vec!["net", "confirm", MAC], "net.confirm", vec![]),
        (vec!["blk", "ls", MAC], "blk.ls", vec![]),
        (vec!["blk", "ls", MAC, "--all"], "blk.ls", vec!["--all"]),
        (vec!["blk", "smart", MAC, "nvme0n1", "--attrs", "--selftest", "short"], "blk.smart", vec!["nvme0n1", "--attrs", "--selftest", "short"]),
        (vec!["fs", "ls", MAC, "/var/log", "-l"], "fs.ls", vec!["/var/log", "--long"]),
        (vec!["fs", "stat", MAC, "/etc/os-release"], "fs.stat", vec!["/etc/os-release"]),
        (vec!["jobs", MAC], "jobs", vec!["ls"]),
        (vec!["jobs", MAC, "kill", "3"], "jobs", vec!["kill", "3"]),
        (vec!["identify", MAC, "--seconds", "60"], "identify", vec!["--seconds", "60"]),
        (vec!["identify", MAC, "--stop"], "identify", vec!["--stop"]),
        (vec!["msg", MAC, "remove", "the", "stick"], "msg", vec!["remove the stick"]),
        (vec!["time-set", MAC, "1794000000"], "time.set", vec!["1794000000"]),
        (vec!["time-set", MAC, "now"], "time.set", vec!["1794000100"]),
        (vec!["tui", "tab", MAC, "Storage"], "tui", vec!["tab", "Storage"]),
        (vec!["tui", "reset", MAC], "tui", vec!["reset"]),
        (vec!["tui", "dump", MAC], "tui.dump", vec![]),
        (vec!["poweroff", MAC, "-y", "--delay", "5"], "poweroff", vec!["--delay", "5"]),
        (vec!["reboot", MAC, "-y", "--uefi", "--force", "--delay", "2"], "reboot", vec!["--force", "--uefi", "--delay", "2"]),
        (vec!["reboot", MAC, "-y", "--to-os"], "reboot", vec!["--to-os"]),
        (vec!["ether", "cmds", MAC], "cmds", vec![]),
    ];
    for (args, wire, want) in cases {
        let before = t.calls().len();
        let (code, _o, e) = t.run(&args);
        assert_eq!(code, 0, "{:?}: {}", args, e);
        let calls = t.calls();
        let c = calls.last().unwrap();
        assert!(calls.len() > before, "{:?} made no call", args);
        assert_eq!(c.cmd, wire, "{:?}", args);
        assert_eq!(argv(c), want, "{:?}", args);
    }
}

#[test]
fn raw_form_never_validates() {
    let t = T::new("raw");
    // blk.write without any safety flags goes out exactly as typed, and the host's REFUSED becomes exit 7
    t.reply(|_, _| Ok(MockOut::status(Status::Refused, "{\"error\":{\"code\":\"REFUSED\",\"message\":\"not destructive\",\"reasons\":[\"NotDestructive\"]}}")));
    let (code, _o, e) = t.run(&["--ether", MAC, "--cmd", "blk.write", "sda"]);
    assert_eq!(code, 7, "{}", e);
    let c = t.last();
    assert_eq!((c.cmd.as_str(), argv(&c)), ("blk.write", vec!["sda"]));
    assert!(e.contains("REFUSED") || e.contains("not destructive"), "{}", e);
    // numeric id of a command the client has never heard of
    t.reply(|_, _| Ok(MockOut::status(Status::Unsupported, "")));
    let (code, _, _) = t.run(&["--ether", MAC, "--cmd", "0x7777", "a", "--b"]);
    assert_eq!(code, 10);
    assert_eq!(argv(&t.last()), ["a", "--b"]);
    // no host option: usage error
    assert_eq!(t.run(&["--cmd", "ping"]).0, 2);
    // unknown name: usage error before connecting
    assert_eq!(t.run(&["--ether", MAC, "--cmd", "frobnicate"]).0, 2);
}

#[test]
fn raw_form_json_and_exec_exit() {
    let t = T::new("rawjson");
    t.reply(|c, _| {
        if c.name == "exec" {
            Ok(MockOut { exit_code: Some(3), stdout: b"hi\n".to_vec(), body: "{\"signal\":0}".into(), ..Default::default() })
        } else {
            Ok(MockOut::ok("{\"pong\":true}"))
        }
    });
    let (code, o, _) = t.run(&["--ether", MAC, "--cmd", "ping", "--json"]);
    assert_eq!(code, 0);
    assert!(o.contains("\"ok\":true") && o.contains("\"cmd\":\"ping\"") && o.contains("\"data\":{\"pong\":true}") && o.contains("\"transport\":\"ether\""), "{}", o);
    let (code, o, _) = t.run(&["--ether", MAC, "--cmd", "exec", "--", "false"]);
    assert_eq!(code, 3);
    assert!(o.contains("hi"), "{}", o);
}

#[test]
fn json_envelope_for_success_and_remote_errors() {
    need_json!();
    let t = T::new("json");
    t.add_host(MAC, 3, &[("board_serial", "SER1")]);
    t.reply(|_, _| Ok(MockOut::ok("{\"v\":1,\"devices\":[]}")));
    let (code, o, _) = t.run(&["blk", "ls", MAC, "--json"]);
    assert_eq!(code, 0);
    assert!(o.starts_with("{\"ok\":true,\"transport\":\"ether\",\"host\":{\"mac\":\"52:54:00:17:00:01\""), "{}", o);
    assert!(o.contains("\"serial\":\"SER1\"") && o.contains("\"cmd\":\"blk.ls\"") && o.contains("\"data\":{\"v\":1,\"devices\":[]}"), "{}", o);
    assert_eq!(o.lines().count(), 1);

    t.out.0.lock().unwrap().clear();
    t.reply(|_, _| Ok(MockOut::status(Status::Refused, "{\"error\":{\"code\":\"REFUSED\",\"message\":\"device mounted: sdb1\",\"reasons\":[\"mounted\",\"filesystem ext4\"]}}")));
    let (code, o, _) = t.run(&["--json", "--ether", MAC, "--cmd", "blk.write", "sdb"]);
    assert_eq!(code, 7);
    assert!(o.contains("\"ok\":false") && o.contains("\"code\":\"REFUSED\"") && o.contains("\"status\":5") && o.contains("\"exit\":7") && o.contains("\"reasons\":[\"mounted\",\"filesystem ext4\"]"), "{}", o);
}

#[test]
fn every_remote_status_maps_to_the_documented_exit() {
    need_json!();
    let t = T::new("status");
    t.add_host(MAC, 3, &[]);
    for st in Status::ALL {
        if st == Status::Ok {
            continue;
        }
        t.reply(move |_, _| Ok(MockOut::status(st, "")));
        let (code, _, e) = t.run(&["id", MAC]);
        assert_eq!(code, st.cli_exit(), "{:?}", st);
        assert!(e.contains(st.name()), "{:?}: {}", st, e);
    }
    // documented table spot checks
    assert_eq!(Status::Eperm.cli_exit(), 5);
    assert_eq!(Status::Refused.cli_exit(), 7);
    assert_eq!(Status::Busy.cli_exit(), 9);
    assert_eq!(Status::Unsupported.cli_exit(), 10);
    assert_eq!(Status::NotFound.cli_exit(), 6);
}

#[test]
fn eperm_with_a_ro_key_says_so() {
    need_json!();
    let t = T::new("ro");
    t.add_host(MAC, 3, &[]);
    t.reply(|_, _| Ok(MockOut::status(Status::Eperm, "")));
    // only the ro key available
    std::fs::remove_file(t.home.join(".config/i7labctl/keys/admin.key")).unwrap();
    let mut env = t.env();
    let code = i7labctl::cli::run_with(vec!["reboot".into(), MAC.into(), "-y".into()], &mut env);
    assert_eq!(code, 5);
}

#[test]
fn key_role_selection() {
    need_json!();
    let t = T::new("role");
    t.add_host(MAC, 3, &[]);
    assert_eq!(t.run(&["--role", "ro", "id", MAC]).0, 0);
    std::fs::remove_file(t.home.join(".config/i7labctl/keys/admin.key")).unwrap();
    let (code, _, e) = t.run(&["--role", "admin", "id", MAC]);
    assert_eq!(code, 5, "{}", e);
    assert!(e.contains("key init"), "{}", e);
    // default falls back to ro
    assert_eq!(t.run(&["id", MAC]).0, 0);
    // no keys at all: exit 5 and the fix is named
    std::fs::remove_file(t.home.join(".config/i7labctl/keys/ro.key")).unwrap();
    let (code, _, e) = t.run(&["id", MAC]);
    assert_eq!(code, 5);
    assert!(e.contains("i7labctl key init"), "{}", e);
}

#[test]
fn other_keyset_exits_5_without_sending_and_no_registry_overrides() {
    need_json!();
    let t = T::new("kid");
    t.add_host(MAC, 3, &[("kid", "a:deadbeef,r:cafef00d")]);
    let (code, _, e) = t.run(&["id", MAC]);
    assert_eq!(code, 5, "{}", e);
    assert!(e.contains("other-keyset") && e.contains("nothing was sent"), "{}", e);
    assert!(t.calls().is_empty());
    // --no-registry: the registry (and its kid) is ignored, the bare MAC is tried and the host decides
    let (code, _, _) = t.run(&["--no-registry", "id", MAC]);
    assert_eq!(code, 0);
    assert_eq!(t.calls().len(), 1);
}

#[test]
fn matching_kid_is_sent() {
    need_json!();
    let t = T::new("kidok");
    let admin = labproto::keys::KeySet::load_dir(&t.home.join(".config/i7labctl/keys")).unwrap().admin.unwrap().fingerprint();
    t.add_host(MAC, 3, &[("kid", &format!("a:{},r:cafef00d", admin))]);
    assert_eq!(t.run(&["id", MAC]).0, 0);
}

#[test]
fn planned_commands_answer_unsupported_locally() {
    need_json!();
    let t = T::new("planned");
    t.add_host(MAC, 3, &[]);
    for args in [vec!["kexec", MAC, "--kernel", "/run/k"], vec!["svc", MAC, "http", "status"], vec!["web"], vec!["key", "rotate"], vec!["image", "info", "x.img"]] {
        let (code, _, e) = t.run(&args);
        assert_eq!(code, 10, "{:?}: {}", args, e);
        assert!(e.contains("planned") || e.contains("not in v1"), "{:?}: {}", args, e);
    }
    assert!(t.calls().is_empty());
    let (code, o, _) = t.run(&["kexec", MAC, "--json"]);
    assert_eq!(code, 10);
    assert!(o.contains("\"code\":\"UNSUPPORTED\"") && o.contains("\"exit\":10"), "{}", o);
    // but the raw form still sends planned commands: the server's answer is what is tested
    t.reply(|_, _| Ok(MockOut::status(Status::Unsupported, "")));
    assert_eq!(t.run(&["--ether", MAC, "--cmd", "kexec"]).0, 10);
    assert_eq!(t.calls().len(), 1);
}

#[test]
fn blk_write_needs_destructive_and_serial_locally() {
    need_json!();
    let t = T::new("blkw");
    t.add_host(MAC, 3, &[]);
    for args in [vec!["blk", "write", MAC, "sdb"], vec!["blk", "write", MAC, "sdb", "--destructive"], vec!["blk", "write", MAC, "sdb", "--serial", "S1"], vec!["blk", "write", MAC, "sdb", "--destructive", "--serial", " "]] {
        let (code, _, e) = t.run(&args);
        assert_eq!(code, 7, "{:?}: {}", args, e);
        assert!(e.contains("--destructive") && e.contains("--serial"), "{}", e);
    }
    assert!(t.calls().is_empty());
}

#[test]
fn blk_write_allow_boot_media_needs_the_other_two_and_is_forwarded() {
    need_json!();
    let t = T::new("blkw-abm");
    t.add_host(MAC, 3, &[]);
    for args in [vec!["blk", "write", MAC, "sdb", "--allow-boot-media"], vec!["blk", "write", MAC, "sdb", "--allow-boot-media", "--destructive"], vec!["blk", "write", MAC, "sdb", "--allow-boot-media", "--serial", "S1"]] {
        let (code, _, e) = t.run(&args);
        assert_eq!(code, 7, "{:?}: {}", args, e);
    }
    assert!(t.calls().is_empty());
    t.reply(|_, _| Ok(MockOut::ok("{\"v\":1,\"dev\":\"sdb\",\"serial\":\"S1\",\"mode\":\"Write\",\"seed\":5,\"ok\":true,\"regions\":[]}")));
    let (code, _, e) = t.run(&["blk", "write", MAC, "sdb", "--destructive", "--serial", "S1", "--yes"]);
    assert_eq!(code, 0, "{}", e);
    assert!(!argv(&t.last()).iter().any(|x| *x == "--allow-boot-media"));
    let (code, _, e) = t.run(&["blk", "write", MAC, "sdb", "--destructive", "--serial", "S1", "--allow-boot-media", "--yes"]);
    assert_eq!(code, 0, "{}", e);
    assert!(argv(&t.last()).iter().any(|x| *x == "--allow-boot-media"));
}

#[test]
fn blk_write_asks_unless_yes_and_picks_a_seed() {
    need_json!();
    let mut t = T::new("blkw2");
    t.add_host(MAC, 3, &[]);
    t.answer = Some(false);
    let (code, _, e) = t.run(&["blk", "write", MAC, "sdb", "--destructive", "--serial", "S1", "--mb", "8"]);
    assert_eq!(code, 7, "{}", e);
    assert!(t.calls().is_empty());
    t.answer = Some(true);
    t.reply(|_, _| Ok(MockOut::ok("{\"v\":1,\"dev\":\"sdb\",\"serial\":\"S1\",\"mode\":\"Write\",\"seed\":5,\"ok\":true,\"regions\":[]}")));
    let (code, o, e) = t.run(&["blk", "write", MAC, "sdb", "--destructive", "--serial", "S1", "--mb", "8"]);
    assert_eq!(code, 0, "{}", e);
    let c = t.last();
    let a = argv(&c);
    assert_eq!(&a[..4], ["sdb", "--destructive", "--serial", "S1"]);
    let at = a.iter().position(|x| *x == "--seed").expect("a seed is always sent");
    assert!(a[at + 1].parse::<u64>().is_ok());
    assert!(o.contains("blk verify"), "the seed is reported so verify can use it: {}", o);
    // --yes skips the question
    t.answer = Some(false);
    let (code, _, _) = t.run(&["blk", "write", MAC, "sdb", "--destructive", "--serial", "S1", "--yes", "--seed", "42"]);
    assert_eq!(code, 0);
    assert!(argv(&t.last()).windows(2).any(|w| w == ["--seed", "42"]));
}

#[test]
fn blk_read_and_verify_arguments() {
    need_json!();
    let t = T::new("blkr");
    t.add_host(MAC, 3, &[]);
    t.reply(|_, _| Ok(MockOut::ok("{\"v\":1,\"dev\":\"sda\",\"serial\":null,\"mode\":\"Read\",\"seed\":null,\"ok\":true,\"regions\":[]}")));
    let (code, _, e) = t.run(&["blk", "read", MAC, "sda", "--mb", "8", "--bs", "1m", "--direct"]);
    assert_eq!(code, 0, "{}", e);
    assert_eq!(argv(&t.last()), ["sda", "--mb", "8", "--bs", "1m", "--direct"]);
    let (code, _, _) = t.run(&["blk", "verify", MAC, "sda", "--seed", "77", "--regions", "start,end"]);
    assert_eq!(code, 0);
    assert_eq!((t.last().cmd.as_str(), argv(&t.last())), ("blk.verify", vec!["sda", "--regions", "start,end", "--seed", "77"]));
}

#[test]
fn blk_results_with_problems_exit_3() {
    need_json!();
    let t = T::new("blk3");
    t.add_host(MAC, 3, &[]);
    t.reply(|_, _| Ok(MockOut::ok("{\"v\":1,\"dev\":\"sda\",\"serial\":null,\"mode\":\"Read\",\"seed\":null,\"ok\":false,\"regions\":[{\"name\":\"mid\",\"offset\":0,\"len\":1048576,\"mib_s\":1.0,\"lat_max_us\":5,\"io_errors\":2,\"mismatches\":0,\"first_mismatch\":null}]}")));
    let (code, o, _) = t.run(&["blk", "read", MAC, "sda"]);
    assert_eq!(code, 3);
    assert!(o.contains("PROBLEMS"), "{}", o);
    let (code, _, _) = t.run(&["blk", "read", MAC, "sda", "--json"]);
    assert_eq!(code, 3);
    t.reply(|_, _| Ok(MockOut::ok("{\"v\":1,\"dev\":\"sda\",\"kind\":\"ata\",\"verdict\":\"fail\",\"reasons\":[\"pending sectors\"]}")));
    let (code, _, _) = t.run(&["blk", "smart", MAC, "sda"]);
    assert_eq!(code, 3);
}

#[test]
fn blk_progress_events_are_ndjson_in_json_mode() {
    need_json!();
    let t = T::new("blkp");
    t.add_host(MAC, 3, &[]);
    t.reply(|_, _| {
        Ok(MockOut { events: vec!["{\"event\":\"progress\",\"region\":\"mid\",\"mib_s\":412.5,\"done\":0.43}".into()], body: "{\"v\":1,\"ok\":true,\"regions\":[]}".into(), ..Default::default() })
    });
    let (code, o, _) = t.run(&["blk", "read", MAC, "sda", "--json"]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = o.lines().collect();
    assert_eq!(lines.len(), 2, "{}", o);
    assert!(lines[0].starts_with("{\"event\":\"progress\""));
    assert!(lines[1].starts_with("{\"event\":\"result\",\"ok\":true,\"exit\":0"), "{}", lines[1]);
}

#[test]
fn exec_passes_exit_status_through_and_own_errors_are_255() {
    need_json!();
    let t = T::new("exec");
    t.add_host(MAC, 3, &[]);
    t.reply(|_, _| Ok(MockOut { exit_code: Some(3), stdout: b"hello\n".to_vec(), stderr: b"oops\n".to_vec(), body: "{\"signal\":0}".into(), ..Default::default() }));
    let (code, o, e) = t.run(&["exec", MAC, "--env", "A=1", "--env", "B=2", "--cwd", "/tmp", "--", "ls", "-la", "--json"]);
    assert_eq!(code, 3);
    assert_eq!(o, "hello\n");
    assert!(e.contains("oops"));
    // everything after `--` reaches the host verbatim, including words that look like i7labctl options
    assert_eq!(argv(&t.last()), ["--env", "A=1", "--env", "B=2", "--cwd", "/tmp", "--", "ls", "-la", "--json"]);

    // remote exit 0 and the 254 cap
    t.reply(|_, _| Ok(MockOut { exit_code: Some(0), ..Default::default() }));
    assert_eq!(t.run(&["exec", MAC, "--", "true"]).0, 0);
    t.reply(|_, _| Ok(MockOut { exit_code: Some(300), ..Default::default() }));
    assert_eq!(t.run(&["exec", MAC, "--", "x"]).0, 254);

    // transport failure, auth failure, host refusal: all 255 for exec
    *t.fail_kind.lock().unwrap() = Some(i7labctl::Kind::Ether);
    let (code, _, e) = t.run(&["exec", MAC, "--", "true"]);
    assert_eq!(code, 255, "{}", e);
    *t.fail_kind.lock().unwrap() = None;
    t.reply(|_, _| Ok(MockOut::status(Status::Eperm, "")));
    assert_eq!(t.run(&["exec", MAC, "--", "true"]).0, 255);
    t.reply(|_, _| Ok(MockOut::status(Status::Busy, "")));
    assert_eq!(t.run(&["exec", MAC, "--", "true"]).0, 255);
    // an unknown host is also an own error
    assert_eq!(t.run(&["exec", "nonesuch", "--", "true"]).0, 255);
    // but a usage error stays 2
    assert_eq!(t.run(&["exec", MAC, "true"]).0, 2);
}

#[test]
fn exec_timeout_detach_stdin_and_json() {
    need_json!();
    let t = T::new("exec2");
    t.add_host(MAC, 3, &[]);
    t.reply(|_, _| Ok(MockOut { exit_code: Some(0), stdout: b"a\xffb".to_vec(), ..Default::default() }));
    let f = t.dir.join("in.txt");
    std::fs::write(&f, "from file").unwrap();
    let (code, o, _) = t.run(&["exec", MAC, "--timeout", "60", "--detach", "--stdin", f.to_str().unwrap(), "--json", "--", "cat"]);
    assert_eq!(code, 0);
    let c = t.last();
    assert_eq!(argv(&c), ["--timeout", "60", "--detach", "--stdin", "--", "cat"]);
    assert_eq!(c.uploaded, b"from file");
    let lines: Vec<&str> = o.lines().collect();
    assert_eq!(lines[0], "{\"event\":\"stdout\",\"b64\":\"Yf9i\"}", "non-UTF-8 output travels as base64: {}", o);
    assert!(lines.last().unwrap().starts_with("{\"event\":\"result\",\"ok\":true,\"exit\":0"), "{}", o);
}

#[test]
fn sh_wraps_in_i7labsh() {
    need_json!();
    let t = T::new("sh");
    t.add_host(MAC, 3, &[]);
    t.reply(|_, _| Ok(MockOut { exit_code: Some(0), ..Default::default() }));
    assert_eq!(t.run(&["sh", MAC, "dmesg | tail -5"]).0, 0);
    assert_eq!((t.last().cmd.as_str(), argv(&t.last())), ("exec", vec!["--", "i7labsh", "-c", "dmesg | tail -5"]));
}

#[test]
fn exec_of_a_shell_builtin_gets_the_sh_hint() {
    need_json!();
    let t = T::new("hint");
    t.add_host(MAC, 3, &[]);
    t.reply(|_, _| Ok(MockOut::status(Status::NotFound, "{\"error\":{\"code\":\"NOT_FOUND\",\"message\":\"mount: no such file\"}}")));
    let (code, _, e) = t.run(&["exec", MAC, "--", "mount", "/dev/vdc1", "/mnt"]);
    assert_eq!(code, 255);
    assert!(e.contains("builtin") && e.contains("i7labctl sh"), "{}", e);
    // exit 127 from a started shell-less command gets it too
    t.reply(|_, _| Ok(MockOut { exit_code: Some(127), ..Default::default() }));
    let (code, _, e) = t.run(&["exec", MAC, "--", "ls"]);
    assert_eq!(code, 127);
    assert!(e.contains("builtin"), "{}", e);
}

#[test]
fn put_uploads_the_file_with_size_and_sha() {
    need_json!();
    let t = T::new("put");
    t.add_host(MAC, 3, &[]);
    let data: Vec<u8> = (0..70_000u32).map(|i| (i % 253) as u8).collect();
    let src = t.dir.join("blob.bin");
    std::fs::write(&src, &data).unwrap();
    let sha = labproto::crypto::hex(&labproto::crypto::sha256(&data));
    let want = sha.clone();
    t.reply(move |_, _| Ok(MockOut::ok(&format!("{{\"bytes\":70000,\"sha256\":\"{}\"}}", want))));
    let (code, o, e) = t.run(&["put", MAC, src.to_str().unwrap(), "/run/blob.bin", "--mode", "0755", "--mkdirs"]);
    assert_eq!(code, 0, "{}", e);
    let c = t.last();
    assert_eq!(c.cmd, "put");
    assert_eq!(argv(&c), ["/run/blob.bin", "--size", "70000", "--sha256", &sha, "--mode", "0755", "--mkdirs"]);
    assert_eq!(c.uploaded, data);
    assert!(o.contains("uploaded 70000 bytes"), "{}", o);
    // bad mode, missing file
    assert_eq!(t.run(&["put", MAC, src.to_str().unwrap(), "/x", "--mode", "rwx"]).0, 2);
    assert_eq!(t.run(&["put", MAC, "/nonexistent/file", "/x"]).0, 2);
}

#[test]
fn put_detects_a_damaged_upload() {
    need_json!();
    let t = T::new("putbad");
    t.add_host(MAC, 3, &[]);
    let src = t.dir.join("f");
    std::fs::write(&src, "payload").unwrap();
    t.reply(|_, _| Ok(MockOut::ok("{\"bytes\":7,\"sha256\":\"0000000000000000000000000000000000000000000000000000000000000000\"}")));
    let (code, _, e) = t.run(&["put", MAC, src.to_str().unwrap(), "/x"]);
    assert_eq!(code, 1);
    assert!(e.contains("damaged"), "{}", e);
}

#[test]
fn get_verifies_and_renames() {
    need_json!();
    let t = T::new("get");
    t.add_host(MAC, 3, &[]);
    let data = b"the file contents".to_vec();
    let sha = labproto::crypto::hex(&labproto::crypto::sha256(&data));
    let (d2, s2) = (data.clone(), sha.clone());
    t.reply(move |_, _| Ok(MockOut { file: d2.clone(), body: format!("{{\"size\":17,\"mode\":420,\"mtime\":1,\"sha256\":\"{}\"}}", s2), ..Default::default() }));
    let dst = t.dir.join("got.txt");
    let (code, o, e) = t.run(&["get", MAC, "/var/log/messages", dst.to_str().unwrap()]);
    assert_eq!(code, 0, "{}", e);
    assert_eq!(std::fs::read(&dst).unwrap(), data);
    assert!(!t.dir.join("got.txt.part").exists());
    assert!(o.contains("downloaded 17 bytes") && o.contains(&sha), "{}", o);
    assert_eq!(argv(&t.last()), ["/var/log/messages"]);

    // a host that reports another hash: the file is not kept
    t.reply(move |_, _| Ok(MockOut { file: b"other bytes".to_vec(), body: format!("{{\"size\":11,\"sha256\":\"{}\"}}", sha), ..Default::default() }));
    let dst2 = t.dir.join("bad.txt");
    let (code, _, e) = t.run(&["get", MAC, "/x", dst2.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(e.contains("sha256 mismatch"), "{}", e);
    assert!(!dst2.exists() && !t.dir.join("bad.txt.part").exists());
}

#[test]
fn get_resume_continues_the_part_file() {
    need_json!();
    let t = T::new("getres");
    t.add_host(MAC, 3, &[]);
    let all = b"0123456789abcdef".to_vec();
    let sha = labproto::crypto::hex(&labproto::crypto::sha256(&all));
    let dst = t.dir.join("r.bin");
    std::fs::write(t.dir.join("r.bin.part"), &all[..6]).unwrap();
    let (tail, s2) = (all[6..].to_vec(), sha.clone());
    t.reply(move |_, _| Ok(MockOut { file: tail.clone(), body: format!("{{\"size\":16,\"sha256\":\"{}\"}}", s2), ..Default::default() }));
    let (code, _, e) = t.run(&["get", MAC, "/f", dst.to_str().unwrap(), "--resume"]);
    assert_eq!(code, 0, "{}", e);
    assert_eq!(argv(&t.last()), ["/f", "--offset", "6"]);
    assert_eq!(std::fs::read(&dst).unwrap(), all);
}

#[test]
fn reboot_confirmation() {
    need_json!();
    let mut t = T::new("reboot");
    t.add_host(MAC, 3, &[]);
    t.answer = Some(false);
    let (code, _, _) = t.run(&["reboot", MAC]);
    assert_eq!(code, 7);
    assert!(t.calls().is_empty());
    let (code, _, _) = t.run(&["reboot", MAC, "--yes"]);
    assert_eq!(code, 0);
    assert_eq!(t.calls().len(), 1);
    t.answer = Some(true);
    assert_eq!(t.run(&["poweroff", MAC]).0, 0);
}

#[test]
fn net_set_over_http_defaults_to_a_confirm_window() {
    need_json!();
    let t = T::new("netcf");
    t.add_host(MAC, 3, &[("ip", "10.0.0.5/24"), ("http", "8080")]);
    assert_eq!(t.run(&["net", "set", MAC, "eth0", "--ip", "10.0.0.9/24"]).0, 0);
    let c = t.last();
    assert_eq!(c.kind, "http");
    assert!(argv(&c).windows(2).any(|w| w == ["--confirm", "30"]), "{:?}", c.args);
    // over ether (forced) no confirm is added
    assert_eq!(t.run(&["net", "set", "--ether", MAC, "eth0", "--ip", "10.0.0.9/24"]).0, 0);
    let c = t.last();
    assert_eq!(c.kind, "ether");
    assert!(!argv(&c).contains(&"--confirm"));
}

#[test]
fn transport_choice_and_fallback() {
    need_json!();
    let t = T::new("plan");
    // fresh v2 host with ip + http port: http first, ether as fallback
    t.add_host(MAC, 3, &[("ip", "10.0.0.5/24"), ("http", "8080")]);
    assert_eq!(t.run(&["id", MAC]).0, 0);
    assert_eq!(t.last().kind, "http");
    // http is down: the call is retried on ether, once, and succeeds
    *t.fail_kind.lock().unwrap() = Some(i7labctl::Kind::Http);
    let n = t.calls().len();
    assert_eq!(t.run(&["id", MAC]).0, 0);
    let calls = t.calls();
    assert_eq!(calls[n].kind, "http");
    assert_eq!(calls[n + 1].kind, "ether");
    assert_eq!(calls.len(), n + 2);
    *t.fail_kind.lock().unwrap() = None;
    // forced transports
    assert_eq!(t.run(&["--transport", "ether", "id", MAC]).0, 0);
    assert_eq!(t.last().kind, "ether");
    assert_eq!(t.run(&["--http", "10.0.0.5:9000", "id"]).0, 0);
    let (k, target) = t.connects.lock().unwrap().last().cloned().unwrap();
    assert_eq!(k, i7labctl::Kind::Http);
    assert_eq!((target.ip.as_deref(), target.http_port), (Some("10.0.0.5"), Some(9000)));
    // no explicit port: none stored in the target, the transport falls back to DEFAULT_PORT (80)
    let tn = T::new("plan-noport");
    assert_eq!(tn.run(&["--http", "10.0.0.5", "id"]).0, 0);
    let (_, target) = tn.connects.lock().unwrap().last().cloned().unwrap();
    assert_eq!((target.ip.as_deref(), target.http_port), (Some("10.0.0.5"), None));
    assert_eq!(i7labctl::http::DEFAULT_PORT, 80);
    // and the old port still works when asked for
    assert_eq!(tn.run(&["--http", "10.0.0.5:8080", "id"]).0, 0);
    let (_, target) = tn.connects.lock().unwrap().last().cloned().unwrap();
    assert_eq!(target.http_port, Some(8080));
    // a stale entry never uses http
    let t2 = T::new("plan2");
    t2.add_host(MAC, 100, &[("ip", "10.0.0.5/24"), ("http", "8080")]);
    assert_eq!(t2.run(&["id", MAC]).0, 0);
    assert_eq!(t2.last().kind, "ether");
    // a v1 stick (no v2 fields, HTTP only) is driven over http
    let t3 = T::new("plan3");
    let mut v1 = labproto::beacon::Beacon { version: 1, fields: vec![] };
    v1.set("mac", MAC);
    v1.set("ip", "10.0.0.7/24");
    let mut reg = i7labctl::hosts::Registry::default();
    reg.observe(&v1, &i7labctl::hosts::ObserveMeta { iface: "eth0".into(), src_mac: labproto::Mac::parse(MAC), vlan: None, tag_ok: None }, t3.now - 2);
    reg.save(&t3.registry_path()).unwrap();
    assert_eq!(t3.run(&["id", MAC]).0, 0);
    assert_eq!(t3.last().kind, "http");
}

#[test]
fn vlan_and_iface_reach_the_connector() {
    let t = T::new("vlan");
    assert_eq!(t.run(&["id", "--ether", MAC, "--vlan", "13", "-i", "enp3s0"]).0, 0);
    let (_, target) = t.connects.lock().unwrap().last().cloned().unwrap();
    assert_eq!((target.vlan, target.iface.as_deref()), (Some(13), Some("enp3s0")));
}

#[test]
fn ping_reports_rtt_and_counts() {
    need_json!();
    let t = T::new("ping");
    t.add_host(MAC, 3, &[]);
    t.reply(|_, _| Ok(MockOut::ok("{\"uptime_ms\":5000,\"boot_id\":\"ab\"}")));
    let (code, o, _) = t.run(&["ping", MAC, "-c", "3"]);
    assert_eq!(code, 0);
    assert_eq!(t.calls().len(), 3);
    assert!(o.contains("3 sent, 3 received"), "{}", o);
    let (code, o, _) = t.run(&["ping", MAC, "-c", "2", "--json"]);
    assert_eq!(code, 0);
    assert!(o.contains("\"sent\":2,\"received\":2"), "{}", o);
    // no reply at all: exit 4
    *t.fail_kind.lock().unwrap() = Some(i7labctl::Kind::Ether);
    let (code, _, e) = t.run(&["ping", MAC, "-c", "2"]);
    assert_eq!(code, 4, "{}", e);
}

#[test]
fn usb_id_filter_is_applied_on_the_client() {
    need_json!();
    let t = T::new("usb");
    t.add_host(MAC, 3, &[]);
    t.reply(|_, _| Ok(MockOut::ok("{\"devices\":[{\"path\":\"1-1\",\"vid\":1921,\"pid\":21889,\"class\":8,\"speed_mbps\":480,\"manufacturer\":\"SanDisk\",\"product\":\"Cruzer\",\"serial\":\"S\",\"driver\":[\"usb-storage\"]},{\"path\":\"1-2\",\"vid\":1,\"pid\":2,\"class\":3,\"speed_mbps\":12,\"manufacturer\":\"Other\",\"product\":\"Kbd\",\"serial\":\"\",\"driver\":[]}]}")));
    let (code, o, _) = t.run(&["usb", MAC, "--id", "0781:5581"]);
    assert_eq!(code, 0);
    assert!(o.contains("Cruzer") && !o.contains("Kbd"), "{}", o);
}

#[test]
fn tui_dump_is_sanitised() {
    need_json!();
    let t = T::new("dump");
    t.add_host(MAC, 3, &[]);
    t.reply(|_, _| Ok(MockOut::ok("{\"frame\":\"Overview  Storage\\n\\u001b[2Jhost lab\"}")));
    let (code, o, _) = t.run(&["tui", "dump", MAC]);
    assert_eq!(code, 0);
    assert!(!o.contains('\x1b') && o.contains("Overview") && o.contains("host lab"), "{:?}", o);
}

#[test]
fn hostile_remote_strings_never_reach_the_terminal_raw() {
    need_json!();
    let t = T::new("hostile");
    t.add_host(MAC, 3, &[]);
    t.reply(|_, _| Ok(MockOut::ok("{\"v\":1,\"devices\":[{\"name\":\"sda\\u001b]0;pwned\\u0007\",\"size_bytes\":1,\"kind\":\"Usb\",\"model\":\"\\u001b[31mred\",\"serial\":\"x\\u202eyz\",\"mounts\":[],\"signatures\":[],\"boot_media\":false,\"write_safety\":{\"verdict\":\"Safe\",\"absolute\":[],\"overridable\":[]}}]}")));
    let (_, o, _) = t.run(&["blk", "ls", MAC]);
    assert!(!o.contains('\x1b') && !o.contains('\u{7}') && !o.contains('\u{202e}'), "{:?}", o);
    t.reply(|_, _| Ok(MockOut::status(Status::Refused, "{\"error\":{\"code\":\"REFUSED\",\"message\":\"bad \\u001b[2J thing\",\"reasons\":[\"a\\u001b[0m\"]}}")));
    let (_, _, e) = t.run(&["blk", "ls", MAC]);
    assert!(!e.contains('\x1b'), "{:?}", e);
}

#[test]
fn version_and_help_exit_zero() {
    let t = T::new("ver");
    let (code, o, _) = t.run(&["--version"]);
    assert_eq!(code, 0);
    assert!(o.starts_with("i7labctl 0.1.0"), "{}", o);
    assert_eq!(t.run(&["version"]).0, 0);
    assert_eq!(t.run(&["help"]).0, 0);
    assert_eq!(t.run(&["blk", "--help"]).0, 0);
    assert_eq!(t.run(&["help", "nonesuch"]).0, 2);
    assert_eq!(t.run(&[]).0, 2);
}

#[test]
fn the_ssh_transport_runs_the_system_ssh_for_exec_and_sh() {
    let mut t = T::new("sshx");
    t.ssh_bin = Some(write_script(&t.dir.join("bin"), "fakessh", &format!("echo \"$@\" > {}/ssh-args; exit 4", t.dir.display())));
    let (code, _, e) = t.run(&["exec", "--ssh", "bob@10.0.0.5", "--", "uname", "-a"]);
    assert_eq!(code, 4, "ssh's exit status is the command's: {}", e);
    let a = std::fs::read_to_string(t.dir.join("ssh-args")).unwrap();
    assert!(a.contains("-l bob") && a.trim_end().ends_with("10.0.0.5 uname -a") && a.contains("StrictHostKeyChecking=yes"), "{}", a);
    let (code, _, _) = t.run(&["sh", "--ssh", "10.0.0.5", "dmesg | tail"]);
    assert_eq!(code, 4);
    let a = std::fs::read_to_string(t.dir.join("ssh-args")).unwrap();
    assert!(a.contains("-l root") && a.trim_end().ends_with("10.0.0.5 dmesg | tail"), "{}", a);
    assert!(t.calls().is_empty(), "no wire command is sent over the ssh transport");
    // a missing ssh program is an own error: 255 for exec
    t.ssh_bin = Some("/nonexistent/ssh".into());
    assert_eq!(t.run(&["exec", "--ssh", "10.0.0.5", "--", "true"]).0, 255);
}

#[test]
fn key_file_flag_and_role_flag_choose_the_key() {
    let t = T::new("keyflag");
    let dir = t.home.join(".config/i7labctl/keys");
    let ks = labproto::keys::KeySet::load_dir(&dir).unwrap();
    let (admin_fp, ro_fp) = (ks.admin.unwrap().fingerprint(), ks.ro.unwrap().fingerprint());
    assert_eq!(t.run(&["id", "--ether", MAC]).0, 0);
    assert_eq!(t.keys_used.lock().unwrap().last().unwrap(), &(labproto::keys::Role::Admin, admin_fp.clone()));
    assert_eq!(t.run(&["id", "--ether", MAC, "--role", "ro"]).0, 0);
    assert_eq!(t.keys_used.lock().unwrap().last().unwrap(), &(labproto::keys::Role::Ro, ro_fp.clone()));
    // an explicit key file wins, and fixes the role
    let ro_file = dir.join("ro.key");
    assert_eq!(t.run(&["id", "--ether", MAC, "--key", ro_file.to_str().unwrap()]).0, 0);
    assert_eq!(t.keys_used.lock().unwrap().last().unwrap(), &(labproto::keys::Role::Ro, ro_fp));
    // --key together with a contradicting --role is a usage error
    assert_eq!(t.run(&["id", "--ether", MAC, "--key", ro_file.to_str().unwrap(), "--role", "admin"]).0, 2);
    // a key file with loose permissions is refused, naming the fix
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&ro_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (code, _, e) = t.run(&["id", "--ether", MAC, "--key", ro_file.to_str().unwrap()]);
    assert_eq!(code, 5);
    assert!(e.contains("chmod 600"), "{}", e);
}
