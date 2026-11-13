//! `i7labctl blk image`: argument checks, confirmation and the wire arguments, against the mock transport.

mod common;

use common::{MockOut, T, MAC};
use labproto::Status;

fn argv(c: &common::Call) -> Vec<String> {
    c.args.clone()
}

fn host_reply(t: &T, dev_size: u64, serial: &'static str) {
    t.reply(move |_c, args| {
        if args.iter().any(|a| a == "--status") {
            Ok(MockOut::ok(&format!(
                "{{\"v\":1,\"device\":{{\"name\":\"nvme0n1\",\"vendor\":\"\",\"model\":\"Test NVMe\",\"serial\":\"{}\",\"size_bytes\":{},\"kind\":\"nvme\",\"partition_table\":{{\"kind\":\"gpt\"}},\"partitions\":[{{\"index\":1,\"first_lba\":2048,\"last_lba\":4095,\"name\":\"ESP\",\"type_guid\":\"x\"}}],\"signatures\":[],\"mounts\":[],\"write_safety\":{{\"verdict\":\"needs_override\"}}}},\"session\":null,\"resume_at\":null}}",
                serial, dev_size
            )))
        } else {
            Ok(MockOut::ok("{\"v\":1,\"done\":true,\"bytes\":1048576,\"sha256\":\"ab\",\"verified\":true,\"gpt\":{\"action\":\"moved\",\"backup_lba\":99},\"rrpart\":\"ok\"}"))
        }
    });
}

fn image(t: &T, len: usize) -> String {
    let p = t.dir.join("win10.img");
    std::fs::write(&p, vec![7u8; len]).unwrap();
    p.to_string_lossy().into_owned()
}

#[test]
fn needs_destructive_serial_and_a_file_before_anything_is_sent() {
    let t = T::new("bi-args");
    t.add_host(MAC, 3, &[]);
    let img = image(&t, 4096);
    for args in [
        vec!["blk", "image", MAC, "nvme0n1", "--file", &img],
        vec!["blk", "image", MAC, "nvme0n1", "--file", &img, "--destructive"],
        vec!["blk", "image", MAC, "nvme0n1", "--file", &img, "--serial", "S1"],
        vec!["blk", "image", MAC, "nvme0n1", "--file", &img, "--destructive", "--serial", " "],
    ] {
        let (code, _, e) = t.run(&args);
        assert_eq!(code, 7, "{:?}: {}", args, e);
        assert!(e.contains("--destructive") && e.contains("--serial"), "{}", e);
    }
    assert_eq!(t.run(&["blk", "image", MAC, "nvme0n1", "--destructive", "--serial", "S1"]).0, 2, "--file is required");
    assert_eq!(t.run(&["blk", "image", MAC, "/dev/nvme0n1", "--file", &img, "--destructive", "--serial", "S1"]).0, 2, "a name, not a path");
    assert_eq!(t.run(&["blk", "image", MAC, "nvme0n1", "--file", &img, "--destructive", "--serial", "S1", "--offset", "100"]).0, 2, "offset alignment");
    assert!(t.calls().is_empty());
}

#[test]
fn declined_confirmation_sends_no_data() {
    let mut t = T::new("bi-no");
    t.add_host(MAC, 3, &[]);
    let img = image(&t, 1 << 20);
    host_reply(&t, 8 << 20, "S1");
    t.answer = Some(false);
    let (code, _, e) = t.run(&["blk", "image", MAC, "nvme0n1", "--file", &img, "--destructive", "--serial", "S1"]);
    assert_eq!(code, 7, "{}", e);
    assert!(e.contains("Test NVMe") && e.contains("gpt") && e.contains("ESP") && e.contains("S1"), "the layout is shown before asking: {}", e);
    let calls = t.calls();
    assert_eq!(calls.len(), 1, "only the status query: {:?}", calls);
    assert!(argv(&calls[0]).contains(&"--status".to_string()));
}

#[test]
fn yes_runs_the_transfer_with_the_wire_arguments_and_reports() {
    let t = T::new("bi-yes");
    t.add_host(MAC, 3, &[]);
    let img = image(&t, 1 << 20);
    host_reply(&t, 8 << 20, "S1");
    let (code, o, e) = t.run(&["--yes", "blk", "image", MAC, "nvme0n1", "--file", &img, "--destructive", "--serial", "S1", "--verify", "--grow-last"]);
    assert_eq!(code, 0, "{}", e);
    let calls = t.calls();
    let w = argv(calls.last().unwrap());
    assert_eq!(w[0], "nvme0n1");
    for want in ["--size", "1048576", "--image-id", "--serial", "S1", "--destructive", "--verify", "--grow-last"] {
        assert!(w.iter().any(|a| a == want), "{} missing in {:?}", want, w);
    }
    assert!(!w.iter().any(|a| a == "--resume"));
    // the upload carried the END record at least (mock reads the stream)
    assert!(!calls.last().unwrap().uploaded.is_empty());
    assert!(o.contains("wrote 1.0 MiB to nvme0n1") && o.contains("verified by reading the disk back") && o.contains("gpt backup: moved"), "{}", o);
    // refusing an image larger than the disk, and a serial that is not the disk's
    let (code, _, e) = t.run(&["--yes", "blk", "image", MAC, "nvme0n1", "--file", &img, "--destructive", "--serial", "S2"]);
    assert_eq!(code, 7, "{}", e);
    assert!(e.contains("serial mismatch"), "{}", e);
    host_reply(&t, 512 << 10, "S1");
    let (code, _, e) = t.run(&["--yes", "blk", "image", MAC, "nvme0n1", "--file", &img, "--destructive", "--serial", "S1"]);
    assert_eq!(code, 7, "{}", e);
    assert!(e.contains("larger than the disk"), "{}", e);
}

#[test]
fn json_output_and_remote_refusal() {
    let t = T::new("bi-json");
    t.add_host(MAC, 3, &[]);
    let img = image(&t, 1 << 20);
    host_reply(&t, 8 << 20, "S1");
    let (code, o, _) = t.run(&["--yes", "--json", "blk", "image", MAC, "nvme0n1", "--file", &img, "--destructive", "--serial", "S1"]);
    assert_eq!(code, 0);
    assert!(o.contains("\"ok\":true") && o.contains("\"cmd\":\"blk.image\"") && o.contains("\"verified\":true"), "{}", o);
    t.reply(|_c, args| {
        if args.iter().any(|a| a == "--status") {
            Ok(MockOut::ok("{\"v\":1,\"device\":{\"name\":\"nvme0n1\",\"serial\":\"S1\",\"size_bytes\":8388608,\"partitions\":[],\"signatures\":[],\"mounts\":[\"/mnt\"],\"write_safety\":{\"verdict\":\"refused\"}},\"session\":null,\"resume_at\":null}"))
        } else {
            Ok(MockOut::status(Status::Refused, "{\"error\":{\"code\":\"REFUSED\",\"message\":\"write refused by the safety gate\",\"reasons\":[{\"code\":\"mounted\",\"detail\":\"/mnt\",\"overridable\":false}]}}"))
        }
    });
    let (code, _, e) = t.run(&["--yes", "blk", "image", MAC, "nvme0n1", "--file", &img, "--destructive", "--serial", "S1"]);
    assert_eq!(code, 7, "{}", e);
    assert!(e.contains("mounted (/mnt)"), "{}", e);
}

#[test]
fn allow_boot_media_is_only_an_addition_to_destructive_and_serial() {
    let t = T::new("bi-abm");
    t.add_host(MAC, 3, &[]);
    let img = image(&t, 1 << 20);
    host_reply(&t, 8 << 20, "S1");
    // the flag alone never gets past the local checks
    for args in [
        vec!["--yes", "blk", "image", MAC, "nvme0n1", "--file", &img, "--allow-boot-media"],
        vec!["--yes", "blk", "image", MAC, "nvme0n1", "--file", &img, "--allow-boot-media", "--serial", "S1"],
        vec!["--yes", "blk", "image", MAC, "nvme0n1", "--file", &img, "--allow-boot-media", "--destructive"],
    ] {
        let (code, _, e) = t.run(&args);
        assert_eq!(code, 7, "{:?}: {}", args, e);
    }
    assert!(t.calls().is_empty());
    // without the flag it is not sent; with it, it is, and the prompt says what it means
    let (code, _, _) = t.run(&["--yes", "blk", "image", MAC, "nvme0n1", "--file", &img, "--destructive", "--serial", "S1"]);
    assert_eq!(code, 0);
    assert!(!argv(t.calls().last().unwrap()).iter().any(|a| a == "--allow-boot-media"));
    let (code, _, e) = t.run(&["--yes", "blk", "image", MAC, "nvme0n1", "--file", &img, "--destructive", "--serial", "S1", "--allow-boot-media"]);
    assert_eq!(code, 0, "{}", e);
    assert!(argv(t.calls().last().unwrap()).iter().any(|a| a == "--allow-boot-media"));
    assert!(e.contains("--allow-boot-media") && e.contains("cannot boot again"), "{}", e);
}
