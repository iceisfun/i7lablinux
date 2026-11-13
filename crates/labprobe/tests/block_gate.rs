//! Write gate, enumeration and serial resolution against a fake sysfs/dev tree (real code paths, regular files
//! standing in for block devices). The loop-device / real-mount variants are #[ignore]d and run with sudo.

mod block_util;

use block_util::{DiskSpec, Fx};
use labprobe::block::parttable::build_gpt;
use labprobe::block::{self, Reason, Verdict, WriteGuard, WriteRequest};
use labproto::json::to_json;

const MIB: u64 = 1 << 20;

fn req(dev: &str, destructive: bool, serial: Option<&str>) -> WriteRequest {
    WriteRequest { dev: dev.into(), destructive, serial: serial.map(str::to_string), allow_boot_media: false, actor: "test key=0 console".into() }
}

fn codes(r: Result<WriteGuard, block::Refusal>) -> Vec<&'static str> {
    match r {
        Ok(_) => vec!["OK"],
        Err(f) => f.reasons.iter().map(Reason::code).collect(),
    }
}

fn blank(fx: &Fx, name: &str, serial: &str) {
    fx.disk(&DiskSpec::virtio(name, 8 * MIB, 0, serial));
}

#[test]
fn blank_disk_needs_both_flags_and_the_right_serial() {
    let fx = Fx::new("blank");
    blank(&fx, "vda", "SER-A\n");
    let ctx = fx.ctx();
    let d = block::enumerate::describe(&ctx, "vda").unwrap();
    assert_eq!(d.serial.as_deref(), Some("SER-A"));
    assert_eq!(d.serial_source, Some(block::SerialSource::Virtio));
    assert_eq!(d.kind, block::DiskKind::Virtio);
    assert_eq!(d.write_safety.verdict, Verdict::Safe);

    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vda", false, Some("SER-A")))), ["not_destructive"]);
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vda", true, None))), ["serial_missing"]);
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vda", true, Some("SER-B")))), ["serial_mismatch"]);
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vda", true, Some("SER-A")))), ["OK"]);
}

#[test]
fn partition_table_is_overridable_but_only_with_both_flags() {
    let fx = Fx::new("gpt");
    blank(&fx, "vda", "SER-A");
    fx.put("vda", 0, &build_gpt(512, 8 * MIB / 512, &[(2048, 4095, "ESP")]));
    let ctx = fx.ctx();
    let d = block::enumerate::describe(&ctx, "vda").unwrap();
    assert_eq!(d.partition_table.as_ref().unwrap().kind, "gpt");
    assert_eq!(d.partitions.len(), 1);
    assert_eq!(d.write_safety.verdict, Verdict::NeedsOverride);
    assert!(d.write_safety.overridable.iter().any(|r| r.code() == "partition_table"));
    assert!(d.write_safety.absolute.is_empty());

    let r = codes(WriteGuard::acquire(&ctx, &req("vda", false, Some("SER-A"))));
    assert_eq!(r, ["not_destructive", "partition_table"]);
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vda", true, Some("WRONG")))), ["serial_mismatch", "partition_table"]);
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vda", true, Some("SER-A")))), ["OK"]);
}

#[test]
fn filesystem_signature_without_table_is_overridable() {
    let fx = Fx::new("sig");
    blank(&fx, "vda", "SER-A");
    fx.put("vda", 0x438, &[0x53, 0xEF]);
    let ctx = fx.ctx();
    let d = block::enumerate::describe(&ctx, "vda").unwrap();
    assert!(d.partition_table.is_none());
    assert_eq!(d.signatures[0].kind, "ext2");
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vda", true, None))), ["serial_missing", "signature"]);
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vda", true, Some("SER-A")))), ["OK"]);
}

#[test]
fn signature_inside_a_partition_is_found_with_absolute_offset() {
    let fx = Fx::new("partsig");
    blank(&fx, "vda", "SER-A");
    fx.put("vda", 0, &build_gpt(512, 8 * MIB / 512, &[(2048, 8000, "root")]));
    fx.put("vda", 2048 * 512 + 0x438, &[0x53, 0xEF]);
    let d = block::enumerate::describe(&fx.ctx(), "vda").unwrap();
    let s = d.signatures.iter().find(|s| s.kind == "ext2").unwrap();
    assert_eq!(s.offset, 2048 * 512 + 0x438);
}

#[test]
fn mounted_partition_is_never_writable_and_root_is_backs_running_system() {
    let fx = Fx::new("mnt");
    blank(&fx, "vda", "SER-A");
    fx.partition("vda", "vda1", 252, 1);
    fx.mountinfo("30 1 252:1 / /mnt rw - ext4 /dev/vda1 rw\n");
    let ctx = fx.ctx();
    let d = block::enumerate::describe(&ctx, "vda").unwrap();
    assert_eq!(d.mounts, ["/mnt"]);
    assert_eq!(d.write_safety.verdict, Verdict::Refused);
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vda", true, Some("SER-A")))), ["mounted"]);

    fx.mountinfo("30 1 252:1 / / rw - ext4 /dev/vda1 rw\n");
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vda", true, Some("SER-A")))), ["backs_running_system"]);
    fx.mountinfo("30 1 252:0 / /run/i7lab rw - ext4 /dev/vda rw\n");
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vda", true, Some("SER-A")))), ["backs_running_system"]);
}

#[test]
fn holders_and_swap_refuse() {
    let fx = Fx::new("hold");
    blank(&fx, "vda", "SER-A");
    fx.partition("vda", "vda1", 252, 1);
    fx.write("sys/block/vda/vda1/holders/dm-0/x", "");
    let ctx = fx.ctx();
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vda", true, Some("SER-A")))), ["held"]);
    std::fs::remove_dir_all(fx.root.join("sys/block/vda/vda1/holders")).unwrap();
    fx.write("proc/swaps", "Filename Type Size Used Priority\n/dev/vda1 partition 1024 0 -2\n");
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vda", true, Some("SER-A")))), ["swap"]);
}

#[test]
fn boot_media_by_devno_and_by_partuuid_never_by_label() {
    let fx = Fx::new("boot");
    blank(&fx, "vda", "SER-A");
    blank(&fx, "vdb", "SER-B");
    fx.disk(&DiskSpec::virtio("vdc", 8 * MIB, 32, "SER-C"));
    fx.put("vda", 0, &build_gpt(512, 8 * MIB / 512, &[(2048, 4095, "i7lab.boot")])); // label is irrelevant
    let mut ctx = fx.ctx();
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vda", true, Some("SER-A")))), ["OK"], "a label alone does not protect");
    // by devno
    ctx.boot_disk = Some((252, 0));
    let d = block::enumerate::describe(&ctx, "vda").unwrap();
    assert!(d.boot_media);
    assert!(codes(WriteGuard::acquire(&ctx, &req("vda", true, Some("SER-A")))).contains(&"boot_media"));
    // by PARTUUID (a clone of the stick on another disk is protected too)
    ctx.boot_disk = None;
    ctx.boot_partuuid = Some("01010101-0101-0101-0101-010101010101".to_uppercase());
    let d = block::enumerate::describe(&ctx, "vda").unwrap();
    assert!(d.boot_media);
    assert!(!block::enumerate::describe(&ctx, "vdb").unwrap().boot_media);
    let r = codes(WriteGuard::acquire(&ctx, &req("vda", true, Some("SER-A"))));
    assert_eq!(r, ["boot_media"], "overridable reasons are not mixed in once refused absolutely: {r:?}");
    assert!(!block::Reason::BootMedia.overridable());
    // resolve_boot_disk finds the disk from the PARTUUID alone
    let found = block::resolve_boot_disk(&fx.ctx(), "01010101-0101-0101-0101-010101010101");
    assert_eq!(found, Some((252, 0)));
    assert_eq!(block::resolve_boot_disk(&fx.ctx(), "ffffffff-0000-0000-0000-000000000000"), None);
}

#[test]
fn read_only_noserial_partition_and_missing() {
    let fx = Fx::new("misc");
    let mut ro = DiskSpec::virtio("vda", 8 * MIB, 0, "SER-A");
    ro.ro = true;
    fx.disk(&ro);
    fx.disk(&DiskSpec { name: "vdb", size: 8 * MIB, devpath: "pci0000:00/0000:00:04.0/virtio1/block", major: 252, minor: 16, ro: false, files: vec![] });
    fx.partition("vdb", "vdb1", 252, 17);
    let ctx = fx.ctx();
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vda", true, Some("SER-A")))), ["read_only"]);
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vdb", true, Some("anything")))), ["no_serial"]);
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vdb1", true, Some("x")))), ["not_a_disk"]);
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("nope", true, Some("x")))), ["not_found"]);
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("../vdb", true, Some("x")))), ["not_found"]);
}

#[test]
fn second_acquire_is_under_test_until_the_guard_drops() {
    let fx = Fx::new("lock");
    blank(&fx, "vda", "SER-A");
    let ctx = fx.ctx();
    let g = WriteGuard::acquire(&ctx, &req("vda", true, Some("SER-A"))).unwrap();
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vda", true, Some("SER-A")))), ["under_test"]);
    let d = block::enumerate::describe(&ctx, "vda").unwrap();
    assert!(d.write_safety.absolute.iter().any(|r| r.code() == "under_test"));
    drop(g);
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vda", true, Some("SER-A")))), ["OK"]);
}

#[test]
fn every_attempt_is_audited() {
    let fx = Fx::new("audit");
    blank(&fx, "vda", "SER-A");
    let ctx = fx.ctx();
    let _ = WriteGuard::acquire(&ctx, &req("vda", false, None));
    let _ = WriteGuard::acquire(&ctx, &req("vda", true, Some("SER-A")));
    let log = fx.audit_log();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 2, "{log}");
    assert!(lines[0].contains("REFUSED reasons=not_destructive,serial_missing"), "{}", lines[0]);
    assert!(lines[1].contains("ALLOWED serial=SER-A") && lines[1].contains("actor=test"), "{}", lines[1]);
}

#[test]
fn serial_resolution_order() {
    let fx = Fx::new("serial");
    // nvme: device/serial, padded
    fx.disk(&DiskSpec {
        name: "nvme0n1",
        size: MIB,
        devpath: "pci0000:00/0000:00:1d.0/0000:3d:00.0/nvme/nvme0",
        major: 259,
        minor: 0,
        ro: false,
        files: vec![("device/serial", "S4EVNX0M123456      \n")],
    });
    // scsi: VPD 0x80
    let sd = fx.disk(&DiskSpec { name: "sda", size: MIB, devpath: "pci0000:00/0000:00:17.0/ata3/host2/target2:0:0/2:0:0:0/block", major: 8, minor: 0, ro: false, files: vec![] });
    let _ = sd;
    let mut vpd = vec![0u8, 0x80, 0, 10];
    vpd.extend_from_slice(b"WD-WX1234 ");
    std::fs::create_dir_all(fx.root.join("sys/block/sda/device")).unwrap();
    std::fs::write(fx.root.join("sys/block/sda/device/vpd_pg80"), vpd).unwrap();
    // usb: serial of the ancestor usb device (no VPD)
    fx.disk(&DiskSpec { name: "sdb", size: MIB, devpath: "pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0/host6/target6:0:0/6:0:0:0/block", major: 8, minor: 16, ro: false, files: vec![] });
    fx.write("sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/idVendor", "0781\n");
    fx.write("sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/serial", "4C530001\n");
    // mmc
    fx.disk(&DiskSpec { name: "mmcblk0", size: MIB, devpath: "pci0000:00/0000:00:1e.4/mmc_host/mmc0/mmc0:0001/block", major: 179, minor: 0, ro: false, files: vec![("device/serial", "0x1234abcd\n")] });
    // nothing
    fx.disk(&DiskSpec { name: "sdc", size: MIB, devpath: "pci0000:00/0000:00:1f.2/host0/target0:0:0/0:0:0:0/block", major: 8, minor: 32, ro: false, files: vec![] });

    let ctx = fx.ctx();
    let get = |n: &str| {
        let d = block::enumerate::describe_basic(&ctx, n).unwrap();
        (d.kind, d.serial, d.serial_source.map(|s| s.name()))
    };
    assert_eq!(get("nvme0n1"), (block::DiskKind::Nvme, Some("S4EVNX0M123456".into()), Some("nvme")));
    assert_eq!(get("sda"), (block::DiskKind::Sata, Some("WD-WX1234".into()), Some("vpd80")));
    assert_eq!(get("sdb"), (block::DiskKind::Usb, Some("4C530001".into()), Some("usb")));
    assert_eq!(get("mmcblk0"), (block::DiskKind::Mmc, Some("0x1234abcd".into()), Some("mmc")));
    assert_eq!(get("sdc"), (block::DiskKind::Scsi, None, None));
}

#[test]
fn enumerate_skips_virtual_unless_all_and_json_is_stable() {
    let fx = Fx::new("enum");
    blank(&fx, "vda", "SER-A");
    fx.disk(&DiskSpec { name: "loop0", size: MIB, devpath: "virtual/block", major: 7, minor: 0, ro: false, files: vec![] });
    let ctx = fx.ctx();
    let r = block::probe(&ctx, false).unwrap();
    assert_eq!(r.devices.len(), 1);
    assert_eq!(block::probe(&ctx, true).unwrap().devices.len(), 2);
    let j = to_json(&r);
    assert!(j.starts_with("{\"v\":1,\"devices\":["), "{j}");
    for k in [
        "name", "devno", "size_bytes", "logical_block", "physical_block", "kind", "model", "vendor", "serial", "serial_source", "wwid",
        "firmware_rev", "rotational", "removable", "read_only", "partition_table", "partitions", "signatures", "mounts", "holders", "swap",
        "boot_media", "write_safety",
    ] {
        assert!(j.contains(&format!("\"{k}\":")), "missing key {k} in {j}");
    }
    assert!(j.contains("\"model\":null") && j.contains("\"verdict\":\"safe\""), "{j}");
}

#[test]
fn unreadable_device_is_refused_not_assumed_blank() {
    let fx = Fx::new("unread");
    blank(&fx, "vda", "SER-A");
    // zero-size device
    std::fs::write(fx.dev("vda"), b"").unwrap();
    assert_eq!(codes(WriteGuard::acquire(&fx.ctx(), &req("vda", true, Some("SER-A")))), ["unreadable"]);
}

fn req_boot(dev: &str, destructive: bool, serial: Option<&str>) -> WriteRequest {
    WriteRequest { allow_boot_media: true, ..req(dev, destructive, serial) }
}

#[test]
fn ram_resident_boot_media_is_overridable_only_with_the_flag_and_the_proof() {
    let fx = Fx::new("bootram");
    blank(&fx, "vda", "SER-A");
    fx.partition("vda", "vda1", 252, 1);
    fx.put("vda", 0, &build_gpt(512, 8 * MIB / 512, &[(2048, 4095, "i7lab.boot")]));
    let mut ctx = fx.ctx();
    ctx.boot_disk = Some((252, 0));
    let ram = "1 0 0:2 / / rw - rootfs rootfs rw\n";
    fx.mountinfo(ram);
    let _ = std::fs::remove_file(fx.root.join("proc/self/exe"));
    std::os::unix::fs::symlink("/usr/sbin/i7labd", fx.root.join("proc/self/exe")).unwrap();

    let d = block::enumerate::describe(&ctx, "vda").unwrap();
    assert!(d.boot_media && d.ram_resident);
    assert!(d.write_safety.absolute.is_empty());
    let o = d.write_safety.overridable.iter().find(|r| r.code() == "boot_media").unwrap();
    assert_eq!((o.detail(), o.overridable()), (Some("ram-resident"), true));
    assert!(labproto::json::to_json(&d.write_safety).contains("{\"code\":\"boot_media\",\"detail\":\"ram-resident\",\"overridable\":true}"));

    // no flag, flag without the other two, wrong serial: refused; with all three: allowed
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req("vda", true, Some("SER-A")))), ["boot_media"]);
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req_boot("vda", false, Some("SER-A")))), ["not_destructive", "boot_media", "partition_table"]);
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req_boot("vda", true, None))), ["serial_missing", "boot_media", "partition_table"]);
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req_boot("vda", true, Some("WRONG")))), ["serial_mismatch", "boot_media", "partition_table"]);
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req_boot("vda", true, Some("SER-A")))), ["OK"]);
    let log = fx.audit_log();
    assert!(log.contains("allow_boot_media=true") && log.contains("ALLOWED serial=SER-A BOOT-MEDIA-OVERRIDE ram-resident"), "{log}");
    assert!(log.contains("allow_boot_media=false") && log.contains("REFUSED"), "{log}");

    // not RAM-resident: root on the disk, or anything mounted from it, or swap, or a holder: absolute even with the flag
    for (why, mi) in [
        ("root on the disk", "1 0 252:1 / / rw - ext4 /dev/vda1 rw\n"),
        ("mount from the disk", "1 0 0:2 / / rw - rootfs rootfs rw\n30 1 252:1 / /data rw - vfat /dev/vda1 rw\n"),
        ("root on another disk", "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"),
    ] {
        fx.mountinfo(mi);
        let d = block::enumerate::describe(&ctx, "vda").unwrap();
        assert!(d.boot_media && !d.ram_resident, "{why}");
        assert!(d.write_safety.absolute.iter().any(|r| r.code() == "boot_media" && !r.overridable()), "{why}");
        let r = codes(WriteGuard::acquire(&ctx, &req_boot("vda", true, Some("SER-A"))));
        assert!(r.contains(&"boot_media"), "{why}: {r:?}");
        assert!(!r.contains(&"OK"), "{why}");
    }
    fx.mountinfo(ram);
    fx.write("proc/swaps", "Filename Type Size Used Priority\n/dev/vda1 partition 1024 0 -2\n");
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req_boot("vda", true, Some("SER-A")))), ["boot_media", "swap"]);
    fx.write("proc/swaps", "Filename Type Size Used Priority\n");
    fx.write("sys/block/vda/vda1/holders/dm-0/x", "");
    let r = codes(WriteGuard::acquire(&ctx, &req_boot("vda", true, Some("SER-A"))));
    assert!(r.contains(&"boot_media") && r.contains(&"held"), "{r:?}");
    std::fs::remove_dir_all(fx.root.join("sys/block/vda/vda1/holders")).unwrap();
    // exe unknown: fail closed
    std::fs::remove_file(fx.root.join("proc/self/exe")).unwrap();
    assert!(codes(WriteGuard::acquire(&ctx, &req_boot("vda", true, Some("SER-A")))).contains(&"boot_media"));
    // the flag on a disk that is not boot media changes nothing
    fx.disk(&DiskSpec::virtio("vdb", 8 * MIB, 32, "SER-B"));
    assert_eq!(codes(WriteGuard::acquire(&ctx, &req_boot("vdb", true, Some("SER-B")))), ["OK"]);
}
