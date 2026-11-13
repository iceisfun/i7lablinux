//! Probe behaviour on small hand-built trees: alarms, USB tree, VLANs, EFI variables and their writers.

#[path = "block_util/mod.rs"]
mod block_util;

use block_util::Fx;
use labprobe::firmware::{self, BootEntry, FirmwareInfo, EFI_GLOBAL_GUID};
use labprobe::{net, serial, thermal, usb, ProbeError};
use std::os::unix::fs::symlink;

fn efivar(fx: &Fx, name: &str, attrs_and_data: &[u8]) {
    let p = fx.root.join(format!("sys/firmware/efi/efivars/{}-{}", name, EFI_GLOBAL_GUID));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, attrs_and_data).unwrap();
}

fn efi_read(fx: &Fx, name: &str) -> Vec<u8> {
    std::fs::read(fx.root.join(format!("sys/firmware/efi/efivars/{}-{}", name, EFI_GLOBAL_GUID))).unwrap()
}

fn utf16(s: &str) -> Vec<u8> {
    let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    v.extend_from_slice(&[0, 0]);
    v
}

/// Load option payload: attrs, path list length, description, device path nodes.
fn load_option(active: bool, desc: &str, nodes: &[u8]) -> Vec<u8> {
    let mut v = vec![0x07, 0, 0, 0]; // variable attributes
    v.extend_from_slice(&(active as u32).to_le_bytes());
    let mut path = nodes.to_vec();
    path.extend_from_slice(&[0x7f, 0xff, 4, 0]);
    v.extend_from_slice(&(path.len() as u16).to_le_bytes());
    v.extend(utf16(desc));
    v.extend(path);
    v
}

fn node(ty: u8, sub: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![ty, sub];
    v.extend_from_slice(&((4 + body.len()) as u16).to_le_bytes());
    v.extend_from_slice(body);
    v
}

#[test]
fn thermal_alarms_and_units() {
    let fx = Fx::new("therm");
    fx.write("sys/class/thermal/thermal_zone0/type", "x86_pkg_temp\n");
    fx.write("sys/class/thermal/thermal_zone0/temp", "99500\n");
    fx.write("sys/class/thermal/thermal_zone0/trip_point_0_type", "passive\n");
    fx.write("sys/class/thermal/thermal_zone0/trip_point_0_temp", "80000\n");
    fx.write("sys/class/thermal/thermal_zone0/trip_point_1_type", "critical\n");
    fx.write("sys/class/thermal/thermal_zone0/trip_point_1_temp", "95000\n");
    let h = "sys/class/hwmon/hwmon2";
    fx.write(&format!("{h}/name"), "nct6798\n");
    fx.write(&format!("{h}/temp1_input"), "41000\n");
    fx.write(&format!("{h}/temp1_label"), "SYSTIN\n");
    fx.write(&format!("{h}/temp1_crit"), "40000\n"); // over critical
    fx.write(&format!("{h}/temp10_input"), "30000\n");
    fx.write(&format!("{h}/fan1_input"), "0\n");
    fx.write(&format!("{h}/fan1_min"), "300\n"); // stopped fan that should spin
    fx.write(&format!("{h}/fan2_input"), "0\n"); // unlabeled, no minimum: empty header, not an alarm
    fx.write(&format!("{h}/in0_input"), "1008\n");
    fx.write(&format!("{h}/power1_input"), "25500000\n");
    fx.write(&format!("{h}/in0_alarm"), "1\n");
    fx.write("sys/class/hwmon/hwmon10/name", "late\n");
    fx.write("sys/class/hwmon/hwmon10/temp1_input", "20000\n");
    let r = thermal::probe(&fx.ctx()).unwrap();
    assert_eq!(r.zones[0].temp_c, Some(99.5));
    assert_eq!(r.zones[0].crit_c, Some(95.0));
    assert_eq!(r.hwmon.iter().map(|h| h.name.as_str()).collect::<Vec<_>>(), ["nct6798", "late"], "numeric hwmon order");
    let n = &r.hwmon[0];
    assert_eq!(n.temps.iter().map(|s| s.index).collect::<Vec<_>>(), [1, 10], "temp10 after temp1");
    assert_eq!(n.temps[0].label, "SYSTIN");
    assert_eq!(n.volts[0].value, 1008.0);
    assert_eq!(n.power[0].value, 25500.0, "uW -> mW");
    assert_eq!(r.alarms.len(), 4, "{:#?}", r.alarms);
    assert!(r.alarms.iter().any(|a| a.contains("thermal_zone0") && a.contains("critical")));
    assert!(r.alarms.iter().any(|a| a.contains("SYSTIN") && a.contains("critical")));
    assert!(r.alarms.iter().any(|a| a.contains("fan1") && a.contains("stopped")));
    assert!(r.alarms.iter().any(|a| a.contains("in0") && a.contains("alarm")));
}

#[test]
fn usb_tree_parents_drivers_classes() {
    let fx = Fx::new("usb");
    let base = "sys/devices/pci0000:00/0000:00:14.0";
    let dev = |name: &str, bus: &str, devnum: &str, vid: &str, pid: &str, class: &str, speed: &str, prod: &str| {
        let d = format!("{base}/{name}");
        fx.write(&format!("{d}/busnum"), bus);
        fx.write(&format!("{d}/devnum"), devnum);
        fx.write(&format!("{d}/idVendor"), vid);
        fx.write(&format!("{d}/idProduct"), pid);
        fx.write(&format!("{d}/bDeviceClass"), class);
        fx.write(&format!("{d}/speed"), speed);
        fx.write(&format!("{d}/product"), prod);
        std::fs::create_dir_all(fx.root.join("sys/bus/usb/devices")).unwrap();
        symlink(format!("../../../devices/pci0000:00/0000:00:14.0/{name}"), fx.root.join("sys/bus/usb/devices").join(name)).unwrap();
    };
    dev("usb1", "1\n", "1\n", "1d6b\n", "0002\n", "09\n", "480\n", "xHCI Host Controller\n");
    dev("1-2", "1\n", "4\n", "0781\n", "5581\n", "00\n", "5000\n", "Ultra\n");
    dev("1-2.1", "1\n", "7\n", "046d\n", "c52b\n", "00\n", "12\n", "Receiver\n");
    fx.write(&format!("{base}/1-2/version"), " 3.10\n");
    // interface of 1-2 is mass storage with the usb-storage driver
    fx.write(&format!("{base}/1-2:1.0/bInterfaceClass"), "08\n");
    std::fs::create_dir_all(fx.root.join("sys/bus/usb/drivers/usb-storage")).unwrap();
    symlink("../../../../bus/usb/drivers/usb-storage", fx.root.join(format!("{base}/1-2:1.0/driver"))).unwrap();
    symlink(format!("../../../devices/pci0000:00/0000:00:14.0/1-2:1.0"), fx.root.join("sys/bus/usb/devices/1-2:1.0")).unwrap();
    let r = usb::probe(&fx.ctx()).unwrap();
    assert_eq!(r.devices.len(), 3, "interface entries are not devices");
    let get = |p: &str| r.devices.iter().find(|d| d.path == p).unwrap();
    assert_eq!(get("usb1").parent, None);
    assert_eq!(get("1-2").parent.as_deref(), Some("usb1"));
    assert_eq!(get("1-2.1").parent.as_deref(), Some("1-2"));
    assert_eq!(get("1-2").drivers, ["usb-storage"]);
    assert_eq!(get("1-2").class_name, "mass-storage", "device class 0 takes the interface class");
    assert_eq!(get("usb1").class_name, "hub");
    assert_eq!((get("1-2").vid, get("1-2").pid, get("1-2").speed_mbps), (0x0781, 0x5581, Some(5000)));
    assert_eq!(get("1-2").version.as_deref(), Some("3.10"));
    assert_eq!(r.devices[0].path, "usb1", "bus then device number order");
}

#[test]
fn net_vlan_and_ipv6_and_perm_mac() {
    let fx = Fx::new("net");
    for (n, idx, mac, assign) in [("eth0", "2", "aa:bb:cc:00:00:01", "0"), ("eth0.13", "5", "aa:bb:cc:00:00:01", "3")] {
        let b = format!("sys/devices/virtual/net/{n}");
        fx.write(&format!("{b}/address"), &format!("{mac}\n"));
        fx.write(&format!("{b}/addr_assign_type"), &format!("{assign}\n"));
        fx.write(&format!("{b}/ifindex"), &format!("{idx}\n"));
        fx.write(&format!("{b}/operstate"), "up\n");
        fx.write(&format!("{b}/mtu"), "1500\n");
        fx.write(&format!("{b}/speed"), "-1\n");
        std::fs::create_dir_all(fx.root.join("sys/class/net")).unwrap();
        symlink(format!("../../devices/virtual/net/{n}"), fx.root.join("sys/class/net").join(n)).unwrap();
    }
    fx.write("sys/devices/virtual/net/lo/address", "00:00:00:00:00:00\n");
    symlink("../../devices/virtual/net/lo", fx.root.join("sys/class/net/lo")).unwrap();
    fx.write("proc/net/vlan/config", "VLAN Dev name\t | VLAN ID\nName-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\neth0.13       | 13  | eth0\n");
    fx.write("proc/net/if_inet6", "fe80000000000000a8bbccfffe000001 02 40 20 80 eth0\n20010db8000000000000000000000005 05 40 00 80 eth0.13\n");
    let r = net::probe(&fx.ctx()).unwrap();
    assert_eq!(r.ifaces.len(), 2, "lo is skipped");
    let (a, v) = (&r.ifaces[0], &r.ifaces[1]);
    assert_eq!((a.name.as_str(), a.perm_mac.as_deref(), a.vlan_of.clone()), ("eth0", Some("aa:bb:cc:00:00:01"), None));
    assert_eq!((v.vlan_of.as_deref(), v.vlan_id, v.perm_mac.clone()), (Some("eth0"), Some(13), None), "assigned MAC is not permanent");
    assert_eq!(a.ipv6, ["fe80::a8bb:ccff:fe00:1/64"]);
    assert_eq!(v.ipv6, ["2001:db8::5/64"]);
    assert_eq!(a.speed_mbps, None, "-1 means unknown");
}

#[test]
fn efi_boot_entries_and_internal_os() {
    let fx = Fx::new("efi");
    fx.write("sys/firmware/efi/fw_platform_size", "64\n");
    efivar(&fx, "SecureBoot", &[6, 0, 0, 0, 1]);
    efivar(&fx, "SetupMode", &[6, 0, 0, 0, 0]);
    efivar(&fx, "BootCurrent", &[6, 0, 0, 0, 0x02, 0x00]);
    efivar(&fx, "BootOrder", &[7, 0, 0, 0, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00]);
    let usb_path = [node(2, 1, &[0xd0, 0x41, 0x03, 0x0a, 0, 0, 0, 0]), node(1, 1, &[0, 0x14]), node(3, 5, &[3, 0])].concat();
    let nvme_path = [node(2, 1, &[0xd0, 0x41, 0x03, 0x0a, 0, 0, 0, 0]), node(1, 1, &[0, 0x1d]), node(3, 0x17, &[0; 12]), node(4, 4, &utf16("\\EFI\\u\\a.efi"))].concat();
    let net_path = [node(1, 1, &[0, 0x1f]), node(3, 0x0b, &[0; 33]), node(3, 0x0c, &[0; 11])].concat();
    efivar(&fx, "Boot0002", &load_option(true, "UEFI: USB stick", &usb_path)); // BootCurrent, USB
    efivar(&fx, "Boot0000", &load_option(true, "Ubuntu", &nvme_path));
    efivar(&fx, "Boot0001", &load_option(true, "PXE", &net_path));
    efivar(&fx, "Boot0003", &load_option(false, "Disabled", &nvme_path));
    efivar(&fx, "OsIndicationsSupported", &[6, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
    let f = firmware::probe(&fx.ctx()).unwrap();
    assert_eq!((f.secure_boot, f.setup_mode, f.boot_current), (Some(true), Some(false), Some(2)));
    assert_eq!(f.boot_order, [2, 0, 1, 3]);
    assert_eq!(f.boot_entries.len(), 4);
    let e = |n: u16| f.boot_entries.iter().find(|e| e.num == n).unwrap();
    assert!(e(2).usb && !e(2).network);
    assert!(e(1).network && !e(1).usb);
    assert!(!e(3).active);
    assert_eq!(e(0).device_path.as_deref(), Some("PciRoot(0x0)/Pci(0x1d,0x0)/NVMe/\\EFI\\u\\a.efi"));
    assert_eq!(e(2).description, "UEFI: USB stick");
    assert_eq!(firmware::internal_os_entry(&f), Some(0), "skips BootCurrent (USB), picks the first non-USB non-network active entry");
    // the only candidate is BootCurrent / inactive / network => none
    let only_bad = FirmwareInfo {
        boot_order: vec![1, 3],
        boot_entries: vec![
            BootEntry { num: 1, active: true, network: true, ..Default::default() },
            BootEntry { num: 3, active: false, ..Default::default() },
        ],
        ..Default::default()
    };
    assert_eq!(firmware::internal_os_entry(&only_bad), None);
}

#[test]
fn efi_writers() {
    let fx = Fx::new("efiw");
    fx.write("sys/firmware/efi/fw_platform_size", "64\n");
    efivar(&fx, "Boot0000", &load_option(true, "Ubuntu", &[]));
    let ctx = fx.ctx();
    // BootNext: only existing Boot#### entries, one write of attributes + u16
    assert!(matches!(firmware::set_boot_next(&ctx, 7), Err(ProbeError::NotFound(_))));
    firmware::set_boot_next(&ctx, 0).unwrap();
    assert_eq!(efi_read(&fx, "BootNext"), [7, 0, 0, 0, 0, 0]);
    assert_eq!(firmware::probe(&ctx).unwrap().boot_next, Some(0));
    // OsIndications: refuses when the firmware does not offer the bit, keeps existing bits otherwise
    assert!(matches!(firmware::set_os_indications(&ctx, 1), Err(ProbeError::Unsupported)));
    efivar(&fx, "OsIndicationsSupported", &[6, 0, 0, 0, 0x05, 0, 0, 0, 0, 0, 0, 0]);
    efivar(&fx, "OsIndications", &[7, 0, 0, 0, 0x04, 0, 0, 0, 0, 0, 0, 0]);
    firmware::set_os_indications(&ctx, 1).unwrap();
    assert_eq!(efi_read(&fx, "OsIndications"), [7, 0, 0, 0, 0x05, 0, 0, 0, 0, 0, 0, 0]);
    assert!(matches!(firmware::set_os_indications(&ctx, 2), Err(ProbeError::Unsupported)), "bit 1 not supported");
}

#[test]
fn bios_boot_has_no_efi_fields() {
    let fx = Fx::new("bios");
    let f = firmware::probe(&fx.ctx()).unwrap();
    assert_eq!(f.boot_mode, "bios");
    assert!(f.secure_boot.is_none() && f.boot_entries.is_empty() && f.boot_order.is_empty());
}

#[test]
fn serial_ports_uart_and_usb_adapters() {
    let fx = Fx::new("serial");
    fx.write("proc/cmdline", "quiet console=tty0 console=ttyS1,115200n8\n");
    for (n, ty, port, irq) in [("ttyS0", "0", "0x0", "0"), ("ttyS1", "4", "0x2F8", "3"), ("ttyS2", "4", "0x3E8", "4"), ("ttyS10", "1", "0x100", "5")] {
        let d = format!("sys/devices/platform/serial8250/tty/{n}");
        fx.write(&format!("{d}/type"), &format!("{ty}\n"));
        fx.write(&format!("{d}/port"), &format!("{port}\n"));
        fx.write(&format!("{d}/irq"), &format!("{irq}\n"));
        std::fs::create_dir_all(fx.root.join("sys/class/tty")).unwrap();
        symlink(format!("../../devices/platform/serial8250/tty/{n}"), fx.root.join("sys/class/tty").join(n)).unwrap();
    }
    let usb = "sys/devices/pci0000:00/0000:00:14.0/usb1/1-3";
    fx.write(&format!("{usb}/idVendor"), "0403\n");
    fx.write(&format!("{usb}/idProduct"), "6001\n");
    fx.write(&format!("{usb}/product"), "FT232R USB UART\n");
    fx.write(&format!("{usb}/1-3:1.0/ttyUSB0/tty/ttyUSB0/dev"), "188:0\n");
    symlink("../../devices/pci0000:00/0000:00:14.0/usb1/1-3/1-3:1.0/ttyUSB0/tty/ttyUSB0", fx.root.join("sys/class/tty/ttyUSB0")).unwrap();
    symlink("../../devices/virtual/tty/tty1", fx.root.join("sys/class/tty/tty1")).ok();
    let r = serial::probe(&fx.ctx()).unwrap();
    let names: Vec<&str> = r.ports.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["ttyS1", "ttyS2", "ttyS10", "ttyUSB0"], "ttyS0 has no UART; numeric order; ttyN consoles are ignored");
    assert_eq!((r.ports[0].uart_type.as_deref(), r.ports[0].io_port, r.ports[0].irq, r.ports[0].console.as_deref()), (Some("16550A"), Some(0x2F8), Some(3), Some("115200n8")));
    assert_eq!(r.ports[2].uart_type.as_deref(), Some("8250"));
    assert_eq!(r.ports[1].console, None);
    let u = &r.ports[3];
    assert_eq!((u.kind.as_str(), u.usb_vid, u.usb_pid, u.usb_product.as_deref()), ("usb-serial", Some(0x0403), Some(0x6001), Some("FT232R USB UART")));
}
