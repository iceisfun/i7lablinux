//! Fixture data for the demo, the headless tests and golden frames: a plausible small-form-factor PC with one
//! USB boot stick, a NVMe disk, a degraded PCIe link and a hostile USB product string. Owner: P5.

use labprobe::block::{
    parttable::{PartTable, Partition},
    signatures::Signature,
    smart::{SmartAll, SmartAttr, SmartReport},
    BlockDevice, BlockReport, DiskKind, Reason, SerialSource, Verdict, WriteSafety,
};
use labprobe::cpu::CpuInfo;
use labprobe::dmi::DmiInfo;
use labprobe::firmware::{BootEntry, FirmwareInfo};
use labprobe::kmsg::{KmsgLine, KmsgReport};
use labprobe::mem::{Dimm, EdacMc, MemInfo};
use labprobe::net::{NetIface, NetReport};
use labprobe::pci::{AerCounters, Bar, PciDevice, PciReport, PcieLink};
use labprobe::system::SystemInfo;
use labprobe::thermal::{Hwmon, Sensor, ThermalReport, Zone};
use labprobe::usb::{UsbDevice, UsbReport};

use crate::model::{Identity, TestView, ViewData};

fn pci(bdf: &str, parent: Option<&str>, ids: (u16, u16), class: u32, class_name: &str, vendor: &str, name: &str, driver: Option<&str>) -> PciDevice {
    PciDevice {
        bdf: bdf.into(),
        parent: parent.map(|s| s.into()),
        vendor: ids.0,
        device: ids.1,
        class,
        class_name: class_name.into(),
        vendor_name: Some(vendor.into()),
        device_name: Some(name.into()),
        driver: driver.map(|s| s.into()),
        iommu_group: Some(1),
        link: Some(PcieLink { cur_gen: Some(3), cur_width: Some(4), max_gen: Some(3), max_width: Some(4), degraded: false }),
        ..Default::default()
    }
}

fn disk(name: &str, size: u64, kind: DiskKind, vendor: &str, model: &str, serial: &str) -> BlockDevice {
    BlockDevice {
        name: name.into(),
        devno: (259, 0),
        size_bytes: size,
        logical_block: 512,
        physical_block: 512,
        kind,
        model: Some(model.into()),
        vendor: Some(vendor.into()),
        serial: Some(serial.into()),
        serial_source: Some(SerialSource::Nvme),
        wwid: None,
        firmware_rev: Some("2B2QEXM7".into()),
        rotational: false,
        removable: false,
        read_only: false,
        partition_table: None,
        partitions: vec![],
        signatures: vec![],
        mounts: vec![],
        holders: vec![],
        swap: false,
        boot_media: false,
        ram_resident: false,
        write_safety: WriteSafety { verdict: Verdict::Safe, absolute: vec![], overridable: vec![] },
    }
}

fn kline(seq: u64, level: u8, ts_s: f64, text: &str, tags: &[&str]) -> KmsgLine {
    KmsgLine { seq, level, ts_us: (ts_s * 1e6) as u64, text: text.into(), tags: tags.iter().map(|s| s.to_string()).collect() }
}

fn iface(name: &str, mac: &str, driver: Option<&str>, up: bool, ip: Option<&str>, speed: Option<u64>) -> NetIface {
    NetIface {
        name: name.into(),
        mac: Some(mac.into()),
        perm_mac: Some(mac.into()),
        driver: driver.map(|s| s.into()),
        bus_info: driver.map(|_| "0000:02:00.0".to_string()),
        operstate: if up { "up".into() } else { "down".into() },
        carrier: Some(up),
        speed_mbps: speed,
        duplex: speed.map(|_| "full".to_string()),
        mtu: 1500,
        ipv4: ip.map(|s| vec![s.to_string()]).unwrap_or_default(),
        rx_bytes: 8_123_456_789,
        tx_bytes: 1_234_567_890,
        ..Default::default()
    }
}

/// The demo host.
pub fn demo_data() -> ViewData {
    let mut d = ViewData::default();
    d.identity = Identity {
        version: "0.1.0".into(),
        build_id: Some("demo-0001".into()),
        hostname: "i7lab-m720q-04".into(),
        ips: vec!["192.0.2.141".into()],
        mac: Some("3c:ec:ef:12:34:56".into()),
        key_summary: "admin  fp 9f3a1c5e77d2\nro     fp 41b0aa90c3e8".into(),
        banners: vec![],
        console_locked: false,
    };
    d.system = Some(SystemInfo {
        hostname: "i7lab-m720q-04".into(),
        kernel: "Linux 6.12.8-i7lab x86_64".into(),
        cmdline: "i7lab.console=open".into(),
        uptime_s: 3725.0,
        load: [0.42, 0.30, 0.21],
        boot_id: "b0".into(),
        boot_mode: "uefi".into(),
        image_build: Some("i7lablinux 0.1.0 2026-11-12".into()),
        ..Default::default()
    });
    d.cpu = Some(CpuInfo {
        vendor: "GenuineIntel".into(),
        model_name: "Intel(R) Core(TM) i7-8700T CPU @ 2.40GHz".into(),
        sockets: 1,
        cores: 6,
        threads: 12,
        freq_mhz: Some(2400.0),
        microcode: Some("0xf6".into()),
        ..Default::default()
    });
    d.mem = Some(MemInfo {
        total_kib: 16 * 1024 * 1024,
        available_kib: 11 * 1024 * 1024,
        swap_kib: 0,
        dimms: vec![
            Dimm { locator: "DIMM A".into(), size_mib: 8192, kind: Some("DDR4".into()), speed_mts: Some(2666), ..Default::default() },
            Dimm { locator: "DIMM B".into(), size_mib: 8192, kind: Some("DDR4".into()), speed_mts: Some(2666), ..Default::default() },
        ],
        ecc: Some("none".into()),
        edac: vec![EdacMc { name: "mc0".into(), ce_count: 0, ue_count: 0, ..Default::default() }],
        ..Default::default()
    });
    d.dmi = Some(DmiInfo {
        fields: vec![
            ("sys_vendor", Some("LENOVO".into())),
            ("product_name", Some("ThinkCentre M720q".into())),
            ("product_serial", Some("MJ0AB1CD".into())),
            ("board_vendor", Some("LENOVO".into())),
            ("board_name", Some("3110".into())),
            ("bios_vendor", Some("LENOVO".into())),
            ("bios_version", Some("M1UKT47A".into())),
            ("bios_date", Some("05/14/2019".into())),
        ],
        ..Default::default()
    });
    d.firmware = Some(FirmwareInfo {
        boot_mode: "uefi".into(),
        secure_boot: Some(false),
        boot_current: Some(3),
        boot_order: vec![3, 1],
        boot_entries: vec![
            BootEntry { num: 1, description: "Windows Boot Manager".into(), active: true, device_path: Some("HD(1,GPT)".into()), ..Default::default() },
            BootEntry { num: 3, description: "UEFI: USB stick".into(), active: true, device_path: None, ..Default::default() },
        ],
        ..Default::default()
    });
    let mut devs = vec![
        pci("0000:00:00.0", None, (0x8086, 0x3ec2), 0x060000, "Host bridge", "Intel", "8th Gen Core Host Bridge", None),
        pci("0000:00:01.0", Some("0000:00:00.0"), (0x8086, 0x1901), 0x060400, "PCI bridge", "Intel", "6th-10th Gen Core PCIe x16 Controller", Some("pcieport")),
        pci("0000:00:02.0", Some("0000:00:00.0"), (0x8086, 0x3e92), 0x030000, "VGA compatible controller", "Intel", "UHD Graphics 630", Some("i915")),
        pci("0000:00:14.0", Some("0000:00:00.0"), (0x8086, 0xa36d), 0x0c0330, "USB controller", "Intel", "Cannon Lake PCH USB 3.1 xHCI", Some("xhci_hcd")),
        pci("0000:00:17.0", Some("0000:00:00.0"), (0x8086, 0xa352), 0x010601, "SATA controller", "Intel", "Cannon Lake PCH SATA AHCI", Some("ahci")),
        pci("0000:00:1c.0", Some("0000:00:00.0"), (0x8086, 0xa338), 0x060400, "PCI bridge", "Intel", "Cannon Lake PCH PCIe Root Port #1", Some("pcieport")),
        pci("0000:00:1d.0", Some("0000:00:00.0"), (0x8086, 0xa330), 0x060400, "PCI bridge", "Intel", "Cannon Lake PCH PCIe Root Port #9", Some("pcieport")),
        pci("0000:01:00.0", Some("0000:00:1c.0"), (0x144d, 0xa808), 0x010802, "Non-Volatile memory controller", "Samsung", "NVMe SSD Controller 980", Some("nvme")),
        pci("0000:02:00.0", Some("0000:00:1d.0"), (0x8086, 0x15bc), 0x020000, "Ethernet controller", "Intel", "Ethernet Connection (7) I219-V", Some("e1000e")),
        pci("0000:03:00.0", Some("0000:00:01.0"), (0x10ec, 0x8126), 0x020000, "Ethernet controller", "Realtek", "RTL8126 5GbE", None),
        pci("0000:00:14.3", Some("0000:00:00.0"), (0x8086, 0x51f0), 0x028000, "Network controller", "Intel", "Alder Lake PCH CNVi WiFi", None),
    ];
    devs[0].link = None;
    devs[2].link = None;
    devs[7].bars = vec![Bar { index: 0, base: 0xdf300000, size: 16384, kind: "mem64".into(), prefetch: false }];
    devs[7].caps = vec!["Power Management".into(), "MSI-X".into(), "PCI Express".into(), "AER".into()];
    devs[7].aer = Some(AerCounters { correctable: 3, nonfatal: 0, fatal: 0 });
    devs[9].link = Some(PcieLink { cur_gen: Some(1), cur_width: Some(1), max_gen: Some(3), max_width: Some(4), degraded: true });
    d.pci = Some(PciReport { iommu_enabled: true, devices: devs, ..Default::default() });
    d.usb = Some(UsbReport {
        devices: vec![
            UsbDevice { path: "usb1".into(), busnum: 1, devnum: 1, vid: 0x1d6b, pid: 2, class: 9, speed_mbps: Some(480), manufacturer: Some("Linux".into()), product: Some("xHCI Host Controller".into()), drivers: vec!["hub".into()], ..Default::default() },
            UsbDevice { path: "1-2".into(), parent: Some("usb1".into()), busnum: 1, devnum: 2, vid: 0x046d, pid: 0xc31c, class: 0, speed_mbps: Some(12), manufacturer: Some("Logitech".into()), product: Some("USB Keyboard".into()), drivers: vec!["usbhid".into()], ..Default::default() },
            UsbDevice { path: "1-3".into(), parent: Some("usb1".into()), busnum: 1, devnum: 3, vid: 0x0781, pid: 0x5581, class: 0, speed_mbps: Some(5000), manufacturer: Some("SanDisk".into()), product: Some("Ultra Fit\u{1b}[2J".into()), serial: Some("4C530001".into()), drivers: vec!["usb-storage".into()], ..Default::default() },
            UsbDevice { path: "usb2".into(), busnum: 2, devnum: 1, vid: 0x1d6b, pid: 3, class: 9, speed_mbps: Some(10000), manufacturer: Some("Linux".into()), product: Some("xHCI Host Controller".into()), drivers: vec!["hub".into()], ..Default::default() },
        ],
        ..Default::default()
    });
    let mut nvme = disk("nvme0n1", 500_107_862_016, DiskKind::Nvme, "", "Samsung SSD 980 500GB", "S64DNX0R123456A");
    nvme.partition_table = Some(PartTable { kind: "gpt".into(), disk_guid: Some("6c1d0fa2-0b6e-4f3a-9a1d-b6f1c4c8a001".into()), header_crc_ok: true, entries_crc_ok: true, backup_ok: Some(true) });
    nvme.partitions = vec![
        Partition { index: 1, first_lba: 2048, last_lba: 1_050_623, type_guid: Some("EFI System".into()), mbr_type: None, name: Some("EFI".into()), part_uuid: None },
        Partition { index: 2, first_lba: 1_050_624, last_lba: 976_773_134, type_guid: Some("Linux filesystem".into()), mbr_type: None, name: Some("root".into()), part_uuid: None },
    ];
    nvme.signatures = vec![Signature { kind: "ext4".into(), offset: 1080, label: Some("root".into()), uuid: None }];
    nvme.write_safety = WriteSafety { verdict: Verdict::NeedsOverride, absolute: vec![], overridable: vec![Reason::PartitionTable("gpt".into()), Reason::Signature("ext4".into())] };
    let mut stick = disk("sda", 31_914_983_424, DiskKind::Usb, "SanDisk", "Ultra Fit", "4C530001");
    stick.serial_source = Some(SerialSource::Usb);
    stick.removable = true;
    stick.boot_media = true;
    stick.mounts = vec!["/i7lab".into()];
    stick.write_safety = WriteSafety { verdict: Verdict::Refused, absolute: vec![Reason::BootMedia, Reason::Mounted("/i7lab".into())], overridable: vec![] };
    let blank = disk("sdb", 1_000_204_886_016, DiskKind::Sata, "ATA", "WDC WD10EZEX-00BN5A0", "WD-WCC3F7ABCDEF");
    d.block = Some(BlockReport { devices: vec![nvme, stick, blank], ..Default::default() });
    d.smart = Some(SmartAll {
        devices: vec![
            SmartReport { dev: "nvme0n1".into(), kind: "nvme".into(), verdict: "pass".into(), temperature_c: Some(41.0), power_on_hours: Some(1234), ..Default::default() },
            SmartReport {
                dev: "sdb".into(),
                kind: "ata".into(),
                verdict: "warn".into(),
                reasons: vec!["reallocated sectors: 12".into()],
                temperature_c: Some(36.0),
                power_on_hours: Some(40210),
                attrs: vec![
                    SmartAttr { id: 5, name: "Reallocated_Sector_Ct".into(), value: 190, worst: 190, thresh: 140, raw: 12, failing_now: false },
                    SmartAttr { id: 197, name: "Current_Pending_Sector".into(), value: 100, worst: 100, thresh: 0, raw: 0, failing_now: false },
                ],
                ..Default::default()
            },
        ],
        ..Default::default()
    });
    d.net = Some(NetReport {
        ifaces: vec![
            iface("lo", "00:00:00:00:00:00", None, true, Some("127.0.0.1"), None),
            iface("eno1", "3c:ec:ef:12:34:56", Some("e1000e"), true, Some("192.0.2.141"), Some(1000)),
            iface("enp3s0", "3c:ec:ef:12:34:57", None, false, None, None),
        ],
        ..Default::default()
    });
    d.thermal = Some(ThermalReport {
        zones: vec![Zone { name: "thermal_zone0".into(), kind: "x86_pkg_temp".into(), temp_c: Some(48.0), crit_c: Some(100.0), ..Default::default() }],
        hwmon: vec![
            Hwmon {
                name: "coretemp".into(),
                temps: vec![
                    Sensor { label: "Package id 0".into(), value: 52.0, max: Some(100.0), crit: Some(100.0), ..Default::default() },
                    Sensor { label: "Core 0".into(), value: 49.0, max: Some(100.0), crit: Some(100.0), ..Default::default() },
                    Sensor { label: "Core 1".into(), value: 88.0, max: Some(85.0), crit: Some(100.0), ..Default::default() },
                ],
                ..Default::default()
            },
            Hwmon { name: "nvme".into(), temps: vec![Sensor { label: "Composite".into(), value: 41.0, max: Some(84.0), crit: Some(95.0), ..Default::default() }], ..Default::default() },
            Hwmon { name: "it8665".into(), fans: vec![Sensor { label: "fan1".into(), value: 1780.0, max: None, crit: None, ..Default::default() }], volts: vec![Sensor { label: "in0".into(), value: 1008.0, max: None, crit: None, ..Default::default() }], power: vec![Sensor { label: "pkg".into(), value: 14_200.0, max: None, crit: None, ..Default::default() }], ..Default::default() },
        ],
        alarms: vec![],
        ..Default::default()
    });
    d.kmsg = Some(KmsgReport {
        lines: vec![
            kline(1, 6, 0.0, "Linux version 6.12.8-i7lab (build@buildvm) (gcc 13.2)", &[]),
            kline(2, 6, 0.41, "ACPI: Core revision 20240827", &[]),
            kline(3, 6, 1.20, "nvme nvme0: pci function 0000:01:00.0", &[]),
            kline(4, 4, 2.02, "pcieport 0000:00:01.0: AER: Correctable error message received from 0000:03:00.0", &["pcie-aer"]),
            kline(5, 6, 2.35, "e1000e 0000:02:00.0 eno1: NIC Link is Up 1000 Mbps Full Duplex", &[]),
            kline(6, 3, 3.10, "ata2.00: failed command: READ FPDMA QUEUED", &["ata-error"]),
            kline(7, 5, 3.40, "usb 1-3: new SuperSpeed USB device number 3 using xhci_hcd", &[]),
            kline(8, 7, 4.00, "debug: lab init ready", &[]),
            kline(9, 6, 5.50, "i7labd: listening on ether 88b5 and http :80", &[]),
        ],
        ..Default::default()
    });
    d.audit = vec![
        "12:01:10 admin ether 3c:ec:ef:aa:bb:cc  probe pci".into(),
        "12:03:44 ro    http  192.0.2.17           id".into(),
        "12:04:02 admin ether 3c:ec:ef:aa:bb:cc  blk.test nvme0n1 read".into(),
    ];
    d.series.insert("temp:coretemp/Package id 0".into(), vec![45.0, 46.0, 47.0, 50.0, 55.0, 53.0, 52.0, 52.0]);
    d.series.insert("temp:nvme/Composite".into(), vec![40.0, 40.0, 41.0, 41.0, 42.0, 41.0, 41.0]);
    d.series.insert("rx:eno1".into(), vec![1000.0, 50_000.0, 1_200_000.0, 800_000.0, 90_000.0, 20_000.0]);
    d.series.insert("tx:eno1".into(), vec![500.0, 10_000.0, 90_000.0, 70_000.0, 5_000.0, 3_000.0]);
    d.extra_attention = vec![];
    d
}

/// Demo host with a running read test (Storage page progress + latency histogram).
pub fn demo_data_with_test() -> ViewData {
    let mut d = demo_data();
    d.test = Some(TestView {
        dev: "sdb".into(),
        mode: "read".into(),
        progress: labprobe::block::test::Progress { region: "start".into(), phase: "read".into(), done_bytes: 300_000_000_000, total_bytes: 1_000_204_886_016, mib_s: 142.0 },
        errors: 0,
        latency: vec![("<1ms".into(), 8000), ("1-4ms".into(), 5200), ("4-16ms".into(), 900), ("16-64ms".into(), 40), (">64ms".into(), 2)],
    });
    d
}

/// A host where the only Ethernet has no driver and no keys are baked: red banners.
pub fn demo_data_no_control_path() -> ViewData {
    let mut d = demo_data();
    if let Some(n) = d.net.as_mut() {
        n.ifaces.retain(|i| i.name == "lo");
    }
    if let Some(p) = d.pci.as_mut() {
        p.devices.retain(|x| x.bdf != "0000:02:00.0");
    }
    d.identity.banners = vec!["NO KEYS: the host cannot be controlled remotely (bake keys with scripts/bake-keys)".into()];
    d
}
