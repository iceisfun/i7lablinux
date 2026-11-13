# PROBES: what the lab image probes and exposes

> **Superseded by docs/PLAN.md (authoritative) on:** PLAN.md C4 (command names: no `probe <name>`/`disktest`), C7 + section 6 (gate rules, lock-first order, flags `--destructive --serial`), C8 (DHCP in i7labd, not init), C11 (no `I7LABBOOT`; boot media by cached PARTUUID only), C13 (no data partition in v0.1), section 6 serial resolution order. Read PLAN.md first; where this note disagrees, PLAN.md wins.


Status: design (R4). Owner crate: `labprobe` (library, std + libc FFI only), consumed by
`i7labd` (HTTP + L2 command frames), `i7labsh` (shell builtins), `labtui` pages and `i7labctl`.

## Principles

1. Read from `/sys`, `/proc`, `/dev`, `/sys/firmware`, `/sys/class/*` and ioctls. No external tools.
   Optional data helpers: `smartctl`, `nvme`, `ethtool`, `lspci` are NOT in the image. We use the
   kernel ioctls directly (ATA PASS-THROUGH, NVME_IOCTL_ADMIN_CMD, SIOCETHTOOL) and embedded data tables.
   If a future add-on ships one of them it is used only to cross-check, never required.
   No busybox anywhere: every applet is our own Rust (builtin of `i7labsh` or a tiny own binary).
2. Every probe is a pure function `fn probe(root: &Path) -> Result<T, ProbeError>` where `root` is
   the sysfs/procfs root. Unit tests point `root` at a fixture tree under `tests/fixtures/`.
   Parsers (`parse_*`) take `&str`/`&[u8]` and never touch the filesystem.
3. Output type is a plain struct with a hand-written `to_json()` (no serde). Same JSON feeds
   HTTP, L2 frames, TUI and `i7labctl`. Schema version field `"v":1` on every top-level object.
4. A probe never panics and never blocks forever: each file read has a 2 s budget (sysfs files
   on dying hardware can hang); slow probes run on worker threads with a deadline and report
   `{"error":"timeout"}` for that sub-tree only.
5. Read-only by default. Anything mutating is an "action" (see Actions) and gated.

## Probe registry

Each probe has a stable name, JSON path `/api/v1/probe/<name>`, shell command `probe <name>`,
and L2 command `probe <name>`.

| name       | source                                   | cost   |
|------------|------------------------------------------|--------|
| system     | /proc/version, uptime, loadavg, cmdline, hostname, boot id, `/proc/sys/kernel/*` | cheap |
| pci        | /sys/bus/pci/devices/*                    | cheap  |
| block      | /sys/block/*, /dev, /proc/mounts, ioctls  | medium |
| smart      | ATA/NVMe ioctls                           | medium |
| usb        | /sys/bus/usb/devices/*                    | cheap  |
| net        | /sys/class/net/*, SIOCETHTOOL             | cheap  |
| cpu        | /proc/cpuinfo, /sys/devices/system/cpu    | cheap  |
| mem        | /proc/meminfo, DMI type 17, edac          | cheap  |
| thermal    | /sys/class/thermal, hwmon, power_supply   | cheap  |
| dmi        | /sys/class/dmi/id, /sys/firmware/dmi/tables | cheap |
| acpi       | /sys/firmware/acpi/tables                 | cheap  |
| firmware   | /sys/firmware/efi, efivars                | cheap  |
| tpm        | /sys/class/tpm, /dev/tpmrm0               | cheap  |
| gpu        | /sys/class/drm, pci class 03xx            | cheap  |
| input      | /proc/bus/input/devices                   | cheap  |
| serial     | /proc/tty/driver/*, /sys/class/tty        | cheap  |
| ipmi       | /dev/ipmi*, DMI type 38, /sys/class/ipmi  | cheap  |
| dmesg      | /dev/kmsg                                 | cheap  |
| wol        | per NIC ethtool get-wol ioctl             | cheap  |
| inventory  | tags file on data partition               | cheap  |

`probe all` runs everything and returns one object; `probe all --brief` returns the Overview data.

## PCIe

Walk `/sys/bus/pci/devices/<domain:bus:dev.fn>`. Per device:

- `bdf`, `domain`, `bus`, `dev`, `fn`.
- `vendor`, `device`, `subsystem_vendor`, `subsystem_device`, `revision`, `class` (24-bit),
  `class_name` (from table: base/sub/prog-if), `vendor_name`, `device_name` from the embedded
  table (see below), fallback `"unknown"`.
- `driver`: basename of `driver` symlink, else `null`. `module` alias from `modalias`.
- `enabled`, `irq`, `numa_node`, `local_cpulist`, `d3cold_allowed`.
- Link: `current_link_speed`, `current_link_width`, `max_link_speed`, `max_link_width`
  from sysfs; a `degraded` boolean when current < max (speed or width). Convert "8.0 GT/s PCIe" to
  gen number (2.5=1, 5=2, 8=3, 16=4, 32=5, 64=6).
- BARs: parse `resource` (start end flags per line; first 6 = BARs, 6 = ROM, rest = bridge windows);
  report index, base, size, type (mem/io, 64-bit, prefetchable). Sizes computed, never by writing.
- Topology: parent from the sysfs path (`.../0000:00:1c.0/0000:03:00.0`), bridge secondary/subordinate
  bus (read config space bytes 0x19/0x1a), so the tree is rebuilt from the path alone.
- Config space: first 64 bytes from `config` (readable unprivileged), 256/4096 as root. Capability
  walk (standard list at 0x34, extended list at 0x100) listing cap id, offset, name (PM, MSI, MSI-X,
  PCIe, SR-IOV, ACS, AER, ATS, ...). Used for ASPM, AER, SR-IOV decode when sysfs lacks it.
- IOMMU: `iommu_group` symlink -> group number, and the other members of the group
  (`/sys/kernel/iommu_groups/N/devices`). Top-level `iommu_enabled` from
  `/sys/class/iommu` + cmdline.
- SR-IOV: `sriov_totalvfs`, `sriov_numvfs`, `sriov_offset`, `sriov_stride`, `physfn`/`virtfn*`.
- AER: `aer_dev_correctable`, `aer_dev_nonfatal`, `aer_dev_fatal` (per-error counters) when present;
  non-zero counters flagged.
- ASPM: `link/l0s_aspm`, `link/l1_aspm` if present, else decoded from PCIe LNKCTL (bits 0..1); also
  the global policy from `/sys/module/pcie_aspm/parameters/policy`.
- Power: `power_state` (D0..D3hot), `power/runtime_status`, `power/control`.
- Resizable BAR and ATS only listed as capabilities in v0.1.

Name table: `data/pci.ids.subset` generated at build time from the public pci-ids file filtered to
vendors/devices we have seen in the lab (plus all class codes). Format is the pci.ids text format;
`labprobe::pciids::lookup(vendor, device)` does a binary search over a pre-sorted binary blob
built by `build.rs`. Size target under 300 KB. The full file is a build option
(`--features full-pciids`, about 1.3 MB). Unknown devices print the numeric id, never fail.

`pci --tree` prints an indented tree; `pci --diff <json>` compares to a stored inventory (useful to
detect a dropped NIC or a link that trained at x1).

## Block devices

Enumerate `/sys/block/*` (skip `loop*`, `ram*`, `zram*`, `dm-*` unless `--all`). Per disk:

- `name`, `dev` major:minor, `size_sectors`, `size_bytes`, `logical_block_size`,
  `physical_block_size`, `optimal_io_size`, `alignment_offset`.
- `type`: nvme / sata / usb-storage / virtio / mmc / scsi / unknown, derived from the sysfs
  device path and driver, plus `transport` details (`/sys/block/X/device/*`).
- `model`, `vendor`, `serial`, `firmware_rev`, `wwid` / `eui` / `nguid` (nvme: `device/serial`,
  `device/model`, `device/firmware_rev`; SCSI/ATA: `device/model`, `device/vendor`, `device/rev`,
  serial via `ATA IDENTIFY` or `/sys/block/X/device/vpd_pg80`).
- `rotational`, `removable`, `read_only`, `discard_granularity`, `discard_max_bytes`,
  `write_zeroes_max_bytes`, `write_cache` mode, `queue/scheduler`, `nr_requests`,
  `zoned`, `hw_sector_size`.
- Partition table: read LBA0/1 directly: protective MBR + GPT header (verify CRCs, report disk GUID,
  partition entries with type GUID names, name, first/last LBA, attributes) or legacy MBR table.
  Flag `gpt_backup_ok` by reading the last LBA header.
- Filesystem signatures: probe the first MiB (and known offsets) for: ext2/3/4 (0x438 magic),
  xfs, btrfs (0x10040), f2fs, FAT12/16/32, exFAT, NTFS, ISO9660, squashfs, LUKS, LVM2 PV, swap,
  linux_raid_member, bcachefs, zfs_member. Also report UUID and label when the superblock has them.
  Pure Rust, table driven, with unit tests on synthetic superblocks.
- Mounted: parse `/proc/self/mountinfo`, map each mount source dev (major:minor) to the disk or partition.
  `in_use_by` also checks swap (`/proc/swaps`), md members (`/sys/block/X/holders`, `slaves`),
  device-mapper holders, and `O_EXCL` open attempt (read-only open with `O_EXCL` on a block device
  fails with EBUSY if claimed).
- `boot_media`: true if this disk (or its partition) provides `/` or the initramfs source
  (matched against the `i7lab.boot=` kernel arg written by the stick builder and the label
  `I7LABBOOT` on the data partition).

### SMART

- SATA/SAS: `SG_IO` ioctl with ATA PASS-THROUGH(16), `IDENTIFY DEVICE`, `SMART READ DATA`,
  `SMART READ THRESHOLDS`, `SMART RETURN STATUS`. Decode attributes with a small name table
  (id 5, 9, 12, 177, 187, 188, 190, 194, 196, 197, 198, 199, 231, 233, 241...), raw value, normalized
  value, threshold, failing-now flag. `power_on_hours`, `temperature`, `reallocated`, `pending`.
- NVMe: `NVME_IOCTL_ADMIN_CMD` with Identify Controller (CNS 1), Identify Namespace (CNS 0),
  Get Log Page 0x02 (SMART/Health): critical warning, composite temperature, available spare,
  percentage used, data units read/written, power cycles, power on hours, unsafe shutdowns, media
  errors, error log entries. Also Get Log Page 0x01 (error log) last 8 entries.
- USB bridges: try SAT pass-through; if it fails report `smart: "unsupported"` (never an error).
- Verdict field: `pass` / `warn` / `fail` / `unknown` with the reasons listed.

### Read/write/verify tests

Command: `disktest <dev> [--mode read|rw] [--pattern P] [--seed S] [--size N] [--region off:len]
[--bs 4k..4m] [--random|--seq] [--qd N] [--direct] [--duration SEC]`.

Patterns (`--pattern`):

- `zeros`, `ones` (0xFF), `aa55` (0xAA/0x55 alternating by sector), `walking1` / `walking0`
  (one bit rotating per byte), `counter` (u64 LE block counter).
- `seeded` (default for rw): position-dependent. For each 8-byte word at absolute byte offset `o`:
  `w = splitmix64(seed ^ (o / 8))`. Result depends on seed AND absolute position, so misdirected
  writes (data landing at the wrong LBA), stuck address lines, dropped writes and stale caches are
  all detected: a block read back from the wrong place does not match the pattern for the place it
  was read from. `seed` is printed in the report and may be supplied to reproduce.
- `random-fresh`: xoshiro256** keyed by seed, also position-addressable (counter mode), so verify
  does not need to store the data.

Modes:

- `read` (default, always allowed): sequential read of region, optional random 4 KiB reads;
  reports throughput (MB/s), IOPS, latency (min/mean/p50/p95/p99/p99.9/max, microseconds via
  `clock_gettime(CLOCK_MONOTONIC)`) per phase, and read errors (EIO with LBA, retries).
  `O_DIRECT` for the device path (aligned buffers via `posix_memalign`).
- `rw` (destructive): write pattern over the region, `fsync`/`BLKFLSBUF`, drop caches with
  `O_DIRECT` re-open, read back and compare; reports first N mismatching offsets, mismatch count,
  and a classification (single-bit, burst, misdirected = data matches pattern for another offset
  within the region). Phases: seq write, seq read-verify, random write (4k), random read-verify,
  mixed 70/30. Each phase reports throughput + latency percentiles.
- `rw-restore` (non-destructive on a live region, only when region is not mounted): read original
  block, write pattern, verify, write original back. Original saved in RAM per chunk (default 64 MiB
  chunks) so power loss mid-chunk can lose at most one chunk; documented as NOT crash-safe.
- Progress is a stream of JSON lines (`{"phase":..,"pct":..,"mbps":..}`); the TUI and HTTP clients
  show a live bar. Cancel via signal or `disktest-cancel <id>`.

### Safety gate (hard rule)

A write mode (`rw`, `rw-restore`, `wipe`, `clone` target, `secure-erase`) refuses unless ALL hold:

1. The device is not mounted, not swap, not an md/dm member, `O_EXCL` open succeeds.
2. The device does NOT hold the boot media (`i7lab.boot` match, label `I7LABBOOT`, or it backs the
   running rootfs/initramfs source). This refusal can never be overridden.
3. The device has no partition table, no recognised filesystem signature and no RAID/LVM/LUKS
   signature, OR the caller passes the explicit destructive flag for a device that does.
4. For case 3-with-override: the caller passes BOTH `--i-understand-this-destroys-data` AND
   `--serial <exact serial of the device as probed>`. The serial is compared to the probe value; a
   mismatch aborts with no write. Devices without a serial refuse the override (use the wwid).
5. Region writes are restricted to `--region` if given; the default is the entire device only for
   case 3 (empty disks). A device with a table writes only inside an explicit region that the
   caller names, never by default.

Every write action is logged to the audit log (who: key id or ip/mac, what, device, serial, when).
Defaults are always read-only. The L2 and HTTP layers have no way to skip the gate: the check is
inside `labprobe::block::WriteGuard::acquire(dev, opts)`, the only way to obtain a writable `File`.

## USB

Walk `/sys/bus/usb/devices`: bus, port path (`1-2.3`), `idVendor/idProduct` + names (usb.ids subset),
`manufacturer`, `product`, `serial`, `speed` (1.5/12/480/5000/10000/20000), `bDeviceClass`,
interfaces + drivers, `bMaxPower`, `removable`, `authorized`, hub topology, runtime-PM status.
Controllers (xHCI/EHCI) appear as PCI devices; the tree links them. Storage devices
cross-reference to `block`. Detect low speed of a SuperSpeed device (cable problem).

## NICs

Per interface in `/sys/class/net` (skip `lo`, `veth*` unless `--all`):

- `name`, `mac`, `perm_addr` (ethtool permanent address ioctl), `mtu`, `operstate`, `carrier`,
  `carrier_changes`, `link_speed`, `duplex`, `autoneg`, `driver`, `bus_info` (pci bdf, usb path),
  `firmware_version` (`ETHTOOL_GDRVINFO`), `supported/advertised/lp_advertising` link modes
  (`ETHTOOL_GLINKSETTINGS`), `wol` supported/enabled, `pause`, ring sizes, channels, offloads
  (`ETHTOOL_GFEATURES`).
- Counters: all of `/sys/class/net/X/statistics/*` plus `ETHTOOL_GSTATS` (driver-specific; names via
  `ETHTOOL_GSSET_INFO` + `GSTRINGS`). Rates computed between two samples (`net --watch`).
- IP state: addresses and routes via rtnetlink (`NETLINK_ROUTE` RTM_GETADDR/RTM_GETROUTE), written
  in Rust with raw `socket(AF_NETLINK)`; no `ip` binary. VLAN, bond, bridge interfaces listed.
- Cable/transceiver: `ETHTOOL_GMODULEINFO`/`GMODULEEEPROM` decode of SFP (vendor, part, serial,
  wavelength, DOM temperature and optical power) when supported.
- LLDP/CDP optional: `lldp` raw `AF_PACKET` listener on ethertype 0x88CC (and CDP multicast
  01:00:0c:cc:cc:cc) for 35 s; decode chassis id, port id, system name, VLAN, management address.
  Also optional LLDP transmit so the switch lists the host.
- Link test: `net --linktest <if>` toggles nothing by default; reports carrier changes over N
  seconds (flap detector).
- Wake-on-LAN: `wol <if> [--set g]` via `ETHTOOL_GWOL/SWOL`. Setting is an action. The setting
  does not persist across power cycles on many NICs, so the stick records the intent and re-applies
  at boot (`wol` key in `/data/lab.conf`).

## CPU

`/proc/cpuinfo` and `/sys/devices/system/cpu`: model name, vendor, family/model/stepping, microcode
revision, flags (as a sorted list plus a decoded feature summary: avx2, avx512*, aes, sha, vmx/svm,
smep/smap, pae, 1gb pages), logical/physical cores, sockets, threads per core (topology:
`topology/{physical_package_id,core_id,thread_siblings_list}`), caches
(`cache/index*/{level,type,size}`), frequencies (`cpufreq/scaling_cur_freq`, min/max, governor,
`intel_pstate` status), NUMA nodes, vulnerabilities (`/sys/devices/system/cpu/vulnerabilities/*`),
offline CPUs, C-state usage (`cpuidle`). A `cpu --burn <sec> [--threads N]` stress test (integer +
float + memory loops) records the temperature and frequency curve to catch throttling.

## Memory

- `/proc/meminfo`, NUMA via `/sys/devices/system/node`, hugepages.
- DMI type 17 (parse `/sys/firmware/dmi/tables/DMI`): per DIMM locator, bank, size, speed, configured
  speed, type (DDR4/5), form factor, manufacturer, part number, serial, rank, voltage, total/data
  width (ECC = total > data). DMI type 16 array: max capacity, ECC type. Empty slots listed.
- ECC / EDAC: `/sys/devices/system/edac/mc/mc*/{ce_count,ue_count,csrow*,dimm*}`, plus
  `rasdaemon`-less polling of MCE counters from `/sys/devices/system/machinecheck`. Non-zero
  UE or growing CE flagged.
- `memtest` mode (`memtest --size 80% --passes N --patterns walking,addr,random`): user-space test:
  `mlock`ed anonymous region, patterns: walking ones/zeros, address-as-data, moving inversions,
  seeded random (same position-dependent generator as disktest). Reports failing virtual addresses
  and, using `/proc/self/pagemap` (root), the physical address, which maps to a DIMM via the DMI
  address ranges (types 19/20). User-space cannot reach memory used by the kernel, so the doc says
  so; a `memtest=boot` option reserves a large region on the kernel cmdline (`memmap=`) for a full
  run. A separate boot-time-only option can chain-load an external memtest binary (not part of v0.x).

## Thermal, hwmon, fans, power, battery

- `/sys/class/thermal/thermal_zone*/{type,temp}`, trip points, cooling devices (fans with state).
- `/sys/class/hwmon/hwmon*/`: `name`, `temp*_input/label/max/crit`, `fan*_input`, `in*_input`
  (voltages), `power*_input`, `curr*_input`, `pwm*`. Drivers: coretemp, k10temp, nct67xx, it87,
  nvme, drivetemp, amdgpu, acpitz, iwlwifi. Kernel config has these enabled (see kernel config in
  the build doc).
- RAPL (`/sys/class/powercap/intel-rapl*`) package and DRAM energy -> average watts over a sample.
- Battery / AC: `/sys/class/power_supply/*` (status, capacity, voltage_now, current_now, energy_*,
  cycle_count, technology, manufacturer, serial).
- Alarm flags: anything over `crit`, any fan reading 0 where a fan label exists.
- `sensors --watch` samples at 1 Hz and keeps a 10 minute ring buffer in RAM for sparkline graphs.

## DMI / SMBIOS / ACPI

- `/sys/class/dmi/id/*`: bios vendor/version/date, system manufacturer/product/version/serial/uuid/sku,
  board vendor/name/serial, chassis type/serial/asset tag.
- Full decode of `/sys/firmware/dmi/tables/{DMI,smbios_entry_point}` for types 0,1,2,3,4,7,9,11,16,17,
  19,22,38,41,43 (BIOS, system, board, chassis, processor, cache, slots, OEM strings, memory, battery,
  IPMI, onboard devices, TPM) with raw hex available.
- ACPI: list `/sys/firmware/acpi/tables/*` with signature, length, OEM id, revision;
  `acpi dump <sig>` returns raw bytes (hex/base64, for diffing). DSDT/SSDT blobs are listed, not
  decompiled. `FACP` sleep states (`/sys/power/state`, `mem_sleep`), `MCFG`, `DMAR`/`IVRS`, `BGRT`,
  `TPM2`, `HPET`, `SPCR` (serial console redirection table, used by the console probe).

## Firmware / UEFI / Secure Boot

- `boot_mode`: `/sys/firmware/efi` exists -> UEFI, else legacy BIOS; platform bitness
  (`firmware/efi/fw_platform_size`).
- Mount `efivarfs` read-only by default. Parse: `SecureBoot`, `SetupMode`, `AuditMode`,
  `DeployedMode`, `BootCurrent`, `BootOrder`, `Boot####` entries (load option decode: description,
  device path, optional data), `BootNext`, `Timeout`, `OsIndications(Supported)`, `PK`/`KEK`/`db`/`dbx`
  (list signature owners and counts, SHA-256 of each cert, not the whole blob), `MokList` if shim.
- Secure Boot summary: enabled, setup mode, custom keys present. This is what the lab operator needs
  when deciding if an unsigned lab kernel will boot. The i7lablinux kernel is shipped signed only if
  Secure Boot keys are enrolled (see ROADMAP.md; v0.x assumes Secure Boot off or MOK enrolled).
- Writes (BootNext, BootOrder, delete entry) are actions: see "Boot control".
- `firmware` also reports BMC/ME presence hints: Intel ME/MEI device (`/sys/class/mei`), AMD PSP.

## TPM

`/sys/class/tpm/tpm*/{tpm_version_major,pcr-sha256/*,caps}`; `/dev/tpmrm0`. Raw TPM2 commands in Rust:
`TPM2_GetCapability` (manufacturer, firmware version, algorithms), `TPM2_PCR_Read` for PCRs 0-7
and 11-14, event log decode from `/sys/kernel/security/tpm0/binary_bios_measurements`. Read-only.
No ownership or clearing in v0.x.

## GPUs

`/sys/class/drm/card*` + PCI class 0x03: vendor, driver (i915/amdgpu/nouveau/simpledrm/efifb),
connectors (`status`, `enabled`, `modes`, EDID decoded: manufacturer, model, serial, native mode,
physical size), VRAM (`mem_info_vram_total` amdgpu), `gpu_busy_percent`, clocks, hwmon temp and fan.
Framebuffer: `/sys/class/graphics/fb0/{virtual_size,bits_per_pixel,name}` (used by TUI layout).
NVIDIA proprietary is not shipped; `nouveau` appears where present, otherwise only the PCI entry.

## Input devices

`/proc/bus/input/devices` (name, bus, vendor/product, handlers, capabilities EV/KEY/REL/ABS/LED).
`input --events <dev>` reads `/dev/input/event*` (struct input_event), prints key/pointer events for
10 s so a remote operator can verify a keyboard works. Keyboard layout is US only (scancode set
via the kernel keymap) in v0.x.

## Serial ports

- 8250/16550 ports: `/proc/tty/driver/serial` (irq, tx/rx counts, errors), `/sys/class/tty/ttyS*`
  (`port`, `irq`, `uartclk`, `type`). Only ports with a non-zero `type` exist.
- USB serial: `ttyUSB*`, `ttyACM*` with the usb parent path (FTDI, CP210x, CH34x, PL2303, cdc-acm).
- `serial --loopback <tty>` and `serial --echo <tty> --baud N` primitives (termios via libc).
- Console redirection: see "Serial console redirection" below.

## Kernel log

`/dev/kmsg` reader (structured: seq, facility, level, timestamp, message), follow mode (poll).
Ring-buffer snapshot at boot copied to `/run/lab/dmesg.boot`. Filters: level, regex-free substring,
since seq. Built-in classifier tags lines: `pcie-aer`, `mce`, `ata-error`, `nvme-timeout`,
`usb-disconnect`, `thermal-trip`, `oom`, `firmware-bug`, `link-flap`. Tags feed the Overview page
"attention" counter.

## Wake-on-LAN

See NICs. Also: the lab image sends magic packets: `wake <mac> [--via <if>] [--ip bcast]` (UDP 9 and
raw ethertype 0x0842 on L2), so one lab host can power on its neighbours.

## Additional capabilities the operator did not list

Each item says what it is, how, and the first version it lands in (see ROADMAP.md).

1. **Serial console redirection.** Kernel cmdline `console=tty0 console=ttyS0,115200n8` is written
   by the stick builder for hosts where SPCR (ACPI) shows a serial port; `i7labd` gets an
   `console` setting that switches which console the TUI binds to (`/dev/tty0`, `/dev/ttyS0`,
   `/dev/ttyUSB0`). A serial TUI uses the 80x25 layout and ASCII-only frames. Also exposes the
   console over L2 (`attach-console`, a byte stream in command frames) so a remote operator
   sees exactly what the local screen shows. (v0.3)
2. **IPMI / BMC detection and SOL.** DMI type 38, `/dev/ipmi0` / `/dev/ipmidev/0` (kernel
   `ipmi_si`, `ipmi_devintf`), `IPMICTL_SEND_COMMAND` ioctl in Rust: Get Device ID, Get Chassis
   Status, LAN config (Get LAN Config Parameters) so we report the BMC IP/MAC, SEL entries, SDR
   sensors, power state. Also scan for a BMC on the network: ARP/UDP 623 RMCP Presence Ping to the BMC
   address. SOL is the host acting as a *client*: `sol <bmc-ip>` speaks IPMI 2.0 RMCP+ over UDP (cipher
   suite 17) to expose another host's serial console through our own TUI. Credentials come from the
   inventory/secret store, never the command line. (v0.5)
3. **Power control via PDU is NOT here.** The lab PDU/JetKVM remains hwlabd's job. We only expose
   the data needed to prove a host rebooted (boot id, uptime) and a `reboot`/`poweroff` action.
4. **Reboot into another OS.** `boot next <entry|name>` writes `BootNext` via efivarfs (UEFI) and
   reboots; `boot order`, `boot list`, `boot delete <id>` (gated). For hosts with the kernel but no
   firmware menu: `kexec` (a static `kexec_load` file-based `kexec_file_load` Rust call) to load a
   kernel+initrd from a block device or from a file received over L2/HTTP (`boot kexec --kernel K
   --initrd I --cmdline C`). "One-time boot next" (UEFI BootNext) is the supported
   remote-handover mechanism: our stick does the work, then the host returns to the installed OS
   with one command and no changes to the permanent boot order. BIOS hosts: fall back to
   writing the boot sector of a flagged disk is NOT done; the documented path is kexec. (v0.4)
5. **Disk wipe and secure erase.** `wipe <dev> --mode zero|random|signature|discard`: signature mode
   clears first/last MiB (partition tables, FS signatures, RAID/LVM metadata); discard mode uses
   `BLKDISCARD`/`BLKSECDISCARD`; `secure-erase` uses ATA SECURITY ERASE UNIT (frozen state check, set a
   temporary password, issue, report) and NVMe Format NVM (SES=1 crypto erase when supported), or
   `sanitize` command. All behind the safety gate and a two-step confirmation token that the first call returns
   and the second call must echo (`--confirm <token>`). Result logged and attached to the inventory.
   (v0.6)
6. **Disk clone / image to ssh.** `image read <dev> --to tcp://host:port` and `image write`. We do not
   ship ssh (no dropbear, no busybox); instead a lab-native streaming protocol on TCP: a framed,
   HMAC-authenticated stream with SHA-256 per 1 MiB chunk and optional zstd-free run-length of zero
   blocks (sparse skipping). The receiving side is `i7labctl image-recv` on the operator machine.
   Use for "read the whole drive before touching it" and for imaging a drive onto the stick data
   partition. Optional `--via-ssh` is not implemented; the doc points to `i7labctl` as the supported
   path. (v0.6)
7. **Network speed test (iperf-like).** `nettest server [--port]`, `nettest client <ip> --time 10
   --streams N --udp --rate R`, plus an L2 mode (`nettest l2 <mac>` blasts own-ethertype frames and
   reports loss and rate). Also `ping`, `arping`, `traceroute` as raw-socket builtins (ICMP raw,
   `AF_PACKET`). (v0.4)
8. **Packet capture.** `capture <if> [--filter eth,arp,ip,udp,port N] [--count N] [--pcap file|-]`
   from `AF_PACKET` + a tiny BPF-free software filter (the kernel BPF `SO_ATTACH_FILTER` for the common
   cases by generating classic BPF in Rust). Writes pcap; `i7labctl capture` streams it for Wireshark
   (`-w -`). (v0.5)
9. **DHCP / PXE probing.** `dhcp discover <if>` sends DHCPDISCOVER (raw packet, no lease taken) and
   lists every offer: server id, offered IP, router, DNS, lease, next-server and boot file (option 66/67,
   PXE vendor options 43/60/93 arch) so the operator can see which PXE server answers on a VLAN and
   whether it is a rogue server. Also `dhcp lease <if>` to actually configure the NIC; the built-in
   DHCP client is part of `i7lab-init`. `pxe-probe` also fetches the first TFTP block of the boot file
   to confirm the server really serves it. (v0.4)
10. **Time sync.** A minimal SNTP client (UDP 123) in `i7lab-init`; step the clock when offset > 1 s,
    log offset. Sources: DHCP option 42, configured server, or the L2 command channel (a controller
    can set the time with `time set`, signed). Writes the RTC (`/dev/rtc0` `RTC_SET_TIME`) on request.
    Reports RTC vs system vs NTP delta, which finds dead CMOS batteries. (v0.3)
11. **Remote file manager.** `fs ls|stat|cat|get|put|rm|mkdir|mv|hash <path>`, `mount <dev> <dir> [ro]`,
    `umount`. Read-only mounts by default (`ro`, `noexec`, `nodev`); `rw` needs the same destructive
    flag as the safety gate when the target is not the data partition. Filesystems: whatever the kernel
    build enables (ext4, xfs, btrfs, vfat, exfat, ntfs3 read-only default, iso9660, squashfs). `get/put`
    are chunked with SHA-256 verify. No sandbox escape: path normalisation happens in labprobe, but
    since the operator owns the host that is convenience not a security boundary. (v0.4)
12. **Log shipping.** `logship <udp|tcp>://host:port` forwards `/dev/kmsg` plus audit log as RFC 5424
    syslog lines, plus an optional "ship to the controller over L2" mode; local buffering in the data
    partition ring (`/data/log/*.ring`, 8 MiB) so logs survive a host that panics. `i7labctl logs --follow`. (v0.4)
13. **Watchdog.** If `/dev/watchdog` exists (iTCO_wdt, sp5100_tco, softdog), `i7lab-init` arms it
    (timeout 120 s default) and pets it from the main loop, so a wedged lab image reboots into the
    stick again instead of hanging. `watchdog test` deliberately stops petting (gated) to verify the
    hardware watchdog works. Disable with `i7lab.watchdog=0` for long destructive tests. (v0.3)
14. **Persistent notes and inventory tags.** A small data partition (label `I7LABDATA`, ext4 or FAT32
    on the stick, 512 MiB) stores `/data/inventory.json` (asset tag, rack/location, owner, free-form
    notes, per-host history), the audit log, saved test results and settings (`lab.conf`).
    `inventory set tag=value`, `inventory note "text"`, `inventory show`, `inventory export`. When
    the stick moves between hosts the inventory is keyed by the DMI system UUID + serial so a host
    recognises itself; `i7labctl discover` shows the tags in the listing. (v0.2)
15. **Update of the stick itself over the net.** `update check|fetch|apply`: the stick has two image
    slots (A/B kernel+initramfs squashfs on the boot partition); `update fetch <url|l2>` downloads
    a manifest + payload, verifies a signature (Ed25519 verify implemented in `labcrypto`, public key baked in),
    writes the inactive slot, flips `boot.cfg` next-slot with a try counter and reverts to the old slot
    if the new one does not report healthy within 3 boots. Controller push: `i7labctl update --ether <mac> file`
    (L2 chunked transfer). (v0.7)
16. **Hardware stress profile.** `stress --profile quick|burnin --duration 1h`: cpu burn + memtest +
    disk read/rw on empty disks + NIC loopback/l2 test, with a pass/fail summary and a report saved to
    inventory. This is the "is this machine good" button for incoming hardware. (v0.6)
17. **Report bundle.** `report [--all]` creates one tar-like archive (own simple format or plain
    `ustar`, written by us) with all probe JSON, dmesg, DMI raw, ACPI raw, PCI config space, SMART, audit
    log, and `report.html` (self-contained, uses the same SPA renderer) for attaching to a bug or a
    ticket. (v0.3)
18. **Console screenshot.** `screenshot` reads `/dev/fb0` and returns PNG (own minimal zlib "stored"
    deflate writer, no compression library) so an operator can see the real display without a
    JetKVM; text console contents are also available from `/dev/vcsa*` as an ANSI dump. (v0.5)
19. **Power-state and sleep test.** `sleep test s2idle|mem [--wake rtc:30]` using `/sys/power/state`
    and an RTC wakealarm; reports whether the host came back and dmesg diffs. Useful for the lab's
    "sleep states" hardware. (v0.7)
20. **DCI / debug-port detection.** Report whether USB debug (DbC) capability is on xHCI
    (`xhci` extended cap id 10), and kernel debug cmdline options. Information only. (v0.7)
21. **PCI hotplug and rescan.** `pci rescan`, `pci remove <bdf>` (gated) for hosts with flaky hot-plug
    slots; `pci reset <bdf>` uses FLR/secondary bus reset via sysfs `reset`. (v0.6)
22. **vfio-readiness check.** For passthrough rigs: per device report IOMMU group isolation, ACS, whether
    the group contains only that device, bound driver, reset method (`reset_method`). (v0.6)
23. **Netboot of other targets.** Run `tftp`/`dhcp-proxy` services from the stick so it can boot
    neighbours. Not in scope before v0.9; the framed protocol leaves room.
24. **Self-test and health of the image.** `selftest` verifies the running image against the baked
    manifest (SHA-256 of init, shell, daemons and kernel module list) and the signature on the
    initramfs; detects a tampered or damaged USB stick. (v0.3)

## Actions and confirmations (cross-cutting)

Action = anything that changes the machine or media. All actions go through one `labproto::action`
type: `{name, args, confirm_token?, actor, source}`. Policy:

- Class R (read): no confirmation.
- Class M (mutate reversibly: set WoL, set hostname, mount ro, set time): no token, audit logged.
- Class D (destructive or availability-affecting: write tests, wipe, secure erase, image write,
  reboot, poweroff, kexec, boot order changes, pci remove): first call returns `{"confirm":"<token>",
  "expires":30,"summary":"will erase /dev/sdb (serial XYZ, 1.0 TB)"}`; the second call must carry the token
  and the same arguments. Tokens are single-use, bound to the actor and to a hash of the arguments.
  The TUI shows the same summary in a confirmation dialog; `i7labctl` prompts or accepts
  `--yes` after printing the summary. Disk safety gate rules (above) are additional.

## Testing strategy

- Fixture trees (captured from real lab hosts via `i7labctl report`, scrubbed of serials) under
  `crates/labprobe/tests/fixtures/<host>/` so that every probe has a deterministic golden JSON test.
- Synthetic images for block parsers: tiny generated GPT/MBR/ext4/FAT/LUKS superblocks built in the
  test code, no binary blobs checked in.
- disktest runs against a regular file (`/tmp/x.img`) and a loop device in the QEMU test (the build host).
  A mismatch injector wrapper (flip one bit, redirect one block) proves verify detects bit flips and
  misdirected writes.
- QEMU smoke (the build host, at most 2 guests): boot image with virtio-blk, nvme, e1000e, usb-storage and an
  ICH9 + iTCO watchdog; assert `probe all` JSON validity and that `disktest rw` on the empty virtio
  disk passes and on the boot disk refuses.
