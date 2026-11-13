# Recon R2: kernel and toolchain for i7lablinux

Measured on the build host (Ubuntu 26.04.1, host kernel 7.0.0-38, 128 cores, 995 GB RAM, /tmp tmpfs 498G),
2026-11-12. No busybox anywhere: all userland is our own Rust (i7lab-init, i7labsh builtins, i7labd, i7labctl).

## Findings on the build host

| Item | State |
|---|---|
| cdn.kernel.org | reachable (HTTP 200); tarball + sha256sums.asc fetchable |
| kernel.org latest stable | 7.3.4 (7.2.15 is EOL); mainline 7.4-rc2 |
| Longterm | 6.18.63, 6.12.117, 6.6.162, 6.1.192, 5.15.225, 5.10.274 |
| gcc 15.2, make, bc, cpio, xz, zstd, perl | present |
| flex, bison, libelf-dev, libssl-dev | were missing, installed by us |
| xorriso, mkfs.vfat, sgdisk, parted, grub-install, grub-mkimage | present; grub i386-pc + x86_64-efi modules were missing (only efi-signed), installed |
| mtools (mcopy), syslinux, extlinux, musl-tools | were missing, installed |
| limine, systemd-boot (bootctl) | not installed, not needed |
| `sudo -n true` | works (passwordless sudo); apt install permitted |
| rust | no rustup/cargo at start; installed apt `rustup` then `rustup default stable` = rustc/cargo 1.99.1, target x86_64-unknown-linux-musl added fine (static std, rust-lld self-contained; musl-gcc NOT required for pure-Rust std+libc FFI crates, musl-tools was installed anyway as a harmless fallback for any C build script) |
| static.rust-lang.org | reachable |

## Exact prerequisites (the build host and any Ubuntu build host)

```
sudo apt-get install -y build-essential flex bison bc cpio xz-utils zstd libelf-dev libssl-dev \
  xorriso dosfstools mtools gdisk parted rsync \
  grub-pc-bin grub-efi-amd64-bin grub-common \
  musl-tools rustup
rustup default stable
rustup target add x86_64-unknown-linux-musl
```
Optional: `syslinux syslinux-common extlinux` (only if the BIOS bootloader choice below is revisited),
`qemu-system-x86 ovmf` for boot tests. Installed on the build host and left in place (apt packages + ~/.rustup, no large files in /tmp).

## Kernel version recommendation

**Linux 6.18 LTS (6.18.63 today)**, tarball
`https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.63.tar.xz`
(sha256 81764a545072d160748beff4d9de2e7d95aa9f16e8261110288f067a2cc61d71, from sha256sums.asc; verify the
signature with the kernel.org key in the build script, pin version + hash in `kernel/VERSION`).

Why: it is "modern" (late 2025 release, supports current NIC/NVMe/xHCI/Wi-Fi hardware including Intel
igc/Alder-Lake+ platforms, RTL8126/8125 in r8169), but a long-term branch, so point releases keep coming
with security fixes while the config stays stable. 7.3.x stable is newer, but stable branches go EOL in
~3 months (7.2 is already EOL), which would force churn in a lab image that should rarely change.
Policy: track the newest LTS; bump to the next LTS when it has had a few point releases or when new hardware
requires it. The host running the operator machine already boots 6.18 (lak-p2), so 6.18 is known-good with this lab.
Build is pinned to an exact version + hash, never "latest".

## Driver set (built in `=y` unless noted; modules only where firmware or size argues for it)

Initramfs-only rootfs, so everything needed to boot and reach the network is built in; no modules needed for
the core. Wi-Fi and exotic gear are modules loaded by i7lab-init from `/lib/modules` in the initramfs.

- Core: 64BIT, SMP, MAXSMP/NR_CPUS=512, ACPI, PCI, PCIEPORTBUS+AER, PCI_MSI, IOMMU (INTEL_IOMMU, AMD_IOMMU,
  default passthrough off), DMI/DMIID, EFI + EFI_STUB + EFI_VARS (efivarfs), RTC, HPET, KEXEC, PRINTK, TTY,
  DEVTMPFS(+MOUNT), PROC_FS, SYSFS, BINFMT_ELF/SCRIPT, CGROUPS minimal, MAGIC_SYSRQ, PANIC_TIMEOUT=10,
  RD_ZSTD/RD_XZ, BLK_DEV_INITRD, CRYPTO + AF_ALG-free (our own crypto in userspace).
- NICs (y): E1000, E1000E, IGB, IGC, IXGBE, IXGBEVF off, R8169 (+REALTEK_PHY), TG3, BNX2, BNX2X (m), BNXT, E100? no,
  VIRTIO_NET, VMXNET3, USB: USB_RTL8152, USB_NET_AX88179_178A, USB_NET_CDCETHER, USB_NET_CDC_NCM, USB_NET_CDC_EEM,
  USB_USBNET, MLX4/MLX5 (m), I40E, ICE (m), NET_VENDOR_* enabled for the above only (others off to cut size).
  Firmware: bnx2/bnx2x/tg3/rtl_nic firmware blobs go in `initramfs/lib/firmware` (see firmware list).
- Networking: INET, IPV6, VLAN_8021Q, BRIDGE, TUN, VETH, PACKET (required: AF_PACKET for our own-ethertype
  command frames), NETFILTER off, BONDING (m), DUMMY, NET_SCHED off.
- Storage: BLK_DEV_NVME (+NVME_CORE), SATA_AHCI, ATA_PIIX, ATA generic/legacy PATA (ATA_SFF, PATA_*), SCSI, BLK_DEV_SD,
  BLK_DEV_SR, CHR_DEV_SG (SMART/ATA passthrough via SG_IO), USB_STORAGE, USB_UAS, VIRTIO_BLK, VIRTIO_SCSI, MEGARAID_SAS /
  MPT3SAS / SCSI_HPSA (m, common server HBAs), MMC + MMC_SDHCI_PCI (y), BLK_DEV_LOOP, DM off, MD off.
  SG/BSG for SMART; NVME_HWMON for NVMe temperature.
- USB: USB, USB_XHCI_HCD (+PCI), USB_EHCI_HCD (+PCI), USB_OHCI_HCD, USB_UHCI_HCD, USB_HID, HID_GENERIC, USB_KBD via
  HID, USB_SERIAL + FTDI_SIO, CP210X, CH341, PL2303, USB_ACM (cdc_acm), USB_TYPEC off, USB_DEBUG off.
- Serial/console: SERIAL_8250 (+CONSOLE, PCI, NR_UARTS=8), VT, VT_CONSOLE, FRAMEBUFFER_CONSOLE, FB, FB_EFI (efifb),
  SYSFB_SIMPLEFB, DRM + DRM_SIMPLEDRM (kernel needs DRM_FBDEV_EMULATION), FB_VESA for BIOS boot, console on both
  tty0 and ttyS0 (command line `console=tty0 console=ttyS0,115200n8`). No GPU drivers (amdgpu/i915/nvidia are NOT
  wanted; the machine is probed, not used for graphics) but DRM_I915/DRM_AMDGPU can be offered as an optional
  fragment if native-resolution console is wanted.
- Input: INPUT_KEYBOARD, ATKBD, I8042 (+SERIO), INPUT_EVDEV (TUI reads keys from the tty; evdev optional).
- Filesystems: EXT4, VFAT (+NLS_CODEPAGE_437, NLS_ISO8859_1), ISO9660 (+JOLIET), SQUASHFS (+ZSTD/XZ), OVERLAY_FS,
  TMPFS, DEVTMPFS, PROC, SYSFS, CONFIGFS, EFIVAR_FS, NTFS3 (m, read inspection), XFS/BTRFS (m, inspection only), FUSE off.
- Thermal/hwmon/sensors: HWMON, THERMAL, X86_PKG_TEMP_THERMAL, SENSORS_CORETEMP, SENSORS_K10TEMP, SENSORS_NVME? via
  NVME_HWMON, SENSORS_DRIVETEMP, SENSORS_IT87/NCT6775 (m), ACPI_THERMAL, ACPI_FAN, CPU_FREQ stats, INTEL_RAPL,
  X86_MSR + X86_CPUID (y: probe via /dev/cpu/*/msr), EDAC (+EDAC_*), IPMI_HANDLER + IPMI_SI + IPMI_DEVICE_INTERFACE (y,
  BMC probing), DMI_SYSFS, WATCHDOG (+ softdog, iTCO_wdt), LEDS off.
- Memory/CPU probing: MEMORY_HOTPLUG off, /dev/mem with STRICT_DEVMEM off for lab (explicit), DEVMEM y, IO_URING off,
  RANDOM_TRUST_CPU, HW_RANDOM, MICROCODE (+ INTEL/AMD, builtin firmware from `/lib/firmware`).
- Wi-Fi (modules, optional fragment `wifi.config`): CFG80211, MAC80211, IWLWIFI+IWLMVM+IWLDVM, RTW88 (8821CE/8822BE...),
  RTW89, RTL8XXXU, RTL8821AU stays out of tree (not planned), ATH9K/ATH10K/ATH11K, MT76 (m), BT off. Firmware list below.
- Off (size/attack surface): sound, GPU 3D, KVM host, virtualisation guests other than virtio/vmxnet3/hyperv-net if the lab
  hosts need them, wireless extensions, NFS, SELinux/AppArmor, audit, modules signing, debug info, kprobes/ftrace except
  what a panic needs. DEBUG_INFO_NONE. `CONFIG_MODULES=y` with MODULE_COMPRESS_ZSTD so the Wi-Fi/extra modules stay small.

### Firmware list (copy from `linux-firmware`, pin a snapshot hash in the build script)
`i915/` and `amdgpu/` skipped. Needed: `rtl_nic/*` (r8169, r8168h/8125/8126), `rtw88/*`, `rtw89/*`, `rtlwifi/*`, `rtl_bt` skip,
`iwlwifi-*` (cc-a0, so-a0, ty-a0, 9260, 8265, 7265D, QuZ, ma), `bnx2/*`, `bnx2x/*`, `tigon/*` (tg3 TSO), `intel/ice/*` (optional),
`e100` none, `ath10k/QCA6174`, `ath11k`, `mediatek/mt76*`, `intel-ucode/*` + `amd-ucode/*` (CPU microcode).
Total ~100-150 MB uncompressed; ship zstd-compressed, load Wi-Fi/rare-NIC firmware only if the module is added to the image.
Build option `LITE=1` omits Wi-Fi + big NIC firmware for a small default image (~40 MB).

## Config approach (reproducible)

1. Start from `make defconfig` (x86_64_defconfig) so Kconfig defaults stay sane.
2. Merge fragments with `scripts/kconfig/merge_config.sh -m .config kernel/fragments/*.config` in fixed order:
   `00-core.config`, `10-net.config`, `20-storage.config`, `30-usb-console.config`, `40-fs.config`, `50-probe-hw.config`,
   `60-wifi.config` (optional, `WIFI=1`), `90-size-trim.config` (turns off sound/gpu/debug).
3. `make olddefconfig`, then fail the build if any symbol requested in a fragment ends up unset
   (script diffs requested `CONFIG_X=y` against final `.config`; catches missing deps silently dropped by Kconfig).
4. Reproducibility: pinned tarball hash, `KBUILD_BUILD_TIMESTAMP`, `KBUILD_BUILD_USER=i7lab`, `KBUILD_BUILD_HOST=i7lab`,
   `SOURCE_DATE_EPOCH` from VERSION file, fixed gcc (record `gcc --version` in the build manifest). The final `.config` is committed
   under `kernel/config-<ver>` for review, never edited by hand.
5. Install: `make bzImage modules`, `make modules_install INSTALL_MOD_PATH=<stage> INSTALL_MOD_STRIP=1`, kernel with
   built-in EFI stub boots directly as `BOOTX64.EFI` under UEFI, and as bzImage under GRUB for BIOS.
6. Optional embedded initramfs: `CONFIG_INITRAMFS_SOURCE` NOT used; initramfs is a separate `initramfs.cpio.zst` (so the kernel build is
   cached and an init change rebuilds in seconds). Init binary is `/init`.

## Build time (measured, the build host, linux-6.18.63)

| Step | Time |
|---|---|
| download 155 MB tarball + untar | 14 s |
| `tinyconfig` + 12 symbols, `make -j8 bzImage` (1.0 MB bzImage) | 78 s (mostly host tools, j8) |
| `make defconfig` + `make -j128 bzImage` (14.5 MB) | 148 s |
| `make -j128 modules` (defconfig, ~all modules) | 82 s |

Toolchain proven end to end (tar -xf, make defconfig, make bzImage). Expect our trimmed config to be **about 2-4 minutes** for
bzImage plus modules at -j128, cold; incremental rebuild is seconds. The Rust userland builds in about a minute cold.
Machines at -j8 (e.g. a laptop) are around 15-25 min. Test tree removed from /tmp afterwards.

## Bootloader plan: one USB stick, UEFI and legacy BIOS

**Pick: GRUB 2** (grub-pc-bin for BIOS, grub-efi-amd64-bin for UEFI), GPT with a protective-MBR hybrid-free layout:

```
GPT
 1  1 MiB    type EF02  BIOS boot partition (core.img for GRUB BIOS-on-GPT)
 2  256 MiB  type EF00  ESP, FAT32, label I7LABESP: EFI/BOOT/BOOTX64.EFI (grub), grub/grub.cfg, i7lab/bzImage, i7lab/initramfs.cpio.zst
 3  rest     type 8300  ext4 or FAT label I7LABDATA: logs, probe archives, persistence (optional, may be created on first boot)
```
Both UEFI and BIOS firmware read the same `grub.cfg` and the same kernel files from the ESP. Commands in `scripts/build-usb-drive`:
`sgdisk`, `mkfs.vfat -F32`, `grub-install --target=i386-pc --boot-directory=<esp>/ <dev>` and
`grub-install --target=x86_64-efi --removable --efi-directory=<esp> --boot-directory=<esp>/ --no-nvram <dev>`
(or `grub-mkimage` for a pure-file build that needs no device for the image-file case: loop device or `-o img` with offsets).

Justification:
- GRUB has first-class support for BOTH modes from the same packages already on the build host (and in every distro), with one config file;
  syslinux needs a separate mechanism for each (extlinux/ldlinux.sys for BIOS, syslinux.efi is 32 or 64 bit and fiddly on GPT/ESP) and
  upstream syslinux is unmaintained; legacy BIOS-on-GPT with syslinux needs gptmbr.bin tweaks.
- systemd-boot is UEFI only; Limine does both well and is smaller, but is not packaged for Ubuntu 26.04 here (not found in
  apt) so it would add an out-of-distro dependency to the build.
- Many lab machines are odd (some BIOS-only, some UEFI-only with CSM off, some with broken GPT-on-BIOS handling): GRUB's
  `BIOS boot` partition + protective MBR with boot flag set (`sgdisk` hybrid `-h` unneeded but `parted set 1 bios_grub on` and legacy
  boot flag `sgdisk --attributes=2:set:2`) is the widest-tested combination. Add a fallback MBR-partitioned variant only if a host proves fussy.
- `grub.cfg` is a few lines: serial + gfxterm console, `linux /i7lab/bzImage console=tty0 console=ttyS0,115200n8 i7lab.keys=...`,
  `initrd /i7lab/initramfs.cpio.zst`, 2 s timeout, a second "debug shell" entry, a third entry "chainload internal disk".
- Secure Boot is NOT supported (lab hosts run with it off; documented). `x86_64-efi-signed` exists on the build host if we need shim later.
- Also produce an `.iso` (xorriso with grub-mkrescue) for virtual media/JetKVM/QEMU testing.

## QEMU test plan (in the build host, max 2 guests)
BIOS: `qemu-system-x86_64 -m 2G -drive file=usb.img,format=raw -nographic -serial mon:stdio` (uses SeaBIOS);
UEFI: add `-bios /usr/share/ovmf/OVMF.fd` (apt `ovmf`). Both must reach i7lab-init and answer an L2 beacon on a `-nic socket/tap`.
NOT yet run (no userland to boot).

## Risks and open items
- Config fragments above are a starting set from knowledge of the 6.18 Kconfig; names (esp. NVME_HWMON, SENSORS_*, DRM_SIMPLEDRM,
  RTW89 sub-options) must be validated by the "symbol requested but unset" check on the first real build.
- rustup via apt works on the build host; the build script should detect missing `x86_64-unknown-linux-musl` and run `rustup target add`.
- GRUB BIOS boot on GPT disks on very old BIOS-only hosts is not verified; fallback is an MBR layout.
- Real hardware coverage of drivers (e.g. which NICs the lab actually has) is unknown; the list is deliberately broad, trim after survey.
