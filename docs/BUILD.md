# Building i7lablinux

One command does it all: `scripts/build-usb-drive` (see [QUICKSTART.md](QUICKSTART.md)). This page explains what runs
where, the pieces, and the choices behind them. **No busybox anywhere**: the image holds only our Rust binaries
(`i7lab-init`, `i7labd`, `i7labsh`) plus the kernel; `scripts/check-no-busybox` runs on every image build and fails it.

## Where things run

| Step | Host | Why |
|---|---|---|
| kernel, cargo, QEMU | **build host** (a big build host, e.g. 128 cores, tmpfs `/tmp`) | not on a small operator machine |
| image assembly | build host | needs `sgdisk mkfs.vfat mtools grub-*` |
| key baking, writing the stick | **your machine** | real keys never leave it; the USB stick is plugged in there |

Scripts started on a small machine re-run themselves on the build host through `scripts/remote` (rsync of the tree to
`/tmp/i7ll-<label>/`, excluding `target`, `keys`, `out`) and fetch `out/<part>` back. A machine counts as a build host
with `nproc >= 64`, or when `I7_ON_BUILD_HOST=1` (set automatically inside a remote run), or `--build-host local`.
Override the host with `I7LL_HOST=...` or `--build-host HOST`; the remote label (default `build`) with `I7_REMOTE_LABEL`.
Caches live in `$I7_CACHE` (default `/tmp/i7ll-cache-$USER`, a tmpfs on a big build host).

## Prerequisites (build host)

```
sudo apt-get install -y build-essential flex bison bc cpio xz-utils zstd libelf-dev libssl-dev kmod curl \
  xorriso dosfstools mtools gdisk parted rsync grub-pc-bin grub-efi-amd64-bin grub-common \
  musl-tools rustup qemu-system-x86 ovmf
rustup default stable && rustup target add x86_64-unknown-linux-musl     # build-userland adds the target if missing
```
Optional: `linux-firmware` (NIC firmware for `FIRMWARE=auto`; missing = warning, no firmware in the image), `gpg` (kernel.org
signature check; the pinned sha256 is the real control), `shellcheck` (scripts are written to be clean under it).
Operator machine: `sgdisk`, `lsblk`, `blkid`, `sudo`; `mtools` is optional (without it `bake-keys` loop-mounts the ESP with
sudo, and the extra stick verification is skipped); `xorriso` for ISO baking.

## The pipeline

```
scripts/build-userland      -> out/bin/{i7lab-init,i7labd,i7labsh,i7labctl}      static x86_64-musl, stripped
scripts/build-kernel        -> out/kernel/{bzImage,config,modules/,BUILD-INFO}   Linux 6.18 LTS, ~13 MB bzImage
scripts/build-initramfs     -> out/initramfs.cpio.zst                            keyless, newc + zstd -19
scripts/build-image         -> out/image/i7lablinux-<kver>-<sha7>.{img,iso}      GPT image (+ i7lablinux.img/.iso symlinks)
scripts/bake-keys           -> adds /i7lab/keys.cpio to an image, ISO or stick   operator machine only
scripts/build-usb-drive     -> everything above + safe write + verify            the entry point
scripts/qemu-test           -> boots image/iso/direct in QEMU (BIOS + UEFI)      build host
scripts/make-release        -> keyless bundle out/release/...tar.zst
scripts/check-no-busybox    -> --repo | --initramfs F | --image F | --dir D
```
`scripts/build-image --full` runs userland, kernel, initramfs and image in order (on the build host).
Each script has `--help`. `scripts/install-ctl` builds `i7labctl` (static) and installs it with `cap_net_raw`.

### Kernel (`build-kernel`)

Pinned in `configs/kernel/VERSION` (`6.18.63`, sha256 checked; the tarball is fetched from cdn.kernel.org into the cache,
the kernel.org signature is checked too when `gpg` has the keys). `make defconfig`, then `merge_config.sh` with the
fragments in `configs/kernel/fragments/` in name order (`00-core`, `10-net`, `20-storage`, `30-usb-console`, `40-fs`,
`50-probe-hw`, `60-wifi` only with `WIFI=1`, `90-size-trim`), then `olddefconfig`. **The build fails if any requested
`CONFIG_X=y|m` did not survive** (a renamed symbol or a missing dependency would otherwise silently drop a driver), and if
any symbol in `configs/kernel/must-be-y.list` (every NIC of the hardware list, NVMe/AHCI/USB storage, xHCI, EFI stub,
console) is not `=y`: a lab host whose only NIC driver is missing is unreachable. `--lenient` turns the first into
warnings while you iterate on fragments. Modules are plain `.ko` (the initramfs is compressed as a whole), installed
stripped. Finished kernels are cached by a hash of VERSION + fragments + must-be-y + gcc version + WIFI, so an
initramfs-only change never rebuilds the kernel. Set `I7_KEEP_RESOLVED=1` to copy the resolved config to
`configs/kernel/config-<ver>.resolved` for review. Measured on the build host (128 cores): configure + `make -j128 bzImage modules`
about 2.5 minutes cold; the 6.18.63 result is a 13 MB bzImage and 32 modules (XFS, btrfs, ntfs3, i40e, ice, mlx, HBAs...).

Reproducibility: pinned tarball and hash, `KBUILD_BUILD_USER=i7lab`, `KBUILD_BUILD_HOST=i7lab`,
`KBUILD_BUILD_TIMESTAMP` and `SOURCE_DATE_EPOCH` from `epoch=` in VERSION, the gcc and binutils versions recorded in
`out/kernel/BUILD-INFO`. Initramfs and image: sorted file lists, uid/gid 0, mtimes = the epoch, deterministic GPT/FAT ids
derived from the content hashes. Two builds on the same toolchain should be byte-identical; a different gcc changes the
kernel (not yet verified bit-for-bit, see Not yet proven).

Supported NICs (all `=y`, so no module loading is needed to get control): Intel e1000/e1000e/igb/igc/ixgbe, Realtek
r8169 (RTL8111/8168/8125/8126), Broadcom tg3/bnx2/bnxt, virtio-net, VMware vmxnet3, USB Ethernet (RTL8152/8153,
ASIX AX88179/178A and AX8817x, CDC-ECM/NCM/EEM). Modules loaded at boot from `configs/image/modules.list`: i40e, ice,
bnx2x, mlx4_en, mlx5_core, MegaRAID/mpt3sas/hpsa, ntfs3/xfs/btrfs/exfat/udf. Everything else needs a USB adapter or a new
fragment line + rebuild.

### Initramfs (`build-initramfs [FIRMWARE=auto|none|wifi] [WIFI=1]`)

Layout (PLAN section 7): `/init` (= `i7lab-init`), `/sbin/i7labd`, `/bin/i7labsh`, `/etc/i7lab/{i7lab.conf,BUILD,MANIFEST}`
(`BUILD` line 1 is the build id, `MANIFEST` the sha256 of every file), `/etc/{passwd,group,hostname,os-release}`,
`/lib/modules/<ver>/...` (only the modules in `modules.list` plus their dependencies, with their own `depmod` data) and
`/lib/modules/modules.order` (one path relative to `/lib/modules` per line, dependencies first: what `i7lab-init` loads),
`/lib/firmware/...` per `configs/image/firmware.list` (`auto` = rtl_nic, tigon, bnx2, bnx2x; `wifi` adds the Wi-Fi sets;
blobs stay zstd-compressed, the kernel has `FW_LOADER_COMPRESS_ZSTD`), `/usr/share/i7lab/LICENSES`. Device nodes
`/dev/console` and `/dev/null` are appended as a second archive without root (the kernel unpacks concatenated archives).
There is no `/bin/sh` and no applet farm. It is **keyless**: keys arrive as a second initrd (see [KEYS.md](KEYS.md)).

### Image (`build-image`)

```
LBA 0        protective MBR + GRUB boot.img (entry marked active: PMBR_ACTIVE=1, `--pmbr-active 0` to drop)
p1  1 MiB    BIOS boot (EF02)   GRUB core.img
p2  64 MiB   ESP (EF00, FAT32 label I7LABESP)
               EFI/BOOT/BOOTX64.EFI        standalone GRUB, finds the ESP by /i7lab/IMAGE-ID, hands over to boot/grub/grub.cfg
               boot/grub/grub.cfg          editable on the stick; boot/grub/{i386-pc,x86_64-efi}/ modules
               i7lab/{bzImage,initramfs.cpio.zst,keys.cpio,IMAGE-ID,BUILD,SHA256SUMS,KEYSET-ID after baking}
no data partition; the backup GPT sits at the image end (build-usb-drive relocates it to the end of the stick: sgdisk -e)
```
Measured: image 67 MiB (ESP content about 26 MiB with stub binaries; the ESP grows automatically if the content needs
more, the total must stay under 256 MiB), ISO about 33 MiB. GPT disk/partition GUIDs and the FAT volume id are derived from the content,
so `i7lab.boot=PARTUUID=...` on the kernel command line (which `i7labd` uses to recognise its own boot media) is stable.
Boot paths: UEFI loads `\EFI\BOOT\BOOTX64.EFI` (no NVRAM entry is created: the stick works in any host); BIOS runs
boot.img -> core.img -> the same `grub.cfg`. Secure Boot is not supported (unsigned).

**BIOS stage, without root.** `grub-install` needs a block device; we write the same bytes by hand: core.img is made with
`grub-mkimage -p '(,gpt2)/boot/grub'` (`(,gpt2)` = partition 2 of whatever drive GRUB was started from), placed at LBA 2048;
boot.img is patched with `kernel_sector = 2048` (offset 0x5c) and the hard-disk `boot_drive_check` nop (0x66), then its first
440 bytes go to LBA 0 (the GPT protective entry stays); the diskboot blocklist in core.img (offset 500) gets
`start=2049, count=n-1, segment=0x820`. Compared byte for byte with a loop-device `grub-install` of the same files: the boot code and core sector 0 are identical
except the blocklist length (grub-install also appends Reed-Solomon codes after core.img, we do not). Proven by booting the result under SeaBIOS in QEMU, both written
to a loop device by `build-usb-drive` and as a file. If a real BIOS host proves fussy, the fallback is `sudo losetup -P` +
`grub-install --target=i386-pc` on the image, then `bake-keys` as usual.

**ISO**: `grub-mkrescue` (BIOS + UEFI hybrid, El Torito + appended GPT/EFI partition) from the same tree, for JetKVM CD mode
and QEMU. Because xorriso cannot re-master such an ISO, its `/i7lab/keys.cpio` is a fixed 8 KiB slot (the empty archive plus
zero padding, which the kernel skips) that `bake-keys --iso` overwrites in place; the ISO keeps its size and boot structures.

### Writing a stick (`build-usb-drive`)

`scripts/build-usb-drive /dev/sdX [--serial S] [--dry-run] [--internal] [--yes-i-am-sure]`. Order: keys exist? -> build
(or `--no-build` / `--from FILE`) -> no-busybox scan -> **device checks** -> summary (model, serial, size, current partitions)
-> typed device name (or `--yes-i-am-sure` + `--serial`) -> `wipefs`, `dd` (`conv=fsync oflag=direct`) -> read-back sha256 of
the whole image from the device -> `sgdisk -e` -> `bake-keys --device` -> verify `i7lab/SHA256SUMS` against the files on the
stick. The checks refuse: not a block device, a partition instead of a disk, read-only, too small, mounted anywhere,
holds `/` (or is in its device stack), device-mapper/md holders, active swap, RAID/LVM/LUKS/ZFS member, non-removable or
non-USB without `--internal`, > 2 TB without `--internal` (> 4.1 TB never), serial mismatch. `--dry-run` runs the build and
all checks and writes nothing. The in-image block-write gate is PLAN section 6.
`--image FILE [--iso FILE]` produces keyed files instead of writing a device.

### QEMU test (`qemu-test`)

Boots on the build host with q35, a USB stick (the image, `snapshot=on`, so the original is never modified), two PCIe root
ports with an NVMe and a virtio-blk disk (serials I7NVME0001, I7VIRT0001), a virtio NIC on a UDP multicast socket netdev
(L2 without root: `i7labctl --link mcast:239.255.71.1:PORT`), and an e1000e on user-mode networking with port 8080 forwarded.
Per firmware (SeaBIOS and OVMF) it checks GRUB, `i7lab-init` on the console, no "busybox" in the log, the key overlay, and,
when an `i7labctl` is available (`--ctl`), `discover` and `--ether MAC --cmd ping`. Evidence in `out/e2e/<timestamp>/`. At most 2
guests at once, every guest under `timeout`. The full e2e plan is `tests/e2e` (docs/TESTING.md, lane P11).

## Variables and options

| | |
|---|---|
| `I7LL_HOST` | build host (`user@host`; default: first line of `~/.config/i7lablinux/build-host`, kept out of the repo) |
| `I7_REMOTE_LABEL` | `/tmp/i7ll-<label>` dir on the build host (default `build`) |
| `I7_CACHE` | tarball and kernel cache (default `/tmp/i7ll-cache-$USER`) |
| `I7_OUT` | output dir (default `./out`) |
| `FIRMWARE=auto\|none\|wifi`, `WIFI=1` | firmware set / Wi-Fi kernel fragment and modules |
| `I7_FIRMWARE_DIR` | firmware source (default `/lib/firmware`) |
| `PMBR_ACTIVE`, `--pmbr-active 0\|1` | mark the protective MBR entry active (default 1) |
| `I7_GRUB_PC`, `I7_GRUB_EFI` | GRUB module dirs (default `/usr/lib/grub/{i386-pc,x86_64-efi}`) |

## Not yet proven

* Real hardware: nothing here has booted a physical machine yet (QEMU SeaBIOS and OVMF only). The first BIOS-only host is the
  real test of the hand-written BIOS stage; JetKVM virtual media has not been exercised either.
* Bit-for-bit reproducibility across two builds, and across toolchain versions.
* The kernel config was iterated once against 6.18.63 (one symbol fixed); firmware/driver coverage of the actual lab hardware
  is unknown, so trim or extend after a hardware survey. Wi-Fi fragment (`WIFI=1`) and `modules.wifi.list` names are untested.
* Kernel signature verification depends on the kernel.org keys being imported on the build host.
