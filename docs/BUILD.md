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
Optional: `gpg` (kernel.org and linux-firmware signature checks against a private keyring in the cache; the pinned sha256 is
the real control; `I7_REQUIRE_SIG=1` makes a failed signature check fatal), `shellcheck` (scripts are written to be clean
under it). The firmware tarball (~700 MB) is downloaded on the build host by `scripts/fetch-firmware`; nothing else needs
`/lib/firmware` any more.
Operator machine: `sgdisk`, `lsblk`, `blkid`, `sudo`; `mtools` is optional (without it `bake-keys` loop-mounts the ESP with
sudo, and the extra stick verification is skipped); `xorriso` for ISO baking.

## The pipeline

```
scripts/build-userland      -> out/bin/{i7lab-init,i7labd,i7labsh,i7labctl}      static x86_64-musl, stripped
scripts/build-kernel        -> out/kernel/{bzImage,config,modules/,BUILD-INFO}   --kernel stable (7.3.x, default) | lts (6.18.x), ~13 MB bzImage
scripts/fetch-firmware      -> build host cache: pinned linux-firmware tree      called by build-initramfs; never committed
scripts/build-initramfs     -> out/initramfs.cpio.zst                            --variant lean|full; keyless, newc + zstd -19
scripts/build-image         -> out/image/i7lablinux-<kver>-<sha7>[-full].{img,iso}   GPT image (+ i7lablinux.img/.iso symlinks)
scripts/bake-keys           -> adds /i7lab/keys.cpio to an image, ISO or stick   operator machine only
scripts/build-usb-drive     -> everything above + safe write + verify            the entry point
scripts/qemu-test           -> boots image/iso/direct in QEMU (BIOS + UEFI)      build host
scripts/make-release        -> keyless bundle out/release/...tar.zst
scripts/check-no-busybox    -> --repo | --initramfs F | --image F | --dir D
```
`scripts/build-image --full` runs userland, kernel, initramfs and image in order (on the build host).
Each script has `--help`. `scripts/install-ctl` builds `i7labctl` (static) and installs it with `cap_net_raw`.

### Kernel (`build-kernel [--kernel stable|lts]`)

Two pinned flavours, exact version + sha256, never "latest": `configs/kernel/VERSION.stable` (default: the newest stable
release on kernel.org when pinned, **7.3.4** on 2026-11-13) and `configs/kernel/VERSION.lts` (fallback: the pinned longterm,
**6.18.63**). Select with `--kernel stable|lts` (or `I7_KERNEL=`); `build-image` / `build-initramfs` / `build-usb-drive` take the
same flag and refuse an `out/kernel` of the other flavour. Stable branches go EOL within months: when kernel.org marks the
pinned series `(EOL)`, bump `VERSION.stable` (version, url, sha256, sign_url; check with
`curl -s https://www.kernel.org/finger_banner` and `.../v7.x/sha256sums.asc`), rebuild, run the e2e, commit.
The tarball is fetched from cdn.kernel.org into the cache and the sha256 is checked. **Signatures**: when `gpg` exists,
build-kernel imports the kernel.org developer keys (WKD) into its own keyring (`$I7_CACHE/gnupg`, never yours) and requires
a valid signature by the fingerprint pinned as `signer_fpr=` (Greg Kroah-Hartman for both pins); the result is recorded as
`signature=` in `out/kernel/BUILD-INFO` (`NOT-verified` is a warning, fatal with `I7_REQUIRE_SIG=1`).
`make defconfig`, then `merge_config.sh` with the fragments in `configs/kernel/fragments/` in name order (`00-core`,
`10-net`, `20-storage`, `30-usb-console`, `40-fs`, `50-probe-hw`, `60-wifi`, `70-hardening`, `90-size-trim`; all always
merged), then `olddefconfig`. **The build fails if any requested `CONFIG_X=y|m` did not survive** (a renamed symbol or a
missing dependency would otherwise silently drop a driver), and if any line of `configs/kernel/must-be-y.list` is violated
(`SYM` = must be `=y`, `SYM=VALUE`, `!SYM` = must be unset): every core NIC, NVMe/AHCI/USB storage, xHCI, EFI stub, console,
and every hardening option. `--lenient` turns the first into warnings while you iterate; `--config-only` stops after the
config check (about 45 s; the resolved config lands in `$I7_CACHE/config-<flavour>.resolved`). The bzImage must stay <= 20 MiB.
Modules are plain `.ko` (the initramfs is compressed as a whole), installed stripped. Finished kernels are cached by a hash of
the VERSION file + fragments + must-be-y + gcc version, so an initramfs-only change never rebuilds the kernel. Set
`I7_KEEP_RESOLVED=1` to copy the resolved config to `configs/kernel/config-<ver>.resolved` for review. Measured on the build
host (128 cores): configure + `make -j128 bzImage modules` about 4 minutes cold now that GPU drivers are modules.

**Driver policy.** The core boot path and the hardware-list NICs stay built in (a lab host whose only NIC driver is a missing
module is unreachable, review F-F18); everything else is a module and `i7lab-init` loads by modalias from `modules.alias`:
NICs (Intel e1000..ice + VFs, Realtek r8169 incl. RTL8125/8126, r8152, rtase, 8139, Broadcom tg3/bnx2/bnx2x/bnxt, Mellanox
mlx4/mlx5, Aquantia atlantic, Atheros alx/atl*, Solarflare sfc, Marvell sky2, forcedeth, virtio/vmxnet3/hv_netvsc/xen-netfront,
USB NICs, bonding/team/bridge/vlan/macvlan/vxlan), Wi-Fi (iwlwifi with iwldvm/iwlmvm/iwlmld, ath9k/10k/11k/12k, mt76 family,
rtw88/rtw89, rtl8xxxu, brcmfmac, mwifiex), Bluetooth basics (btusb + btintel/btrtl/btbcm), storage (nvme, ahci, sata_*, pata_*,
megaraid, mpt3sas/mpi3mr, aacraid, hpsa/smartpqi, FC HBAs, virtio, usb-storage/uas, sdhci/mmc/rtsx), USB serial, GPUs (i915,
xe, amdgpu, nouveau; simpledrm owns the console until one loads), I2C-HID/LPSS/ISH, hwmon/EDAC/IPMI/TPM/PMC, and filesystems
(ext4, vfat, iso9660, squashfs, overlayfs built in; xfs, btrfs, f2fs, exfat, ntfs3, udf modules).

**Hardening** (`70-hardening.config`, all repeated in `must-be-y.list` so removing a line fails the build): KASLR (base + memory),
stack protector strong, VMAP_STACK, kstack offset randomisation, STRICT_KERNEL_RWX / STRICT_MODULE_RWX / DEBUG_WX,
HARDENED_USERCOPY, FORTIFY_SOURCE, INIT_ON_ALLOC_DEFAULT_ON, SLAB freelist random + hardened, page allocator shuffle,
LIST_HARDENED, BUG_ON_DATA_CORRUPTION, `mmap_min_addr` 65536, no vsyscall, STRICT_DEVMEM + IO_STRICT_DEVMEM, DEBUG_FS off (the
daemon denies `/sys/kernel/debug` anyway), no /proc/kcore, dmesg restricted. **Deliberate exceptions**: `/dev/mem` and
`/dev/port` exist (restricted by STRICT_DEVMEM), module signing is off (the initramfs is the trust root; modules never come
from disk), and **KEXEC / KEXEC_FILE stay enabled** because the planned kexec command needs them (no signed-kexec enforcement
until we sign kernels).

Reproducibility: pinned tarball and hash, `KBUILD_BUILD_USER=i7lab`, `KBUILD_BUILD_HOST=i7lab`,
`KBUILD_BUILD_TIMESTAMP` and `SOURCE_DATE_EPOCH` from `epoch=` in VERSION, the gcc and binutils versions recorded in
`out/kernel/BUILD-INFO`. Initramfs and image: sorted file lists, uid/gid 0, mtimes = the epoch, deterministic GPT/FAT ids
derived from the content hashes. Two builds on the same toolchain should be byte-identical; a different gcc changes the
kernel (not yet verified bit-for-bit, see Not yet proven).

### Initramfs (`build-initramfs [--variant lean|full] [FIRMWARE=none]`)

Layout (PLAN section 7): `/init` (= `i7lab-init`), `/sbin/i7labd`, `/bin/i7labsh`, `/etc/i7lab/{i7lab.conf,BUILD,MANIFEST}`
(`BUILD` line 1 is the build id, then `variant=`, `kernel_flavour=`, `firmware=<variant>-<tag>`; `MANIFEST` the sha256 of every
file), `/etc/{passwd,group,hostname,os-release}`, `/lib/modules/<ver>/...` with their own `depmod` data (`modules.alias` is
what `i7lab-init` loads by) and `/lib/modules/modules.order` (dependencies first), `/lib/firmware/...`,
`/usr/share/i7lab/LICENSES`. Device nodes `/dev/console` and `/dev/null` are appended as a second archive without root (the
kernel unpacks concatenated archives). There is no `/bin/sh` and no applet farm. It is **keyless**: keys arrive as a second
initrd (see [KEYS.md](KEYS.md)).

### Variants: lean and full

| | `lean` (default) | `full` |
|---|---|---|
| purpose | JetKVM virtual media and quick tests: uploads fast | a real USB stick for any hardware |
| kernel modules | all of them except `configs/image/modules.lean.exclude` (amdgpu, radeon, nouveau) | all |
| firmware | `configs/firmware-lean.list`: Intel Wi-Fi/BT (newest ucode per family), rtw88/89, mt7921/22/25, ath10k/11k/12k top families, rtl_nic, tigon, bnx2/bnx2x, ice DDP, i915 DMC/GuC/HuC, xe, regulatory.db | everything in the pinned linux-firmware minus `configs/firmware-full.exclude` (ARM SoC blobs, audio/camera, switch ASICs, old iwlwifi API versions); includes amdgpu, i915, xe, nvidia GSP |
| image budget | image and ISO < 256 MiB (build fails above) | < 1100 MiB |
| file names | `i7lablinux-<kver>-<sha7>.{img,iso}` | `i7lablinux-<kver>-<sha7>-full.{img,iso}` |

`build-usb-drive --variant lean|full` and `build-image --variant ...` pick one; `out/image/i7lablinux.{img,iso}` always point
at the last build. The two GPU exclusions in lean are deliberate: a GPU driver whose firmware is missing still takes the
console away from simpledrm during its probe and then fails, leaving a black screen, so lean ships no GPU driver that needs a
big firmware set (i915 and xe need only small files and are in).

### Firmware (`fetch-firmware`, `configs/firmware/VERSION`)

The blobs are never committed (licences: [THIRD_PARTY.md](THIRD_PARTY.md)). `configs/firmware/VERSION` pins one
linux-firmware tag (`20261019`) with sha256 and the release signer's key fingerprint; `scripts/fetch-firmware` downloads
the tarball on the build host, verifies it, unpacks it into `$I7_CACHE/firmware-<tag>/tree` and prints that path.
`build-initramfs` reads the tree's `WHENCE` (what `copy-firmware.sh` would install, links included), selects per variant
(globs on installed names; a selected link pulls in its target; `@latest N GLOB` keeps the newest N API versions of a
family), compresses every file with `zstd -19` (the kernel loads `NAME.zst` via `FW_LOADER_COMPRESS_ZSTD`, and the compressed
files keep RAM use of the unpacked initramfs low), keeps links as relative symlinks and caches the staged set per
variant + list hash (`$I7_CACHE/fwstage-*`). `scripts/fetch-firmware --stats lean|full [--stage-to DIR]` prints file count and
size of a variant to tune the list files. Staging needs the build host (`build-image --full` does it there); for a one-off
local tree use `I7_FIRMWARE_TREE=DIR`. `FIRMWARE=none` builds a firmware-free image (what `make-release` does).

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
Measured (kernel 7.3.4, linux-firmware 20261019; the 6.18.63 LTS numbers are within 1 MiB): **lean** image 108 MiB with ISO 106 MiB
(initramfs 81 MiB: 259 modules 87 MiB unpacked + 73 MiB of zstd firmware); the same lean image built with `FIRMWARE=none` (the
release bundle) 67 MiB / ISO 42 MiB; **full** image 383 MiB / ISO 380 MiB (261 modules 118 MiB, 372 MB of firmware). The lean
total must stay under 256 MiB, full under 1100 MiB (the build fails above); the ESP grows automatically if the content needs
more (clusters are 4 KiB above 300 MiB). On a BIOS machine GRUB reads the initrd through int13, so the full image takes a
while from a slow stick; UEFI is faster. GPT disk/partition GUIDs and the FAT volume id are derived from the content,
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
(L2 without root: `i7labctl --link mcast:239.255.71.1:PORT`), and an e1000e on user-mode networking with guest ports 80 and 8080 forwarded.
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
| `I7_KERNEL`, `--kernel stable\|lts` | kernel flavour (default stable) |
| `I7_VARIANT`, `--variant lean\|full` | image variant (default lean) |
| `FIRMWARE=auto\|none` | firmware on or off (`WIFI=1` and `FIRMWARE=wifi` are accepted and ignored: Wi-Fi is always built) |
| `I7_FIRMWARE_TREE` | use an unpacked linux-firmware tree instead of fetching the pinned tag |
| `I7_REQUIRE_SIG=1` | make a failed kernel.org / linux-firmware signature check fatal |
| `I7_ALLOW_BIG_KERNEL=1` | allow a bzImage above 20 MiB |
| `PMBR_ACTIVE`, `--pmbr-active 0\|1` | mark the protective MBR entry active (default 1) |
| `I7_GRUB_PC`, `I7_GRUB_EFI` | GRUB module dirs (default `/usr/lib/grub/{i386-pc,x86_64-efi}`) |

## Not yet proven

* Real hardware: nothing here has booted a physical machine yet (QEMU SeaBIOS and OVMF only). The first BIOS-only host is the
  real test of the hand-written BIOS stage; JetKVM virtual media has not been exercised either.
* Bit-for-bit reproducibility across two builds, and across toolchain versions.
* Driver coverage was proven by building (both kernels, every requested symbol survives) and by QEMU module-load tests
  (virtio/e1000e built in, rtl8139 -> 8139cp/8139too and megasas -> megaraid_sas loaded by modalias in lean and full). No Wi-Fi,
  GPU, 10G NIC or HBA module has run on its hardware; firmware lists are curated by size and family, not by a hardware survey.
* The full variant has been booted only under QEMU (UEFI via the e2e, BIOS via IDE; a QEMU USB stick under SeaBIOS needs
  more than 6 minutes for the 340 MB initrd, real sticks are faster but this is unmeasured).
* GPU drivers in the full image (amdgpu, nouveau, i915, xe) are not exercised in a guest at all; `nouveau` on a Turing+ card
  without GSP firmware matching the tag, or `amdgpu` on an ASIC newer than the tag, can leave a blank console; `i7lab-init` has no module blacklist, so such a host needs the lean image (no amdgpu/nouveau).
* Signature checks need `gpg` and the network on the build host; the kernel.org keys come from WKD and the linux-firmware signer
  key from keys.openpgp.org (a failed check is a warning unless `I7_REQUIRE_SIG=1`).
