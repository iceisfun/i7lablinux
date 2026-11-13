# End-to-end results (task X1, 2026-11-13)

Host: the build host (128 cores, KVM). Guests: q35, 4 vCPU, 2 GiB, USB stick (the image, `snapshot=on`), NVMe `I7NVME0001`,
virtio disks `I7VIRT0001` and `I7PART0001` (GPT + ext4), virtio-net on a multicast L2 segment (no IP configured on it) and
an e1000e on QEMU user networking (DHCP, HTTP forwarded). Firmware: SeaBIOS and OVMF (UEFI). A random THROWAWAY key set (made per
run) is baked into a scratch copy of the image.

> **Note:** these results were recorded before the public demo keys were removed (the run used them, with admin allowed
> because the guest is a VM). Demo keys no longer exist; `scripts/e2e` now generates throwaway keys per run. The numbers
> below are history and were not rewritten.

Full transcript of the last run (every command and its output): [e2e/transcript-20261113.txt](e2e/transcript-20261113.txt).
VGA console (tty1 TUI, UEFI guest, QEMU screendump): [e2e/tui-vga-uefi.png](e2e/tui-vga-uefi.png).

## Result: 91 checks, 91 passed (BIOS, UEFI, serial TUI, image audit)

```
cd /tmp/i7ll-integ    # on the build host, after: scripts/build-image --full ; cargo build --release -p i7labctl ; cp target/release/i7labctl out/bin/
PYTHONPATH=/tmp/i7ll-pyte I7_ON_BUILD_HOST=1 scripts/e2e --fw both
RESULT: 91 passed, 0 failed
```

Per firmware (BIOS and UEFI each ran all of these):

| Check | Command (host `52:54:00:17:00:01`, `C` = `i7labctl --link mcast:239.255.71.1:PORT`) | Observed |
|---|---|---|
| beacon over raw L2, no IP | `C discover --listen 5` | `52:54:00:17:00:01  i7lab  6.18.63-nogit  ready  ... demo` |
| ping, id, inv over ether, no IP | `C --ether MAC --cmd ping`, `C id MAC`, `C --ether MAC --cmd inv` | `{"echo":"","uptime_ms":36760,...}`, `role admin`, QEMU inventory |
| PCIe probe lists the q35 devices | `C pcie MAC` | 00:00.0 Intel 82G33 host bridge, QEMU PCIe root ports, NVMe 01:00.0, virtio blk 02/03:00.0, e1000e, ICH9 |
| USB, thermal | `C usb MAC`, `C thermal MAC` | answers |
| block enumeration | `C blk ls MAC` | nvme0n1 / vda `WRITE-SAFE`; sda `BOOT UNSAFE: boot_media ...`; vdb `UNSAFE: partition_table(gpt) ...` |
| read test | `C blk read MAC nvme0n1 --mb 16` | `RESULT: ok` (~390 MiB/s on KVM) |
| write + verify | `C blk write MAC nvme0n1 --destructive --serial I7NVME0001 --mb 16 --seed 77 --yes` then `C blk verify MAC nvme0n1 --seed 77 --mb 16` | both `RESULT: ok`, 0 IO errors, 0 mismatches |
| gate: no flags | `C blk write MAC vdb --yes` | exit 7 locally, nothing sent |
| gate: wrong serial on a partitioned disk | `... vdb --destructive --serial WRONG` | `REFUSED: write refused by the safety gate`, exit 7 |
| gate: boot media with the right serial | `... sda --destructive --serial I7STICK0001` | refused, exit 7 (no override exists) |
| gate: mounted disk | `C sh MAC "mount /dev/vdb1 /mnt"`, then write with the right serial | refused, exit 7 (`blk ls` shows `MOUNTED /mnt`, `UNSAFE: mounted(/mnt) ...`) |
| gate: partitioned, unmounted, right serial | after `umount`, same command | allowed, `RESULT: ok` |
| read-only key cannot write | `blk write` with only `ro.key` | `EPERM: admin key required`, exit 5; `blk ls` works with it |
| a key the host does not hold | `--no-registry ping` with a random admin key | host stays silent: `no CHALLENGE ... (timeout)`, exit 4 |
| no key at all | `ping` with an empty key dir | clear error, exit 5 |
| exec over ether | `C sh MAC "echo hello-ether"`, `C exec MAC -- /bin/i7labsh -c "echo exec-ether"` | output returned |
| net ls, logs over ether | `C net ls MAC`, `C logs MAC --dmesg -n 20` | eth1 `10.0.2.15/24` (DHCP) |
| HTTP API after DHCP | `curl .../api/v1/hello`, unsigned `POST /api/v1/cmd/reboot`, `GET /` | `{"name":"i7labd",...}`, **401**, `<title>i7lablinux` |
| signed HTTP | `i7labctl --http 127.0.0.1:PORT ping`, `inv --json`, `sh`, `exec`, `blk read`; `GET /api/v1/openapi.json` | all ok |
| VGA console | QEMU `screendump` of tty1 | coloured TUI, see the PNG |
| reboot command accepted | `C reboot MAC --delay 30` | accepted (the guest is killed right after) |

Serial console TUI (GRUB entry "serial TUI, ASCII", driven through the serial socket with `tests/e2e/tuicap.py`, which feeds
the stream to a VT emulator and prints the screen): the Overview, PCIe, Storage, Network, USB, Sensors, Log and Actions pages
render (Right arrow, Tab, `1`..`8`, Shift-Tab), F12 opens About, **F10 starts `i7labsh` on the serial tty** and a typed
command runs. A booted-image excerpt:

```
 i7lablinux 0.1.0  host:i7lab  up 00:00:10  ip 10.0.2.15/24  mac 52:54:00:17:0~
[Overview]  PCIe   Storage   Network   USB   Sensors   Log   Actions
 DEMO KEYS (VM): public keys, full control. Test use only.
+- Overview -------------------------------------------------------------------+
|Attention                                                                    #|
|nothing needs attention                                                      #|
|System                                                                       #|
|Product:       QEMU Standard PC (Q35 + ICH9, 2009)                           #|
```

Also run (`scripts/qemu-test --both --ctl out/bin/i7labctl`): image and ISO (as USB CD-ROM, the JetKVM path), each under BIOS
and UEFI: GRUB, PID 1, no busybox string on the console, beacon ok, ether ping ok, all four PASS.

`scripts/build-usb-drive --image out/my.img --iso out/my.iso` from the operator machine with the real generated key set (`scripts/gen-keys`):
build on the build host (kernel cache hit), rsync back, `bake-keys` into both files, read-back verified, exit 0. No root, no loop device.

## Boot media overwrite (`scripts/e2e-bootmedia`, 2026-11-13)

One QEMU guest booted from a virtual USB stick (sda), throwaway keys: 20 checks, 20 passed. Refused without `--allow-boot-media`
(`blk image`, `blk write`), refused with the flag but without `--destructive`, with a wrong serial, and with the stick's ESP mounted
in the guest (boot_media absolute again); allowed with `--destructive --serial --allow-boot-media --verify` on the RAM-resident guest
(64 MiB GPT image over the boot disk), the guest kept answering `id`/`ping`, `blk ls` showed the new table, the audit log carried
`allow_boot_media=true ... BOOT-MEDIA-OVERRIDE ram-resident`. Controls: the same image onto a blank virtio disk and a blank non-boot USB
disk. Transcript: [e2e/transcript-bootmedia-20261113.txt](e2e/transcript-bootmedia-20261113.txt). Note: QEMU `snapshot=on` keeps its
overlay in `$TMPDIR` (default `/var/tmp`); on a build host with a full root filesystem the guest pauses on ENOSPC (seen as a hung
`blk image` at >32 MiB), so the script points `TMPDIR` at the run directory.

## Sizes

| Artifact | Size |
|---|---|
| kernel `bzImage` (Linux 6.18.63, `-j128`, about 2.5 min cold) | 12,968,960 bytes (12.4 MiB) |
| kernel modules (32, uncompressed, in the initramfs) | 24 MB on disk |
| `initramfs.cpio.zst` (107 files incl. 55 firmware files, 1.5 MB) | 7.0 MB |
| `i7lab-init` / `i7labd` / `i7labsh` (static musl, stripped) | 0.60 / 1.85 / 1.18 MB |
| `i7labctl` (host build, glibc) | 1.15 MB |
| `i7lablinux.img` (GPT, 64 MiB ESP + BIOS boot partition) | 67 MiB (70,254,592 bytes) |
| `i7lablinux.iso` | 31 MiB (32.9 MB) |

Unit and integration tests: `cargo test --workspace` on the build host, **728 passed, 0 failed** (1 ignored: the sudo-only loop-device test); `cargo build --workspace --all-targets`: 0 warnings;
`cargo build --release --target x86_64-unknown-linux-musl --workspace`: ok.

## Failures seen during integration and what became of them

| Seen | Diagnosis | Resolution |
|---|---|---|
| First `qemu-test`: GRUB and PID 1 fine, beacon FAIL, ping FAIL | `i7labctl --link mcast:` and the server NIC loop both hit stubbed `labproto` (`UdpLink::multicast`, `PacketLink`) | implemented, [integration log](design-history/integration-log.md) 1-2 |
| Host log after the first boot: nothing after `started i7labd` | same stubs: the daemon could not open any NIC; TUI was `Unsupported` | [integration log](design-history/integration-log.md) 1, 8 |
| `blk ls` table printed `UNSAFE: {"code":"boot_media",...}` | renderer expected strings, daemon sends objects | [integration log](design-history/integration-log.md) 10 |
| Overview "attention: 3" on a healthy boot | kernel-log classifier false positives | [integration log](design-history/integration-log.md) 11 |
| e2e script: SPA check failed once on BIOS only | my script, `printf big | grep -q` under `pipefail` (SIGPIPE), not the product | here-string grep |
| e2e script died silently after a command with no output | my script, `grep -v` returning 1 under `set -e` | `|| true` |

## NOT RUN

* Any real hardware, a real USB stick, the real PDU/JetKVM remote-boot procedure (docs/REMOTE-BOOT.md is not exercised here).
* Booting an image with the operator's REAL keys (the real-key image was built and read-back verified, but running it needs the real key on the build host, which I did not copy there). The (since removed) demo-key paths were identical code.
* 802.1Q/802.1ad tagged L2 (the BPF program and aux-data parser are unit-tested; no tagged frames were sent through QEMU).
* `i7labctl` over a real NIC with `cap_net_raw` (`PacketLink` on the client side): only the server side uses `PacketLink` in these runs (the guest's NIC loop); the client used the multicast test link.
* DHCP failure paths, static address hints (`I7LR2`), netcfg rollback, the `net set/vlan` commands against the live kernel.
* SMART (`labprobe::block::smart` is still a stub), Wi-Fi image (`WIFI=1`), Secure Boot, kexec, `i7labctl shell` (pty), `put`/`get`, jobs.
* The write-test dialog on the TUI (off by default in v0.1) and the TUI's Dhcp/Ping/BootNext actions (compile and unit-tested only).
* Browser run of the SPA against a live guest (the SPA has its own mock-server browser tests; here only `GET /` was checked).
* KMS/framebuffer on real GPUs (only QEMU VGA).

## Open issues

1. `labprobe::block::smart` is a stub (SMART column shows `-`). Owner: probes lane.
2. The kernel has `CONFIG_DUMMY=y` (creates `dummy0`) and the default `sit0`: both show in every NIC list. Drop `DUMMY` from `configs/kernel/fragments/10-net.config` if nothing needs it (not changed here: a kernel rebuild without a requirement).
3. The console TUI shares one global saved-termios and SIGWINCH flag in `labtui::term`; two consoles at once (tty1 plus `i7lab.serial=`) work in the runs, but a resize on one can be consumed by the other's loop. Fix in labtui if both are used on real hardware.
4. `i7labd` console `Ping` uses a TCP connect (no ICMP without a library); say so in TUI.md or add a raw ICMP in `labproto::sys`.
5. `scripts/build-userland` does not build `i7labctl`; `scripts/e2e` and `qemu-test` expect `out/bin/i7labctl` (documented at the top of `scripts/e2e`). `scripts/install-ctl` builds it for operators.
6. `build-usb-drive` prints "mtools not installed here: skipped the no-busybox scan of the image" on the operator machine; the build host scan ran (ok).
7. With `--http IP:PORT`, `exec` takes no host argument but `sh` does (found by trial; I7LABCTL.md should say so).
8. Initramfs ships 55 firmware files (1.5 MB) from `linux-firmware` on the build host; the list is whatever `configs/image/firmware.list` finds there (build-initramfs warns when missing).
