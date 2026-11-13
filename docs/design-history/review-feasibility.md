# Review D3: feasibility and completeness of the i7lablinux plan

Reviewer: D3 (adversarial, feasibility/completeness). Date 2026-11-12.
Inputs: `docs/PLAN.md` (authoritative) and every other file in `docs/` (PROTOCOL, I7LABCTL, PROBES, TUI, WEB,
EXPANSION, OPERATOR-NOTES-JETKVM, recon-kernel-toolchain), the scaffold (`crates/*/src`,
`scripts/*`, `configs/*`), and read-only checks on the build host (section C at the end).
Busybox rule: nothing below adds or suggests busybox. Every fix uses our own Rust, or build-host tools that never ship
in the image.

Severity: **B** = blocker (the plan as written cannot meet the brief or the test cannot pass), **M** = major (it works
but leaves a real gap or a lane will stall), **m** = minor (inconsistency or polish).

## Verdict

The architecture is sound and most of the brief is covered. The single registry, the sans-transport `Link` trait,
`UdpLink` for QEMU, the write gate as the only constructor of a writable handle, and GRUB for both firmware modes are
all good decisions. The plan is **not yet executable as written**, for these reasons:

1. The build and stick-writing flow ignores the fact that the operator machine (where the stick and the keys are) cannot compile, and
   the build host (where compiling happens) never receives the keys (F1).
2. The JetKVM requirement added mid-build has no owner, no image-size budget and no test (F2).
3. Some e2e assertions contradict the protocol or the no-applet rule, and would fail even with a correct
   implementation (F19 to F26).
4. The session engine, netlink, FFI and the console/SSE snapshot have no single owner. Two or three lanes would each
   build their own copy (F6 to F9).
5. A read-only key can read the admin key through `/proc`, and `key.set` sends the new key in clear (F31, F32).

Apply the fixes to F1, F2, F6, F7, F19, F20, F21, F31 and F32 before fanning out the lanes.

---

## A. Operator brief, bullet by bullet

| brief bullet | covered in | status | findings |
|---|---|---|---|
| No busybox anywhere | PLAN header, C9, C15, §7 "no applets", `check-no-busybox` | covered | F21 (exec of builtins), F36 |
| Free-standing project, no prototype crate deps | §3 (no crates.io, no the earlier prototype path deps) | covered | - |
| Basic PCIe probing | §4.2 `pci::probe`, `pcie` cmd | covered | - |
| Block enumeration, read AND write tests | §4.2 block, §6 | covered | F14, F21, F22, F23 |
| Write-test safety rule (mounted / partition table / FS signature / boot media; destructive flag + serial) | §6, C7 | covered, matches the rule | F14, F31 |
| Baked-in simple keys, documented, super easy | §5 | covered, but more moving parts than "super easy" | F1, F32, F33 |
| Modern custom-built kernel | §7 (6.18.63 LTS, pinned) | covered | F15, F18 |
| Rust init in initramfs + minimal shell | §4.5, §4.6 | covered | F21, F37 |
| Ether command frames, own ethertype, MAC-addressed, authenticated, no IP, VLAN | PROTOCOL, §4.1 | covered | F6, F20 |
| `i7labctl --ether <mac> --cmd CMD params` | I7LABCTL 2.3 | covered | - |
| `i7labctl discover` (L2 beacons) | PROTOCOL 10, I7LABCTL 3.1 | covered | F25 (shared test socket) |
| Full `i7labctl help` with every command | §4.7, I7LABCTL 3.6 | covered, scope unclear | F29, F30 |
| HTTP debug/API server | C3, C4, C17, §10 | covered | F10 |
| Full-screen ANSI TUI (colour frames, tab, arrows) | TUI.md, C2 | covered | F8, F16, F24 |
| `./scripts/build-usb-drive` compiles, builds, writes the stick | §6 tail, §7 | **not feasible as written** | F1, F3, F5 |
| Documented remote-boot procedure (remove the drive, power cycle, host boots lab linux) | §9 | covered, but the brief's wording is ambiguous, and getting back to the OS is v0.2 | F35 |
| General probing (CPU, mem, thermal, DMI, NICs, USB, SMART, ...) | §4.2 | covered | F34 |
| Web UI / SPA decision | §10 | covered | - |
| Plan to expand | §15 | covered | F28, F30 |
| JetKVM virtual media (OPERATOR-NOTES-JETKVM, added mid-build) | one line in §7 (`.iso`) | **missing** | F2 |

---

## B. Findings

### Build, keys, USB writer

**F1 (B). `build-usb-drive` cannot run end to end on the machine that holds the stick and the keys.**
The keys live in `<repo>/keys` on the operator machine. The rules forbid cargo and rustc on the operator machine. `scripts/remote`
rsyncs with `--exclude keys --exclude out`. So the the build host build cannot bake the real keys, and the operator machine cannot build.
PLAN §5 says "the image bakes them in" without saying where that happens.
*Fix:* split the image into a reproducible, keyless part and a local key overlay:
- the build host builds the image with **no keys**: `initramfs.cpio.zst`, kernel and GRUB, BIOS stage included.
- `build-usb-drive` on the operator machine writes the image, then adds `i7lab/keys.cpio` to the ESP. This is an
  uncompressed newc archive holding `/etc/i7lab/keys/{admin,ro}.key` and `KEYSET-ID`, written by a ~30-line bash
  `cpio_node`-style writer (prior art `build-lib.sh`). No cpio binary is needed.
- `grub.cfg` loads `initrd /i7lab/initramfs.cpio.zst /i7lab/keys.cpio`. GRUB concatenates both, and the kernel
  unpacks concatenated archives even when their compression differs.
- `ALLOW_DEMO_KEYS=1` puts the demo `keys.cpio` in at build time for e2e.

This also gives EXPANSION's "key section is a separate replaceable file" for free, keeps secrets off the build host's shared
tmpfs, and lets `key rotate` rewrite one file on the stick without a rebuild.
The flow becomes `build-usb-drive /dev/sdX --serial S [--build-host the build host|local]`:
1. `scripts/remote -l usb -- scripts/build-image` (skipped with `--no-build` or `--image`)
2. `rsync` `out/*.img` back
3. local safety checks
4. `dd`
5. `sgdisk -e`
6. mount the ESP with sudo (the operator machine has no `mcopy`; checked) or use `mtools` if present, copy `keys.cpio`, unmount
7. read back and verify

Document that local root (sudo) is needed only for steps 4 to 6.

**F2 (B). The JetKVM requirement (`docs/OPERATOR-NOTES-JETKVM.md`) is not in the plan.** It is missing from the work
split, the image layout, the acceptance tests and the remote-boot section.
Its specific requirements are: an image of at most 256 MiB (PLAN §7 gives ~386 MiB), a CD-ROM (El Torito) mode, no
writes to the boot media (PLAN C13 mounts the data partition rw), an `i7labctl jetkvm` group or hwlab integration
with a `lab-boot` verb, and a JetKVM section in REMOTE-BOOT.md.
*Fix:*
- (a) **Image budget.** ESP 64 MiB FAT32 (`mkfs.vfat -F32 -s 1`, still above the FAT32 cluster minimum). No data
  partition in the image file. `build-usb-drive` creates `I7LABDATA` in the free space of the real stick after `dd`
  (sgdisk new partition plus `mkfs.vfat`). Expected image size: kernel ~15 MB + initramfs ~20-40 MB + GRUB, so
  about 70 MiB, well under 256 MiB. Record the measured size in BUILD.md.
- (b) **ISO.** `grub-mkrescue` builds a BIOS+UEFI hybrid ISO from the same ESP tree. It is in P10's deliverables.
  P11 boots it as a USB CD-ROM (F19 step 13).
- (c) **Media writes.** i7labd never mounts the boot media rw by default. The data partition is mounted only by an
  explicit `data.mount` / `--persist` action. Persistence is v0.2 anyway (PLAN §15; PLAN §5 line 534 says v0.3: pick
  one).
- (d) **Power and media control.** Memory says hwlabd on the operator machine already owns the PDU and JetKVMs ("use it, not raw
  curl"), so `i7labctl lab-boot --jetkvm HOST --image PATH` should drive hwlabd (its CLI or API) rather than the
  JetKVM JSON-RPC directly. Assign it to P9 as `cmds/labboot.rs`, behind a `HWLAB=` setting, and write the REMOTE-BOOT
  JetKVM section in P10. Ask the operator to confirm hwlabd as the integration point (open decision 8, section D).
- (e) **Gate on JetKVM media.** The write gate must treat a JetKVM Disk-mode device as boot media (it carries the same
  PARTUUID) and a CD-mode `sr0` as read-only, which already means refused.

**F3 (M). BIOS stage: "needs a loop device (sudo) or the real target device; an image built without root is UEFI-only".**
C10 lets the default image silently lose BIOS boot. Checked on the build host: `grub-bios-setup` is not installed,
`grub-install` and `losetup` exist, and `sudo -n` works.
*Fix:* make BIOS mandatory in the default image, and install it without root:
1. `grub-mkimage -O i386-pc -p '/boot/grub' biosdisk part_gpt fat search_fs_file normal linux serial terminal configfile echo -o core.img`
2. `dd` `boot.img` bytes 0..439 into LBA 0, keeping the partition table.
3. Patch the u64 at boot.img offset 0x5c with the LBA of p1.
4. `dd` core.img into p1.
5. Patch the diskboot blocklist (first sector of core.img, last 12 bytes: start LBA u64 = p1+1, length u16 =
   sectors-1, segment u16 = 0x820).

This is about 40 lines of bash, root-less and reproducible. It is exactly what grub-bios-setup does. Fall back to
`sudo losetup` + `grub-install --target=i386-pc` only if the patch fails the SeaBIOS e2e. The image build fails
(instead of quietly producing UEFI-only) when the BIOS stage cannot be installed, unless `--no-bios` is given.

**F4 (M). BIOS boot of a GPT stick on real legacy firmware.** Many older Lenovo, HP and Dell BIOSes will not boot a
USB disk whose MBR has no active partition entry. A pure protective MBR has none.
*Fix:* a build option `PMBR_ACTIVE=1` (default on) sets byte 0x80 on the protective MBR entry (offset 446). It is not
strictly UEFI-spec, but it is the widely used compromise. List "BIOS host refuses stick" in REMOTE-BOOT.md caveats
with the `PMBR_ACTIVE=0` alternative, and test both on the one BIOS-only lab host in the hardware checklist.

**F5 (M). `build-usb-drive` "refuses non-removable devices unless `--nvme`".** USB SSD enclosures and many USB 3
sticks report `removable=0`. The operator would have to pass `--nvme` for a USB device, which is misleading.
*Fix:* accept when `transport == usb` (sysfs path through a USB host controller) whatever `removable` says. Require
`--internal` only for non-USB transports. Keep the serial match and the typed confirmation.

### Work split, ownership and interfaces

**F6 (B). The session engine (handshake, reliability, streams, idempotence) is implemented twice.** P6 writes the
server and P9 writes the client, over P1's primitives. This is the hardest and most bug-prone code in the project.
Acceptance test 2 (client and server over `MemLink` with 10 % loss) has no owner, because it needs both halves.
*Fix:* P1 owns a new `labproto::session` module with sans-IO `ClientSession` and `ServerSession` state machines.
Their API is `on_frame(&[u8], now) -> Vec<Action>`, `poll(now) -> Vec<Action>`, `send_req(..)` and
`on_data(..)`, with an injected clock. P1 also owns acceptance test 2. P6 and P9 only drive these state machines over
`Link`, with threads and sinks. This removes 1.5 to 2k lines of duplicated logic and makes the loss/reorder test a
pure unit test.

**F7 (B). `labproto::sys` is owned by P2, but every lane needs FFI.** PLAN line 327 says "add what you need", which
would be an edit of P2's file. Lanes block on each other or each writes its own `extern "C"`.
*Fix:* P2 delivers, in its first push, an agreed list of safe wrappers:
- tty and process: termios get/set, `TIOCGWINSZ`, `TIOCSWINSZ`, `TIOCSCTTY`, openpty, setsid, poll, pipe2,
  sigaction (flag-only handler), kill/killpg, waitpid, dup2
- block and file: `BLK*` ioctls (`BLKGETSIZE64`, `BLKSSZGET`, `BLKPBSZGET`, `BLKROGET`, `BLKFLSBUF`, `BLKRRPART`),
  `SG_IO`, `NVME_IOCTL_ADMIN_CMD`, `O_DIRECT` open flags, aligned buffer helper, flock, `FS_IOC_GETFLAGS`/`SETFLAGS`
  (efivars)
- sockets and net: `SIOCETHTOOL`, socket/bind/sendto/recvmsg with cmsg
- console and misc: `KDSETLED`/`KDSKBLED` (identify), `VT_ACTIVATE`, `klogctl`, getrandom, statfs, mount/umount,
  reboot, finit_module, kexec_file_load

Until that lands, lanes put private FFI in `crate::ffi` (crate-private, not exported) and migrate later. State this
rule in §12.

**F8 (M). No owner for the shared snapshot and event bus used by the TUI, SSE, beacon `state` and `attention`.**
P5 (TUI) and P7 (`/api/v1/events` SSE) both need a 2 s overview snapshot, audit tail, session list, protocol stats,
job progress and `msg` / `tui tab` / `identify` events. `Daemon` (§4.4) has no field for any of these. The TUI-facing
handlers `cmds/console.rs` (`msg`, `tui`, `identify`) are owned by P6, but their effect lives in P5's `console.rs`.
*Fix:* P6 adds to `daemon.rs`:
- `pub snapshot: Snapshots` (an `Arc<Snapshot>` swapped every 2 s by a P6 thread, holding labprobe summaries,
  attention list, NIC/IP, sessions, stats)
- `pub events: EventBus` with `subscribe() -> Receiver<Event>`, where `Event` is one of `Audit`, `Job`, `Msg(String)`,
  `TuiTab(String)`, `Identify(Duration)` and `Link`

P5 and P7 only consume them. Freeze these types in the scaffold now, as was done for `Registry`.

**F9 (M). No owner for netlink.** P6 `netcfg` needs RTM_NEWADDR, RTM_NEWROUTE and RTM_NEWLINK with VLAN linkinfo.
P8's `ip` builtin needs addr/link/route show/set/add/del. P3's net probe needs RTM_GETADDR/GETROUTE. Three lanes would
write three netlink encoders.
*Fix:* add `labproto::netlink` (owned by P2, next to `packet`) with `get_links`, `get_addrs`, `get_routes`,
`add/del_addr`, `add/del_route`, `link_set_up/down`, `add_vlan(parent, vid)` and `del_link`, plus encoder tests from
captured byte vectors. Do the same for ethtool: `labprobe::net` (P3) exposes `ethtool_*` helpers that P6 uses for
`identify` (`ETHTOOL_PHYS_ID`).

**F10 (M). HTTP mapping of byte streams.** C17 makes every streaming command chunked NDJSON. `get` and `put` of a
multi-GiB file as base64 NDJSON is slow and memory-hungry, and `Sink::data(Chan::File)` has no defined HTTP form.
*Fix:*
- `get` over HTTP is `GET /api/v1/file?path=..&offset=..&len=..`, returning a raw `application/octet-stream` body with
  `X-Sha256` as a trailer, or in a following `fs.stat` call.
- `put` is `PUT /api/v1/file?path=..&mode=..` with a raw body and the `X-Lab-Auth` body hash over the streamed body.
  This needs a streaming SHA-256 in the auth check, which P1's `Sha256` supports.
- NDJSON stays for exec, logs and blk progress.

Write this into C17 so P7 and P9 agree.

**F11 (M). The local socket protocol (`/run/i7lab/ctl.sock`) is unspecified.** P8's `lab` builtin cannot be written.
*Fix:* reuse the ether REQ body encoding. Each request is one message: `u16 cmd id | argv codec`, and the reply is
`u16 status | i32 exit | JSON/bytes`, length-prefixed (u32). Role = admin, `Source::Local`, authorised by
`SO_PEERCRED` uid 0. P6 owns the server and P8 the client. Both sides use `labproto::args`.

**F12 (M). Ownership gaps in tests and fixtures.** P3 owns `tests/fixtures/` but not `crates/labprobe/tests/*.rs`
(only P4's `block_*.rs` is listed). Acceptance test 3 asks for fixture trees from "at least one Intel and one AMD lab
host", but nobody has a tool to capture a sysfs tree. Sysfs cannot simply be tarred: attributes report size 4096, and
it contains symlinks and unreadable files.
*Fix:*
- P3 owns `crates/labprobe/tests/probe_*.rs`.
- P3 also owns a new `scripts/capture-fixture`: bash with `find` and `cat`, a read-only allow-list of paths, symlinks
  recorded as files, serials scrubbed. P3 runs it read-only on the operator machine (Intel) and the build host (AMD EPYC, if so) and commits
  the scrubbed trees.
- Later, real lab hosts provide trees via `i7labctl exec` with a builtin `capture` (v0.2).

**F13 (m). Cmdline parsing is duplicated.** `i7lab-init/cmdline.rs` (P2) and `i7labd::Config::load(cmdline)` (P6)
both parse `i7lab.*` arguments.
*Fix:* put one quote-aware tokenizer in `labproto::cmdline` (P1 or P2) and use it in both.

**F14 (M). The write gate's "already under test" lock and the audit log are in-process only.** `i7labsh blk write`
must work with i7labd dead (it is the fallback shell). An in-memory lock in i7labd does not stop a concurrent write
from i7labsh, and an audit log written only by i7labd misses writes made from the shell.
*Fix:*
- `WriteGuard::acquire` takes `flock(LOCK_EX|LOCK_NB)` on `/run/i7lab/blk/<devname>.lock`, alongside the `O_EXCL` open
  (which is cross-process already).
- `labprobe::block::audit_write(...)` appends one line to `/run/i7lab/audit.log` with `O_APPEND`, so both binaries log.

### Kernel and boot

**F15 (M). UEFI console video: the TUI can be invisible on real UEFI hosts.** GRUB EFI without a video module may
hand the kernel no GOP framebuffer. Then efifb/simpledrm never appear, and the screen is blank after GRUB.
*Fix:* the GRUB EFI image includes `all_video` (`efi_gop`, `efi_uga`), and `grub.cfg` sets `gfxpayload=keep` before
`linux`. Pick one fbdev path to avoid double framebuffers: `SYSFB_SIMPLEFB` + `DRM_SIMPLEDRM` + `DRM_FBDEV_EMULATION`,
with `FB_EFI` off. Keep `VGA_CONSOLE=y` for BIOS text mode, because `vesafb` needs a `vga=` mode that GRUB does not set
by default. Add an e2e check that `/sys/class/graphics/fb0` exists under OVMF.

**F16 (m). Kernel messages corrupt the TUI.** With `console=tty0` and `loglevel=4`, warnings (USB disconnects, AER)
print over the TUI frame.
*Fix:* i7lab-init lowers the console level with `klogctl(SYSLOG_ACTION_CONSOLE_LEVEL, 1)` once the TUI is up. The
debug entry keeps 7. The TUI redraws on Ctrl-L anyway.

**F17 (M). `efivarfs` is mounted read-only (PLAN §4.5), but `reboot --uefi` (OsIndications) and `--to-os`
(BootNext) need to write it.**
*Fix:* i7labd remounts efivarfs rw only inside these handlers (`MS_REMOUNT`), writes with attributes
NV|BS|RT (`0x07`), and remounts ro. labprobe::firmware (P3) gets `set_boot_next(u16)` and `set_os_indications(u64)`.
Writing a new variable needs no immutable-flag change. Document the "internal OS entry" heuristic: the first
`BootOrder` entry whose device path is not USB and is not `BootCurrent`.

**F18 (m). Kernel config fragments are empty except `00-core` and `10-net`.** This is fine for the scaffold, but the
recon list is long and some symbol names are unverified. Budget P10 for 3 to 5 config iterations on the build host, at 2 to
4 minutes each. Add one more symbol check: every NIC driver in the hardware list must be `=y`, and the build fails if
not. This catches a silent drop of R8169 or IGC, which would make a lab host unreachable (F31).

### QEMU end-to-end test (PLAN §14)

Checked on the build host: QEMU 10.2.1, `-netdev dgram`, `tap` and `stream` available, `/dev/kvm` group `kvm` (user `it` is
a member), passwordless sudo, no QEMU guests running. **Raw L2 control end to end is possible on the build host without root**
(dgram), and **with AF_PACKET and VLAN using sudo** (tap). The issues are in the details:

**F19 (B). The OVMF path is wrong.** `/usr/share/ovmf/` is empty on the build host. The firmware is at
`/usr/share/qemu/OVMF.fd` and `/usr/share/OVMF/OVMF_CODE_4M.fd` + `OVMF_VARS_4M.fd`.
*Fix:* use pflash, which is needed anyway for `--to-os` and BootNext tests that persist variables across a reboot:
`-drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd -drive if=pflash,format=raw,file=$EV/vars.fd`,
where `vars.fd` is a copy of `OVMF_VARS_4M.fd`. `qemu-test` should discover the firmware path and fail clearly if it
is missing.

**F20 (B). Step 3, "with a wrong key exits 5", contradicts PROTOCOL 4.1.** A host silently drops a HELLO with an
unknown key id, so the client times out and exits 4.
*Fix:* define the client behaviour, then test it:
- If the target's beacon is in the registry and its `kid` lists no local key id, i7labctl exits 5 (`E_AUTH`, "host
  uses another key set: kid=a:..,r:..") without sending.
- With no beacon known (bare `--ether`), a HELLO timeout exits 4 with the hint "no CHALLENGE: wrong key set or host
  unreachable".

The e2e asserts exit 5 after a `discover` run, and exit 4 with `--no-registry`.

**F21 (B). Step 6, `exec -- mount /dev/vdb1 /mnt`, cannot work.** `exec` runs argv directly (C15), and there is no
`/bin/mount` (no applets, by the busybox rule). Also, the previous sub-step wrote over `vdb`, which destroys its GPT,
while the kernel still has a stale `vdb1` until a re-read.
*Fix:* use `exec -- i7labsh -c 'mkdir -p /mnt && mount /dev/vdc1 /mnt'` on a **separate** GPT+ext4 disk `vdc`
(serial `I7VIRT0003`), and assert `Mounted` on `vdc` with flags. `blk.write` should issue `BLKRRPART` after a write
that destroyed a partition table, so `blk.ls` reflects reality. In I7LABCTL `exec`, add a convenience: when argv[0]
is an i7labsh builtin and there is no such file in PATH, the client prints "`mount` is an i7labsh builtin: use
`exec -- i7labsh -c '...'` or `i7labctl sh H 'mount ...'`". Add a `sh` alias subcommand that wraps
`exec -- i7labsh -c`.

**F22 (M). Step 5 relies on device names that QEMU does not guarantee.** `vd0` sits on `rp2` (secondary bus) and `vd1`
on bus 0. Bus-0 devices usually probe first, so `vd1` (the GPT image) may become `vda`.
*Fix:* every e2e assertion selects disks by **serial** from `blk ls --json`, never by name. This is also the habit the
operator needs on real hosts.

**F23 (M). Serial sources for USB disks.** QEMU's `usb-storage,serial=` sets the USB iSerial string. The SCSI VPD page
0x80 under it can be empty, and many real USB sticks and enclosures have no VPD 0x80 either. NVMe serials are
space-padded to 20 characters.
*Fix:* P4's serial resolution order is NVMe `device/serial` (trimmed), then VPD 0x80 (trimmed), then ATA IDENTIFY
(SAT), then the USB iSerial of the ancestor USB device, then WWID. The resolved `serial_source` goes into
`BlockDevice` and is shown in `blk ls`. The e2e asserts that the stick resolves `I7STICK0001` through `usb`.

**F24 (M). Step 10, the TUI over serial, is brittle and needs a GRUB entry nobody selects.** A diff renderer emits
cursor moves, so `[Storage]` does not appear contiguously in raw serial bytes. Choosing GRUB entry 2 needs serial
keystrokes.
*Fix:*
- (a) Add an R command `tui.dump` (new id 0x0083) that returns `Buffer::to_text()` of the current console frame. It is
  also very useful to a remote operator on day one, as a text screenshot.
- (b) For the serial boot, `qemu-test` writes a test copy of the image with `set default=1`, or boots with
  `-kernel/-initrd/-append`, which is enough to test the TUI.
- (c) Assert on `tui.dump` output, not on serial bytes.

**F25 (M). Several i7labctl processes cannot share one dgram link.** The dgram netdev is point-to-point. Only one
process can bind `$HP`, so `discover --watch` or `wait` cannot run next to a command, and step 11 (`reboot --wait`)
plus a parallel watcher conflict.
*Fix:* use QEMU's multicast dgram form (`remote.type=inet,remote.host=239.255.71.1,remote.port=$P`, no local) and have
`UdpLink` join the group with `SO_REUSEADDR`. Several clients then see the same segment. Pick ports from a per-label
hash so lanes running e2e at the same time do not collide. VLAN tagging (`--vlan 13`) also works over dgram without
root, because the guest sees an in-band 802.1Q tag. Only the "kernel sub-interface" case needs the tap scenario.

**F26 (M). Step 3's replay helper (`i7labctl ether frame --replay`) is not in I7LABCTL or in P9's deliverables.**
Step 6 must also exercise the **server** gate, not a client-side pre-check.
*Fix:* add the hidden `ether replay --capture N` test subcommand (or the env var `I7LABCTL_TEST_REPLAY=1` that re-sends
the last REQ frame verbatim) to P9's list. In e2e, send refusal cases with the raw `--cmd blk.write ...` form, which
must not pre-validate.

**F27 (m). The plan lacks e2e steps for the JetKVM and Secure Boot cases.**
*Fix:* add to §14:
- 13: boot the ISO as a USB CD-ROM (`-device usb-bot,id=cd -device scsi-cd,bus=cd.0,drive=iso`) under OVMF and
  SeaBIOS, and assert the beacon arrives and `blk ls` shows `sr0` Refused.
- 14 (optional, negative): boot the stick under `OVMF_CODE_4M.secboot.fd` + `OVMF_VARS_4M.ms.fd`, and assert that the
  serial log shows no kernel start within 60 s. This documents the "Secure Boot must be off" claim with evidence.

### Effort and sequencing

**F28 (M). Effort per lane.** Estimates in non-test lines, from the scaffold signatures and the doc scope:

| lane | scope as planned | estimate | realistic for one agent pass? | fix |
|---|---|---|---|---|
| P1 proto-core (opus) | crypto, json, text, keys, catalog, args, frame, handshake, replay, reliable, beacon, httpauth | 3-4k + tests | yes; with `session` (F6) ~5k, still OK for opus | take `session` + loopback test |
| P2 sys-net + init (sonnet) | FFI, AF_PACKET+BPF, links, PID 1 port | 2.5-3k (+0.6k netlink) | yes, if the FFI list is fixed early (F7) | first push = FFI list |
| P3 probes (sonnet) | 12 probes, DMI decoder, pci.ids subset, fixtures | 4-5k | borderline | v0.1 depth: DMI types 0,1,2,3,4,16,17 only; ASPM/SR-IOV/ACS later |
| P4 block (opus) | enum, GPT/MBR, ~15 signatures, gate, engine, SMART ATA+NVMe | 4k | yes | loop/mount tests run with sudo on the build host as `#[ignore]` tests invoked explicitly; file tests must tolerate `O_DIRECT` EINVAL on tmpfs (the build host `/tmp` is tmpfs) |
| P5 tui (sonnet) | renderer + 8 pages + actions | 3.5-4k | borderline | v0.1 pages: Overview, PCIe, Storage, Network, Log, About; Actions = reboot/poweroff/shell only |
| **P6 agent core (opus)** | registry + ~35 handlers + ether server + exec/pty + jobs + beacon/hints + DHCP port + netcfg/VLAN + localsock + audit + snapshot | **8-10k** | **no** | split: **P6a** registry, handlers, exec/pty, jobs, audit, localsock, snapshot/events (F8); **P6b** ether server over `labproto::session`, beacon/hints, DHCP, netcfg over `labproto::netlink` |
| P7 http + web (sonnet) | HTTP/1.1, nonce HMAC, API, NDJSON, SSE, SPA with JS SHA-256 | 3k | yes | - |
| P8 shell (sonnet) | parser, pipes, ~60 builtins, line editor | 4-5k | borderline | builtins that duplicate labprobe (lspci, lsblk, lsusb, sensors, probe) are thin wrappers; `ip` over `labproto::netlink` (F9) |
| P9 ctl (opus) | ~40 subcommands, help, completions x4, registry, discover, ether client, http client, fleet tui, web, image, ssh | 6k+ | no, as listed in I7LABCTL | v1 list = F29; client session from `labproto::session` (F6) |
| P10 build (sonnet) | kernel, initramfs, GPT, GRUB x2, ISO, USB writer, gen-keys, docs | 1.5k bash + iterations | yes | add F1/F2/F3 work explicitly |
| P11 e2e (sonnet) | §14 | 0.8k + debugging | only after integration works | see F28b |

**F28b (M). There is no integration milestone and no integration owner.** Eleven lanes stub against frozen signatures
and P11 "runs last". The first real boot would then surface every cross-lane mismatch at once.
*Fix:* define **M0, a vertical slice**, before the wide fan-out finishes:
- P10: the kernel with 00/10 fragments plus a minimal initramfs.
- P2: init brings `lo` up and execs i7labd.
- P6b: beacons plus `ping`/`id` over `labproto::session`.
- P9: `discover` + `--ether .. --cmd ping` over `UdpLink`.
- P11 runs steps 1 to 3 in QEMU.

Name one integrator (D1, or P11 from day one) who keeps `cargo test --workspace` and the M0 e2e green on the build host
after every lane push.

### i7labctl scope and help

**F29 (M). The v1 subcommand list is undefined.** P9's deliverable is "all subcommands of I7LABCTL.md section 3 that
v1 serves". I7LABCTL still lists `ssh`, `--ssh`, `svc sshd` (removed by C9), `image build|write|info|verify`
(duplicates P10's scripts), `web` (v0.5), `tui` fleet dashboard, completions for powershell/fish, and inv sections
`sys,board,bios,...` (replaced by C5).
*Fix:* add to PLAN §4.7 the exact v1 list:
- discovery and inventory: `discover ls ping id inv pcie usb thermal logs net blk`
- execution and files: `exec sh shell put get fs jobs`
- power and lifecycle: `reboot poweroff wait identify msg tui(dump/tab)`
- keys and test: `key init|show|verify|import|export`, `ether cmds|probe|hello|sniff|frame|replay`
- help and output: `api help version completions bash`

Everything else answers `UNSUPPORTED (planned vX.Y)`.

**F30 (m). `help` would advertise commands that return UNSUPPORTED.** Examples: `kexec`, `key.set`, `reboot --to-os`
and `svc`, which are in `CATALOG` but are v0.2 to v0.4 work.
*Fix:* add `since: &'static str` (or `planned: bool`) to `CmdSpec`. `i7labctl help` and the SPA mark planned commands
`(planned v0.4)`, and the TUI Actions menu hides them. This keeps the "full help with every command" honest.

### Security findings that affect the plan

**F31 (B, security). A read-only key can read the admin key.** The `get`/`fs.*` read-only allow-list includes
`/proc` and `/sys` (PROTOCOL §7, `RoLimitedPaths`). Two paths escalate:
- `get /proc/self/root/etc/i7lab/keys/admin.key` (or `/proc/1/root/...` or `/proc/self/cwd/...`) resolves through
  magic links to the key file.
- `get /proc/self/mem --offset <addr>` reads i7labd's own memory.

So the ro key, which I7LABCTL §7 says "is meant to be shared", is effectively an admin key.
*Fix:* `ro_path_allowed` checks the **resolved** path. Open with `openat2(RESOLVE_NO_MAGICLINKS|RESOLVE_BENEATH)` from
an allowed root dir fd (Linux 5.6+, fine on 6.18), or `realpath` and re-check. Deny `/proc/*/{mem,root,cwd,exe,fd,
fdinfo,map_files,environ,pagemap,kcore}`, `/proc/kcore` and `/sys/firmware/efi/efivars` for ro. Add host tests with
exactly these paths to acceptance test 7 / the P6 test list.

**F32 (B, security). `key.set <role> --hex HEX` sends the new key in clear.** The protocol has no confidentiality
(PROTOCOL §1), so a passive listener captures the new admin key during a rotation.
*Fix:* for v1, drop `key.set` (rotate by rewriting `keys.cpio` on the stick, which F1 makes a one-file change). Or wrap
the new key: `new XOR HMAC-SHA256(SK, "i7c-keywrap\0" | req_id | counter)` keystream with a tag over the plaintext.
That is 20 lines with the existing primitives. Do not ship `key rotate` until one of these exists.

### Day-one operator gaps

**F33 (M). There is no install path for `i7labctl` on the operator machine.** It is built on the build host. The operator needs it on PATH
with `cap_net_raw`, and with the key dir set up.
*Fix:* add `scripts/install-ctl`, owned by P10. It builds on the build host (static musl) through `scripts/remote`, fetches
`out/i7labctl`, installs it to `~/bin`, runs `sudo setcap cap_net_raw+ep`, and runs `i7labctl key show` as a check.
QUICKSTART in README: `gen-keys`, then `install-ctl`, then `build-usb-drive`, then `discover`.

**F34 (M). A host whose NIC has no driver is unreachable, and nothing says so.** Neither ether nor HTTP works without a
driver. This is the most likely day-one failure on new lab hardware (RTL8126, odd Intel, Aquantia, Marvell).
*Fix:*
- `labprobe::pci` flags network-class (0x02) devices with no bound driver.
- The TUI Overview shows a red "NO CONTROL PATH: no usable NIC (unbound: 10ec:8126 at 03:00.0)" banner.
- The beacon-less boot leaves the console shell open.
- REMOTE-BOOT.md tells the person at the machine to plug in a USB Ethernet adapter. `r8152`, `ax88179_178a` and
  `cdc_ether/ncm` are already `=y` in the recon list. Memory notes an AmazonBasics USB NIC was ordered for exactly
  this.
- The supported NIC list goes in BUILD.md.

**F35 (M). The remote-boot procedure: the brief's wording is ambiguous, and getting back is v0.2.** The brief says
"instruct a user to remove the drive and power cycle, the host boots lab linux". PLAN §9 reads this as either "use the
boot menu" or "remove the internal drive". If the stick stays in the machine (procedure A), the host can only return
to its installed OS with `reboot --to-os`, which is v0.2 (UEFI) or v0.4 (BIOS). On day one, a stick-resident host is
therefore stuck in lab linux unless someone pulls the stick.
*Fix:*
- (a) Confirm the reading with the operator (open decision 9). Make "remove the internal drive, power on, the
  firmware falls back to the USB drive" step B1, with the exact phrases to read out, and "reinsert the drive, run
  `i7labctl poweroff H`, power on" as its inverse.
- (b) Pull `reboot --to-os` for UEFI (BootNext, F17: ~150 lines in labprobe::firmware + handler) into v0.1.
- (c) BIOS: GRUB entry 5 needs a keyboard. Document that BIOS hosts return to the OS only by pulling the stick until
  v0.4.

**F36 (M). Day one needs the tools that are not builtins.** "Do pretty much anything" means `lspci -vvv`-level detail,
`ethtool`, `nvme-cli`, `fio` and `stress-ng` equivalents are sometimes needed. The image deliberately has none, and
`#!/bin/sh` scripts fail (there is no `/bin/sh`).
*Fix:* document the supported escape hatch:
1. `i7labctl put H ./static-tool /run/bin/tool --mode 0755`
2. `i7labctl exec H -- /run/bin/tool ...`
3. optionally `/data/bin` on the stick's data partition, added to PATH when the operator mounts it.

The busybox ban applies to these operator toolboxes too, and `check-no-busybox --dir` can check a toolbox dir. State
in KEYS/REMOTE-BOOT docs that there is no POSIX `/bin/sh`.

**F37 (m). Further day-one conveniences missing from v0.1:**
- **Host aliases.** `~/.config/i7labctl/aliases` (`m900 = 00:1f:..`), resolved by the host selector.
- **Visibility when i7labd never starts.** Optionally `CONFIG_NETCONSOLE=y` with an `i7lab.netconsole=` passthrough,
  or a kmsg-in-beacon tail: the beacon carries the last kernel error line, and `ls` shows it.
- **Clock.** `ping` already returns the host time. Add `time.set` (signed, through ether) to v0.1 so audit timestamps
  mean something before SNTP (v0.3).
- **Init fallback shell versus i7labd.** When i7labd recovers after the fallback `i7labsh` took tty1, init must
  restart i7labd with the TUI disabled (`I7LAB_TUI=off`) so the two do not fight over tty1. Specify this in §4.5.

### Documentation drift (PLAN wins, but implementers read the notes)

**F38 (M). The design notes contradict PLAN in many places, and each lane is told to use them "as detailed reference".**
- PROTOCOL §11 uses `/nonce` and `/health` (vs C3 `/api/v1/nonce`).
- PROTOCOL §7 `inv --section sys,board,...` (vs C5).
- WEB.md uses a bearer token, `POST /api/v1/cmd {"cmd","args":{}}`, confirm tokens, and `ui.html` under `ui/` (vs C3,
  C4, C6, `web/index.html`).
- PROBES.md has `probe <name>`, `disktest`, `--i-understand-this-destroys-data`, label `I7LABBOOT`, and DHCP in init
  (vs C4, C7, C8, C11).
- TUI.md describes a separate `i7lab-tui` binary and "retype last 4 serial characters" (vs C2; the serial rule should
  be stated for the TUI).
- EXPANSION has `labcrypto`, `i7lab-tui`, `labtests` crates, "BIOS unsupported" and `kernel/` paths (vs C1, C10,
  `configs/kernel`).
- I7LABCTL: see F29, plus the `ssh_ed25519` path vs §5 `ssh/operator_ed25519`.
- Watchdog is armed in §4.5 (v0.1) but listed as v0.3 in §15.

*Fix:* D1 adds a three-line banner under each note's title: "Superseded by PLAN.md §1 on: C3, C4, ... Read PLAN first."
Fix the two in-PLAN inconsistencies (watchdog version, persist version). The TUI write dialog asks for the full
serial, pre-filled from the probe but not auto-confirmed, so the brief's "device serial given" stays true from the
console too.

---

## C. Checks run for this review

All read-only. No builds and no guests.

| command | result |
|---|---|
| `ssh the build host 'qemu-system-x86_64 --version; qemu-system-x86_64 -netdev help'` | QEMU 10.2.1; netdevs `socket stream dgram hubport tap passt user l2tpv3 bridge vhost-user vhost-vdpa` |
| `ssh the build host 'ls /usr/share/ovmf /usr/share/OVMF /usr/share/qemu'` | `/usr/share/ovmf` empty; `OVMF_CODE_4M.fd`, `OVMF_VARS_4M.fd`, `.ms`, `.secboot` variants in `/usr/share/OVMF`; `/usr/share/qemu/OVMF.fd` present (F19) |
| `ssh the build host 'ls -l /dev/kvm; id; sudo -n true'` | `/dev/kvm` root:kvm 0660, user `it` in `kvm`; passwordless sudo works |
| `ssh the build host 'which grub-install grub-mkimage grub-mkstandalone grub-mkrescue grub-bios-setup losetup mcopy sgdisk xorriso'` | all present except `grub-bios-setup` (F3); `/usr/lib/grub/{i386-pc,x86_64-efi}` present |
| `ssh the build host 'pgrep -c qemu-system'` | 0 |
| `which mcopy sgdisk grub-install cpio zstd mkfs.vfat` on the operator machine | `mcopy` missing; others present (F1) |
| scaffold read | `labproto::link::UdpLink`/`MemLink` exist; `CATALOG` has 35 entries incl. `kexec`, `key.set`, `reboot --to-os`, `tui`; kernel fragments 20..90 empty; all `scripts/*` except `remote` are `not_implemented` stubs |

## D. Open decisions this review adds for the operator

8. JetKVM driven through hwlabd (recommended) or directly by i7labctl (F2d).
9. The meaning of "remove the drive and power cycle": the internal OS drive (recommended reading) or something else,
   such as netboot (F35).
10. `key.set` dropped from v1, or key-wrap added (F32).
11. `PMBR_ACTIVE=1` default for legacy BIOS compatibility (F4).
