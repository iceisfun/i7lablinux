# EXPANSION: roadmap, packaging and project hygiene

> **Superseded by docs/PLAN.md (authoritative) on:** PLAN.md C1 (seven crates; no `labcrypto`, `i7lab-tui`, `labtests`), C10 (BIOS supported, mandatory), C19 (keys as a separate `keys.cpio` overlay), paths `configs/kernel` (not `kernel/`), section 15 (roadmap and v1 cut lines). Read PLAN.md first; where this note disagrees, PLAN.md wins.


Status: design (R4). Everything here is a proposal except where it says "operator decision".
Hard rule carried through every version: no busybox. Every userland tool in the image is our own Rust
(builtins in `i7labsh`, or a small own binary), the image build does not fetch or compile busybox, and no
document lists it as a dependency.

## Name

Working name: **i7lablinux** (the repo directory). Operator decision needed on the public name.
Options: keep `i7lablinux`; or a neutral name such as `labboot` / `rackstick` / `stickd`, since "the earlier prototype"
is the operator's other project and this repo is meant to stand alone. Binaries keep the short prefix
`i7lab-*`/`i7labctl` for now (renaming is a mechanical change if the operator picks a new name: the prefix
lives in one `names.rs` constants file and in the script header). Crates: `labproto`, `labprobe`, `labcrypto`, `labtui`,
`i7lab-init`, `i7labsh`, `i7labd`, `i7labctl`, `labtests`.

## Licence options (operator decision)

| option | consequence |
|--------|-------------|
| MIT | Shortest, maximum reuse; no patent grant. |
| Apache-2.0 | Includes patent grant and clear contribution terms; NOTICE file; slightly heavier. |
| MIT OR Apache-2.0 (dual, the Rust ecosystem norm) | Recommended default. Users pick; compatible with almost everything. |
| No licence (all rights reserved) | Legally nobody else can use or contribute; fine while private, wrong for a published repo. Must be chosen consciously. |
| GPL-2.0 | Matches the kernel but forces copyleft on derived tooling; not recommended for a lab tool people may embed. |

Note: the image itself contains the Linux kernel (GPL-2.0-only). Distributing the image binaries needs the
corresponding kernel source offer: the release page links the exact kernel tarball URL + our config + patches
(satisfies the written offer by hosting them). Our Rust userland licence is independent of the kernel's. Firmware
blobs (`linux-firmware`) have their own redistribution licences: do not bundle them in v0.1; list the NIC firmware
needed per driver and make the builder optionally include it from a local checkout the operator provides. The embedded `pci.ids`/`usb.ids`
subsets are under BSD-3-Clause or GPL-2.0-or-later (dual) and the notice goes in `THIRD_PARTY.md`.

## Repository layout

```
i7lablinux/
  Cargo.toml                 workspace
  crates/
    labproto/                command table, L2 frame format, JSON writer/parser, action/confirm types
    labcrypto/               SHA-256, HMAC-SHA256, Ed25519 verify, ChaCha20-Poly1305 (own, test-vectored)
    labprobe/                all probes (PROBES.md)
    labtui/                  renderer library (TUI.md)
    i7lab-init/              PID 1: mounts, modules, net bring-up, DHCP client, SNTP, watchdog, supervises daemons
    i7labsh/                 minimal shell with builtins (cat ls cp mv rm mkdir mount umount ip dmesg ps kill ... )
    i7labd/                  L2 listener + HTTP server + job runner + embedded UI
    i7labctl/                host-side client (discover, --ether, --http, tui, image-recv, update...)
    i7lab-tui/               console UI binary
  kernel/
    config/                  kernel .config fragments (base + per-feature), `defconfig` generation script
    patches/                 (empty by default)
    VERSION                  pinned kernel version + sha256 of the source tarball
  scripts/
    build-usb-drive          compile + build + write a USB drive
    build-image              produce lab.img (disk image) and lab.iso (optional)
    gen-keys                 generate keys (never commits secrets)
    boot-qemu                run the image in QEMU for tests
    check-no-busybox         CI guard: fails if the string/binary appears anywhere in the image or tree
  docs/                      PROBES.md TUI.md WEB.md EXPANSION.md KEYS.md PROTOCOL.md BUILD.md REMOTE-BOOT.md
  tests/                     integration tests (QEMU), fixtures
  data/                      pci.ids.subset, usb.ids.subset
  .github/workflows/         CI
  LICENSE-*, THIRD_PARTY.md, CHANGELOG.md, README.md
```

The repo must not depend on any prototype crate. Prior art (lab-init, lab-proxy) is copied in and
adapted, with the busybox-using parts replaced by builtins. The origin of copied files is noted in commit
messages (not in code comments) and in `THIRD_PARTY.md` if the licence differs.

## Versioning

- SemVer for the whole project, one version for image + tools (`0.x.y` until the protocol is frozen).
- Wire protocol versioned separately (`proto=1` in the beacon and in every frame header); an `i7labctl`
  of version N must talk to images of N-1 and N+1 within the same proto number; incompatible changes bump proto.
- Image name: `i7lablinux-<version>-<gitsha7>-x86_64.img`. The build id (git sha + kernel version + dirty flag)
  is printed in the TUI, the beacon, the HTTP `hello` and the `About` page.
- `CHANGELOG.md` in "Keep a Changelog" form; tags `v0.1.0`.

## Reproducible builds

Goal: the same git commit, kernel tarball hash and toolchain produce a bit-identical image.

- Pinned Rust toolchain (`rust-toolchain.toml`), `Cargo.lock` committed, `--locked`, `--frozen` in CI.
  Build with `RUSTFLAGS="--remap-path-prefix=$PWD=/src -C strip=symbols"`, `-C codegen-units=1`, fixed
  `CARGO_INCREMENTAL=0`.
- Pinned kernel version + sha256, `KBUILD_BUILD_TIMESTAMP=@$SOURCE_DATE_EPOCH`, `KBUILD_BUILD_USER=lab`,
  `KBUILD_BUILD_HOST=lab`, pinned `gcc` version (CI uses a fixed container image digest).
- initramfs assembled by our own `mkcpio` (Rust, in the scripts dir as a `cargo xtask`-like binary): sorted entries,
  uid/gid 0, mtime = `SOURCE_DATE_EPOCH`, no host dependencies, deterministic compression (one fixed
  zstd/xz level; or none, since the kernel image is XZ-compressed already).
- Disk image assembly (GPT + FAT32 ESP + data partition) by our own Rust image writer with fixed GUIDs derived
  from the version and fixed timestamps. No `mkfs.*` from the host if it can be avoided; otherwise
  `SOURCE_DATE_EPOCH` and `-U <fixed uuid>`.
- CI job `repro` builds twice on different runners and compares SHA-256; failure blocks release.
- Keys are NOT part of the reproducible artefact: release images ship with a documented public demo key set
  ("easy keys" for the lab). Operator images are rebuilt locally with `scripts/gen-keys` output baked in.
  The release image's key section is a separate, replaceable file inside the initramfs so the rest stays reproducible.

## CI (GitHub Actions)

Workflows under `.github/workflows/`:

1. `ci.yml` (push, PR): `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace` (host),
   cross-build musl targets, `scripts/check-no-busybox`, docs link check, license check (`cargo deny` or a
   small own script over `Cargo.lock`, since we allow nothing beyond libc).
2. `image.yml` (tag or manual): builds the kernel (cached by config+version hash; roughly 10 min on a 4-core runner with
   a minimal config), builds userland, assembles the image, boots it in QEMU (TCG, no KVM needed on hosted
   runners) and runs the smoke test (probe JSON validity, an L2 command round trip over a tap/`-netdev
   socket`, `disktest` against a virtio disk, refusal on the boot disk), uploads artefacts: `.img.zst`,
   `.iso` (optional), `SHA256SUMS`, `i7labctl` binaries for linux-x86_64 and macOS/Windows if the build
   is portable (L2 frames need raw sockets: Linux first, macOS BPF and Windows Npcap later), kernel source
   offer file, and a `build-info.json`.
3. `release.yml`: on tag creates the GitHub release with the artefacts, signs `SHA256SUMS` with the project's
   release key (Ed25519, key held by the operator as an Actions secret; the same signature scheme the
   update mechanism verifies), publishes `update-manifest.json` for the self-update feature.
4. `repro.yml` (nightly): rebuild and diff.

Test hardware (real USB boot, SMART on real disks, WoL) cannot run on hosted CI; it stays a documented manual
checklist (`docs/HW-TEST-CHECKLIST.md`) run by the operator on the lab machines before each minor release, with
results recorded in the release notes.

## Roadmap

Each version has an exit criterion that can be demonstrated.

### v0.1 "stick boots, tells you the truth"
- Kernel config (modern LTS, minimal but wide hardware: storage, NIC drivers for e1000e/igc/igb/ixgbe/r8169/
  r8125-in-kernel/tg3/bnx2x/virtio-net, xHCI, NVMe, AHCI, USB storage, EFI framebuffer, simpledrm, hwmon drivers),
  built from a pinned tarball. `scripts/build-usb-drive` produces a bootable UEFI (+ legacy BIOS via a tiny
  own bootloader-free approach: kernel as EFI stub, CSM hosts documented as unsupported or served by syslinux
  from the distro only if the operator allows; decision below).
- `i7lab-init`, `i7labsh` with the core builtins, DHCP client, static IP fallback (link-local).
- `labprobe`: system, pci, block (enumeration + signatures), net, cpu, mem (DMI), usb, dmi, kmsg.
- `i7labctl` local `probe` over HTTP with the baked token.
- Exit: boot on 3 different real hosts and QEMU; `probe all` JSON validates; no busybox anywhere (CI guard).

### v0.2 "remote control without IP"
- L2 command frames (own ethertype, MAC-addressed, authenticated + replay protected): `i7labctl discover`,
  `--ether <mac> --cmd ...`, `help`, request/response with fragmentation, retry, per-host session keys from the baked key.
- Inventory partition and tags. Baked keys documented (KEYS.md). Audit log.
- HTTP API v1 and token auth; minimal SPA (Overview, PCIe, Storage, Network, Log).
- Exit: with no IP and across a VLAN-tagged port, `discover` finds the host and `--ether` runs `probe all`.

### v0.3 "you can see it and trust it"
- `labtui` console UI (all pages), serial console support, SNTP, watchdog, `selftest`, report bundle.
- SMART (ATA + NVMe), PCIe AER, thermal/hwmon pages, sensors history.
- Exit: demo on a 4K console and a serial console; report bundle opens in browser.

### v0.4 "hands in the box"
- `disktest` with safety gate (read, rw, patterns, latency), file manager, `mount`, log shipping,
  nettest, ping/arping, DHCP/PXE probe, boot-next/kexec, WoL set + wake.
- Exit: write test refuses mounted/boot/partitioned disks in QEMU and on real hardware, passes on an empty disk,
  detects an injected bit flip and a misdirected write.

### v0.5 "see the screen, capture the wire"
- Remote TUI parity over L2/HTTP, screenshot, packet capture to pcap, IPMI/BMC probe and SOL client, console attach.

### v0.6 "bring-up toolkit"
- Wipe + secure erase, imaging stream, stress profiles, memtest mode, PCI reset/rescan, vfio-readiness.

### v0.7 "keeps itself current"
- Network update (A/B slots, signed manifest, rollback), sleep-state tests, DbC detection, more NIC drivers
  from the lab inventory, optional firmware bundle for NICs.

### v0.8 "many hosts"
- Fleet view (controller aggregates discover + inventory), group commands (`--all`), scripting (`i7labctl run
  script.txt` with simple conditionals), result history, `i7labctl` for macOS/Windows.

### v0.9 "hardening"
- TLS option, key rotation tooling, per-key capabilities (read-only key vs full), rate limiting everywhere, fuzzers
  for all parsers (frames, HTTP, GPT, DMI, EDID), threat model document, external review.
  Secure Boot: shim-signed path or documented MOK/db enrolment, measured boot into the TPM.

### v1.0 "stable"
- Frozen proto=1 and API v1, documented compatibility promise, release process exercised twice, reproducible
  builds verified, HW test checklist passed on a published list of machines, licence and name settled, docs complete.

### Later / ideas
- aarch64 image (Raspberry Pi class lab hosts, Apple VM), netboot variant (same initramfs from PXE, see lab proxy prior art),
  plugin commands (signed Rust-compiled modules loaded as static helper binaries), Prometheus `/metrics`, a
  ring-buffer flight recorder (always-on event log to the data partition), disk benchmarking database across hosts,
  battery discharge test, USB device passthrough tests, built-in iperf3-wire-compatible server, Bluetooth/Wi-Fi
  survey, GPU compute sanity test, hardware photo/label OCR inventory (no), a TFTP/proxy-DHCP service to boot neighbours.

## Operator decisions needed

1. Licence: MIT OR Apache-2.0 (recommended) vs MIT vs Apache-2.0 vs none.
2. Public name (keep `i7lablinux` or rename).
3. Legacy BIOS support: v0.x is UEFI-first (kernel as EFI stub, a FAT ESP). BIOS-only hosts need a bootloader.
   Option A: unsupported. Option B: one small own stage-1 loader (substantial work, v0.6+). Option C: allow syslinux/GRUB
   from the build host as a build-time dependency only. Default proposal: A until a lab host needs it.
4. TLS for HTTP: accept plain HTTP with HMAC mode until v0.9?
5. Release signing key custody (Actions secret vs offline signing of `SHA256SUMS`).
6. Whether to publish the demo "easy keys" in a public repo (they are public by design: protects against accidents, not
   an adversary; operator images use generated keys).
7. Firmware blobs: ship none (default) vs bundle selected `linux-firmware` files.

## Risks

- Kernel size/hardware coverage: a minimal config misses unusual NICs. Mitigation: module tarball on the data
  partition + `modprobe` builtin in `i7lab-init`; an "everything" kernel flavour built weekly.
- L2 frames can be blocked by switches that filter unknown ethertypes: document the fallback (HTTP) and the
  need for same-VLAN reachability; discovery uses a locally administered multicast destination too.
- A destructive command reaching the wrong host: every Class D action requires the host's unique id in the
  confirmation (DMI UUID short form) and the target device serial; the audit log records it.
- Security of baked keys: documented clearly as convenience credentials. Anyone with the stick has the keys.
  Use generated keys for any host on a shared network, rotate by rebuilding.
- Supply chain: no external crates beyond a vetted minimum; vendored sources checked into `vendor/` only if the operator
  approves a dependency; kernel tarball hash pinned.
