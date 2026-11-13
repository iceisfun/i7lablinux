# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: one SemVer for image and tools, `0.x` until
the wire protocol is frozen; the protocol carries its own version number.

## [Unreleased]

### Added
- Project documentation set: README, docs index, CONTRIBUTING, SECURITY, ROADMAP, licence decision page, THIRD_PARTY,
  CI workflow and Makefile.

### Changed
- Working notes (recon, reviews, original web and expansion proposals, integration log) moved to `docs/design-history/`.
- `docs/WEB.md` rewritten to describe the implemented HTTP API and page; the proposal is archived.

## [0.1.0] - 2026-11-13 (pre-release, not tagged)

First end-to-end build, proven in QEMU only.

### Added
- Seven crates: `labproto`, `labprobe`, `labtui`, `i7labd`, `i7lab-init`, `i7labsh`, `i7labctl`; no external dependencies.
- Layer-2 control: beacons (ethertype 0x88B5) and authenticated command frames (0x88B6), MAC-addressed, VLAN-aware, replay
  protected; `i7labctl discover` and `--ether <mac> --cmd ...`.
- HTTP API with nonce-HMAC authentication and an embedded single-file web page.
- Probes: system, CPU, memory, DMI, PCI, USB, block, NICs, thermal, firmware, kernel log.
- Block read, write and verify tests behind a write gate (mounted, partitioned, signature-bearing and boot devices refused
  unless `--destructive` and the serial are given).
- Console TUI on tty1 and serial, with `i7labsh` on F10.
- Kernel built from a pinned Linux 6.18 tarball with config fragments; GRUB image for UEFI and BIOS plus a hybrid ISO for
  virtual media; keyless images with keys baked on the operator machine (`scripts/bake-keys`).
- Scripts: `gen-keys`, `install-ctl`, `build-usb-drive`, `build-image`, `qemu-test`, `e2e`, `check-no-busybox`, `make-release`.

### Known gaps
- Not run on physical hardware, a real USB boot or a real JetKVM; SMART is a stub; no Secure Boot. See
  [docs/E2E-RESULTS.md](docs/E2E-RESULTS.md).
