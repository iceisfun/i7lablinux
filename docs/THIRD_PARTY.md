# Third-party material

Our source tree has no third-party crates. Built images and release bundles contain the following. This list is a
summary for the licence decision, not legal advice; the image carries the full texts under `/usr/share/i7lab/LICENSES`
(see [PLAN.md](PLAN.md) section 11).

| component | in | licence | notes |
|---|---|---|---|
| Linux kernel (pinned version in `configs/kernel/VERSION`) | image, release | GPL-2.0-only | source offer: the pinned tarball URL plus our fragments in `configs/kernel/fragments/` |
| GRUB 2 (boot loader, taken from the build host) | image, ISO | GPL-3.0-or-later | build-time tool and the binaries it installs on the ESP |
| linux-firmware blobs (`configs/image/firmware.list`, default: `rtl_nic tigon bnx2 bnx2x`) | initramfs | per file, see `WHENCE` | optional: `FIRMWARE=none` ships none; `WHENCE` is copied into the image |
| Rust standard library and `musl` libc | linked into the static binaries | MIT OR Apache-2.0 (Rust), MIT (musl) | statically linked, so their notices apply to the binaries |
| PCI names in `crates/labprobe/data/pci-ids.tsv` | `labprobe` | ours | hand-curated subset written in the pci.ids format, not a copy of the pci.ids database |

Not present, by operator rule: busybox and any other third-party userland. `scripts/check-no-busybox` enforces it in the
tree and on every built image.
