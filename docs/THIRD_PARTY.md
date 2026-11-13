# Third-party material

Our source tree has no third-party crates. Built images and release bundles contain the following. This list is a
summary for the licence decision, not legal advice; the image carries the full texts under `/usr/share/i7lab/LICENSES`
(see [PLAN.md](PLAN.md) section 11).

| component | in | licence | notes |
|---|---|---|---|
| Linux kernel (pinned versions in `configs/kernel/VERSION.stable` and `VERSION.lts`) | image, release | GPL-2.0-only | source offer: the pinned tarball URL plus our fragments in `configs/kernel/fragments/` |
| GRUB 2 (boot loader, taken from the build host) | image, ISO | GPL-3.0-or-later | build-time tool and the binaries it installs on the ESP |
| linux-firmware blobs (tag pinned in `configs/firmware/VERSION`, selection in `configs/firmware-lean.list` and `configs/firmware-full.exclude`) | initramfs of locally built images only | per file, see `WHENCE`; several are redistributable binary-only licences, a few forbid modification or require the licence text to travel with them | never in this repository and never in the release bundle; `WHENCE` and the licence files are copied into every image that has firmware |
| Rust standard library and `musl` libc | linked into the static binaries | MIT OR Apache-2.0 (Rust), MIT (musl) | statically linked, so their notices apply to the binaries |
| PCI names in `crates/labprobe/data/pci-ids.tsv` | `labprobe` | ours | hand-curated subset written in the pci.ids format, not a copy of the pci.ids database |

Not present, by operator rule: busybox and any other third-party userland. `scripts/check-no-busybox` enforces it in the
tree and on every built image.

## Firmware policy

`linux-firmware` is a collection of binary blobs from many vendors, each under its own licence (`WHENCE` names the licence per
file; the common ones are redistribution-allowed binary licences such as `LICENCE.iwlwifi_firmware`, `LICENCE.Realtek`,
`LICENCE.amdgpu`, `LICENCE.broadcom_bcm43xx`). Three rules follow from that, enforced by the scripts:

1. **The public repository contains no firmware.** `configs/firmware/VERSION` pins an exact tag and sha256 plus the release
   signer's key fingerprint; `scripts/fetch-firmware` downloads the tarball from kernel.org on the build host, verifies it and
   keeps it in the build host's cache.
2. **The release bundle is firmware-free.** `scripts/make-release` builds the lean variant with `FIRMWARE=none` (all drivers
   present as modules, no blobs) and fails if the resulting image carries any `/lib/firmware` file, unless `--with-firmware`
   is passed, which produces a local operator artifact with a NOTICE and must not be published from the repository.
3. **The operator builds the real images locally**: `scripts/build-usb-drive --variant lean|full` fetches the pinned firmware
   on the build host, selects the variant's subset (`lean`: the curated list; `full`: everything except the listed exclusions),
   compresses each blob with zstd (the kernel loads `.zst` firmware directly) and packs it into the initramfs under
   `/lib/firmware`. The tag is recorded in `/etc/i7lab/BUILD` (`firmware=<variant>-<tag>`), and `WHENCE` plus the licence texts
   are copied to `/usr/share/i7lab/LICENSES/firmware/` inside the image. Whoever hands such an image to a third party takes on
   the redistribution terms of the blobs they included.

Drivers whose firmware is missing still load as modules and fail their probe harmlessly, except GPU drivers that take over
the firmware framebuffer: `amdgpu`, `radeon` and `nouveau` are therefore left out of the lean image
(`configs/image/modules.lean.exclude`).
