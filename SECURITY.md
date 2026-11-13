# Security

i7lablinux is a **lab tool** for machines you own, on a network you control. It is built so that "plug it in and drive
it" works, which means some defaults are deliberately open. Read this before putting a stick into anything.

## Never expose it to the internet

Do not route its Ethernet segment or its HTTP port (8080) to the internet, a guest network, a shared office network or any
segment with hosts you do not trust. There is no TLS and no encryption: control traffic is authenticated, not secret.

## What the keys are

* Two symmetric 32-byte HMAC keys: `admin` (full control) and `ro` (read-only commands). Generated once by
  `scripts/gen-keys`, stored 0600 in `./keys` (gitignored) and `~/.config/i7labctl`.
* They are **baked into the stick** as a second initrd on a FAT partition. Anyone who holds the stick, an image baked with
  your keys, or the `keys/` directory has the admin key. Treat a stick like a house key. Hosts booted from it can be
  commanded as root by whoever has the key.
* Real keys never go to the build host. Images built there are keyless and identical for everybody; keys are added on your
  own machine by `bake-keys`.
* Rotation is by re-baking (`scripts/gen-keys --rotate`); there is no remote key change in v0.1.
* There are **no public or derivable keys**: the agent accepts only the keys baked into the image. QEMU tests generate a
  random throwaway set per run (`scripts/gen-keys --out DIR --throwaway`). An earlier "demo key" set was removed.

## Threat model

Assumed attacker: on the same Ethernet segment (or able to reach the HTTP port), can sniff, spoof source MACs, inject,
replay, delay and flood frames; does not hold a key. What is defended: commands and replies are HMAC-authenticated with
replay protection, nonces for HTTP are single-use, file paths for the read-only role are confined, hardware strings are
sanitised before display, parsers are bounded and property-tested, block writes pass a gate (below). Full analysis:
[docs/PROTOCOL.md](docs/PROTOCOL.md) section 13 and the archived adversarial review
[docs/design-history/review-security.md](docs/design-history/review-security.md).

Out of scope or accepted:

* Physical access. The console is open by default (TUI plus a root shell on quit): someone at the machine can do
  anything. `i7lab.console=locked` gives a read-only console.
* Confidentiality of traffic, and anyone holding a key.
* Ether replies and HTTP are on every NIC and address unless you narrow them with `i7lab.ether=` and `i7lab.http_bind=`.
* The audit log is held by the daemon but an admin can stop local logging through `exec`.
* No Secure Boot: the image needs Secure Boot off. No measured boot.
* The image is RAM-resident and does not write to its boot media on its own, but it can write to **other** disks if you ask it to, and, because it runs entirely from RAM, it can overwrite its own boot disk when an admin passes `--allow-boot-media` with `--destructive` and the serial. The host allows that only after proving it is RAM-resident (root on rootfs/tmpfs/ramfs, nothing mounted from, held on, swapped on, or executing from that disk); otherwise the boot media stays absolutely refused.

## Destructive operations

Block write tests never write a device that is mounted, held (md/dm), swap, read-only, without a serial/WWID, or the boot
media (the boot media only becomes writable on a host proven RAM-resident, with the extra `--allow-boot-media` flag). A device with a partition table or a filesystem/RAID/LVM signature is written only when you pass both
`--destructive` and its serial. The default is read-only. The gate decides again on the
host regardless of what a client or the web page does. Block names are never trusted; devices are selected by serial.

## Supply chain

No crates.io dependencies (std plus hand-written libc FFI). The kernel tarball is pinned by version and sha256. No
busybox and no other third-party userland in the image (`scripts/check-no-busybox`, run on every build and in CI).

## Reporting a vulnerability

This is a private operator project. Report privately to the maintainer (the person who gave you the repository), not in a
public issue. Include the version (`i7labctl id <host>` prints the build id), what you sent or did, and what you
observed. Do not include real keys.
