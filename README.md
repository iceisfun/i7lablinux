# i7lablinux

A small Linux image you boot from a USB drive (or virtual media) on any lab machine so that you can drive it remotely:
probe its hardware, test its disks, run commands, move files, reboot it. Control works **without an IP address** over
authenticated Ethernet frames (own ethertype, MAC-addressed, any VLAN), or over HTTP when the host has an address.
The person at the machine sees a full-screen status TUI.

Everything in the image is our own Rust and a kernel we compile: `i7lab-init` (PID 1), `i7labd` (agent), `i7labsh`
(shell with the applets as builtins). There is no busybox and no other third-party userland. The operator side is
`i7labctl`. Standard library plus hand-written libc FFI only, no crates.io dependencies.

> Lab tool. The keys are baked into the stick and traffic is authenticated but not encrypted. Never expose it to the
> internet. Read [SECURITY.md](SECURITY.md) first.

## 60-second quickstart

```sh
scripts/gen-keys                       # once: admin + read-only keys into ./keys and ~/.config/i7labctl (never committed)
scripts/install-ctl                    # once: i7labctl into ~/bin, with raw-Ethernet permission
lsblk -o NAME,SIZE,MODEL,SERIAL,TRAN,RM
scripts/build-usb-drive /dev/sdX --serial <stick serial>    # builds on the build host, writes, bakes keys, verifies
# ... boot the target machine from the stick; the first build takes a while (kernel), later ones use the cache
i7labctl discover                      # hosts on this Ethernet segment: MAC, state, key set
i7labctl --ether 52:54:00:12:34:56 --cmd ping     # no IP needed
i7labctl inv <host>                    # full hardware inventory
i7labctl help                          # every command
```

`build-usb-drive` **erases the target drive** and refuses anything mounted, holding `/`, not removable or with the wrong
serial. Builds run on a big build host (`$I7LL_HOST` or `~/.config/i7lablinux/build-host`, see [docs/BUILD.md](docs/BUILD.md)), not on your laptop;
`--build-host local` builds locally. Full walk-through: [docs/QUICKSTART.md](docs/QUICKSTART.md). Getting a machine that
you are not standing at to boot it: [docs/REMOTE-BOOT.md](docs/REMOTE-BOOT.md).

## Architecture

```
 operator machine                               lab host (booted from USB / virtual media)
 +-----------------------+                     +-----------------------------------------------+
 | i7labctl              |  L2 frames          | GRUB (UEFI + BIOS) -> Linux 6.18 LTS          |
 |  discover / --ether   |  0x88B5 beacons     |   initramfs only, RAM-resident, no disk writes|
 |  --http / --link      |  0x88B6 commands    |                                               |
 |  keys: ~/.config/...  |<------------------->|  i7lab-init (PID 1: mounts, modules, DHCP,    |
 |                       |  HMAC, replay-safe, |                  supervisor, watchdog)        |
 |                       |  no IP, any VLAN    |    |                                          |
 |                       |                     |    +-> i7labd  agent                          |
 |                       |  HTTP :80/:8080       |    |     ether server  beacon  HTTP API + SPA |
 |  browser (SPA)        |<------------------->|    |     command registry + path policy       |
 +-----------------------+  nonce-HMAC         |    |     probes (labprobe)  block write gate  |
                                               |    |     console TUI (labtui) on tty1/serial  |
                                               |    +-> i7labsh  shell + builtins (F10 on TUI) |
                                               +-----------------------------------------------+
 shared library crates: labproto (frames, crypto, sessions, keys, netlink)  labprobe  labtui
```

| crate | role |
|---|---|
| `labproto` | wire formats, HMAC sessions, replay protection, beacons, key files, netlink and syscall wrappers |
| `labprobe` | read-only probes (system, CPU, memory, DMI, PCI, USB, block, NIC, thermal, firmware, SMART, kernel log) and the block test engine with its write gate |
| `labtui` | terminal library: screen buffer, widgets, input, themes |
| `i7labd` | the agent: ether server, beacons, HTTP API, embedded web page, console TUI, audit log, jobs |
| `i7lab-init` | PID 1 |
| `i7labsh` | minimal shell with builtins |
| `i7labctl` | operator CLI (host build) |

## Features

| feature | where |
|---|---|
| Hardware inventory: PCIe, CPU, memory, DMI, NICs, USB, thermal, firmware, SMART, kernel log, GPUs | [docs/PROBES.md](docs/PROBES.md) |
| Block devices: enumeration, read, write and verify tests; writes only behind the gate (refuses mounted, partitioned, signature-bearing or boot devices unless `--destructive` AND the device serial) | [docs/PROBES.md](docs/PROBES.md), [docs/PLAN.md](docs/PLAN.md) section 6 |
| Control with no IP: `i7labctl --ether <mac> --cmd CMD args`, `discover`, VLANs | [docs/PROTOCOL.md](docs/PROTOCOL.md) |
| `i7labctl help`: every command, completions, JSON output, exit codes | [docs/I7LABCTL.md](docs/I7LABCTL.md) |
| HTTP API and a single-page web UI served by the host | [docs/WEB.md](docs/WEB.md) |
| Full-screen console TUI (coloured frames, Tab and arrows), also on a serial console | [docs/TUI.md](docs/TUI.md) |
| Exec, shell, file put/get, reboot, poweroff, boot-next, messages | [docs/I7LABCTL.md](docs/I7LABCTL.md) |
| Baked keys: two files, generated once, found automatically | [docs/KEYS.md](docs/KEYS.md) |
| USB drive builder, ISO for virtual media, keys baked after the build | [docs/BUILD.md](docs/BUILD.md) |
| Remote boot procedure (person at the machine, or JetKVM) | [docs/REMOTE-BOOT.md](docs/REMOTE-BOOT.md) |

## Status

Version 0.1.0, pre-release, in daily use on physical lab hosts. Proven in QEMU (BIOS and UEFI, image and ISO): boot,
beacon, L2 commands with no IP, HTTP, signed API, write gate refusals, console and serial TUI, exec, key baking. It has
also been installed on several physical lab machines, including a System76 Darter Pro laptop (booted from its NVMe and
from a USB stick): beacon, signed HTTP API, `exec`, hardware inventory (PCIe, ACPI tables, DMI, thermals, NVMe SMART),
and writing a 40 GiB Windows image onto the machine's own boot NVMe with `i7labctl blk image` (the host runs entirely from
RAM, so the gate allows this with `--allow-boot-media`). 888 host tests pass. Not yet recorded in
[docs/E2E-RESULTS.md](docs/E2E-RESULTS.md) as passed: a real JetKVM virtual-media run, Secure Boot, tagged VLAN frames
through a real switch, and a hardware checklist per machine. The failure list and the QEMU details are in that file;
what comes next is in [docs/ROADMAP.md](docs/ROADMAP.md).

## Developing

`make help` lists the targets. Unit tests run with plain `cargo test --workspace` on a machine with a Rust toolchain; the
image, QEMU and the full end-to-end run need the build host. See [CONTRIBUTING.md](CONTRIBUTING.md) and the
[docs index](docs/README.md).

## Licence

MIT, see [LICENSE](LICENSE). Built images contain third-party components under their own
licences ([docs/THIRD_PARTY.md](docs/THIRD_PARTY.md)).
