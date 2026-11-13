# i7lablinux quickstart

Goal: a USB stick that turns any lab machine into one you can drive from your desk. Five commands, about ten minutes
(most of it the first kernel build).

```
scripts/gen-keys                               # 1. once: your keys (./keys and ~/.config/i7labctl)
scripts/install-ctl                            # 2. once: i7labctl into ~/bin, with raw-Ethernet permission
lsblk -o NAME,SIZE,MODEL,SERIAL,TRAN,RM        # 3. find the stick: the one with TRAN=usb RM=1 and the right size
scripts/build-usb-drive /dev/sdX --dry-run     #    check first: builds, then only prints what it would do
scripts/build-usb-drive /dev/sdX               # 4. build, write, bake keys, verify (asks you to type /dev/sdX)
i7labctl discover                              # 5. boot a machine from the stick; it shows up within seconds
```

What `build-usb-drive` does: builds kernel + userland + initramfs + image on the build host (no cargo or QEMU is
needed on your machine), copies the keyless image back, checks the target drive, writes it, reads it back, adds *your*
keys to the stick, and verifies the files on the stick. **It erases the drive.** It refuses a drive that is mounted,
holds `/`, is not removable (unless `--internal`), or whose serial does not match `--serial`. Details: [BUILD.md](BUILD.md).

## Drive a host

```
i7labctl discover                              # list hosts on this L2 segment (MAC, state, key set)
i7labctl --ether 52:54:00:12:34:56 --cmd ping  # no IP needed: raw Ethernet, authenticated, any VLAN (--vlan 13)
i7labctl help                                  # every command; `i7labctl help <cmd>` for one
i7labctl id <host> ; i7labctl inv <host>       # identity, then the full hardware inventory
i7labctl blk ls <host>                         # disks; writes are refused unless --destructive AND the serial match
```
The console of the booted host shows a full-screen status TUI (Tab / arrows). An HTTP API and web page also answer on
port 80 (`http://<ip>/`; 8080 also answers, kept for older clients) once the host has an IP (DHCP runs in the
background). Plain HTTP is fine here: every request is signed.

## No stick? An image file

```
scripts/build-usb-drive --image out/mine.img --iso out/mine.iso      # keyed image + ISO (JetKVM virtual media, QEMU)
scripts/qemu-test --both                                             # boot-level check in QEMU on the build host (throwaway keys)
```

## Getting a remote machine to boot it

Tell the person at the machine what is in [REMOTE-BOOT.md](REMOTE-BOOT.md). Keys: [KEYS.md](KEYS.md).
Everything else: [docs index](README.md). Planned work: [ROADMAP.md](ROADMAP.md).
