# Remote boot: getting a host into i7lablinux when you are not at it

Everything runs from RAM. The host's disks are not touched (writes need an explicit `--destructive` plus the disk
serial), so removing the USB drive afterwards or power cycling is safe. There are three ways; pick one.

**Before anything: Secure Boot must be off** on the target (the stick is unsigned: the firmware silently skips it or
shows a security violation). **BitLocker/TPM-sealed disks:** changing the boot order or booting another OS can trigger
BitLocker recovery at the next Windows boot; have the recovery key, or use the one-time boot menu (B2), which on most
firmware does not change the saved order.

## A. The stick lives in the machine (best for lab hosts)

Once (with someone at the host, or over JetKVM): put USB first in the firmware boot order and turn off "fast boot" /
"USB skip" options so USB is always enumerated. From then on the host boots i7lablinux on every power cycle, including
after a PDU/hwlab power cycle. To return to the installed OS for one boot: `i7labctl reboot <host> --to-os` (UEFI hosts:
writes BootNext; BIOS hosts can only return by pulling the stick until v0.4).

## B. Ad hoc: you instruct a person

Read this to them. They need no other knowledge.

### B1. Remove the internal drive (default; the fallback is automatic)

1. "Shut the machine down completely. If it does not respond, hold the power button for five seconds."
2. "Plug the i7lablinux USB drive into a USB port on the **back** of the machine (motherboard ports; not a hub, not the
   front panel if you can avoid it)."
3. "With the power **off**, remove or unplug the machine's internal drive." (An M.2 NVMe needs a screwdriver; a SATA
   drive just needs its data cable pulled.) "Now press the power button. The machine finds no operating system and starts
   from the USB drive."
4. "Wait about a minute. When you see a text screen titled **i7lablinux** with the machine's name, you are done. Leave it
   running; do not press keys. If I ask you to, you may pull the USB drive out afterwards."
5. When you are done: "Shut it down (I will do it), plug the internal drive back in, remove the USB drive, power on."
   (`i7labctl poweroff <host>` does the shutdown.)

### B2. Boot menu (does not touch the disks)

Steps 1 and 2 as above, then: "Press the power button and immediately tap the **boot-menu key** over and over until a
menu appears. Choose the entry that names the USB drive (often `UEFI: <drive name>`; if there are both a `UEFI:` and a
plain entry, take `UEFI:`). Then continue at step 4."

| Vendor | One-time boot menu key |
|---|---|
| Dell | F12 |
| HP | Esc, then F9 |
| Lenovo (ThinkCentre / ThinkPad) | F12 (some models: Novo button) |
| Intel NUC | F10 |
| ASUS | F8 (desktop), Esc (laptop) |
| MSI | F11 |
| Gigabyte | F12 |
| ASRock | F11 |
| Supermicro | F11 |
| Acer | F12 (must be enabled in setup first) |
| Microsoft Surface | hold Volume-Down while pressing power |

`i7labctl help boot-keys` prints the same table.

### What they will see

1. The vendor logo, then a small black GRUB menu `i7lablinux` for two seconds (it starts by itself; entries: normal, serial
   TUI, locked console, debug, "boot the internal disk").
2. A short burst of kernel text, then a full-screen status page titled **i7lablinux** with the machine name, coloured
   frames, tabs along the top (Overview, PCIe, Storage, Network, USB, Sensors, Log, Actions; F12 opens About). A red banner `NO KEYS` means the stick was
   not baked; `NO CONTROL PATH` means no network card works (see below).
3. Within about 15 seconds of the GRUB menu the host sends layer-2 beacons; with an IP (DHCP) it also answers HTTP on port 8080.

### How you verify it came up (from your desk, on the same Ethernet segment)

```
i7labctl discover                  # the host appears with its MAC, state=ready and your key set ("other-keyset" = wrong stick)
i7labctl wait --state ready        # or: i7labctl discover --watch
i7labctl id <host>                 # name, versions, key fingerprints, build id
i7labctl msg <host> "Please leave this machine running, thank you"     # text on its screen (see note)
i7labctl identify <host>           # blink the NIC LED / banner so the person can point at the right box (see note)
```
Note: in the v0.1 build `msg`, `identify` and `tui tab|dump` are in the catalogue and in `i7labctl help`, but `i7labd` has
no handler for them yet and answers `UNSUPPORTED` (exit 10); see [BRIEF-CHECKLIST.md](BRIEF-CHECKLIST.md). Until then,
tell the person by phone/chat and use `i7labctl id <host>` plus the host name on the TUI header to confirm the box.

Different VLAN: `i7labctl --vlan 13 discover` (802.1Q tagging is unit-tested but not yet proven end to end, see
BRIEF-CHECKLIST item 6). No IP is needed anywhere. After the first command, `i7labctl blk ls <host>` shows the internal
disk as `UNSAFE: partition_table(..)` (writable only with `--destructive --serial`) and the stick as `BOOT UNSAFE:
boot_media` (never writable).

## C. JetKVM virtual media (no stick at all)

Bake keys into the ISO (`scripts/build-usb-drive --image out/mine.img --iso out/mine.iso`), upload the ISO (CD-ROM mode)
or the `.img` (disk mode) to the JetKVM, mount it, power cycle with a one-time boot to the virtual device, wait for the
beacon. `i7labctl lab-boot --jetkvm HOST --image PATH` drives this through hwlabd. The first real run on real hardware is
still part of acceptance (never exercised on a real device yet).

## When it does not come up

| Symptom | Likely cause and fix |
|---|---|
| The machine boots its own OS | The firmware ignored the stick: Secure Boot is on, USB is not first, fast boot skipped USB, or the port is not bootable. Try a rear USB 2 port, or B2. |
| "Security violation" / "invalid signature" | Secure Boot is on. Turn it off. |
| BIOS-only machine refuses the stick | Some legacy BIOSes want an active MBR entry (the default, `PMBR_ACTIVE=1`); if one refuses that, rebuild with `scripts/build-image --full --pmbr-active 0` (BUILD.md). |
| Screen stays black on a UEFI machine | Pick the second GRUB entry (serial/ASCII) or the debug entry; check the Log tab over serial. |
| TUI shows `NO CONTROL PATH: no usable NIC (unbound: 10ec:8126 at 03:00.0)` | The onboard NIC has no driver in the image. Plug in a USB Ethernet adapter (RTL8152/8153, ASIX AX88179, CDC-ECM/NCM adapters are built in). |
| `discover` shows nothing | Not the same Ethernet segment/VLAN, a switch port that blocks the multicast-like beacon, or the host never reached the TUI (ask the person what the screen says). |
| `i7labctl` says `other-keyset` / exit 5 | The stick was baked with another key set (`i7labctl ls`; keep old sets in `keys/old/`). |

Cautions: remove an internal drive only with the power off. Sticks in front-panel or hub ports and USB 3 sticks on old
xHCI firmware sometimes do not boot; use a rear USB 2 port. There is **no `/bin/sh`** in the image (only `i7labsh`);
to run extra tools, push a static binary: `i7labctl put <host> ./tool /run/bin/tool --mode 0755`, then
`i7labctl exec <host> -- /run/bin/tool`. Nothing in the image or in pushed toolboxes may be busybox
(`scripts/check-no-busybox --dir DIR`).
