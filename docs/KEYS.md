# Keys

Short version: run `scripts/gen-keys` once. Everything after that finds the keys by itself.

| file | what it is | where it lives |
|---|---|---|
| `admin.key` | 32 random bytes, `i7k1:admin:<64 hex>`. Full control: exec, file transfer, block writes, reboot | `./keys/` and `~/.config/i7labctl/keys/` (mode 0600), and on every stick you bake |
| `ro.key` | same format, read-only commands. Safe to hand to a colleague who may look but not touch | same places |
| `KEYSET-ID` | label: date + the two 8-hex fingerprints. Not secret, hosts advertise the fingerprints in beacons | same places |
| `keys/ssh/*` | optional ssh host and operator keypairs (made with `ssh-keygen`). **Not used in v1** (no sshd in the image); reserved for the optional add-on | `./keys/ssh`, `~/.config/i7labctl/ssh` |

Both HMAC keys are symmetric secrets: whoever holds a stick or a baked image holds the keys (a FAT partition is readable
by anyone). Treat a stick like a house key. The images built on the build host are **keyless** and identical for everybody; your
keys are added on your own machine.

## Everyday use

```
scripts/gen-keys                  # first time only. Running it again changes nothing ("already present").
scripts/build-usb-drive /dev/sdX  # bakes ./keys (or ~/.config/i7labctl/keys) into the stick it writes
i7labctl discover                 # finds the keys itself; `i7labctl ls` marks hosts whose key set is not yours (other-keyset)
```
`i7labctl` looks for a key in this order, first hit wins, per role: `--key FILE`, `$I7LABCTL_KEY`,
`$I7LABCTL_KEYDIR/<role>.key`, `~/.config/i7labctl/keys/<role>.key` (under `sudo`: the invoking user's home), `./keys/<role>.key`.
Role: `--role`, else admin if present, else ro. Without any key it prints the command that creates one.

## Put keys on something that already exists

```
scripts/bake-keys --device /dev/sdX --serial <SERIAL>      # a written stick: rewrites one file, no rebuild
scripts/bake-keys --image out/i7lablinux.img -o mine.img   # an image file (writes the copy mine.img)
scripts/bake-keys --iso   out/i7lablinux.iso -o mine.iso   # an ISO for JetKVM virtual media (patched in place, same size)
```
Mechanism: the keys travel as a second initrd, `/i7lab/keys.cpio` (a newc archive that unpacks to
`/etc/i7lab/keys/{admin,ro}.key`, mode 0600). GRUB loads `initrd /i7lab/initramfs.cpio.zst /i7lab/keys.cpio`. A keyless
image carries an empty placeholder archive, so it still boots and its console says `NO KEYS: run scripts/bake-keys`.
`bake-keys` checks that a device carries the `I7LABESP` partition and that its serial matches, and re-reads what it wrote.
It refuses to run on a shared/build host (hostname `docker*`, `$I7_SHARED_HOST=1`, `/etc/i7lab-shared-host`, or a `/tmp/i7ll-*` tree).

## Rotate (replace the keys)

```
scripts/gen-keys --rotate         # old set moves to keys/old/<timestamp>/ ; new set installed
scripts/bake-keys --device /dev/sdX --serial <SERIAL>      # per stick; old sticks keep the OLD keys until you do this
```
Hosts booted from an old stick stay controllable with the old key set (keep `keys/old/...` until they are retired:
`I7LABCTL_KEYDIR=keys/old/<timestamp> i7labctl ...`). `i7labctl ls` shows them as `other-keyset` otherwise, and a command
to a host with a known-different key set exits 5 without sending anything. `key.set` (changing keys over the wire) is
**not** in v1 because a key sent to a host would outlive the baked one; it is planned for v0.3.

## Demo keys (QEMU tests only)

`scripts/gen-keys --demo` writes the documented, public set to `keys/demo/` (`K = SHA256("i7lablinux-demo-<role>")`,
never installed in `~/.config`). `ALLOW_DEMO_KEYS=1 scripts/bake-keys --demo --image X` bakes them. Because everybody
knows them, `i7labd` treats demo-key requests as read-only on real hardware and grants admin only inside a VM; the
beacon says `demo=1` and the console shows a red DEMO banner. Use with `I7LABCTL_KEYDIR=keys/demo i7labctl ...`.
`scripts/build-usb-drive` and `bake-keys` refuse them without `ALLOW_DEMO_KEYS=1`.

## Threat statement

* Anyone who holds a stick, a baked image or the `keys/` directory can do whatever the admin key allows: run commands as
  root on every host booted from that key set, write disks (past the safety gate if they know the serial), reboot.
* The `ro` key is shareable: it cannot read key files, other processes' memory, or write anything.
* Control traffic is authenticated (HMAC, replay-protected), **not encrypted**. On layer 2 the host answers on every NIC unless
  `i7lab.ether=` narrows it; with an IP, the HTTP API listens on all addresses unless `i7lab.http_bind=` narrows it.
* One key set per operator; per-host keys are future work. Real keys never leave your machine and never go to the build host:
  `scripts/remote` excludes `keys/` and `out/`, and the build never reads them.
* Key files are created 0600 under umask 077 in directories 0700; `i7labctl` refuses group/other-readable key files.
