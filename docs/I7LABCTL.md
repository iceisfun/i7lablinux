# i7labctl: the operator command line

> **Superseded by docs/PLAN.md (authoritative) on:** PLAN.md C9 (no ssh, `svc sshd`, `--ssh` in v1), section 4.7 (the v1 subcommand list, exit-code rules, `sh`, aliases, `--link mcast:`), C5 (`inv` sections), section 5 (key paths, rotation via `bake-keys`, no `key rotate`/`key.set` in v1), `image build|write` replaced by `scripts/build-usb-drive` and `scripts/bake-keys`. Read PLAN.md first; where this note disagrees, PLAN.md wins.


Status: design. `i7labctl` is a single static-ish Rust binary for the lab host (builds for the host, not for the image). It talks to `i7labd` on booted i7lablinux hosts over three transports:

* **ether**: raw Ethernet command frames, no IP needed, works on any VLAN at L2 (protocol: `PROTOCOL.md`).
* **http**: the HTTP API of `i7labd` (routable, same command set, same keys).
* **ssh**: plain OpenSSH to a host where `sshd` is running (started with `svc sshd start`); only for `ssh`, `shell --via ssh`, and file/exec fallbacks.

No busybox anywhere: the host side of every command is in `i7labd` or the `i7labsh` shell builtins.

Contents: 1 Quick start; 2 Conventions; 3 Command reference; 4 JSON output; 5 Exit codes; 6 Files and environment; 7 Key management; 8 Completions; 9 Examples; 10 Open issues.

## 1. Quick start

```
./scripts/build-usb-drive /dev/sdX          # compile kernel + init + i7labctl, bake keys, write the stick (asks first)
sudo setcap cap_net_raw+ep $(command -v i7labctl)   # once, so ether works without root
i7labctl discover                            # boot the stick in the target; hosts appear within a few seconds
i7labctl ls
i7labctl inv 02:00:00:9d:01:57
i7labctl --ether 02:00:00:9d:01:57 --cmd ping
i7labctl shell 02:00:00:9d:01:57             # interactive, over ether, no IP
```

Remote boot of a host: see `docs/REMOTE-BOOT.md` (operator procedure: ask the person at the machine to remove the drive from the OS disk path, insert the stick, power cycle, boot from USB; `i7labctl wait --state up` tells you when it is there).

## 2. Conventions

### 2.1 Host selector

`<host>` is any of: MAC (any NIC of the host), IPv4, board serial, board name, hostname, or a unique prefix of a MAC. Exact (case-insensitive) match against the registry (`discover` keeps it). Ambiguous key: exit 8 with the candidates listed. A bare IPv4 or MAC not in the registry still works (HTTP resp. ether, with the interface from `--iface`).

### 2.2 Global options (before or after the subcommand)

| option | meaning |
|---|---|
| `-H, --host <sel>` | host selector (also positional where a command takes one) |
| `--ether <mac>` | select the **ether** transport and the target NIC MAC; `--cmd` then names the command (2.3) |
| `--cmd <name>` | wire command name for the raw form |
| `--http <ip[:port]>` | select the http transport and address (port default 8080). The address is the target, so commands then take **no** `<host>` word (`--http 10.0.0.5 exec -- dmesg`, `--http 10.0.0.5 put a.bin /run/a.bin`); `sh` is the exception and still takes one (`--http 10.0.0.5 sh 10.0.0.5 "ls /"`). |
| `--ssh [user@]ip` | select the ssh transport (user default root) |
| `--transport auto\|ether\|http\|ssh` | default `auto` |
| `-i, --iface <if>` | lab-side interface (repeatable); default every physical Ethernet NIC with carrier |
| `--vlan <id>` | send/listen with 802.1Q tag `id` (repeatable for listening; ether) |
| `--role admin\|ro` | which key to use; default `admin` if its file exists else `ro` |
| `--key <file>` | explicit key file (overrides `--role`) |
| `--keys <dir>` | key directory holding `admin.key` / `ro.key`; same as `$I7LABCTL_KEYDIR` and wins over it (`key init` and `key import` write there too) |
| `--timeout <sec>` | whole-command timeout (default 30; commands that stream default to none) |
| `--retries <n>` | extra full handshake attempts after the session engine's own retries (default 0) |
| `--json` | machine output, see section 4 |
| `-q, --quiet` / `-v, --verbose` (`-vv` frame trace) | |
| `--no-color` | also `NO_COLOR` |
| `--registry <file>` | registry file (default `~/.cache/i7labctl/hosts.json`, shared with lab-proxy's format) |
| `-y, --yes` | do not ask for confirmation of destructive actions (never skips the serial requirement of `blk write`) |
| `-h, --help`, `-V, --version` | |

**Transport `auto`**: if the registry has a live entry with an IP seen in the last 15 s and the HTTP API answered, use http (fastest for big transfers); else if the host is known on an interface at L2, use ether; else error. `ssh` is only chosen by `ssh`, `shell --via ssh`, `--ssh` or `--transport ssh`. The ether transport needs `CAP_NET_RAW`.

### 2.3 The raw ether form

```
i7labctl --ether <mac> --cmd <name> [params...]
```

`<name>` is any wire command from the table in `PROTOCOL.md` section 7 (`ping`, `id`, `inv`, `blk.ls`, `exec`, `net.set`, ...); `params` are passed as the argv words of the request, exactly as the CLI subcommands would build them. Output is the same as the matching subcommand (`--json` for the raw JSON result). This is the escape hatch for commands without a friendlier wrapper and the basis for testing the protocol. `i7labctl ether cmds <mac>` fetches the live list (`cmds` command); `i7labctl help ether` shows it offline.

Every subcommand below is a front end for one or more wire commands and accepts all global options.

## 3. Command reference

Transport column: `E` ether, `H` http, `S` ssh, `L` local only (no host contact). "(E)" = works but not preferred. Role: `R` read-only key is enough, `W` admin key.

### 3.1 Discovery and inventory

| command | E | H | S | L | role | description |
|---|---|---|---|---|---|---|
| `discover` | E | | | | none | listen for L2 beacons (and optionally probe); fills the registry |
| `ls` | | | | L | none | list registry hosts |
| `ping` | E | H | S | | R | round trip time, uptime, boot id |
| `id` | E | H | S | | R | identity, versions, key fingerprints |
| `inv` | E | H | S | | R | system inventory |
| `pcie` | E | H | S | | R | PCIe devices |
| `usb` | E | H | S | | R | USB devices |
| `net` | E | H | S | | R/W | NICs, addresses, VLANs, configuration |
| `thermal` | E | H | S | | R | temperatures, fans |
| `logs` | E | H | S | | R | dmesg, init, daemon, http logs |
| `blk` | E | H | S | | R/W | block devices, SMART, read/write/verify tests |

#### `discover`

```
i7labctl discover [--listen SECS] [--active] [--watch] [--all] [--assign MAC=IP/PFX/GW]...
                  [-i IF]... [--vlan ID[,ID|-ID]...] [--daemon] [--no-registry] [--json]
```

* Default: listen 4 s on every NIC with carrier and print what was seen (table: MAC, IP, board, serial, host, build, state, VLAN, proto, kernel, age).
* `--listen SECS`: listen window; `--watch`: run until interrupted, print events (`new`, `lost` after 15 s silence, `reboot` when `boot=` changes, `ip` changes, `state` changes).
* `--active`: send PROBE frames (PROTOCOL 10.4) to get replies in under half a second; with `--vlan 1-200` probes and listens on each VLAN id (on a trunk; 802.1Q tags added by the tool; needs a trunk/tagged port).
* `--assign MAC=IP/PFX/GW`: answer that MAC's address-less beacon with an address hint (I7LR2 to v2 hosts, I7LR1 to v1 hosts; at most one hint per MAC per 10 s).
* `--daemon`: run as the registry writer (what lab-proxy `registry` did): writes the registry every second and keeps entries 7 days; run it under a supervisor if you want a persistent registry. Without it `discover` writes the registry once on exit.
* Beacons from v1 sticks (`I7LP1`) are shown with `proto=-`.

#### `ls`

```
i7labctl ls [--all] [--sort mac|ip|age|board] [--state live|stale|any] [--json]
```
Reads the registry (no network). `live` is seen within 15 s, `stale` older; entries older than 10 min are hidden unless `--all`. Flags in the note column: `src-mac-mismatch`, `v1`, `unverified-tag`.

#### `ping`, `id`

```
i7labctl ping <host> [-c COUNT] [-W SEC]           (ether: one CHALLENGE round trip + REQ per count)
i7labctl id <host>
```
`ping` prints RTT min/avg/max per transport and the host's `boot_id` and uptime; it exits 4 if no reply. `id` prints the beacon-v2 fields, `proto`, key fingerprints (`kid`), image build id, command groups, role granted to your key.

#### `inv`

```
i7labctl inv <host> [--section sys,board,bios,cpu,mem,thermal,nic,disk,usb,pcie,power,dmi] [--raw]
```
All sections by default. Human output: system/board/BIOS, CPU (model, cores, flags that matter), memory and DIMMs, NICs, disks with SMART verdict, thermal, PCIe summary. `--raw` prints the server JSON as received (same as `--json` without the envelope).

#### `pcie`

```
i7labctl pcie <host> [--tree] [--id VVVV:DDDD] [--class CC] [--verbose] [--aer]
```
Lists devices with bus address, ids, class, driver, current/max link speed and width, IOMMU group; `--verbose` adds BARs and a config-space hex dump (read-only); `--aer` shows AER error counters; `--tree` prints the topology.

#### `usb`

```
i7labctl usb <host> [--tree] [--id VVVV:PPPP]
```

#### `thermal`

```
i7labctl thermal <host> [--follow] [--interval SEC]
```

#### `logs`

```
i7labctl logs <host> [--dmesg|--init|--daemon|--http] [-n LINES] [-f]
```
Default `--dmesg -n 200`. `-f` follows until Ctrl-C (sends CANCEL).

#### `net`

```
i7labctl net ls <host> [<iface>] [--all]
i7labctl net set <host> <iface> (--dhcp | --ip A.B.C.D/N [--gw A.B.C.D] [--dns A,B]) [--mtu N] [--confirm SEC]
i7labctl net vlan add <host> <iface> <vid> [--ip A.B.C.D/N]
i7labctl net vlan del <host> <iface> <vid>
i7labctl net link <host> <iface> up|down
i7labctl net confirm <host>
```
`net ls` is R; the rest W. `net ls` has a KIND column (`ethernet`, `wifi`, `vlan`, `virtual`, `virtual/kernel`) and hides the kernel's own `virtual/kernel` devices (`dummy0`, `sit0`, tunnel base devices) unless `--all` (or an explicit `<iface>`). `--confirm SEC` makes the change revert automatically unless confirmed: `net set` over http or ssh uses it by default (30 s) to avoid cutting yourself off; over ether it is not needed (ether works with any IP state) and not applied by default. After `net vlan add` the host sends beacons on that VLAN.

#### `blk`

```
i7labctl blk ls <host> [--all]
i7labctl blk smart <host> <dev> [--attrs] [--selftest short|long]
i7labctl blk read <host> <dev> [--mb N] [--regions start,mid,end] [--offset BYTES --len BYTES] [--bs 1m] [--direct]
i7labctl blk write <host> <dev> --destructive --serial SERIAL [--allow-boot-media] [--mb N] [--regions ...] [--offset B --len B] [--seed N]
i7labctl blk verify <host> <dev> --seed N [--regions ...]
i7labctl blk image <host> <disk> --file IMG --serial SERIAL --destructive [--allow-boot-media] [--yes] [--verify] [--offset N] [--resume] [--grow-last] [--no-relocate] [--verify-chunk MIB]
i7labctl blk image <host> <disk> --file IMG --serial SERIAL --verify-only [--from-range N] [--skip-gpt-head] [--offset N] [--verify-chunk MIB]
```
* `blk ls`: name, size, model, serial, transport, rotational, partition table, filesystems, mounted, boot media, the SMART verdict (PASSED / WARNING / FAILED / UNKNOWN; `-` when not asked), and the **write-safety verdict** (`WRITE-SAFE` or `UNSAFE: mounted | partition table | filesystem sdb1 ext4 | boot media | ...`).
* `blk smart`: verdict (PASSED/WARNING/FAILED/UNKNOWN) with reasons, model/serial/firmware, temperature, power-on hours; NVMe: critical warning, spare, percentage used, data read/written, power cycles, unsafe shutdowns, media errors; SATA: the attribute table with `--attrs` (reallocated, pending, wear, ...). A USB-attached disk answers `UNKNOWN: not available (bridge)` when its bridge does not pass SMART through. Exit 3 on FAILED. `--selftest` (not implemented by the host yet) starts a SMART self test (W) and returns at once; run again to read the result.
* `blk read`: **read-only**. Default `--mb 256` as three regions (start, middle, end) read with `O_DIRECT` and `--bs 1m`; per-region MiB/s, I/O errors, latency max. Exit 3 on any error. Runs for minutes on large `--mb`; progress streams.
* `blk write`: **destructive**. Requires `--destructive` and the device's real `--serial` (taken from `blk ls`), checked by the host. The host refuses (exit 7) if the device is mounted, has any mounted partition, has a partition table or a filesystem/RAID/LUKS signature, backs the running system, or is the boot media. The boot media is the one exception to "never": only when the host PROVES it is fully RAM-resident (see below) `blk ls` shows `boot_media(ram-resident: --allow-boot-media)` and the write is allowed with `--allow-boot-media` in addition to `--destructive` and `--serial`. On a host that is not proven RAM-resident there is no flag to override the boot media rule. The test writes a seeded pseudo-random pattern into the regions, syncs, reads it back and reports mismatches. `--seed` defaults to a random value that is printed so `blk verify` can re-check it later (for example after a reboot or power cut test).
* **`--allow-boot-media` (blk write, blk image)**: overwrite the disk this host booted from. The host (`i7labd`) allows it only when it proves it runs entirely from RAM: the root filesystem (`/`) is rootfs, tmpfs or ramfs; no mount at all has its source on that disk or any of its partitions; the disk has no device-mapper/md/loop holders and no swap; `i7labd`'s own executable (`/proc/self/exe`) is not on it; and the usual mounted/held/busy checks pass. Anything else (for example root on `/dev/nvme0n1p3`, or `/data` mounted from the stick) keeps `boot_media` ABSOLUTE and the flag is refused. The flag is additional: it never replaces `--destructive` and `--serial`, and it does not lift any other refusal. The host keeps answering after the write (everything is hot in memory) but cannot boot from that disk again; the audit log line carries `allow_boot_media=true` and `BOOT-MEDIA-OVERRIDE ram-resident`. Prompts mention the flag explicitly.
* `blk verify`: read-only compare against a seeded pattern from an earlier `blk write`.
* `blk image`: **destructive**. Streams a raw disk image from this machine onto a **whole disk** of the host (for example a 20-60 GiB Windows 10 image onto a laptop's NVMe) over the authenticated transport, ether or HTTP, without staging it in the host's RAM (the older route was `put` into `/dev/shm` and `i7labwr`, capped at half the host's RAM). Safety is the same gate as `blk write` (admin key, `--destructive`, the real `--serial`, no mounted/held/swap disk, a boot-media disk only on a proven RAM-resident host and only with `--allow-boot-media`, a partition table needs the same two flags), plus: the model, size, serial and current partition layout are shown and the operator is asked to confirm (`--yes` skips the question, not the serial; without a terminal and without `--yes` it refuses), and an image larger than the disk is refused before anything is sent.
  * The file is read once, sequentially. Data goes in chunks of 256 KiB (ether) or 512 KiB (HTTP), each with its offset and SHA-256, with a bounded window of unacknowledged bytes; all-zero 1 MiB blocks are not sent at all (a ZERO record, executed as BLKZEROOUT or zero writes), so a sparse 60 GiB image costs only its data. A progress line shows bytes, percent, MiB/s, elapsed and ETA on a terminal.
  * The whole-image SHA-256 is computed on both ends and compared; `--verify` also reads the disk back and compares (exact: zero ranges are real zeros on the disk, never a discard). The host fsyncs at the end and at every 64 MiB.
  * **Verification is chunked** (works for any image size: a 40 GiB read-back takes minutes and must never be one request). After the last byte is written the host keeps the session open; the client asks for the SHA-256 of the disk in ranges of 256 MiB (`--verify-chunk MIB`, 1..1024), each request taking a second or two, and compares each with the hash of the same range of the local image (zero blocks are hashed too, nothing is skipped). A range that differs is read once more, then reported with its offset (`VERIFY MISMATCH: ... range 17 (offset 4563402752, 268435456 bytes): image <sha> disk <sha>`, exit 3, up to 16 bad ranges are listed); a request that fails is retried once. Every request refreshes the host session's 300 s idle timer, so the total time is unbounded. Progress prints `verify: range i/N  X / Y  MB/s  elapsed` and ends with the final report; on success the GPT step runs and the result shows the whole-image SHA-256. A resumed transfer (the host did not see the first part) is always verified this way. If the link breaks during the verify, rerun with `--resume` (END only is resent, the verify starts over), or after the session expired run `--verify-only`.
  * **`--verify-only`** compares a disk with an image without writing anything and can be rerun at any time: `i7labctl blk image <host> <disk> --file IMG --serial SERIAL --verify-only`. It is read-only, so it needs the admin key and the real `--serial` but not `--destructive` (and refuses the write flags). It prints `verify OK <image sha256>` and exits 0, or names the bad ranges and exits 3. `--from-range N` starts at range N (a verify that was interrupted, or a re-check of a range reported bad; no whole-image hash is printed then). It is refused while a write session holds the disk. Note: after a flash that moved the GPT backup (the disk is larger than the image) the first 8192 bytes (LBA 0 and 1) differ from the image by design; use `--skip-gpt-head` to leave them out (the rest of the image still is compared); a flash with `--verify` compares before that move and is exact.

  * `--resume` (and the automatic retry after a dropped or damaged chunk, a cut connection or a stalled link, up to 8 times) asks the host how far it got (`--status`) and continues from that offset; it needs the same `--serial`/`--destructive` and the same image file. The host keeps a paused session for 5 minutes and a state file for longer; after a host reboot it starts over.
  * Afterwards the GPT backup is moved to the end of the disk (like `sgdisk -e`) and the kernel re-reads the partition table (BLKRRPART). `--grow-last` also extends the partition that ends last to the new end of the usable area (the filesystem inside is not resized); `--no-relocate` leaves the disk exactly as streamed; `--offset N` (multiple of 4096) writes the image at byte N of the disk and skips the GPT move. Exit 3 if the GPT move or the partition re-read failed after a verified write, or if the read-back does not match.
  * Example: `i7labctl blk image darter nvme0n1 --file win10.img --serial S5XYNX0R123456 --destructive --verify`. Protocol: PROTOCOL.md section 7.1.
* The write test is deliberately separate from read: default is always read-only.

### 3.2 Execution and files

| command | E | H | S | L | role | description |
|---|---|---|---|---|---|---|
| `exec` | E | H | S | | W | run a command on the host, streaming output |
| `shell` | E | (H) | S | | W | interactive shell on a pty |
| `put` | E | H | S | | W | upload a file |
| `get` | E | H | S | | R/W | download a file |
| `fs` | E | H | S | | R/W | ls, stat, rm on the host |
| `jobs` | E | H | S | | W | detached jobs |

#### `exec`

```
i7labctl exec <host> [--timeout SEC] [--env K=V]... [--cwd DIR] [--stdin FILE|-] [--tty] [--detach] [--no-stream] -- <command> [args...]
```
* Runs `<command>` directly (no shell). For shell syntax: `i7labctl exec H -- i7labsh -c 'dmesg | tail'` (the in-image shell, see HOST-SHELL docs; builtins ls cat cp mv rm mkdir mount umount ip dmesg ps kill ...).
* stdout and stderr go to the matching local streams as they arrive. `--stdin -` forwards local stdin. `--tty` allocates a pty (window size and `^C` forwarded).
* Default timeout 300 s, `--timeout 0` none. `--detach` starts it as a job (output in `/run/i7lab/jobs/<id>`, see `jobs`), prints `job <id>` and exits 0 (with `--json`: the result event with `data.job`).
* **Exit status is the remote command's status** (0 to 254); i7labctl's own errors (transport, auth, ...) exit 255 for `exec`, `shell` and `ssh`, with the reason on stderr and, under `--json`, in the envelope (section 5).

#### `shell`

```
i7labctl shell <host> [--via ether|ssh|http] [--term TERM] [--escape CHAR]
```
Interactive pty. Default via ether (works without IP, runs `i7labsh`); `--via ssh` starts sshd on the host first (if needed) and runs `ssh`. Local escape: `~.` quits, `~?` lists, `~r` reboots the host after confirmation (`--escape ''` disables). Terminal resize is forwarded.

#### `put`, `get`, `fs`

```
i7labctl put <host> <local> <remote> [--mode 0644] [--resume] [--no-verify] [--mkdirs]
i7labctl get <host> <remote> <local> [--resume] [--no-verify]
i7labctl fs ls <host> <path> [-l]
i7labctl fs stat <host> <path>
i7labctl fs rm <host> <path> [-r]
```
Transfers are chunked, checksummed (SHA-256, both ends), written to a `.part` file and renamed at the end, resumable (`--resume` continues at the size of the partial file). Progress bar on a tty. With the ro key, `get`, `fs ls`, `fs stat` are limited to `/var/log`, `/run/i7lab`, `/proc`, `/sys`.
Examples: upload a kernel and initrd, then `kexec`: `i7labctl put H bzImage /run/k && i7labctl put H initrd.img /run/i && i7labctl kexec H --kernel /run/k --initrd /run/i --cmdline 'console=ttyS0'`.

#### `jobs`

```
i7labctl jobs <host> [ls] | kill <id> | out <id> [-f]
```

### 3.3 Power and lifecycle

| command | E | H | S | L | role | description |
|---|---|---|---|---|---|---|
| `reboot` | E | H | S | | W | reboot (also to firmware setup, or kexec) |
| `poweroff` | E | H | S | | W | power off |
| `kexec` | E | H | S | | W | load and exec another kernel |
| `wait` | E | | | | none | wait for a host to appear, disappear, reboot |
| `identify` | E | H | S | | W | blink LEDs and show a banner on the host |
| `msg` | E | H | S | | W | show a message on the host console |

```
i7labctl reboot <host> [--force] [--delay SEC] [--uefi] [--wait [SEC]]
i7labctl poweroff <host> [--delay SEC]
i7labctl kexec <host> --kernel PATH [--initrd PATH] [--cmdline STR] [--wait [SEC]]
i7labctl wait <host> [--timeout SEC] [--state up|down|ready|reboot] [--boot-id ID]
i7labctl identify <host> [--seconds N] [--stop]
i7labctl msg <host> <text...>
```
* `reboot`/`poweroff` ask for confirmation on a tty (`--yes` skips). `--uefi` reboots into firmware setup. `--wait` is shorthand for a following `wait --state reboot`.
* `wait`: listens for beacons (needs no session). `up`: host seen (default); `down`: no beacon for 15 s or `state=shutdown`; `ready`: `state=ready`; `reboot`: the `boot` id changed from the one seen at start (or `--boot-id`). Exit 4 on timeout (default 300 s).
* `identify` blinks the keyboard LEDs and NIC LED and fills the console with the host name for `N` seconds (default 30) so you can find a machine in a rack; `msg` puts a line on the console: `i7labctl msg H "Remove the USB stick now, then press the power button"`.
  **Not served yet:** the v0.1 `i7labd` has no handler for `identify`, `msg`, `tui` or `tui.dump` (nor `svc`, `kexec`, `key.set`, which are planned). `i7labctl` hides these from `help` and the quick start (`help --all` lists them marked `(not available in this image yet)`), and a call prints one line, `'msg' is not available in this image yet (the host does not serve it)`, exit 10, instead of the raw host error. The list is `labproto::catalog::NOT_YET_SERVED`; pinned from the host side by `crates/i7labd/tests/brief_coverage.rs`; tracked in `docs/BRIEF-CHECKLIST.md`.
* **Remote boot procedure** (the full text, with checks for a BIOS boot order, is `docs/REMOTE-BOOT.md`): (1) the user inserts the stick; (2) `i7labctl msg` or an instruction, "remove the OS drive's boot path / select USB in the boot menu, power cycle"; (3) `i7labctl discover --watch` or `wait` until the host's beacon shows `state=ready`; (4) `i7labctl id <host>`.

### 3.4 Services, SSH, interactive

| command | E | H | S | L | role | description |
|---|---|---|---|---|---|---|
| `svc` | E | H | S | | W | start/stop host services (sshd, http, beacon, ether) |
| `ssh` | | | S | | W | ssh to the host, starting sshd if needed |
| `tui` | (E) | | | L | R | full-screen lab dashboard on this machine |
| `web` | (E) | (H) | | L | R/W | local web UI gateway |

```
i7labctl svc <host> sshd|http|beacon|ether start|stop|status [--port N] [--force]
i7labctl ssh <host> [--no-start] [-- ssh-args...] [command...]
i7labctl tui [--iface IF]... [--host <sel>]
i7labctl web [--listen 127.0.0.1:8081] [--open] [--role ro|admin]
```
* `svc ... start sshd`: starts the in-image `sshd` (host keys generated at first boot and pinned in `~/.cache/i7labctl/known_hosts` on first use via an authenticated ether/http channel, so there is no trust-on-first-use over the network). `ssh` does that automatically (unless `--no-start`) and then runs OpenSSH with `BatchMode=yes`, `StrictHostKeyChecking=yes`, `UserKnownHostsFile=<pinned file>`, `GlobalKnownHostsFile=/dev/null`, `ForwardAgent=no`, `ClearAllForwardings=yes`, user `root`, with the baked-in authorized key (the file `~/.config/i7labctl/ssh_ed25519`, created by `key init`). Refuses entries flagged `src-mac-mismatch`.
* `svc ether stop` is refused on the connection that carries it unless `--force`.
* `tui`: the lab-side fleet dashboard: tabs (Hosts, Detail, Logs, Help), arrow keys and Tab to move, Enter for detail, `r` refresh, `q` quit; coloured frames; works in a 24x80 terminal. This is separate from the TUI on the host's own console (which is built into `i7labd` and shows that host's state: NICs, disks, errors, sessions).
* `web`: starts a local HTTP server serving the single-page web UI (decision and plan: `docs/WEB.md`; the SPA is static files embedded in the binary) and proxies its API calls to hosts over the transport you selected, **including ether**, which a browser cannot speak. Binds to 127.0.0.1 by default; non-loopback needs `--listen` explicitly and prints a warning, since the proxy holds your key.

### 3.5 Keys and images

| command | description |
|---|---|
| `key init\|show\|rotate\|export\|import\|verify` | key management (section 7) |
| `image build\|write\|info\|verify` | build and write the boot image |
| `completions` | shell completion scripts |
| `help` | help |
| `version` | versions |
| `ether` | raw frame tools |
| `api` | raw HTTP call |

#### `image`

```
i7labctl image build [--out DIR] [--kernel-config FILE] [--jobs N] [--keys DIR] [--no-kernel]
i7labctl image write <device> [--image FILE] [--yes] [--no-verify] [--persist-size MiB]
i7labctl image info <image>
i7labctl image verify <image> | <device>
```
* `build`: compiles the kernel (from the pinned source tarball with the project config; `--no-kernel` reuses the last bzImage), the musl-static `i7labd`/`i7lab-init`/`i7labsh`/applets, assembles the initramfs (our own cpio writer, no external archiver required), bakes the keys from `--keys` (default `./keys`, `~/.config/i7labctl`), and produces the image (GPT with an ESP and a small config partition, bootloader). Needs a build host with the toolchain; `scripts/build-usb-drive` is a thin wrapper around `image build` + `image write`.
* `write <device>`: writes the image to a USB drive. **Safety**: refuses non-removable devices, anything mounted, anything larger than 2 TiB, or the device holding `/`; shows model, size, serial and the current partition table and asks you to type the device serial (`--yes` skips the question but not the other refusals). Verifies by reading back (`--no-verify` to skip).
* `info`: print build id, kernel version, key fingerprints (`kid`), contents, size. `verify`: check the image or a written device against its manifest.

#### `ether` (protocol tools)

```
i7labctl ether cmds <mac>                       list the host's supported commands (the cmds command)
i7labctl ether probe [--vlan ..]                 send PROBE, print replies
i7labctl ether sniff [-i IF] [--vlan N] [--decode]    print 0x88B5/0x88B6 frames (headers decoded; tags are shown, bodies not)
i7labctl ether hello <mac>                       handshake only, print session parameters and RTT
i7labctl ether frame <hex>                       decode a frame offline
```

#### `api`

```
i7labctl api <host> <METHOD> <path> [--data JSON|@file]       raw authenticated HTTP request (http transport)
```

### 3.6 Help

`i7labctl help` prints the full command tree with one line per command and the transport letters; `i7labctl help <command>` prints that command's synopsis, options and examples; `i7labctl <command> --help` is the same. `i7labctl help --all` is the complete manual (about 400 lines, this document's section 3 in plain text). `i7labctl help ether` lists the wire commands (offline copy; with a host it asks `cmds`). `i7labctl help exit-codes` prints section 5.

## 4. JSON output

`--json` works on every command that prints data. One JSON document on stdout (or NDJSON for streams), nothing else on stdout; diagnostics go to stderr.

Envelope:

```
{"ok":true,"transport":"ether","host":{"mac":"02:00:00:9d:01:57","ip":"192.0.2.195","vlan":null,"serial":"BTKY000000XX","boot":"9f3c..."},
 "cmd":"inv","rtt_ms":0.8,"data":{ ...the server result... }}

{"ok":false,"transport":"ether","host":{...},"cmd":"blk.write","error":{"code":"REFUSED","status":5,"exit":7,"message":"device mounted: sdb1 at /mnt","reasons":["mounted","filesystem ext4"]}}
```

* `data` is exactly the server's JSON for the command (PROTOCOL 7), so scripts written against ether work against http.
* Streaming commands (`exec`, `logs -f`, `blk read/write` progress, `discover --watch`) emit **NDJSON**, one event per line: `{"event":"stdout","data":"..."}` (base64 in field `b64` for non-UTF-8 bytes), `{"event":"stderr",...}`, `{"event":"progress","region":"mid","mib_s":412.5,"done":0.43}`, `{"event":"host","state":"new",...}`, ending with a final line `{"event":"result","ok":true,"exit":0,...}`.
* `ls` and `discover` print `{"ok":true,"data":{"hosts":[{...registry entry fields...}]}}`.
* Errors carry `code` (names of the status table in PROTOCOL.md, plus client-side codes `E_USAGE`, `E_TRANSPORT`, `E_TIMEOUT`, `E_AUTH`, `E_NOHOST`, `E_AMBIGUOUS`, `E_SAFETY`) and `exit`, the process exit status.
* Timestamps are unix seconds (integers) or milliseconds with an `_ms` suffix. MACs are lower case with colons.

## 5. Exit codes

| code | meaning |
|---|---|
| 0 | success |
| 1 | generic failure (command ran but reported failure, for example `inv` section missing) |
| 2 | usage error (bad option or arguments), nothing was sent |
| 3 | remote test or probe found a problem: `blk read/write/verify` errors or mismatches, `blk smart` verdict FAILED |
| 4 | no response or timeout (transport, retries exhausted, `wait` timeout, `ping` no reply) |
| 5 | authentication failure (server proof invalid, key unknown to the host, no key file, `EPERM`, role too low) |
| 6 | host not found in the registry / not reachable at L2 |
| 7 | refused by a safety rule (`REFUSED`; local refusals in `image write` and `blk write`) |
| 8 | ambiguous host selector |
| 9 | host busy (`BUSY`, `NOT_READY`) |
| 10 | unsupported command or version mismatch (`UNSUPPORTED`, protocol version) |
| 130 | interrupted (Ctrl-C) |
| 255 | for `exec`, `shell` and `ssh` only: i7labctl's own error (the exit status of the remote command is passed through, so 1 to 254 mean the remote command) |

`blk read` with a clean result exits 0, with errors exits 3. `exec` exits with the remote status.

## 6. Files and environment

| path | purpose |
|---|---|
| `~/.config/i7labctl/keys/admin.key`, `ro.key` | the two keys, mode 0600 (one line `i7k1:<role>:<64 hex>`) |
| `~/.config/i7labctl/ssh_ed25519(.pub)` | ssh client key whose public half is baked into images |
| `~/.cache/i7labctl/hosts.json` | registry |
| `~/.cache/i7labctl/known_hosts` | pinned host keys for ssh |
| `./keys/` (build tree, gitignored) | keys generated by `scripts/gen-keys` / `key init`, source for the image |

Key lookup order (first hit wins, per role): `--key`, `$I7LABCTL_KEY`, `--keys` / `$I7LABCTL_KEYDIR`, `~/.config/i7labctl/keys`, `./keys`. When nothing is found the error lists every place it looked, in that order. Under `sudo` HOME is `/root` and your keys are not there: i7labctl then says so and suggests running without sudo (the HTTP transport needs no root; only raw Ethernet needs `cap_net_raw`, see `setcap` above), `sudo -E`, or `--keys DIR`.

Environment: `I7LABCTL_KEYDIR`, `I7LABCTL_KEY` (a key file), `I7LABCTL_ROLE`, `I7LABCTL_REGISTRY`, `I7LABCTL_IFACE` (comma separated), `I7LABCTL_TRANSPORT`, `NO_COLOR`. Under `sudo`, the invoking user's home is used.

## 7. Key management

Goal: baked-in simple keys that are documented and trivial to use. One command creates them, the image build picks them up, the CLI finds them without flags.

* Two keys per **key set**: `admin` (everything) and `ro` (read-only commands). Each is 32 random bytes from `getrandom`.
* File format: one line, `i7k1:admin:<64 lowercase hex>`, mode 0600. Fingerprint: first 4 bytes of `SHA256("i7c-keyid" | key)` shown as 8 hex digits; it is what hosts advertise (`kid`).
* Tracked files never contain real keys. Only the scheme (this section) is documented in git.

```
i7labctl key init [--dir DIR] [--force]       create ~/.config/i7labctl/keys/{admin,ro}.key and ./keys/ copies + ssh key; refuses to overwrite without --force
i7labctl key show [--role admin|ro] [--secret]   print fingerprints (and with --secret the key line, after confirmation)
i7labctl key rotate [--no-build]              new key set; for each host in the registry you can reach with the old key, push the new keys with `key.set`
                                              (RAM only until the image is rebuilt/rewritten), then rebuild the image with the new set; old key set is kept as keys/old/<date> until deleted
i7labctl key export [--role ro] [--file F]     copy a key to hand to a colleague (the ro key is meant to be shared, admin is not)
i7labctl key import <file>                    install a key line into the key dir
i7labctl key verify <host>                    check that the key authenticates to the host (OPEN_OK) and print the granted role
```
`key rotate` replaces keys on running hosts through the authenticated channel using the old admin key; hosts that are off or on another build keep the old keys until reimaged. After a rotation the old key stops working on the hosts that took the change. Per-host derived keys (`K_host = HMAC(K_master, board_serial)`) are future work.

## 8. Completions

```
i7labctl completions bash|zsh|fish|powershell > file
eval "$(i7labctl completions bash)"
```
Completions are generated from the same command table that drives `help` and complete subcommands, options, and host selectors (from the registry: MACs, hostnames, board serials).

## 9. Examples

```
# who is out there
i7labctl discover --active --listen 3
i7labctl ls --state live

# a host with no IP on VLAN 13
i7labctl --ether 02:00:00:9d:01:57 --vlan 13 --cmd ping
i7labctl inv --ether 02:00:00:9d:01:57 --json | jq '.data.disk[] | {name,model,serial}'

# are the disks healthy, then a read test of a specific disk
i7labctl blk ls  02:00:00:9d:01:57
i7labctl blk smart 02:00:00:9d:01:57 nvme0n1
i7labctl blk read 02:00:00:9d:01:57 nvme0n1 --mb 1024

# destructive write test of a blank scratch disk (host refuses anything else)
i7labctl blk write 02:00:00:9d:01:57 sdb --destructive --serial S3Z9NB0K123456 --mb 512
i7labctl blk verify 02:00:00:9d:01:57 sdb --seed 8812

# run something, upload a file, reboot and wait
i7labctl exec 02:00:00:9d:01:57 -- dmesg
i7labctl put  02:00:00:9d:01:57 ./test.elf /run/test.elf --mode 0755
i7labctl exec 02:00:00:9d:01:57 --timeout 60 -- /run/test.elf --self-check
i7labctl reboot 02:00:00:9d:01:57 --wait 120

# give it an address, start ssh, use ssh
i7labctl net set 02:00:00:9d:01:57 eth0 --ip 192.0.2.195/24 --gw 192.0.2.1
i7labctl ssh 02:00:00:9d:01:57 uname -a

# find the machine in the rack
i7labctl identify 02:00:00:9d:01:57 --seconds 60
```

## 10. Open issues and decisions to confirm

1. **Privileged ether access.** Raw sockets need `CAP_NET_RAW`. Options: `setcap` (quick start), run `discover --daemon` as root and have `i7labctl` relay through its unix socket (planned, not specified), or sudo. Decision needed on the relay.
2. **Wiping non-blank disks.** `blk write` refuses disks with partition tables or filesystems. A deliberate `blk wipe-signatures <dev> --serial S --destructive` (not in protocol v1) would let the operator clear a test disk; leaving it out keeps v1 safer.
3. **Encryption.** v1 authenticates but does not encrypt; the ENC flag is reserved. Decide if file contents or shell sessions justify an AEAD mode.
4. **Per-host keys** (derived from the board serial) instead of one key per image.
5. **`shell` over http.** Needs a WebSocket in the server; listed as optional.
6. **Web UI.** `web` assumes a static SPA served by `i7labctl` and by `i7labd`; the decision record is in `docs/WEB.md`.
7. **Registry compatibility.** `hosts.json` stays compatible with lab-proxy's `labp` (version field 2 adds fields); `labp` is not needed once `i7labctl` is installed.
8. **Exit code overlap.** `exec` uses the remote exit code, so tool errors are 255 there; scripts that need to tell them apart should use `--json`.
