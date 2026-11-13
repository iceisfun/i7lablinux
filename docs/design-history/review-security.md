> **Note (added later):** the public demo keys discussed here no longer exist; they were removed. The text below is unchanged design history.

# i7lablinux security/safety review (D2, adversarial)

Status: review of the design as written in `PLAN.md`, `PROTOCOL.md`, `PROBES.md`, `WEB.md`,
`I7LABCTL.md` (no code exists yet). Role: break the design. Every finding is numbered, has a
severity, a concrete attack, and a concrete fix to the **design** (not a vague "be careful").

Threat model I assume (stricter than PROTOCOL.md section 13): the lab segment is shared with
hosts I do not trust; an attacker can sniff, spoof source MACs, inject, replay, delay and
flood L2 frames, and can reach the HTTP port if the host has an IP; the attacker does **not**
hold the admin or ro key unless a finding says otherwise. Physical possession of a stick = keys
is accepted and out of scope except where the design widens that blast radius.

Severity: CRITICAL = remote takeover / data loss with no key; HIGH = privilege escalation or
takeover under a weak but reachable precondition; MEDIUM = targeted DoS, persistence, or secret
exposure; LOW = hardening / documentation.

---

## F1 (HIGH) — ro key escalates to admin via path traversal in `get`/`fs.*`

PROTOCOL.md 7 and `i7labd::ro_path_allowed` limit the read-only key to `/var/log`, `/run/i7lab`,
`/proc`, `/sys`, `/etc/os-release`. The baked admin key lives at `/etc/i7lab/keys/admin.key`.

Attack: a holder of only the **ro** key (which the design explicitly says is meant to be shared —
`key export --role ro`, `docs/I7LABCTL.md:376`) calls:

* `get /proc/1/root/etc/i7lab/keys/admin.key` — `/proc/<pid>/root` is a symlink to `/`, so the
  allow-listed prefix `/proc` leads straight to the admin key.
* `get /proc/../etc/i7lab/keys/admin.key` — naive prefix check on an un-normalised string passes
  (`/proc/..` == `/etc`).
* `get /sys/kernel/...` symlinks and `/proc/self/cwd`, `/proc/self/root` similarly escape.

Result: the shared ro key reads the admin key → full root control (exec, blk.write, kexec). This
is a straight privilege escalation and the single most dangerous flaw in the design.

Fix: `ro_path_allowed` must (1) `realpath`/`O_NOFOLLOW`-resolve the final target and every
component, reject any `..` and any symlink that leaves the allow-listed root; (2) open with
`openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` against an fd for each
allowed root, never by string prefix; (3) explicitly deny `/proc/<pid>/root`, `/proc/<pid>/cwd`,
`/proc/<pid>/fd`, and the whole `/etc/i7lab/keys` tree for every role including admin reads over
`get`. Add a test: ro `get` of `/proc/1/root/etc/i7lab/keys/admin.key` must return `EPERM`.

## F2 (HIGH) — WEB.md bearer-token scheme contradicts PLAN C3 and is a cleartext replayable secret

`PLAN.md` C3 replaced the HTTP auth with the lab-proxy nonce-HMAC scheme and states "No bearer
token, no separate token file." `WEB.md:34-45` still specifies `Authorization: Bearer <token>`,
a 128-bit token stored in `~/.config/i7labctl/token`, and a `#token=` URL fragment. These two
documents disagree, and the WEB.md path is dangerous:

* There is no TLS (WEB.md:29). A bearer token is a **static secret sent in clear on every
  request**; one passive sniff and the attacker replays it forever. The nonce-HMAC scheme never
  puts a secret on the wire.
* `#token=` in the URL leaks into browser history, referrer headers, and any `window.name`
  reflection, and "stripped immediately" does not undo history.
* A persisted token file is a second long-term secret to steal, with none of the key hygiene
  (0600, key-id matching) the real keys get.

Fix: delete the entire bearer-token path from WEB.md; keep only PLAN C3 (nonce-HMAC keyed by the
same admin/ro keys, server proof `X-Lab-Proof`). State in WEB.md that there is no token file and
no URL-fragment auth. Make the doc defer to PLAN.md explicitly so this cannot drift again.

## F3 (HIGH) — demo keys are remote-root and the only guard is at build time

`PLAN.md` section 5: demo keys are `K = SHA256("i7lablinux-demo-<role>")`, "public by
construction." The admin demo key grants `exec` (root), `blk.write`, `kexec`, `key.set`. The only
protections are build-time (`ALLOW_DEMO_KEYS=1`), a `demo=1` beacon field, and a CLI warning.

Attack: any image that ships (or is accidentally rebuilt) with demo keys is fully owned by anyone
on the segment who runs the public `i7labctl` with the public demo key — remote root, disk wipe,
boot an attacker kernel. The beacon `demo=1` flag is unauthenticated advisory text and changes no
server behaviour. On the shared the build host build host (see F11) a demo-key initramfs is trivially
reused.

Fix (defence in the running daemon, not only the builder): when `i7labd` detects it is running on
a demo key set, it must (1) refuse every Class-D command (exec, shell, blk.write, kexec, reboot,
poweroff, net.set, key.set, fs.rm) and serve only read-only probes, or (2) require a physical
console confirmation for each Class-D command. Print a permanent red banner in the TUI and in
`id`. Document that demo images are read-only lab toys, never a control plane.

## F4 (HIGH) — block write gate is probe-then-open: TOCTOU between safety check and the writable handle

`PLAN.md` section 6 and PROBES.md "Safety gate" describe the order: probe mount state / holders /
partition table / signatures, **then** `WriteGuard::acquire` opens `O_RDWR|O_EXCL|O_DIRECT`.
The checks read `/proc/self/mountinfo`, sysfs holders and the on-disk signature regions *before*
the exclusive handle exists.

Attack / accident window: between the signature/mount probe and the `O_EXCL` open, another actor
(a second session — the limit is 2 sessions per MAC and 8 total; or an auto-mounter; or udev)
mounts a partition, assembles an md member, or a signature gets written. The write test then runs
on a device the operator believes was blank/unmounted. `O_EXCL` taken *after* the decision does
not retroactively validate the decision.

Fix: invert the order. `WriteGuard::acquire` must (1) open the whole-disk node `O_EXCL|O_RDWR`
*first* (this is the kernel's exclusive-claim, and it fails if any partition is mounted or the
disk is held); (2) **re-read** partition table, filesystem/RAID/LVM/LUKS signatures and
mountinfo/holders **from the now-locked device fd**; (3) only then decide Safe/Refused. All reads
that back the decision must come from the same fd that will be written, under the exclusive claim.
Add a test that mounts a partition in the window and proves the write is refused.

## F5 (HIGH) — persisted data-partition keys preferred over baked keys = persistence backdoor

`PLAN.md` section 5 and PROTOCOL.md `key.set --persist`: `key.set --persist` writes a role key to
the data partition `/data/keys/`, and i7labd "prefers over the baked keys at boot."

Attack: an attacker who holds the admin key once (including a one-time exposure, a leaked demo
image, or F1/F2/F3) runs `key.set admin --hex <attacker> --persist`. Their key now survives reboot
and **overrides** the operator's baked key. The operator's `key rotate` (RAM push) does not help
because the attacker's key is on persistent media; only a full reimage of the stick removes it,
and the operator has no signal that a persisted override exists.

Fix: baked keys in the initramfs must always win; a persisted key may only *add* a key, never
replace the baked admin key, and must itself be signed by the baked admin key with a monotonic
counter checked at boot. At minimum, make `--persist` require a build-time opt-in
(`allow_persist_keys=0` default), surface "running on a persisted key, not the baked key" loudly
in `id`/TUI/beacon, and give `key verify` a way to report baked-vs-persisted provenance.

## F6 (MEDIUM) — unauthenticated I7LR1 address hint is accepted by default (segment attacker steers the host's IP)

PROTOCOL.md 10.5: I7LR1 is unauthenticated, accepted while the host has no IPv4, once per NIC,
`accept_v1_hint` default on.

Attack: at boot an attacker on the segment races a forged I7LR1 to assign the host an IP/gateway
of the attacker's choosing. The host then DHCP-less uses the attacker as its gateway; HTTP traffic
and any later routed access flow through the attacker. One frame, no key.

Fix: default `accept_v1_hint=0`. Prefer I7LR2 (HMAC-authenticated) only. If v1 must stay for old
tools, gate it behind a build option, log it to the audit log and TUI, and never let a hinted
gateway be used for anything the daemon initiates. Document that an L2 attacker can otherwise
set the host's address.

## F7 (MEDIUM) — per-source-MAC penalty box enables targeted DoS of a legitimate controller

PROTOCOL.md 8: 5 bad tags from one source MAC → 10 s penalty (doubling to 5 min) in which *every*
frame from that MAC is dropped before crypto. Source MAC is trivially spoofable on L2.

Attack: the attacker spoofs the operator controller's MAC and sends 5 malformed-tag frames. The
host now drops all frames from the real controller for 10 s–5 min — the operator is locked out of
their own host on demand, repeatedly, with ~5 frames.

Fix: the penalty must not apply to a source MAC that currently holds a verified session with a
valid `ctr`. Scope the pre-crypto penalty to the handshake path only, and never let it drop frames
that pass the cheap session-id + ctr-window check (which an attacker without SK cannot forge). Keep
the global unauthenticated-frame cap as the real flood defence. Note in the doc that MAC-keyed
limits are advisory because MACs are spoofable.

## F8 (MEDIUM) — PROBE / PROBE_REPLY is an L2 reflection toward a spoofed victim

PROTOCOL.md 10.4: PROBE is broadcast and unauthenticated; every host replies unicast with the full
beacon-v2 text (larger than the 8-byte-nonce probe). Reply rate limit is per-NIC (2/s), not per
destination.

Attack: the attacker broadcasts probes with the **victim's** source MAC. Every i7lablinux host on
the segment unicasts a ~400+ byte PROBE_REPLY to the victim. With N hosts the victim receives up to
2N replies/s of amplified size — an N× reflection/amplification aimed at one L2 target.

Fix: reply only to probes whose source is a unicast MAC, rate-limit PROBE_REPLY **per destination
MAC** as well as per NIC, and cap the global reply rate. Consider requiring the probe to echo a
value the responder can bind so a blind spoof costs the attacker a round trip. Blast radius is one
L2 segment, hence MEDIUM, but it is a free amplifier.

## F9 (MEDIUM) — HTTP streaming responses (NDJSON / SSE) are not covered by the response proof

WEB.md / PLAN.md C17: `X-Lab-Proof = response_mac(key, nonce, status, body)` authenticates a
whole-body response. Streaming endpoints (`?stream=1` chunked NDJSON, `GET /api/v1/events` SSE)
emit chunks over time with no final fixed body.

Attack (active MITM, no key): the attacker lets the authenticated request through, then injects or
rewrites streamed chunks — faked `blk.write` "ok, no mismatches", faked probe output, suppressed
error events. The client has no per-chunk authenticity and the proof (if sent at all) arrives after
the client already acted on the stream.

Fix: authenticate each NDJSON/SSE event — e.g. every event object carries `"seq"` and a truncated
HMAC over `nonce | seq | canonical(event)`; the client verifies each event and detects gaps
(dropped/injected). The ether transport already tags every DATA frame; the HTTP transport must
match it or the design is weaker on HTTP than on L2 for exactly the destructive commands.

## F10 (MEDIUM) — baking real keys requires copying them to a shared multi-tenant build host

`scripts/remote` rsyncs the tree to `the build host:/tmp/i7ll-<label>` and `--exclude keys`. But the image
build must bake real `admin.key`/`ro.key` into the initramfs. Either the keys are excluded (then
only demo images can be built on the build host) or they are copied to a shared 128-core host where other
lanes/agents operate, and the built initramfs on `/tmp` (tmpfs) contains the keys in cleartext,
readable by anyone with access to that box.

Fix: make it explicit and enforced — real operator images are **never** built on the build host; the build host
builds use demo keys only (`ALLOW_DEMO_KEYS=1`), and `build-image`/`build-usb-drive` refuse to run
with non-demo keys on a host flagged as shared. Document a trusted single-tenant build host for
operator images. Ensure `remote` continues to exclude `keys/` and `out/` and that no build step
prints key material (F17).

## F11 (MEDIUM) — audit log is deletable by an admin-key holder and lost on reboot

PROTOCOL.md 8: "The audit log cannot be disabled by a command." It lives at
`/run/i7lab/audit.log` (tmpfs). But an admin-key holder can `exec -- i7labsh -c 'rm ...'` or
`fs.rm /run/i7lab/audit.log`, and a reboot clears tmpfs. So the "cannot be disabled" guarantee is
illusory against exactly the actor who does the dangerous things.

Fix: hold the audit log as an append-only fd internal to i7labd (not a path any command resolves),
deny `fs.rm`/`get`-write and `exec` cwd access to `/run/i7lab` for the daemon's own control files,
and stream audit records to the controller over the authenticated channel (and to the data
partition ring) so a local wipe does not erase the off-box copy. State honestly that an admin-key
holder can still stop future logging on the box itself; off-box shipping is the real integrity
control.

## F12 (MEDIUM) — VLAN parse vs BPF filter can disagree (QinQ / auxdata), confusing session binding

PROTOCOL.md 2.1: accept 0/1/2 stacked tags; BPF matches the ethertype "plain or behind a tag";
VLAN id is "the in-band tag if present, else auxdata when `TP_STATUS_VLAN_VALID`." The session is
keyed on `(src MAC, tag stack, session id)`.

Problems: (1) the kernel may strip one tag into auxdata while a second remains in-band (QinQ); the
"in-band if present else auxdata" rule then records only the inner tag and silently drops the outer
one from the key, so the same session can be reached on two different physical tag stacks, defeating
the "different tag stack is dropped" defence. (2) If the classic BPF only matches "ethertype or
ethertype-behind-one-tag," a QinQ (two in-band tags) frame may be delivered via `ETH_P_ALL` but
parsed at the wrong offset, or dropped inconsistently with the stack check. (3) A frame carrying
both an in-band tag and a valid auxdata tag needs one canonical interpretation.

Fix: define one canonical tag stack = concat(auxdata tag if valid, then in-band tags in order),
bounded to 2; build the session key from that canonical stack; make the receive parser and the BPF
filter agree on exactly which shapes are accepted (reject >2 tags). Add parser tests for: untagged,
one in-band, one auxdata, auxdata+in-band, two in-band (QinQ), and assert the session key is stable
and distinct per real stack.

## F13 (MEDIUM) — streaming (unknown-length) channels have no explicit out-of-order buffer cap

PROTOCOL.md 6.1: chan-0 reassembly is bounded by `msg_len` (REQ 64 KiB, RESP 16 MiB). Stream
channels use `msg_len = 0xFFFFFFFF` and are "written to their sink in order." Out-of-order stream
fragments must be held until the gap fills, but the only stated bound is the flow-control window
(default 16, max 64 frames).

Attack: a client sending `exec --stdin` or `put` data (chan 3/4, client→server) sends fragment at a
high `off` then streams many later fragments while never filling the first hole. If the server
buffers every out-of-order fragment up to the advertised window it is bounded; if it buffers by
`off` without tying the held bytes to the receive window it can be pushed past the 2 MiB/session
cap, and the per-host 24 MiB cap is reached with few sessions.

Fix: state explicitly that out-of-order bytes held for a stream never exceed `window * frag`
(≤ 64·1400 ≈ 90 KiB) and that a fragment beyond `next_expected + window*frag` is dropped (not
buffered); account held stream bytes against the same 2 MiB/session and 24 MiB/host budget. Add a
test that a one-hole-plus-flood stream stays within the cap.

## F14 (MEDIUM) — control plane is exposed widely by default (HTTP on 0.0.0.0, ether on every NIC)

WEB.md:27 binds HTTP "to all interfaces when an IP exists"; PROTOCOL.md 8 listens for ether on
"every Ethernet NIC with carrier" with `ether.deny` default empty. A lab host plugged into a
production or office segment therefore exposes a single-shared-key root control plane to that whole
broadcast domain and to anything routable to :8080.

Fix: default the ether listener to a configured allow-list of NICs/VLANs (or at least require
`i7lab.ether=all` to listen everywhere), default HTTP to bind only on an operator-designated
interface/VLAN (and `i7lab.http=off` unless set), and document the exposure plainly. Combined with
one key set per image (section 13), unexpected exposure is the realistic path to compromise.

## F15 (LOW) — kexec loads an unsigned, uploaded kernel (document as by-design persistence)

PROTOCOL.md 7 `kexec`: files are `put` then loaded with no signature check. With the admin key this
is intended, but it is the cleanest persistence/pivot primitive in the system (boot an attacker OS,
new `boot_id` hides it).

Fix: document it as a full-takeover primitive that admin-key possession grants; optionally require
the kernel to carry an Ed25519 signature verifiable against the baked update key (the design
already plans Ed25519 for A/B updates) so kexec payloads reuse that trust root. Audit the sha256 of
the loaded kernel/initrd/cmdline.

## F16 (LOW) — cookie_secret / RNG at early boot

PROTOCOL.md 4.2: `cookie_secret` is random per boot; `crypto::random_bytes` is "getrandom(2),
fallback /dev/urandom." A non-blocking read before the pool is seeded yields low-entropy secrets.
Session keys derive from `K` (safe), but a predictable `cookie_secret` weakens the stateless-cookie
anti-DoS (an attacker could precompute cookies and skip CHALLENGE), and key generation on a
freshly booted builder could be weak.

Fix: use `getrandom` in blocking mode (no `GRND_NONBLOCK`) for `cookie_secret`, nonces and any key
generation so it waits for the pool to be initialised; never fall back to a non-blocking
`/dev/urandom` read for these. Document the single blocking point at daemon start.

## F17 (LOW) — key material must be kept out of build logs and `i7labd --check` output

`i7labd --check` loads config/keys; `build-image`/`gen-keys` handle real keys. Any debug print of a
`Key` (its `Display`/`Debug`) or a verbose build log would leak 32-byte secrets into terminal
scrollback, CI logs, or the shared the build host `/tmp`.

Fix: `Key`'s `Debug`/`Display` must redact to the fingerprint only (never the hex); `--check` prints
fingerprints, never key lines; `key show --secret` is the single intentional disclosure and must
confirm first (already specified). Add a test that `format!("{:?}", key)` contains no hex of the
secret. Grep build scripts to ensure no `set -x` region echoes a key file.

## F18 (LOW) — boot-media / "backs running system" detection can be spoofed into false negatives/positives

`PLAN.md` section 6 identifies boot media by `i7lab.boot` PARTUUID, the FAT labels `I7LABESP`/
`I7LABDATA`, and backing the running system. Everything runs from RAM and the stick may be removed
after boot, after which "backs running system" matches nothing.

Problems: (1) a target disk that happens to carry a cloned PARTUUID or a duplicated `I7LABESP`/
`I7LABDATA` label gets wrongly flagged boot media → `blk.write` refused (a DoS / confusing, but
fails safe). (2) More worrying direction: if detection relied on the stick still being present and
the stick is pulled, a device that *is* the real boot disk of the host's installed OS is not
i7lablinux's boot media and is correctly writable — fine — but operators may assume the tool
protects "the internal disk," which it does only via the partition-table/signature gate, not the
boot-media rule.

Fix: detect boot media by the *device currently backing the mounted ESP/initramfs source and the
`i7lab.boot` PARTUUID resolved at boot and cached in RAM*, not by rescanning labels on arbitrary
disks (labels are attacker/clone-controlled data). Document that the never-overridable boot-media
rule protects the i7lablinux stick, while the internal OS disk is protected only by the
partition-table/signature override gate, so wiping it requires `--destructive --serial`.

## F19 (LOW) — SPA holds the admin key in the browser under a CSP that allows inline script

WEB.md: the SPA takes a key line into `sessionStorage` and signs with JS HMAC; CSP is
`default-src 'self'; style-src 'self' 'unsafe-inline'` with one inline script via nonce. The key
never leaves the browser, but any HTML-injection bug (a single `innerHTML` of a hostile hardware
string — product names, SMART fields, DMI strings are all attacker-influenceable on a scanned host)
could read `sessionStorage` and exfiltrate the admin key.

Fix: keep the strict `textContent`-only discipline for all probe data (already stated) and make it
testable (a render test that feeds `<img onerror>`/`<script>` in model/serial/DMI fields and
asserts inert output); drop `'unsafe-inline'` for scripts entirely (nonce only) and prefer the
**ro** key in the SPA by default, requiring an explicit step to load the admin key for Class-D
actions, so an XSS by default cannot steal admin.

---

## Summary table

| # | sev | one-line |
|---|-----|----------|
| F1 | HIGH | ro key reads admin.key via `/proc/<pid>/root` and `..` traversal |
| F2 | HIGH | WEB.md cleartext bearer token contradicts PLAN C3; replayable |
| F3 | HIGH | demo keys = remote root; only guarded at build time |
| F4 | HIGH | block write gate probes before taking O_EXCL (TOCTOU) |
| F5 | HIGH | persisted data-partition key overrides baked key = backdoor |
| F6 | MED | unauthenticated I7LR1 hint accepted by default |
| F7 | MED | MAC-spoof penalty box locks out the real controller |
| F8 | MED | PROBE_REPLY reflection/amplification to a spoofed victim |
| F9 | MED | HTTP stream chunks not authenticated by the response proof |
| F10 | MED | baking real keys needs them on the shared the build host host |
| F11 | MED | audit log deletable by admin; tmpfs-only, no off-box copy |
| F12 | MED | VLAN QinQ/auxdata parse vs BPF filter disagreement |
| F13 | MED | no explicit out-of-order buffer cap for stream channels |
| F14 | MED | HTTP 0.0.0.0 + ether on every NIC by default |
| F15 | LOW | kexec loads unsigned uploaded kernel (document) |
| F16 | LOW | early-boot RNG for cookie_secret/key gen must block |
| F17 | LOW | keys must be redacted in logs and `--check` |
| F18 | LOW | boot-media detection trusts attacker-controllable labels |
| F19 | LOW | SPA admin key in sessionStorage under unsafe-inline CSP |

The three I would fix before any code ships: **F1** (silent ro→admin escalation), **F4** (TOCTOU
in the one safety gate the whole project rests on), and **F2/F3** (cleartext/weak HTTP auth and
demo-key root). F5 is the worst *persistence* once an attacker gets in once.
