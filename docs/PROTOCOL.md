# i7lablinux wire protocols

> **Superseded by docs/PLAN.md (authoritative) on:** PLAN.md C3 (HTTP paths `/api/v1/nonce`, `/api/v1/hello`; no `/nonce`, `/health`), C5 (`inv` sections), C20 (no public keys), C21 (one `labproto::session` engine), C22 (file path policy), C23 + section 4.4 (`accept_v1_hint` default off, `i7lab.ether=`), `frame::canonical_tags` (VLAN stack), new ids `time.set` 0x0005 and `tui.dump` 0x0083, `key.set` planned v0.3 (section 5). Read PLAN.md first; where this note disagrees, PLAN.md wins.


Status: design, version 1 of the command protocol, version 2 of the beacon. No code implements this yet.
Scope: the Ethernet (L2) control channel, the L2 beacon, address hints, and a short informative mapping to the HTTP API.
The command client is `i7labctl` (see `I7LABCTL.md`); the server is `i7labd` inside the initramfs.
Everything is our own code. No busybox, no shell-outs for protocol work.

Contents

1. Goals and non-goals
2. Ethertypes and framing (VLAN tolerance)
3. Command frame layout (byte exact)
4. Session establishment and authentication
5. Requests, responses, streams
6. Fragmentation, reliability, flow control
7. Command catalogue
8. Rate limiting and abuse rules
9. Versioning and extension
10. L2 beacon v2 (and v1 compatibility), probe, address hints
11. HTTP mapping (informative)
12. Test vector
13. Threat model and what is not defended

## 1. Goals and non-goals

Goals
* Control a booted lab host with no IP address, no DHCP, on any VLAN reachable at L2: `i7labctl --ether <mac> --cmd <name> [params]`.
* Authenticated (a baked-in shared secret, never sent on the wire), replay-protected, and safe against a hostile L2 neighbour as far as a shared-secret scheme can be.
* Reliable over a lossy segment: requests and responses of any size, streamed command output, file transfer.
* Std-only implementation on both ends: SHA-256 and HMAC are about 150 lines, no TLS stack.

Non-goals
* Confidentiality. Frames are authenticated, not encrypted. Do not put secrets in command arguments or file contents you would not send in clear over the lab segment. (Option for v2 of the protocol: ChaCha20-Poly1305 with the session key; reserved flag bit, see 9.)
* Routing. Ethernet frames do not cross routers. Use the HTTP or ssh transport for routed access.
* High throughput. Target: some tens of MB/s on gigabit, enough for logs and kernel/initrd uploads.

## 2. Ethertypes and framing

| ethertype | use | notes |
|---|---|---|
| `0x88B5` | beacon, address hint, probe (existing, lab-proxy) | IEEE local experimental ethertype 1 |
| `0x88B6` | command channel (new) | IEEE local experimental ethertype 2; free in this lab, not used by lab-proxy |

Both are in the IEEE 802 "local experimental" range, so no registration is needed. The beacon keeps `0x88B5` for compatibility; the command channel
is separate so a legacy registry that sees `0x88B6` frames ignores them.

All multi-byte integers on the wire are big-endian. Strings are UTF-8. "MAC" is 6 bytes.

### 2.1 Ethernet framing and VLAN tags

```
dst MAC (6) | src MAC (6) | [tag]* | ethertype (2) | payload | (pad to 46) | FCS (NIC)
tag = TPID (0x8100 or 0x88A8) (2) | TCI (2)      (PCP 3 bits, DEI 1, VID 12)
```

Receiver (both ends):
* Accept zero, one or two stacked tags (0x8100 then optionally 0x8100/0x88A8). Walk the tag stack until a non-tag ethertype; accept the frame if it is `0x88B5`/`0x88B6`.
* Linux strips an outer VLAN tag into packet metadata before a protocol-specific socket sees it. Both ends therefore use one `AF_PACKET`/`SOCK_RAW`/`ETH_P_ALL` socket
  with a kernel BPF filter (the two ethertypes, plain or behind a tag, as lab-proxy does) and `PACKET_AUXDATA`. The VLAN id is the in-band tag if present, else auxdata `tp_vlan_tci` when `TP_STATUS_VLAN_VALID`.
* Payload length comes from the header (`plen`), never from the frame length: short frames are padded by the NIC to 46 bytes of payload, and trailing bytes are ignored.

Sender:
* A reply uses the **same tag stack** (TPIDs and TCI) as the request it answers and goes out the NIC the request arrived on. The server stores the stack per session. A session is keyed on (source MAC, tag stack, session id).
* Tags are not authenticated; switches may rewrite them. The HMAC covers MACs (through the session key) but not the tags. A frame that arrives with a different tag stack than the session was opened with is dropped (cheap defence against cross-VLAN confusion).
* The client sends untagged by default; `--vlan N` makes it send 802.1Q tag N (PCP 0). If the NIC is a VLAN sub-interface (`eth0.13`), tags are added by the kernel and the client sends untagged on it.
* Maximum frame payload (the part after the ethertype) is the interface MTU, 1500 by default. A tag adds 4 bytes outside the MTU, so tags never shrink the payload.

## 3. Command frame layout (ethertype 0x88B6)

The payload after the ethertype is exactly:

```
offset size field
  0     2   magic        0x49 0x37 ("I7")
  2     1   ver          protocol major version, 1
  3     1   type         frame type, table below
  4     1   flags        bit0 FIN, bit1 ACK_REQ, bit2 REPLY (keepalive), bit3..6 reserved 0, bit7 ENC (reserved, 0 in v1)
  5     1   chan         data channel (table below), 0 for non-data frames
  6     2   cmd          command id (REQ/RESP), 0 otherwise
  8     4   session      session id (0 in HELLO/CHALLENGE/PROBE)
 12     4   req_id       request id (0 when not applicable)
 16     8   ctr          per-session, per-direction frame counter (replay protection)
 24     4   msg_len      total length of the message on this channel in bytes, 0xFFFFFFFF if unknown (stream)
 28     4   off          byte offset of this frame's payload within the message/stream on (req_id, chan); for ACK: next expected offset
 32     2   plen         payload length in this frame
 34     2   win          ACK: receiver window in frames; otherwise 0
 36     2   status       RESP/ERR: status code; otherwise 0
 38     2   rsv          0, ignored on receive
 40   plen  payload
 40+plen 16  tag         HMAC-SHA256 truncated to 128 bits
```

Header 40 bytes, tag 16 bytes: overhead 56 bytes. The fragment payload size negotiated at session open (`frag`) defaults to 1400, so a full frame is
`14 + 40 + 1400 + 16 = 1470` bytes on the wire (1474 tagged); the hard maximum is `mtu - 56`. A frame whose `plen` does not fit in the received length, or exceeds `frag`, is dropped.

Frame types

| type | name | direction | tag key | purpose |
|---|---|---|---|---|
| 1 | HELLO | c->s | K (long-term) | client starts a session, carries client nonce |
| 2 | CHALLENGE | s->c | K | server nonce cookie, proves server knows K |
| 3 | OPEN | c->s | SK | client confirms the cookie, session is created |
| 4 | OPEN_OK | s->c | SK | session parameters, role |
| 5 | REQ | c->s | SK | request body (command arguments) |
| 6 | RESP | s->c | SK | final result and status |
| 7 | DATA | both | SK | stream data on a channel (stdout, stdin, file chunks, control) |
| 8 | ACK | both | SK | cumulative ack plus selective bitmap for one (req_id, chan) |
| 9 | CANCEL | c->s | SK | abort request `req_id` (signal for exec) |
| 10 | CLOSE | both | SK | end session |
| 11 | KEEPALIVE | both | SK | liveness; REPLY flag marks the answer |
| 12 | NO_SESSION | s->c | K | "I do not know session N", client re-opens |
| 13 | ERR | s->c | SK | protocol-level error for a session (status) |
| 16 | PROBE | c->broadcast | none | active discovery request |
| 17 | PROBE_REPLY | s->c | none | same body as a beacon v2 |

Unknown types are dropped silently.

Channels (`chan`)

| chan | name | direction | content |
|---|---|---|---|
| 0 | MSG | REQ body c->s, RESP body s->c | structured message, whole body fragmented by `off` |
| 1 | STDOUT | s->c | exec/shell/log/test output, or progress lines |
| 2 | STDERR | s->c | |
| 3 | STDIN | c->s | exec/shell input |
| 4 | FILE | c->s for put, s->c for get | file bytes |
| 5 | CTL | c->s | signals and pty resize: `'S' signo(1)`, `'W' cols(2) rows(2)` |

For each (req_id, chan) data flows in exactly one direction, so an ACK always acknowledges the opposite end's data.

### 3.1 Payload encodings

* **Arguments** (REQ body, chan 0): `u16 count`, then `count` times `u16 len` + bytes (argv style, each at most 65535 bytes, total at most 64 KiB unless the command says otherwise).
  Command options are encoded as ordinary argv words (`"--mb" "256"`), so the CLI maps 1:1 onto the wire and unknown future options fail with `BAD_ARGS`, not silently.
* **Results** (RESP body, chan 0): UTF-8 JSON text for structured commands (inventory, probes), raw bytes where the command says so (file data is on chan 4). `status` carries the numeric result; the body for `exec` starts with `i32 exit_code` (see 7).
* JSON written by the server is compact, one object, strings escaped, no NaN. The client parses it and re-emits it under `--json`.

Status codes (`status` field)

| code | name | meaning |
|---|---|---|
| 0 | OK | |
| 1 | EPERM | role (read-only key) may not run this command |
| 2 | BAD_ARGS | unknown option, missing parameter, malformed value |
| 3 | UNSUPPORTED | unknown or compiled-out command |
| 4 | BUSY | concurrency limit, try later (retry-after in body) |
| 5 | REFUSED | safety rule refused (for example block write on a mounted device) |
| 6 | NOT_FOUND | device, file, interface |
| 7 | IO | I/O error (details in body) |
| 8 | TIMEOUT | command exceeded its time limit |
| 9 | TOO_BIG | body or stream limit |
| 10 | CANCELED | canceled by the client |
| 11 | EXISTS / CONFLICT | for example sshd already running, interface in use |
| 12 | NOT_READY | subsystem not up yet (boot still in progress) |
| 13 | STREAM_GONE | retransmitted REQ whose streamed output is no longer replayable (see 6.4) |
| 14 | INTERNAL | server bug; body has a one-line message |

## 4. Session establishment and authentication

### 4.1 Keys

Two 32-byte keys are baked into each image: `admin` (key id 0, any command) and `ro` (key id 1, read-only commands, marked R in section 7).
`key_id` on the wire is `first4(SHA256("i7c-keyid" | K))`, so it identifies which key without revealing it. Generation, files and rotation are in `I7LABCTL.md` (`key init|show|rotate`).
The raw key is never transmitted. A host with unknown key id silently drops the HELLO.

### 4.2 Handshake (two round trips, stateless until the client proves itself)

```
client                                                    server
  HELLO     (tag K, cn = 16 random bytes)  ------------->  verify tag; no state kept
            <------------  CHALLENGE (tag K, sn = stateless cookie, boot_id, caps)
  client verifies CHALLENGE tag (the server knows K), derives SK
  OPEN      (tag SK, echoes cn and sn)     ------------->  recompute cookie, check age, derive SK, verify tag, create session
            <------------  OPEN_OK  (tag SK: session params, role)
  REQ ... (client may pipeline the first REQ right after OPEN; the server holds it until OPEN has been processed)
```

HELLO payload (padded to at least 48 bytes so that CHALLENGE is never larger than HELLO; see 8):

```
0   16  cn          client nonce (random)
16   4  key_id
20   1  ver_min
21   1  ver_max
22   2  max_frag    largest fragment payload the client accepts
24   4  client_caps bit0 = understands STREAM_GONE replay hints, rest 0
28  20  pad (zero)
```

Header: `type 1`, `session 0`, `ctr 0`, `req_id 0`, `plen 48`.
Tag: `HMAC(K, "i7c-hello\0" | hdr | payload)` truncated to 16 bytes. The key in use is the one selected by `key_id`.

CHALLENGE payload (36 bytes):

```
0   16  sn          server cookie
16   8  boot_id     random per boot
24   4  uptime_ms   ms since boot (monotonic, wraps at 49 days)
28   1  ver         chosen version (highest in common)
29   1  rsv
30   2  max_frag    min(client max_frag, server max_frag), the session fragment size
32   4  server_caps bit set of supported command groups (section 7)
```

The cookie is stateless: `sn = first16(HMAC(cookie_secret, cli_mac | srv_mac | cn | tag_ids | bucket))`, `bucket = uptime_ms / 15000`, `cookie_secret` random at boot.
The server accepts the current and the previous bucket (15 to 30 s validity). Tag: `HMAC(K, "i7c-chal\0" | hdr | payload | cn)`; including `cn` proves the server saw this very HELLO and knows K.

Session key and session id (both ends compute):

```
SK = HMAC(K, "i7c-sess\0" | cn | sn | client_mac | server_mac | ver)     (32 bytes)
session id = big-endian u32 of sn[0..4]
```

`client_mac` and `server_mac` are the Ethernet source and destination MACs of the HELLO. Binding both MACs stops a frame captured to one host being replayed to another.

OPEN payload: `cn (16) | sn (16)`, `ctr 1`, tag `HMAC(SK, 0x01 | hdr | payload)`.
The server recomputes the cookie, rejects it if older than 30 s, derives SK, verifies the tag, then allocates the session. A duplicate OPEN for an existing session id (retransmission) gets the same OPEN_OK again, without creating a second session.

OPEN_OK payload:

```
0   1  role       0 admin, 1 ro
1   1  rsv
2   2  idle_s     idle timeout in seconds (default 120)
4   2  frag       session fragment size
6   2  window     initial window in frames the server accepts for REQ/DATA (default 16)
8   4  caps       supported command groups
12  2  hostlen
14  n  hostname   UTF-8
```

### 4.3 Per-frame authentication and replay protection

Every frame after the handshake carries `tag = trunc16(HMAC(SK, dir | hdr | payload))` where `dir` is one byte (`0x01` client to server, `0x02` server to client) and `hdr` is the 40 header bytes exactly as sent (including `ctr`).
Tag comparison is constant time.

* `ctr` is a per-session, per-direction counter starting at 1 (OPEN is 1, OPEN_OK is 1) and increasing by exactly 1 per **transmitted frame, including retransmissions** (a retransmission gets a new `ctr`).
* The receiver keeps `max_ctr` and a 64-bit bitmap. A frame is accepted if `ctr > max_ctr` or `max_ctr - 63 <= ctr <= max_ctr` and its bit is clear. The bit is set only **after** the tag verified. Everything else is dropped. Ethernet reorders rarely; the window tolerates it.
* The ordering of work is: parse length, check `session` exists, check `ctr` window (cheap, no crypto), verify tag, then update window and act. A forged frame with a bogus session id or an old `ctr` costs no HMAC.
* Session lifetime: idle timeout 120 s (refreshed by any authenticated frame), absolute lifetime 1 hour, then CLOSE and the client re-handshakes (it does so transparently). A `ctr` reaching 2^40 also ends the session.
* Reboot or `i7labd` restart changes `boot_id` and `cookie_secret`; old sessions are gone. A frame for an unknown session is answered with NO_SESSION (tag `HMAC(K, "i7c-nosess\0" | session | boot_id)`), rate limited, same size as the request or smaller, and the client re-handshakes. The client reports the `boot_id` change (`i7labctl wait` uses it).

CHALLENGE, OPEN, NO_SESSION and HELLO replays: a replayed HELLO gets a CHALLENGE with a fresh cookie and costs the server one HMAC and no state; a replayed OPEN older than 30 s fails the cookie check; a replayed OPEN inside the window is idempotent (see above).

Role check: at OPEN the role is fixed by `key_id`. A REQ for a command not allowed for the role gets `RESP status=EPERM` (still authenticated; the client learns why).

## 5. Requests, responses, streams

* `req_id` is a client counter starting at 1, unique within the session; at most 8 requests outstanding per session (the 9th gets `BUSY`).
* REQ: chan 0 body (arguments), `cmd`, `msg_len` = body length, fragments by `off`, `FIN` on the last. A single-frame request is the common case.
* The server executes once the body is complete. **Idempotence:** the server keeps the last 16 `req_id`s with state. A retransmitted fragment or complete REQ with a known `req_id` never starts the command again; the server re-sends the stored RESP (kept up to 1 MiB, last 16 results) or, for a still-running command, an ACK.
* RESP: `status`, body on chan 0 (`msg_len` known), `FIN` on the last fragment. A RESP is complete when the client has acknowledged all its fragments.
* Streaming commands (exec, shell, logs follow, blk tests with progress, get) send DATA on chan 1/2/4 as the output appears, then RESP when the command ended and all its DATA have been acknowledged (so RESP never overtakes output).
* `put`: REQ describes the file (path, size, mode, sha256), the server replies OK in RESP only after receiving chan 4 fully and verifying size and sha256 (see 7).
* CANCEL for `req_id` makes the server send SIGTERM to the command process group, then SIGKILL after 3 s; RESP `CANCELED` follows. `chan 5` signals allow other signals (`exec` with a tty maps `^C` to chan 5 'S' 2).
* Stdin end is a DATA with FIN on chan 3. Closing the session (CLOSE or idle timeout) kills the session's commands, except commands started with `--detach` (7), which are children of `i7labd` with output logged to `/run/i7lab/jobs/<id>`.

## 6. Fragmentation, reassembly, reliability, flow control

### 6.1 Fragmentation

A message or stream on (req_id, chan) is split into fragments of exactly `frag` payload bytes except the last (FIN set). The fragment is identified by `off`. The receiver reassembles into a buffer of `msg_len` bytes (chan 0 only; limits: REQ body 64 KiB, RESP body 16 MiB), writes streams to their sink in order, and never allocates more than the declared `msg_len`. A fragment with `off + plen > msg_len`, `off` not a multiple of `frag` (except FIN), or `msg_len` exceeding the limit is dropped and the session gets an ERR(TOO_BIG or BAD_ARGS). Overlapping duplicates must carry identical bytes (otherwise the first wins).

### 6.2 Acknowledgement

ACK frame: `chan` and `req_id` name the stream, `off` is the **next expected contiguous byte**, `win` the receiver's remaining window in frames, payload (optional) an 8-byte big-endian SACK bitmap: bit *i* set means the fragment at `off + (i+1)*frag` was received.
Receivers send an ACK
* immediately when `ACK_REQ` is set on a fragment, or the FIN fragment arrives,
* after every 8 data frames,
* after 20 ms of an unacknowledged frame (delayed ack),
* immediately when a fragment arrives out of order (shows the hole).

ACKs themselves are not acknowledged and have a `ctr` like every frame.

### 6.3 Sender behaviour

* Window: start with the `win` the peer advertised in OPEN_OK or its last ACK (default 16 frames), at most 64. The sender never has more than `win` unacked fragments in flight per stream, and not more than 128 across a session.
* Retransmission timer: initial RTO 250 ms; after RTT samples, `RTO = clamp(srtt + 4*rttvar, 100 ms, 2 s)` (Jacobson/Karels as for TCP); each retry doubles RTO. On an ACK with a SACK hole, the missing fragment is retransmitted at once (fast retransmit, once per RTT).
* Retry limit: 8 retransmissions of one fragment (about 30 s at the cap); then the stream and session are marked dead, the client reports `E_TIMEOUT` (exit code 4), the server CLOSEs the session.
* A session with nothing in flight and idle for 20 s: the client sends KEEPALIVE; the server answers with KEEPALIVE+REPLY. No answer in 3 tries: session dead.
* Pacing: bursts are limited to 16 frames, then the sender waits for an ACK or 1 ms, so a slow NIC or switch is not flooded.
* Handshake frames (HELLO, OPEN) are retried by the client 5 times at 250/500/1000/1000/1000 ms. HELLO and OPEN go to a **unicast** MAC; there is no broadcast HELLO.

### 6.4 Server replay limits

Short results (RESP up to 1 MiB) are cached by `req_id`, so a lost RESP is re-sent without re-running a command. Streamed output is **not** cached beyond the unacknowledged window: if the client's ACK is lost and the window slid, a retransmitted REQ for a streaming command gets `STREAM_GONE`. The client then reports that the command ran but its output is incomplete. Retried REQs are deduplicated anyway, so no command ever runs twice because of retransmission.

## 7. Command catalogue

`R` means the read-only key may run it; `W` means admin only. Ids are u16. The CLI name is what `--cmd` takes. Groups give the `caps` bits (bit number = group number).

| id | name | grp | role | arguments (argv words) | result |
|---|---|---|---|---|---|
| 0x0001 | `ping` | 0 | R | optional echo bytes (up to 1024) | echo, `uptime_ms`, `boot_id`, load, time |
| 0x0002 | `id` | 0 | R | | beacon-v2 fields as JSON, versions, role, key fingerprints, kernel, image build id |
| 0x0003 | `cmds` | 0 | R | | JSON list of supported commands with ids, role and argument summary (feeds `i7labctl help`) |
| 0x0004 | `stats` | 0 | R | | protocol counters: frames rx/tx, bad tags, drops, sessions, retransmits, rate-limit hits |
| 0x0010 | `inv` | 1 | R | `[--section sys,board,bios,cpu,mem,thermal,nic,disk,usb,pcie,power,dmi]` | JSON inventory (CPU model/flags/topology, memory incl. DIMMs from DMI, thermal zones and fans, hwmon, DMI tables, NICs with link/speed/driver/MAC, disks with model/serial, USB, PCIe, battery/power) |
| 0x0011 | `pcie` | 1 | R | `[--tree] [--id vvvv:dddd] [--class cc] [--verbose]` | JSON devices: bus/dev/fn, ids, class, driver, link speed/width (and max), BARs, IOMMU group, AER counters, config space dump with `--verbose` |
| 0x0012 | `usb` | 1 | R | `[--tree]` | JSON: bus, port path, vid:pid, class, speed, manufacturer, product, serial |
| 0x0013 | `blk.ls` | 1 | R | `[--all]` | JSON: name, size, model, serial, wwn, rotational, transport, partition table, filesystem signatures, mounted, holds-boot-media flag, **write_safe** verdict with reasons |
| 0x0014 | `blk.smart` | 1 | R | `<dev> [--attrs] [--selftest short\|long]` | JSON SMART/NVMe health (verdict, temperature, power-on hours, realloc/pending, wear, error log); `--selftest` starts a self test (W) |
| 0x0015 | `blk.read` | 1 | R | `<dev> [--mb N] [--regions start,mid,end\|--offset B --len B] [--bs 1m] [--direct]` | progress on chan 1, result JSON per region MiB/s, errors, checksum |
| 0x0016 | `blk.write` | 1 | W | `<dev> --destructive --serial S [--mb N] [--regions ..] [--offset B --len B] [--seed N]` | pattern write then read back and compare; progress on chan 1; result JSON per region MiB/s, mismatches |
| 0x0017 | `blk.verify` | 1 | R | `<dev> --seed N [--regions ..]` | re-read and compare a region previously written by `blk.write`, no write |
| 0x0018 | `net.ls` | 2 | R | `[<iface>]` | JSON NICs: MAC, driver, link state, speed, duplex, carrier changes, IPv4/IPv6, VLAN subifs, rx/tx counters, route, DNS |
| 0x0019 | `thermal` | 1 | R | `[--follow]` | JSON temperatures/fans, streamed with `--follow` |
| 0x0020 | `exec` | 3 | W | `[--timeout S] [--env K=V]... [--cwd D] [--tty COLSxROWS] [--detach] [--stdin] -- argv...` | chan 1/2 streams; RESP body: `i32 exit_code` + JSON `{signal,duration_ms}`; `status` OK unless the command could not start |
| 0x0021 | `shell` | 3 | W | `[--cols N --rows N] [--term T]` | like exec of `/bin/i7labsh` on a pty (the in-image shell); chan 3/1/5 |
| 0x0030 | `put` | 4 | W | `<path> --size N --sha256 HEX [--mode 0644] [--offset N] [--mkdirs]` | after chan 4 data and verification: JSON `{bytes,sha256}`; writes to `<path>.part`, renames at the end; `--offset` resumes |
| 0x0031 | `get` | 4 | R/W | `<path> [--offset N] [--len N]` | RESP body JSON `{size,mode,mtime,sha256}`; chan 4 data. R key limited to `/var/log`, `/run/i7lab`, `/proc`, `/sys`, `/etc/os-release`; W any path |
| 0x0032 | `fs.ls` | 4 | R/W | `<path> [--long]` | JSON directory listing (same path limits as get) |
| 0x0033 | `fs.stat` | 4 | R/W | `<path>` | JSON stat |
| 0x0034 | `fs.rm` | 4 | W | `<path> [--recursive]` | |
| 0x0040 | `reboot` | 5 | W | `[--force] [--delay S] [--uefi]` | RESP OK sent first, reboot 1 s later; `--uefi` sets `OsIndications` to enter firmware setup |
| 0x0041 | `poweroff` | 5 | W | `[--delay S]` | same pattern |
| 0x0042 | `kexec` | 5 | W | `--kernel PATH [--initrd PATH] [--cmdline STR]` | files uploaded earlier with `put`; loads and execs; the host reappears with a new `boot_id` |
| 0x0050 | `net.set` | 2 | W | `<iface> (--dhcp \| --ip A.B.C.D/N [--gw A.B.C.D] [--dns A,..]) [--mtu N] [--confirm S]` | `--confirm S` reverts the change after S seconds unless `net.confirm` arrives (safe remote reconfiguration) |
| 0x0051 | `net.vlan` | 2 | W | `add <iface> <vid> [--ip ..] \| del <iface> <vid>` | creates or removes an 802.1Q sub-interface; the beacon starts on it |
| 0x0052 | `net.confirm` | 2 | W | | cancels the pending revert of `net.set` |
| 0x0053 | `net.link` | 2 | W | `<iface> up\|down` | |
| 0x0060 | `svc` | 6 | W | `<sshd\|http\|beacon\|ether> start\|stop\|status [--port N]` | JSON state. `ether stop` is refused on the transport carrying the request unless `--force` |
| 0x0070 | `logs` | 7 | R | `[--dmesg\|--init\|--daemon\|--http] [-n LINES] [-f]` | chan 1 stream, `-f` follows until CANCEL |
| 0x0080 | `identify` | 8 | W | `[--seconds N] [--stop]` | blink the keyboard LEDs (caps/num/scroll) and NIC LED (ETHTOOL_PHYS_ID) and print a large banner on the console TUI; default 30 s |
| 0x0081 | `msg` | 8 | W | `<text>` | shows a message in the console TUI for the operator at the host ("remove the stick now") |
| 0x0082 | `tui` | 8 | W | `tab <name> \| reset` | switch the console TUI tab |
| 0x0090 | `key.set` | 9 | W | `<role> --hex HEX [--persist]` | replaces the role key in RAM for this boot; `--persist` writes it to the config partition of the boot media if writable. The reply is authenticated with the old key; all sessions of that role close |
| 0x00A0 | `jobs` | 3 | W | `[ls\|kill ID\|out ID]` | list and manage `--detach` jobs |

Command groups (`caps` bit numbers): 0 core, 1 probes, 2 net, 3 exec, 4 files, 5 power, 6 services, 7 logs, 8 identify/console, 9 keys.

Semantics worth stating exactly

* **exec**: runs as root in a new process group (not a login shell: `argv` is executed directly; `i7labsh` builtins are reachable via `exec -- i7labsh -c "..."`). Default timeout 300 s (`--timeout 0` = none). Output is capped at 64 MiB per exec unless streamed with an active window (the server stops reading the child when the window is closed, which is the backpressure). At most 4 concurrent execs per host.
* **shell**: pty session; the server sets `TERM`, applies `chan 5` resizes, and ends the session with the child. Interactive use needs about 1 frame per keystroke; typical latency is under 2 ms on a LAN.
* **blk.write safety** (enforced by the server, not the client). The command is refused with `REFUSED` and a reason list unless **all** hold: `--destructive` is present; `--serial` equals the device's actual serial (or WWN if no serial); the device is not mounted and none of its partitions are; it has no partition table and no recognised filesystem or RAID/LVM/LUKS signature in the probed regions; it is not the device holding the boot media or any device backing the running root, `/run/i7lab` or the config partition; it is not already under test. The result of the checks is in `blk.ls` (`write_safe`, `write_unsafe_reasons`) so the client shows it before the operator types the serial. There is no override for the boot-media rule. A device that fails only the "has partition table / filesystem" rule can be wiped by a separate explicit `blk.wipe-signatures <dev> --serial S --destructive` (not in v1; see I7LABCTL open issues).
* **put/get**: both sides compute SHA-256 over the file; `put` refuses to rename to the final name when it differs. `--offset` resumes at a given byte (the `.part` file is truncated to that offset). File size is limited to 4 GiB - 1 per request by the 32-bit `off`; larger files are sent in several `put --offset` requests with a sub-range sha256 per request.
* **net.set --confirm**: a remote IP/VLAN change that would lock the operator out reverts itself. The client confirms from its new address (or over ether, which is not affected by IP changes).
* **reboot / kexec**: the RESP is sent and acknowledged (or the 1 s grace period passes) before the action starts.
* **identify** has no hardware requirement: if there is no keyboard LED or NIC LED control, it still draws the console banner.
* There is no command to read memory or PCI config of other machines; `pcie --verbose` reads local config space only (read-only).

Commands that need a missing subsystem return `UNSUPPORTED` (compiled-out) or `NOT_READY` (for example `blk.ls` before udev-equivalent discovery finished).

## 8. Rate limiting and abuse rules

The server is on a shared lab segment and runs as root: every unauthenticated path is cheap, bounded and silent.

* **Silent drops.** A frame with wrong magic, version out of range, unknown key id, bad length, bad `ctr`, or a bad tag is dropped with no reply (no oracle). The only unauthenticated replies are CHALLENGE (needs a valid HELLO tag), NO_SESSION (rate limited), PROBE_REPLY (rate limited) and beacons.
* **No amplification.** Any unauthenticated reply is no larger than the frame that caused it (HELLO is padded to 48 for this reason). PROBE_REPLY is the exception (it is larger than a PROBE) and is therefore limited to 2 per second per NIC and jittered.
* **Per-source token buckets** (keyed on source MAC): HELLO 5 per second, burst 20; all frames without a valid session 50 per second; NO_SESSION 2 per second. Global: 200 HELLO per second, 500 unauthenticated frames per second.
* **Auth failures.** 5 bad tags from one source MAC within 10 s start a 10-second penalty in which every frame from that MAC is dropped before any crypto. Penalty doubles on repeats up to 5 minutes; reset after a quiet hour. Counters are visible in `stats` and the console TUI.
* **Sessions.** At most 8 sessions in total, 2 per source MAC, at most 4 handshakes in progress (the cookie scheme keeps no state for them, so this bound only applies to OPEN). Idle sessions expire at 120 s. A new session from an already-connected MAC and role is allowed up to the limit and the oldest is closed when the limit is hit.
* **Per-session limits.** 8 outstanding requests, 4 concurrent execs per host, 1 concurrent block write test per host, 2 concurrent block read tests, 128 frames in flight, request body 64 KiB, response body 16 MiB, stream length 4 GiB - 1. Violations return `BUSY` or `TOO_BIG` and, if repeated 20 times, close the session.
* **Memory.** Per session at most 2 MiB of reassembly and 1 MiB of response cache; per host at most 24 MiB for all sessions.
* **CPU.** The receive loop does: header sanity, MAC rate-limit lookup, session lookup and counter window, then one HMAC. Time budget: a saturated 1 Gbit/s stream of garbage must not stop the beacon and the console TUI (receive loop is single-threaded but bounded to a 5 ms slice per 20 ms; excess frames are dropped by the socket buffer).
* **Dangerous commands** (`reboot`, `poweroff`, `kexec`, `blk.write`, `fs.rm`, `net.set`, `svc ... stop`, `key.set`) require the admin key; they are logged to the console TUI and `/run/i7lab/audit.log` (time, session, source MAC, VLAN, command, argv without file contents). The audit log cannot be disabled by a command.
* **Bound to NICs.** `i7labd` listens on every Ethernet NIC with carrier except interfaces listed in `/etc/i7lab/ether.deny` (a baked option, default empty). `svc ether stop` stops all NICs.

## 9. Versioning and extension

* `ver` is the **major** version of the frame layout; v1 is this document. A server speaking versions *a..b* answers a HELLO with `ver_min..ver_max` containing a common version, or drops it. The negotiated version goes into SK, so downgrade is impossible without K.
* Minor evolution happens without a version bump: new commands (ids are never reused), new options (argv words, rejected with `BAD_ARGS` by old servers), new beacon keys (unknown keys are ignored by readers), new `caps` bits and `client_caps`/`flags` bits that old peers ignore. `flags` bits 3 to 6 and `rsv` must be sent as zero and are ignored on receive.
* `flags.ENC` (bit 7) is reserved for an AEAD mode (payload encrypted with a key derived from SK). A v1 receiver drops frames with ENC set.
* A command id of the form `0x8xxx` is reserved for vendor/private experiments and never assigned by the project.
* The `cmds` command is the source of truth for the live command list; `i7labctl help <cmd>` falls back to the compiled-in table for an older server.
* `i7labctl` checks `ver`, `image build id` and `caps` in OPEN_OK and warns when talking to a host from a different build.

## 10. L2 beacon v2, probe, hints (ethertype 0x88B5)

### 10.1 Beacon v1 (existing, I7LP1)

Broadcast frame, payload `I7LP1\n` then lines `key=value\n`, keys `mac iface host product vendor serial board board_serial kernel link ip`. Values may contain spaces; control characters are replaced by spaces; the first occurrence of a key wins; fields are cut to 128 bytes.
This is documented in `docs/design/lab-proxy.md` of the prior art and is not changed.

### 10.2 Beacon v2 (I7LP2)

Same transport (dst `ff:ff:ff:ff:ff:ff`, ethertype `0x88B5`, one frame per NIC), payload `I7LP2\n` followed by the **same key=value lines**, with these differences:

* The magic is `I7LP2`.
* All v1 keys are present with the same meaning, so a v2 beacon is a strict superset.
* New keys (unknown keys must be ignored by readers):

| key | meaning |
|---|---|
| `v` | beacon version, `2` |
| `proto` | command protocol versions, `1` or `1-2` |
| `ctl` | ethertype of the command channel, `88b6`; empty if `svc ether stop` was run |
| `boot` | `boot_id`, 16 hex digits; changes at every boot |
| `up` | uptime in seconds |
| `gen` | beacon sequence number since boot (lets a reader detect dropped frames and reboots) |
| `state` | `booting`, `ready`, `busy` (destructive test running), `degraded` (a subsystem failed), `shutdown` |
| `build` | image build id (git describe or date) |
| `kid` | key fingerprint set: `a:<8hex>,r:<8hex>` = first 4 bytes of SHA256("i7c-keyid" \| K) of admin and ro keys, so a lab tool can tell which key set to try |
| `caps` | `caps` bits in hex |
| `http` | HTTP port or empty |
| `ssh` | `1` if sshd is running |
| `vlan` | the VLAN this beacon was sent on (`0`/empty = untagged) |
| `tag` | beacon authenticity tag, see below; always the **last** line |

* Example (one line per key in the frame; shown here on one line):

```
I7LP2 v=2 mac=02:00:00:9d:01:57 iface=eth0 host=lab-proxy board=NUC6i7KYB board_serial=BTKY000000XX kernel=6.18 link=up(up) ip=192.0.2.195/24 proto=1 ctl=88b6 boot=9f3c...e1 up=412 gen=204 state=ready build=2026-11-12 kid=a:14b746da,r:7c01de33 caps=3ff http=8080 ssh=0 tag=<32 hex>
```

* **Authenticity tag** (optional to verify): `tag = hex(trunc16(HMAC(K_beacon, "i7c-beacon\0" | src_mac | all lines before the tag line)))`, `K_beacon = HMAC(K_ro, "i7c-beacon-key")`. A verifying reader knows the host was built with its key set; a missing or failing tag is displayed as *unverified*, never as an error, and never changes behaviour (the beacon stays untrusted data, as in lab-proxy: **no secret is ever sent to an address learned from a beacon**). The tag is not fresh (replayable); `up` and `gen` reveal stale replays.
* Sender behaviour: every 2 s plus or minus 250 ms jitter on every Ethernet NIC with carrier, **and** on every VLAN sub-interface the host created (`net.vlan add`); 5 frames at 200 ms spacing right after link-up and after any address change; `state=shutdown` frame before reboot/poweroff. No more than 5 frames per second per NIC overall.
* Reader rules (unchanged from lab-proxy, extended): drop unless `mac=` is a well formed unicast address equal to the Ethernet source (else flag `src-mac-mismatch`); one frame per 500 ms per source MAC; at most 10 new hosts per second; cap 1024 hosts; `ip=` must be an IPv4 address or empty; strip to 128 bytes; the registry file adds `proto`, `boot`, `state`, `build`, `kid`, `ctl`, `tag_ok` fields to `hosts.json` (file `version` becomes 2; v1 readers ignore the extra fields).

### 10.3 Compatibility with I7LP1

* **Readers** (`i7labctl discover`, the registry) accept both magics. When both a v1 and a v2 frame from the same MAC arrive, the v2 frame wins and the v1 frame only refreshes `last_seen`.
* **Senders**: `i7labd` sends v2. While `beacon_compat=1` (default for the first two releases, a baked option in `/etc/i7lab/i7lab.conf`) it also sends a v1 frame, 1 s offset from each v2 frame, with exactly the 12 v1 keys, so an old `lab-proxy registry`/`labp` keeps working. When switched off, v1 readers see nothing.
* Old sticks (v1) show up in `i7labctl ls` with `proto=-` and are controllable only through their HTTP API (`transport http`); `i7labctl` says so.

### 10.4 Probe (active discovery)

`PROBE` (command-channel frame type 16, ethertype `0x88B6`, or the same on `0x88B5` for old tools: v1 stick ignores it) is broadcast by `i7labctl discover --active`. Payload `nonce (8 random bytes)`. Hosts reply with a PROBE_REPLY: unicast to the prober, ethertype `0x88B6`, body = the beacon-v2 text, delayed by random 0 to 400 ms, at most 2 per second per NIC. There is no authentication: it carries what beacons broadcast anyway. A prober sends at most 1 probe per second per NIC and 5 per run.
The point of probing is VLAN scouting without waiting: probe on each VLAN id given with `--vlan 1-4094` on a trunk (at most 20 ids per second).

### 10.5 Address hints

* **I7LR1** (existing): `I7LR1\nmac=<target>\nip=A.B.C.D/N\ngw=A.B.C.D\n`, unicast to the stick, applied only while the stick has no IPv4 and at most once per NIC, with a unicast /8../30 address and a gateway inside the subnet. Unchanged and still accepted (option `accept_v1_hint`, default on).
* **I7LR2** (new, authenticated): `I7LR2\nmac=<target>\nip=A.B.C.D/N\ngw=A.B.C.D\nvlan=<id or empty>\nboot=<boot id from beacon>\nseq=<u32>\ntag=<32 hex>`, `tag = trunc16(HMAC(K_admin, "i7c-hint\0" | dst_mac | all lines before tag))`. The sender must have seen the current `boot` in a beacon (so a captured hint does not apply after a reboot), `seq` must be greater than the last accepted one (RAM only, resets at boot). Accepted at any time, not only while address-less. `i7labctl discover --assign MAC=IP/PFX/GW` sends an I7LR2 to v2 hosts and an I7LR1 to v1 hosts.
* Preferred way to configure an address over the command channel is `net.set` (authenticated session); hints exist for sticks that have no usable session yet and for v1 compatibility.

## 11. HTTP mapping (informative)

The HTTP API (owned by the server task, `docs/HTTP.md`) exposes the same catalogue: `POST /api/v1/<cmd>` with `{"args":[...]}` and the same JSON result and `status` mapping, `GET /api/v1/stream/<req>` for streams (chunked or SSE).
Authentication reuses the lab-proxy scheme: `GET /nonce` (single use, 30 s), `X-Lab-Nonce`, `X-Lab-Auth = HMAC-SHA256(K, "lp-req" | nonce | method | target | sha256(body))`, reply proof `X-Lab-Proof`. The same two keys (admin, ro) apply. `/health` and `/id` are open. The raw key is never sent.
Every command in section 7 is available over HTTP except `svc ether ...` against the HTTP transport itself and the pty `shell` (done via WebSocket upgrade on `/api/v1/shell`, optional).

## 12. Test vector

All values for implementers' unit tests. `K` is the 32 bytes `00 01 02 ... 1f`.

```
key id        = first4(SHA256("i7c-keyid" | K))      = 14b746da
cn            = 11 * 16 bytes
sn            = 22 * 16 bytes
client_mac    = 02:00:00:00:00:01     (frame source)
server_mac    = 02:00:00:00:00:02     (frame destination)
ver           = 1
SK = HMAC(K, "i7c-sess\0" | cn | sn | client_mac | server_mac | 01)
             = 3e2246060b62e669bcbbe0ab430f8bc9a42f16e84c77a0eaae64ec744a36e2c1
session id    = 0x22222222
```

REQ `ping` with echo payload `"abcd"` (cmd 0x0001, session 0x22222222, req_id 1, ctr 2, msg_len 4, off 0, plen 4, flags 0) from client to server:

```
header (40 bytes)
49 37 01 05 00 00 00 01 22 22 22 22 00 00 00 01
00 00 00 00 00 00 00 02 00 00 00 04 00 00 00 00
00 04 00 00 00 00 00 00
payload  61 62 63 64
tag      59 d9 0c e8 42 12 0b 5d 66 85 d8 24 6b cc 44 99
         = trunc16(HMAC(SK, 01 | header | payload))
```

Whole Ethernet frame (without FCS, 74 bytes; the payload is 60 bytes, over the 46 byte minimum, so no padding):

```
020000000002 020000000001 88b6
493701050000000122222222000000010000000000000002000000040000000000040000000000006162636459d90ce842120b5d6685d8246bcc4499
```

(The value of `tag` above is for the header and payload exactly as listed; implementers check `HMAC` with `dir = 0x01`.)

## 13. Threat model

Defended: a passive or active attacker on the segment without K cannot execute any command, cannot learn K or SK, cannot replay a captured frame (counter window and per-session key bound to nonces and both MACs), cannot replay a captured session setup beyond 30 s, cannot make the server do more than a bounded amount of work (rate limits, one HMAC per accepted-shape frame, stateless cookie), and cannot use the server for amplification beyond the PROBE_REPLY bound. The client rejects a spoofed server (CHALLENGE and every RESP carry tags only a K holder can make).
Not defended: anyone holding an image copy or a USB stick has K (rebuild with `i7labctl key rotate` to change it); an attacker on the segment can read everything (no encryption); a man in the middle can drop, delay or reorder frames (denial of service) and can inject frames with a wrong VLAN tag or stack that the server drops; saturating the segment denies service; a host without a trustworthy time source gives only uptime based freshness (cookie age).
A one-key scheme: compromise of any one host image compromises all hosts built from the same key set. Per-host keys derived from the machine id (`K_host = HMAC(K_master, board_serial)`) are a planned improvement, documented in `I7LABCTL.md` under key management as future work.
