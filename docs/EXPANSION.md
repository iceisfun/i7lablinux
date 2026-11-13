# Expansion: gaps found by the brief audit

The large gaps from [BRIEF-CHECKLIST.md](BRIEF-CHECKLIST.md) (audit V2, 2026-11-12), as roadmap items. The version plan
itself is [ROADMAP.md](ROADMAP.md) and [PLAN.md](PLAN.md) section 15; the original long proposal is archived in
[design-history/expansion-proposal.md](design-history/expansion-proposal.md). Each item names the owner area, what "done"
means, and how it is proven. Rule for every item: no busybox; new tools are `i7labsh` builtins or small own Rust binaries.

## Fix requests for owners (small, but in code this audit does not own)

| id | area | defect (evidence) | the fix | proof |
|---|---|---|---|---|
| G3 | `crates/i7labctl/src/http.rs` `call_put` | `i7labctl --http IP put ..` always exits 5 "not authentic (no valid X-Lab-Proof)". The client signs `request_mac_hashed(.., sha)` but never sends the `X-Lab-Body-Sha256` header; `i7labd::http::put_file` then answers 400 "PUT file needs Content-Length and X-Lab-Body-Sha256" with no proof, which the client reports as an auth failure ([AUDIT](e2e/brief-audit-20261112.txt), runs 1 and 3) | push `("X-Lab-Body-Sha256", hex(&sha))` into the request headers; make `tests/common/fake_http.rs` require the header like the real server does, and have the client report a 400 without a proof as "server rejected the request" rather than as an auth failure | a `http_fake.rs` test, plus `--http put` + `get` + `cmp` in `scripts/e2e` |
| G4 | `crates/i7labctl/src/stream.rs` `exec` | `exec --detach` starts the job (`jobs ls` shows it running) but i7labctl prints nothing and exits 254; `--json` gives `{"event":"result","ok":false,"exit":254}`. The host replies a plain JSON `{"v":1,"job":N}`, not a stream result with an exit code; help says "print the job id" | treat a `--detach` reply as a simple call: print `job N` (or the JSON), exit 0 | `ether_fake.rs` test; e2e check `exec --detach` then `jobs out N` |

## Roadmap items

### G1. SMART and NVMe health (v0.2; probes)

`labprobe::block::smart::probe` is a stub (`kind=unsupported`). Implement ATA PASS-THROUGH(16) over `SG_IO` (IDENTIFY,
SMART READ DATA/THRESHOLDS, verdict from attribute thresholds) and NVMe admin passthrough (`NVME_IOCTL_ADMIN_CMD`:
Identify, Get Log Page 0x02 SMART/Health), USB bridges via SAT where they allow it. Pure decoders over captured byte
buffers so they are host-tested; `scripts/capture-fixture` gains raw SMART pages. Proof: decoder tests from real drives;
QEMU NVMe (QEMU emulates the health log) and an `-device ide-hd` disk in `scripts/e2e`; the TUI Storage SMART column and
`blk smart` exit 3 on a failing verdict.

### G2. Console commands `identify`, `msg`, `tui`, `tui.dump` (v0.1 debt; i7labd console lane)

They are `since = v0.1` in the catalogue and advertised by `i7labctl help`, the SPA and REMOTE-BOOT.md, but
`i7labd/src/cmds/console.rs` has an empty table, so the host answers UNSUPPORTED "not implemented in this build".
`msg` and `identify` are the remote-boot helpers (tell the person at the machine what to do, point at the right box);
`tui.dump` is how a remote operator sees the console (PLAN F-F24, `Snapshots::console_frame`). Either implement them
(console event to the TUI loop; `identify` = keyboard LEDs via `KDSETLED` + ethtool PHYS_ID + full-screen banner) or move
their `since` to v0.2 so help and dispatch say "planned". Proof: `crates/i7labd/tests/brief_coverage.rs` (update its
`KNOWN_UNSERVED`), e2e checks `msg` then `tui dump` contains the text.

### G5. 802.1Q end to end (v0.2; labproto P2 + i7labd ether)

`--vlan 13 ping` over the QEMU test segment got no CHALLENGE (5 tagged requests sent, no reply); not diagnosed. Candidates:
the guest's tag handling (stripped tag + `PACKET_AUXDATA` vs in-band), the server replying untagged, or the client
filtering replies by tag. Proof: an e2e step with a tagged segment (`--vlan` on the client and either `i7lab.vlan=` hints
or a `net vlan add` on the guest), then a real trunk port on a lab switch; QinQ (0x88A8) the same way.

### G6. Hardware validation (v0.2; operator + integrator)

None of this has run outside QEMU:

* `scripts/build-usb-drive /dev/sdX` writing a real stick (the audit's loop device was correctly refused as `type loop`;
  a `scsi_debug` disk or a real stick on the operator machine is the next step), then booting it on 3 real hosts incl. a
  BIOS-only one and a UEFI one with CSM off.
* `i7labctl` on a real NIC with `cap_net_raw` (client-side `PacketLink`); every e2e run so far used `--link mcast:`.
* An image baked with the operator's real keys, booted.
* REMOTE-BOOT.md procedures B1/B2 read to a person, and C (JetKVM via `lab-boot --jetkvm` / hwlabd).
* KMS/framebuffer TUI on real GPUs, USB Ethernet fallback for hosts without a NIC driver.

Record results in a `docs/HW-RESULTS.md` table (host, firmware, boot path, beacon, ether ping, blk read, notes).

### G7. E2E coverage of every command in `help` (v0.2; integrator)

`scripts/e2e` covers the core path (91 checks). The audit had to run `put`/`get`, `fs`, `jobs`, `time-set`, `wait`,
`poweroff`, `inv --section`, `blk smart`, `help` by hand. Add them to `scripts/e2e`, plus: interactive `shell` on a pty
(drive it like `tests/e2e/tuicap.py`), `net set --confirm` with rollback, `net vlan add/del`, DHCP failure and static
hints (`I7LR2`), `reboot --to-os` under OVMF (check BootNext in the vars file), SPA in a headless browser against the live
guest. Goal: one e2e check per command line in `i7labctl help`, so `help` cannot advertise something that does not work.

### G8. Small cleanups carried from E2E-RESULTS

Kernel `CONFIG_DUMMY=y` (`dummy0`, `sit0` in every NIC list); shared termios/SIGWINCH state between tty1 and serial
TUIs; console `Ping` is a TCP connect (raw ICMP in `labproto::sys` or say so in TUI.md); `scripts/build-userland` does
not build `i7labctl`.
