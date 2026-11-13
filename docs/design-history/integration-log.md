# Integration log (task X1, 2026-11-13)

Every change the integrator made to another lane's crate or script, with the smallest-change rule: what, where, why.
Build host: the build host (`/tmp/i7ll-integ`). Starting point: the workspace compiled and all lane tests passed (the lanes had
stubbed the shared foundation, see 1-7), nothing booted.

## Foundation that was still a stub (labproto, P1/P2) and blocked every transport

| # | What | Where | Why |
|---|---|---|---|
| 1 | `PacketLink`: AF_PACKET `ETH_P_ALL` socket, classic BPF accepting 0x88B5/0x88B6 plain or behind one 0x8100/0x88A8 tag, PACKET_AUXDATA VLAN recovery, own transmissions (PACKET_OUTGOING) dropped, poll-based recv with timeout, MAC from sysfs. BPF program is unit-tested by a tiny interpreter. | `crates/labproto/src/packet.rs` | Was `Unsupported`: i7labd's ether server could not open any NIC, i7labctl could not open a raw socket. Ported from the earlier prototype `tools/lab-proxy/src/net.rs`. |
| 2 | `UdpLink::multicast` (SO_REUSEADDR before bind, join group, loop on) plus `sys::udp_reuse_socket` | `link.rs`, `sys.rs` | `--link mcast:` is how QEMU `-netdev dgram` test segments are reached (scripts/qemu-test, scripts/e2e); was `Unsupported`. |
| 3 | rtnetlink client: dump links/addrs/routes, add/del address and route, link up/down, MTU, create/delete 802.1Q sub-interface. Pure encoders/parsers with byte-level tests. | `crates/labproto/src/netlink.rs` | Was all `Unsupported`: i7labd `netcfg` (DHCP result, static, VLAN hints) could not configure anything. |
| 4 | `sys::reboot`, `finit_module`, `if_up`, `openat2_beneath` | `crates/labproto/src/sys.rs` | Were stubs: reboot/poweroff did nothing, init loaded no modules, `get`/`fs` refused every file (openat2 failed closed). |
| 5 | JSON parser (bounded recursive descent, RFC 8259, depth/size/item limits, surrogate pairs, trailing-garbage and control-character rejection) | `crates/labproto/src/json.rs` | `parse` accepted only `null`; i7labctl rendering, host registry and ~50 i7labctl tests were silently skipping. |
| 6 | Key files readable by group/other are refused (`KeyError::Permissions`), with a test | `crates/labproto/src/keys.rs` | Documented requirement left as `STUB(P1)`. |
| 7 | Fuller unsafe-code-point table (bidi isolates, line separators, BOM, private use, tags, noncharacters) | `crates/labproto/src/text.rs` | Hardware strings are sanitised with this; only a placeholder range set existed. |

## Console TUI was not wired (P5)

| # | What | Where | Why |
|---|---|---|---|
| 8 | `console::run`: opens the tty, raw mode, labtui event loop, a data thread (probes every 2 s, disks/PCIe every 30 s) feeding `ViewData`, F10/quit starts `i7labsh -l` on the tty and resumes, reboot/poweroff/boot-next/read-test/DHCP go through `Registry::dispatch` with `Source::Console`, `tui.up` marker for init. Locked mode blocks writes and the shell. | `crates/i7labd/src/console.rs` | The function returned `Unsupported`; the console showed nothing. |
| 9 | Second console thread for `i7lab.serial=ttyS0` | `crates/i7labd/src/daemon.rs` | The serial TUI was a comment only. |

## Contract mismatches found by running it

| # | What | Where | Why |
|---|---|---|---|
| 10 | `blk ls` write-safety reasons rendered from `{"code":..,"detail":..}` objects (`mounted(/mnt)`), strings still accepted | `crates/i7labctl/src/render.rs` | i7labd sends objects, the renderer assumed strings and printed raw JSON in the table. New unit test. |
| 11 | Kernel-log classifier no longer flags the "AER: enabled" banner, empty SATA ports ("SATA link down"), or the optional `regulatory.db` | `crates/labprobe/src/kmsg.rs` | The Overview page showed three permanent false "attention" items on a healthy boot. Tests extended. |
| 12 | Header MAC shows a NIC with a driver, not the first interface (was `dummy0`) | `crates/i7labd/src/console.rs` | cosmetic, found on the VGA screendump. |
| 13 | `scripts/qemu-test` exports the demo key dir for its `i7labctl` calls | `scripts/qemu-test` | beacon/ping checks could not authenticate. |

## New

`scripts/e2e` and `tests/e2e/tuicap.py`: repeatable end-to-end run (91 checks) with a transcript; results in
[E2E-RESULTS.md](../E2E-RESULTS.md).

## Observations that did not need a fix (see E2E-RESULTS.md, open issues)

* `scripts/build-userland` builds the three image binaries only; `i7labctl` is built separately (`cargo build --release -p i7labctl`).
* With `--http IP:PORT` the command takes no host argument for `exec` (the address is the target); `sh` takes one.
