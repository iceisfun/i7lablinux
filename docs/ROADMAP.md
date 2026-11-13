# Roadmap

Honest state first, then what comes next. The detailed per-version rules are in [PLAN.md](PLAN.md) section 15; the original
long-form proposal is archived in [design-history/expansion-proposal.md](design-history/expansion-proposal.md).

## Where it stands (v0.1.0)

Working and tested in QEMU: kernel build from a pinned tarball, image and ISO (BIOS and UEFI), keyless image plus key baking,
USB writer, PID 1, agent, L2 beacons and commands without IP, HTTP API and web page, console and serial TUI, probes,
block read/write/verify with the safety gate, exec, shell, file transfer, reboot. 728 host tests.
Evidence: [E2E-RESULTS.md](E2E-RESULTS.md).

Not proven: any physical machine, a real USB boot, a real JetKVM, Secure Boot, tagged VLAN frames over a real switch,
SMART data (stub), Wi-Fi, kexec, bit-for-bit reproducible builds. These are the first items of v0.2.

## Versions

| version | theme | contents |
|---|---|---|
| v0.1 | boots and tells the truth | the list above |
| v0.2 | hardware validation | boot on 3 real hosts incl. a BIOS-only one; first real JetKVM virtual-media run; SMART; `svc`; `net.vlan` probing on trunks; TUI write dialog; fix the open issues below |
| v0.3 | data and persistence | data partition, persistent logs and results, `key.set` with key wrap, SNTP, `selftest`, report bundle, sensor history |
| v0.4 | hands in the box | kexec, file manager mounts, network tests, DHCP/PXE probe, LLDP, Wake-on-LAN, log shipping |
| v0.5 | see the screen | remote TUI parity, screenshot, pcap capture, IPMI/BMC and SOL, `i7labctl web` proxy |
| v0.6+ | bring-up toolkit | wipe and secure erase, imaging, stress and memtest, PCI reset/rescan, A/B self-update with signed manifests, AEAD, per-host keys, Secure Boot path, TLS |
| v1.0 | stable | frozen wire protocol and API, release process exercised twice, hardware checklist passed on a published machine list, licence and name settled |

## Open issues carried from the first end-to-end run

From [E2E-RESULTS.md](E2E-RESULTS.md):

1. SMART (`labprobe::block::smart`) is a stub.
2. The kernel carries `CONFIG_DUMMY=y`, so `dummy0` and `sit0` show in every NIC list.
3. The console TUI shares one saved-termios and one resize flag between tty1 and a serial console.
4. Console `Ping` is a TCP connect, not ICMP.
5. `scripts/build-userland` builds the image binaries only; `i7labctl` comes from `scripts/install-ctl` or `cargo build -p i7labctl`.

## Ideas, not scheduled

aarch64 image; netboot variant of the same initramfs; signed plugin commands; Prometheus `/metrics`; always-on flight
recorder on a data partition; cross-host disk benchmark history; USB passthrough tests; GPU compute sanity test;
`i7labctl` for macOS and Windows (needs raw-socket back ends).

## Operator decisions waiting

Licence ([LICENSE-DECISION.md](LICENSE-DECISION.md)), public name, console open by default, optional ssh add-on,
firmware bundling default, raw-socket privilege model for `i7labctl`, JetKVM through
hwlabd or directly. The full list with the assumptions made is [PLAN.md](PLAN.md) section 16.
