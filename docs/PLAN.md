# i7lablinux: architecture and implementation plan

Status: **authoritative design (D1, revised by D4 after reviews D2 security + D3 feasibility; dispositions in
Appendix A)**. This is the design as planned; what is implemented and proven today is in the [README](../README.md),
[E2E-RESULTS.md](E2E-RESULTS.md) and [ROADMAP.md](ROADMAP.md). Where this file disagrees with the reference docs
(`PROTOCOL.md`, `I7LABCTL.md`, `PROBES.md`, `TUI.md`, `WEB.md`) or with the archived notes in
[design-history/](design-history/) (recon, reviews, the original web and expansion proposals), **this file wins**;
section 1 lists every conflict and how it was resolved.

Hard rule: **no busybox** anywhere (image, build, docs as a dependency). Every userland tool in the
image is our own Rust: `i7lab-init`, `i7labd`, `i7labsh` (builtins), `i7labctl` on the operator side.
`scripts/check-no-busybox` enforces it in CI and in every image build.

Goal (operator): a host booted from the i7lablinux USB drive can be driven remotely for nearly anything:
probe it (PCIe, CPU, memory, thermal, DMI, NICs, USB, SMART, block devices), test its disks (read; write only
behind the safety gate), run commands, move files, reboot it, all **without IP** over authenticated Ethernet
command frames, or over HTTP when it has an address, plus a full-screen console TUI for the person at the machine.

Contents

1. Conflicts resolved
2. Architecture overview
3. Repository and crate map (dependency graph)
4. Interface contracts (Rust signatures)
5. Keys
6. Safety model (block write gate)
7. Kernel, initramfs, image and USB layout
8. Boot flow (UEFI and BIOS)
9. Remote-boot procedure
10. Web UI decision
11. Licence
12. Work split (owned paths)
13. Acceptance tests
14. End-to-end QEMU test plan (the build host)
15. Plan to expand
16. Open decisions for the operator
A. Review disposition (D2 security, D3 feasibility)

---

## 1. Conflicts resolved

| # | topic | notes said | decision |
|---|---|---|---|
| C1 | crates | EXPANSION: extra `labcrypto`, `i7lab-tui`, `labtests` | **Seven crates only** (task list): `labproto`, `labprobe`, `labtui`, `i7labd`, `i7lab-init`, `i7labsh`, `i7labctl`. Crypto, JSON, sanitiser, libc FFI and AF_PACKET live in `labproto` (the shared foundation crate). The console TUI *application* lives in `i7labd::console`; `labtui` is the renderer library. |
| C2 | console TUI process | TUI.md: separate `i7lab-tui` binary | **Thread inside `i7labd`**, so TUI actions call the same in-process command registry as ether and HTTP (no IPC). Init keeps a fallback: if `i7labd` crash-loops, init puts `i7labsh` on the console. |
| C3 | HTTP auth | WEB: bearer token file `~/.config/i7labctl/token` or ts-signing; PROTOCOL 11: lab-proxy nonce HMAC | **One scheme**: lab-proxy nonce HMAC (`GET /api/v1/nonce`, `X-Lab-Auth`, server `X-Lab-Proof`), keyed by the **same admin/ro keys** as ether. No bearer token, no separate token file; the raw key never crosses the wire. The SPA carries a ~100 line JS SHA-256/HMAC (WebCrypto is unavailable on plain-HTTP non-localhost origins). WEB.md's bearer-token text is void (review S-F2). |
| C4 | command names | PROBES: `probe <name>`, `disktest`; WEB: `POST /api/v1/cmd {"cmd":..,"args":{..}}` | **One catalogue**: PROTOCOL.md section 7 names and ids (`inv`, `pcie`, `blk.read`, ...). Arguments are always an **argv word list** on every transport. HTTP: `POST /api/v1/cmd/<name>` body `{"args":["--mb","256"]}`; `GET /api/v1/probe/<section>` is sugar for `inv --section <section>`. `disktest`/`probe` are not command names. |
| C5 | probe set vs `inv` sections | PROTOCOL `inv --section sys,board,...`; PROBES probe names | `inv` sections **are** the labprobe probe names: `system cpu mem dmi pci usb block net thermal firmware smart kmsg` (later: `acpi tpm gpu input serial ipmi`). `pcie`, `usb`, `blk.ls`, `net.ls`, `thermal` are commands that call the same probe functions with options. |
| C6 | Class D confirm tokens | PROBES/WEB: two-step confirm token for destructive actions | **Dropped for v1.** The device serial is the confirmation for disk writes; reboot/poweroff/kexec need the admin key and an interactive `y` in `i7labctl` (or `--yes`) and a dialog in the TUI. Keeps L2 round trips and scripting simple. |
| C7 | block write override | PROTOCOL: partition table / FS never overridable in v1; PROBES: overridable with flag + serial + region; task: refuse unless destructive flag **and** serial | Section 6: **every** write needs `--destructive` + `--serial`. Partition table and FS/RAID/LVM/LUKS signatures are refused unless those are given (task rule). **Never overridable**: boot media, backs the running system, mounted/held/swap/O_EXCL busy, read-only device, already under test. Unmount first, then the override applies. |
| C8 | DHCP owner | prior art: DHCP in PID 1 | **`i7labd` owns all network configuration** (DHCP client ported from `dhcp.rs`, static, VLAN, hints) because `net.set`/`net.vlan` must control it. Init only brings `lo` up. |
| C9 | ssh | I7LABCTL: in-image sshd via `svc sshd`; recon: no ssh in v1 | **No sshd in the v1 image** (no third-party C daemon; "own Rust" rule). Key scheme still generates the ssh host key and operator keypair so an optional later `SSH=1` add-on does not change the key layout. `i7labctl ssh` and `svc sshd` return `UNSUPPORTED` until then. `shell` over ether is the interactive path. |
| C10 | bootloader / BIOS | recon-kernel: GRUB for UEFI + BIOS; EXPANSION: UEFI-first, BIOS unsupported | **GRUB 2 for both** (build-host tool, `grub-efi-amd64-bin` + `grub-pc-bin`), one `grub.cfg`, GPT with BIOS-boot partition. The BIOS stage is **mandatory** and installed **root-less** (`grub-mkimage -O i386-pc` + `dd` of `boot.img` bytes 0..439 + patch of the core.img LBA at boot.img 0x5c and the diskboot blocklist; review F-F3); fallback `sudo losetup` + `grub-install --target=i386-pc` only if the SeaBIOS e2e fails. The build fails rather than silently producing UEFI-only (`--no-bios` to opt out). Protective MBR entry marked active by default (`PMBR_ACTIVE=1`, F-F4). |
| C11 | labels / cmdline prefix | `labstick.*`, `i7lab.*`, `I7LABBOOT`, `I7LABESP` | Kernel args `i7lab.*` (old `labstick.*` not accepted). Partition labels: ESP FAT label `I7LABESP`, data FAT label `I7LABDATA` (v0.3, C13). Boot media is identified by `i7lab.boot=PARTUUID=<esp partuuid>` written into `grub.cfg` at image build, resolved to a disk **once at daemon start** and cached (S-F18). Labels and `/i7lab/IMAGE-ID` are for humans and GRUB `search`; the write gate never trusts labels on arbitrary disks. |
| C12 | firmware blobs | EXPANSION: bundle none; recon: copy NIC/Wi-Fi blobs | `FIRMWARE=auto` (default): copy the small NIC set (`rtl_nic tigon bnx2 bnx2x`) plus `WHENCE` from the build host's `/lib/firmware` if present; `FIRMWARE=none` skips; `FIRMWARE=wifi` adds Wi-Fi sets (needs `WIFI=1` kernel fragment). Microcode not shipped in v1. |
| C13 | data partition fs | recon: ext4 or FAT; PROBES: ext4 or FAT32 | **No data partition in v0.1** (JetKVM: no writes to boot media, image <= 256 MiB; F-F2). v0.3: `build-usb-drive --data` creates a FAT32 `I7LABDATA` in the free space of the real stick; i7labd mounts it only on an explicit `data.mount` action, never at boot. |
| C14 | token "easy key" vs two keys | WEB: 128-bit token; PROTOCOL: two 32-byte keys | **Two 32-byte keys** (`admin`, `ro`), file format `i7k1:<role>:<64 hex>` (section 5). |
| C15 | shell exec form | argv vs `sh -c` | `exec` runs argv directly (no shell). Shell syntax via `exec -- i7labsh -c '...'`. |
| C16 | DEFAULT console policy | prior art: locked console by default  | **Console open by default** (TUI + `i7labsh` on quit): the operator wants a console shell; physical presence is trusted in this lab. `i7lab.console=locked` gives a read-only TUI and no shell. Documented as a deliberate change. |
| C17 | streams on HTTP | WEB: jobs + SSE | Streaming commands answer `POST /api/v1/cmd/<name>?stream=1` with **chunked NDJSON** using the same event objects as `i7labctl --json` (`{"event":"stdout",...}`), ending in `{"event":"result",...}`. `GET /api/v1/events` (SSE) carries the 2 s snapshot for the SPA. **Every NDJSON/SSE event carries `seq` + `mac`** (`httpauth::event_mac`; S-F9). **Files are raw, not NDJSON** (F-F10): `GET /api/v1/file?path=..&offset=..&len=..` (octet-stream, `X-Lab-Proof` as trailer over the streamed body hash) and `PUT /api/v1/file?path=..&mode=..` (raw body; `X-Lab-Auth` over the streamed body hash, `request_mac_hashed`). `--detach` + `jobs` for long runs. |
| C19 | where keys enter the image | PLAN 5: "the image bakes them in" (unspecified; keys are excluded from the build host) | **Keyless image + local key overlay** (F-F1, S-F10). the build host builds a reproducible image with **no keys** and a placeholder `/i7lab/keys.cpio` (empty newc archive). On the operator machine `scripts/bake-keys` writes `keys.cpio` (uncompressed newc: `/etc/i7lab/keys/{admin,ro}.key`, `KEYSET-ID`, written by a bash `cpio_node` writer) onto the ESP of the stick, into a `.img`, or into an ISO (`xorriso`, present on the operator machine). GRUB: `initrd /i7lab/initramfs.cpio.zst /i7lab/keys.cpio`; the kernel unpacks both. Real keys never leave the operator machine. |
| C20 | demo keys | PLAN 5: refused at build unless `ALLOW_DEMO_KEYS=1`, beacon `demo=1` | Also enforced **at run time** (S-F3): when any loaded key is a demo key, i7labd runs every request as **ro on real hardware** and with full admin only inside a VM (DMI `sys_vendor` QEMU or CPU `hypervisor` flag: what e2e uses). Red banner in TUI/`id`, `demo=1` in the beacon. |
| C21 | session engine | P6 writes the server, P9 the client | **One sans-IO engine in `labproto::session`** (P1): `ClientSession` + `ServerSessions`, `on_frame/poll/send_req/respond/stream_data -> Vec<Action>`, injected clock. i7labd and i7labctl only drive it (F-F6). |
| C22 | ro file access | `ro_path_allowed` string prefix allow-list | **Path policy** `i7labd::registry::path_policy(role, op, path)` (S-F1, F-F31): PATH must be the first argv word and is rewritten to its lexical normal form; `/etc/i7lab/keys` denied for every role; writes under `/run/i7lab` and `/etc/i7lab` denied for every role; ro: allow-listed roots only, `/proc/*/{root,cwd,exe,fd,fdinfo,map_files,environ,mem,pagemap,auxv,syscall}`, `/proc/kcore|kmem`, efivars, debugfs denied; the handler then opens with `openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)` from the root's fd (`labproto::sys::openat2_beneath`, fails closed until implemented). |
| C23 | exposure defaults | WEB: HTTP on all interfaces; ether on every NIC | **Kept** (the brief: plug any lab host in and drive it with no IP or config), with knobs `i7lab.ether=IFACE,..`/`all`, `i7lab.http_bind=IFACE|ADDR`, `i7lab.http=off`, and the exposure stated in KEYS.md (S-F14, partly rejected; Appendix A). Unauthenticated I7LR1 hints are **off** by default (S-F6). |
| C18 | probe JSON writer location | task: labprobe "JSON writer" | The **writer/parser lives in `labproto::json`** (both i7labd and i7labctl need it); labprobe implements `labproto::json::ToJson` for every probe struct. |

---

## 2. Architecture overview

```
 operator machine (the operator machine or laptop)                     target host booted from the i7lablinux USB drive
 ---------------------------------                     ---------------------------------------------------
 i7labctl ----- ether 0x88B6 (HMAC, any VLAN) ------>  i7labd (one static musl binary, root)
    |    <---- beacon 0x88B5 (broadcast, 2 s) -------     |- ether server  (labproto frame + session)
    |----- HTTP :8080 (nonce HMAC) ----------------->     |- http server   (API + web/index.html SPA)
    |                                                     |- beacon sender, DHCP client, net config
 browser ---- HTTP :8080 ---------------------------->    |- console TUI thread (labtui) on tty1 / ttyS0
                                                          |- registry ---> command fns ---> labprobe (probes, block engine, write gate)
                                                          |                              \--> exec / pty / files / power
                                                          `- audit log, jobs, local socket /run/i7lab/ctl.sock
                                                       i7lab-init (PID 1): mounts, modules, supervise i7labd,
                                                          console fallback i7labsh, reaper, power, watchdog
                                                       i7labsh: console shell when the TUI is quit; builtins
```

Single source of truth: `labproto::catalog::CATALOG` (ids, names, roles, usage) + `i7labd::registry::Registry`
(name -> handler). Ether, HTTP, TUI actions and the local socket all call `Registry::dispatch`, which does the role
check, concurrency limits and audit logging **once**. `i7labctl help`, the SPA's command list, the TUI Actions menu and
`GET /api/v1/openapi.json` are generated from `CATALOG`.

Everything runs from the initramfs. Nothing reads the USB drive after the kernel has loaded the initramfs except the
optional data partition, so pulling the drive after boot is safe.

---

## 3. Repository and crate map

```
i7lablinux/
  Cargo.toml                 workspace (resolver 2, edition 2021, no external dependencies at all)
  rust-toolchain.toml        pinned stable (1.99.1 today, matches the build host) + musl target
  crates/
    labproto/    lib   foundation: crypto, json, text sanitiser, keys, catalog, status, argv codec, frame codec,
                       handshake, session (sans-IO client+server engine), replay, reliability, beacon/hint, http auth,
                       local (ctl.sock codec), mac, link trait, sys (libc FFI), packet (AF_PACKET + BPF + VLAN
                       auxdata), netlink (rtnetlink), cmdline (kernel cmdline tokenizer)
    labprobe/    lib   probes (typed structs -> ToJson), block enumeration, signatures, GPT/MBR, write gate,
                       block test engine, SMART (SG_IO / NVMe admin)
    labtui/      lib   raw terminal, cell buffer, diff renderer, widgets, key decoder, themes
    i7labd/      lib+bin  agent: registry + command handlers, ether server, beacon, http + web/index.html,
                       exec/pty, net config + DHCP, console TUI app, audit, jobs, local socket
    i7lab-init/  bin   PID 1
    i7labsh/     lib+bin  minimal shell with builtins
    i7labctl/    lib+bin  operator CLI (host build)
  configs/
    kernel/VERSION             pinned kernel version + sha256
    kernel/fragments/*.config  00-core 10-net 20-storage 30-usb-console 40-fs 50-probe-hw 60-wifi(opt) 90-size-trim
    grub/grub.cfg.in           template (@BOOT_PARTUUID@, @CMDLINE@, @IMAGE_ID@)
    image/i7lab.conf           baked daemon defaults (http port, beacon_compat, ether.deny)
    image/modules.list         extra modules to load (Wi-Fi etc.), order matters
    image/firmware.list        firmware globs per FIRMWARE= set
  scripts/
    gen-keys  bake-keys  install-ctl  build-kernel  build-userland  build-initramfs  build-image
    build-usb-drive  qemu-test  check-no-busybox  capture-fixture  remote  lib/common.sh
  tests/e2e/                   QEMU e2e test cases (driven by scripts/qemu-test)
  docs/                        PLAN.md (this), design notes, later KEYS.md BUILD.md REMOTE-BOOT.md SAFETY.md
  out/  keys/  target/         gitignored
```

Dependency graph (no cycles, no crates.io):

```
labproto  <-- labprobe  <-- i7labd  --> labtui --> labproto
    ^             ^            |
    |             '-- i7labsh -'(lib: i7labsh uses labprobe; i7labd spawns the i7labsh binary)
    |-- i7lab-init (labproto::sys, ::text only)
    '-- i7labctl  (labproto; labtui for `i7labctl tui`)
```

Workspace rules: `edition = "2021"`, `panic = "unwind"` in all profiles (PID 1 and i7labd catch panics per duty),
release `opt-level = "s"`, `lto = true`, `codegen-units = 1`, `strip = true`. Image binaries:
`--target x86_64-unknown-linux-musl` (static, rust-lld). i7labctl: host target (glibc dynamic is fine; musl static
also works and is what we ship to other operators). No `libc` crate: hand-written `extern "C"` declarations in
`labproto::sys` (x86_64 Linux, identical for musl and glibc for the calls we use).

---

## 4. Interface contracts

These signatures are in the scaffold (`crates/*/src`), compile today, and are the contract between implementers.
Bodies are stubs returning `Unsupported`/empty values. **Changing a public signature in another lane's crate needs a
note in your final report; adding items is free.** Revision D4 changed or added the items marked `// D4` below; the
scaffold is authoritative where this text abbreviates. Implemented in the scaffold already (keep, refine, test more):
`frame::canonical_tags`, `cmdline`, `local`, `httpauth::*_hashed`/`event_mac`, `sys::getrandom_blocking`/`flock`,
`keys` redaction + demo detection, `labprobe::block::decide`, `i7labd::registry::path_policy`, `i7labd::events`,
`i7labd::daemon::KeyPolicy`.

### 4.1 labproto

```rust
// labproto::crypto  (port of lab-proxy auth.rs; test vectors FIPS 180-4, RFC 4231)
pub struct Sha256 { .. }
impl Sha256 { pub fn new() -> Self; pub fn update(&mut self, data: &[u8]); pub fn finish(self) -> [u8; 32]; }
pub fn sha256(data: &[u8]) -> [u8; 32];
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32];   // parts are concatenated
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool;
pub fn random_bytes(buf: &mut [u8]) -> std::io::Result<()>;     // D4: blocking getrandom(2) only, no fallback (S-F16)
pub fn hex(bytes: &[u8]) -> String;
pub fn unhex(s: &str) -> Option<Vec<u8>>;

// labproto::keys
pub enum Role { Admin = 0, Ro = 1 }
pub struct Key { pub role: Role, pub bytes: [u8; 32] }
impl Key {
    pub fn generate(role: Role) -> std::io::Result<Key>;
    pub fn parse_line(line: &str) -> Result<Key, KeyError>;     // "i7k1:admin:<64 hex>"
    pub fn to_line(&self) -> String;
    pub fn key_id(&self) -> [u8; 4];                             // first4(SHA256("i7c-keyid" | K))
    pub fn fingerprint(&self) -> String;                         // 8 hex of key_id
    pub fn demo(role: Role) -> Key; pub fn is_demo(&self) -> bool; // D4 (C20)
}
impl Debug for Key / Display for Key                             // D4: "Key(<role> <fp>)", never the bytes (S-F17)
pub struct KeySet { pub admin: Option<Key>, pub ro: Option<Key> }
impl KeySet {
    pub fn load_dir(dir: &Path) -> Result<KeySet, KeyError>;     // admin.key, ro.key; refuses group/world readable
    pub fn by_id(&self, id: &[u8; 4]) -> Option<&Key>;
    pub fn beacon_key(&self) -> Option<[u8; 32]>;               // HMAC(K_ro, "i7c-beacon-key")
    pub fn is_demo(&self) -> bool;                               // D4
}
pub enum KeyError { Io(std::io::Error), Format(String), Permissions(PathBuf) }

// labproto::json  (hand-written; bounded parser ported from lab-proxy invview/json.rs)
pub struct JsonWriter { .. }
impl JsonWriter {
    pub fn new() -> Self; pub fn finish(self) -> String;
    pub fn begin_object(&mut self); pub fn end_object(&mut self);
    pub fn begin_array(&mut self);  pub fn end_array(&mut self);
    pub fn key(&mut self, k: &str);
    pub fn str(&mut self, v: &str); pub fn opt_str(&mut self, v: Option<&str>);
    pub fn u64(&mut self, v: u64);  pub fn i64(&mut self, v: i64);
    pub fn f64(&mut self, v: f64);  // NaN/inf written as null
    pub fn bool(&mut self, v: bool); pub fn null(&mut self);
    pub fn field_str(&mut self, k: &str, v: &str); pub fn field_u64(&mut self, k: &str, v: u64); // + i64/f64/bool/opt
    pub fn value<T: ToJson + ?Sized>(&mut self, v: &T);
}
pub trait ToJson { fn write_json(&self, w: &mut JsonWriter); }
pub fn to_json<T: ToJson + ?Sized>(v: &T) -> String;
pub enum Value { Null, Bool(bool), Num(f64), Str(String), Arr(Vec<Value>), Obj(Vec<(String, Value)>) }
impl Value { pub fn get(&self, key: &str) -> Option<&Value>; pub fn as_str(&self) -> Option<&str>;
             pub fn as_f64(&self) -> Option<f64>; pub fn as_u64(&self) -> Option<u64>; pub fn as_array(&self) -> Option<&[Value]>; }
pub struct Limits { pub max_bytes: usize, pub max_depth: usize, pub max_items: usize }
pub fn parse(s: &str, limits: &Limits) -> Result<Value, JsonError>;

// labproto::text  (port of invview/text.rs + unsafe_ranges.txt; also escapes a literal backslash)
pub fn sanitize(s: &str) -> std::borrow::Cow<'_, str>;         // C0/C1/ESC/bidi/zero-width/... made visible
pub fn sanitize_bytes(b: &[u8]) -> String;                      // invalid UTF-8 -> \xNN

// labproto::status
#[repr(u16)] pub enum Status { Ok=0, Eperm=1, BadArgs=2, Unsupported=3, Busy=4, Refused=5, NotFound=6, Io=7,
    Timeout=8, TooBig=9, Canceled=10, Exists=11, NotReady=12, StreamGone=13, Internal=14 }
impl Status { pub fn from_u16(v: u16) -> Option<Status>; pub fn name(self) -> &'static str;
              pub fn http_status(self) -> u16; pub fn cli_exit(self) -> i32; }

// labproto::catalog  (PROTOCOL.md section 7 is the table; ids never reused)
pub enum Access { Ro, Admin, RoLimitedPaths }                 // RoLimitedPaths: get/fs.* path allow-list for ro
pub struct CmdSpec { pub id: u16, pub name: &'static str, pub group: u8, pub access: Access,
                     pub streams: bool, pub usage: &'static str, pub summary: &'static str,
                     pub since: &'static str }                  // D4 (F-F30): "v0.1" served; else planned
pub const CURRENT_RELEASE: &str = "v0.1";
impl CmdSpec { pub fn planned(&self) -> bool; pub fn path_op(&self) -> Option<PathOp>; }  // D4
pub enum PathOp { Read, Write }                                  // D4: get/fs.ls/fs.stat Read; put/fs.rm Write
pub static CATALOG: &[CmdSpec];
pub fn by_name(name: &str) -> Option<&'static CmdSpec>;
pub fn by_id(id: u16) -> Option<&'static CmdSpec>;
pub fn caps_bits() -> u32;

// labproto::args  (argv codec of PROTOCOL 3.1 + a small option parser shared by i7labd handlers and i7labsh)
pub fn encode_argv<S: AsRef<[u8]>>(argv: &[S]) -> Vec<u8>;
pub fn decode_argv(body: &[u8]) -> Result<Vec<String>, ArgsError>; // UTF-8 required for v1
pub struct Opts { .. }                                           // parsed --flag / --key value / positionals
impl Opts {
    pub fn parse(argv: &[String], flags: &[&str], valued: &[&str]) -> Result<Opts, ArgsError>; // unknown option => error
    pub fn flag(&self, name: &str) -> bool; pub fn value(&self, name: &str) -> Option<&str>;
    pub fn values(&self, name: &str) -> Vec<&str>; pub fn positional(&self) -> &[String];
}

// labproto::mac
pub struct Mac(pub [u8; 6]);
impl Mac { pub const BROADCAST: Mac; pub fn parse(s: &str) -> Option<Mac>; pub fn is_unicast(&self) -> bool; }
impl Display for Mac  // lower case, colons

// labproto::frame  (byte-exact PROTOCOL.md section 3; test vector of section 12 must pass)
pub const ETHERTYPE_BEACON: u16 = 0x88B5; pub const ETHERTYPE_CTL: u16 = 0x88B6;
pub const HDR_LEN: usize = 40; pub const TAG_LEN: usize = 16; pub const DEFAULT_FRAG: u16 = 1400;
#[repr(u8)] pub enum FrameType { Hello=1, Challenge=2, Open=3, OpenOk=4, Req=5, Resp=6, Data=7, Ack=8, Cancel=9,
                                 Close=10, Keepalive=11, NoSession=12, Err=13, Probe=16, ProbeReply=17 }
#[repr(u8)] pub enum Chan { Msg=0, Stdout=1, Stderr=2, Stdin=3, File=4, Ctl=5 }
pub mod flags { pub const FIN: u8 = 1; pub const ACK_REQ: u8 = 2; pub const REPLY: u8 = 4; pub const ENC: u8 = 0x80; }
pub struct Header { pub ver: u8, pub ftype: u8, pub flags: u8, pub chan: u8, pub cmd: u16, pub session: u32,
                    pub req_id: u32, pub ctr: u64, pub msg_len: u32, pub off: u32, pub plen: u16, pub win: u16,
                    pub status: u16 }
impl Header { pub fn encode(&self) -> [u8; HDR_LEN]; pub fn decode(b: &[u8]) -> Result<Header, FrameError>; }
pub enum Dir { ClientToServer = 1, ServerToClient = 2 }
pub enum TagKey<'a> { Hello(&'a [u8; 32]), Challenge { k: &'a [u8; 32], cn: &'a [u8; 16] },
                      Session { sk: &'a [u8; 32], dir: Dir }, NoSession(&'a [u8; 32]), None }
pub fn seal(hdr: &Header, payload: &[u8], key: TagKey) -> Vec<u8>;           // ethertype payload incl. tag
pub struct Frame<'a> { pub hdr: Header, pub raw_hdr: &'a [u8], pub payload: &'a [u8], pub tag: &'a [u8] }
pub fn open(buf: &[u8]) -> Result<Frame<'_>, FrameError>;                    // parse only, no crypto
pub fn verify(frame: &Frame, key: TagKey) -> bool;                            // constant time
pub struct EthHeader { pub dst: Mac, pub src: Mac, pub tags: Vec<(u16, u16)>, pub ethertype: u16 }
pub fn eth_parse(buf: &[u8]) -> Option<(EthHeader, &[u8])>;
pub fn eth_build(h: &EthHeader, payload: &[u8]) -> Vec<u8>;                  // pads to 60 bytes
pub fn canonical_tags(aux: Option<(u16,u16)>, inband: &[(u16,u16)]) -> Option<Vec<(u16,u16)>>; // D4 (S-F12): aux then in-band, >2 => None

// labproto::handshake
pub struct Hello { pub cn: [u8; 16], pub key_id: [u8; 4], pub ver_min: u8, pub ver_max: u8, pub max_frag: u16, pub caps: u32 }
pub struct Challenge { pub sn: [u8; 16], pub boot_id: [u8; 8], pub uptime_ms: u32, pub ver: u8, pub max_frag: u16, pub caps: u32 }
pub struct OpenOk { pub role: Role, pub idle_s: u16, pub frag: u16, pub window: u16, pub caps: u32, pub hostname: String }
impl Hello/Challenge/OpenOk { pub fn encode(&self) -> Vec<u8>; pub fn decode(b: &[u8]) -> Result<Self, FrameError>; }
pub fn session_key(k: &[u8; 32], cn: &[u8; 16], sn: &[u8; 16], client: &Mac, server: &Mac, ver: u8) -> [u8; 32];
pub fn session_id(sn: &[u8; 16]) -> u32;
pub struct CookieJar { .. }                                    // stateless cookie, 15 s buckets, random secret per boot
impl CookieJar { pub fn new() -> io::Result<Self>;
    pub fn make(&self, now_ms: u64, cli: &Mac, srv: &Mac, cn: &[u8; 16], tags: &[(u16,u16)]) -> [u8; 16];
    pub fn check(&self, now_ms: u64, cli: &Mac, srv: &Mac, cn: &[u8; 16], tags: &[(u16,u16)], sn: &[u8; 16]) -> bool; }

// labproto::replay
pub struct ReplayWindow { .. }                                 // 64-bit bitmap, PROTOCOL 4.3
impl ReplayWindow { pub fn new() -> Self; pub fn check(&self, ctr: u64) -> bool; pub fn commit(&mut self, ctr: u64); }

// labproto::reliable  (fragmentation, reassembly, ACK/SACK, RTO; transport independent, clock injected)
pub struct Reassembler { .. }  impl Reassembler { pub fn new(msg_len: u32, frag: u16, limit: u32) -> Result<Self, FrameError>;
    pub fn insert(&mut self, off: u32, data: &[u8], fin: bool) -> Result<(), FrameError>; pub fn next_expected(&self) -> u32;
    pub fn sack_bitmap(&self) -> u64; pub fn complete(&self) -> bool; pub fn take(self) -> Vec<u8>; }
pub struct SendWindow { .. }   impl SendWindow { pub fn new(frag: u16, win: u16) -> Self;
    pub fn on_ack(&mut self, next: u32, sack: u64, win: u16, now: Instant); pub fn due(&mut self, now: Instant) -> Vec<u32>; /*offsets to (re)send*/ 
    pub fn rto(&self) -> Duration; }

// labproto::link  (transport of raw Ethernet frames; lets the protocol run over AF_PACKET or a QEMU dgram socket)
pub struct RecvMeta { pub len: usize, pub ifindex: i32, pub aux_tag: Option<(u16, u16)> }  // D4: (TPID, TCI) from auxdata
pub trait Link: Send {
    fn send(&mut self, ifindex: i32, frame: &[u8]) -> io::Result<()>;          // full Ethernet frame
    fn recv(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<RecvMeta>>;
    fn local_mac(&self, ifindex: i32) -> io::Result<Mac>;
}
pub struct UdpLink { .. }   // test transport: one Ethernet frame per UDP datagram (QEMU -netdev dgram)
impl UdpLink { pub fn new(local: SocketAddr, remote: SocketAddr, mac: Mac) -> io::Result<Self>;
               pub fn multicast(group: Ipv4Addr, port: u16, mac: Mac) -> io::Result<Self>; } // D4 (F-F25), drop own src MAC
pub struct MemLink { .. }  // in-process pair for session tests
impl MemLink { pub fn pair(a: Mac, b: Mac) -> (MemLink, MemLink); }

// labproto::packet  (port of lab-proxy net.rs: AF_PACKET + classic BPF for 0x88B5/0x88B6 plain or behind one tag, PACKET_AUXDATA)
pub struct PacketLink { .. }
impl PacketLink { pub fn open(ifaces: &[String]) -> io::Result<Self>; pub fn ifindex(name: &str) -> io::Result<i32>; }
impl Link for PacketLink
pub fn ethernet_ifaces() -> io::Result<Vec<String>>;          // ARPHRD_ETHER, not lo, physical or vlan

// labproto::beacon
pub struct Beacon { pub version: u8, pub fields: Vec<(String, String)> }  // ordered, first key wins on parse
impl Beacon { pub fn get(&self, k: &str) -> Option<&str>;
    pub fn encode_v2(&self, beacon_key: Option<&[u8; 32]>, src: &Mac) -> Vec<u8>;  // adds tag= last
    pub fn encode_v1(&self) -> Vec<u8>;
    pub fn parse(payload: &[u8]) -> Result<Beacon, FrameError>;                   // I7LP1 and I7LP2
    pub fn tag_ok(&self, raw: &[u8], beacon_key: &[u8; 32], src: &Mac) -> bool; }
pub struct Hint { pub target: Mac, pub ip: [u8; 4], pub prefix: u8, pub gw: Option<[u8; 4]>, pub vlan: Option<u16>,
                  pub boot: Option<String>, pub seq: u32 }
impl Hint { pub fn encode_v2(&self, admin: &[u8; 32]) -> Vec<u8>; pub fn encode_v1(&self) -> Vec<u8>;
            pub fn parse(payload: &[u8], admin: Option<&[u8; 32]>) -> Result<Hint, FrameError>; }

// labproto::httpauth  (lab-proxy scheme, domain strings kept)
pub const H_NONCE: &str = "X-Lab-Nonce"; pub const H_AUTH: &str = "X-Lab-Auth"; pub const H_PROOF: &str = "X-Lab-Proof";
pub const H_KEYID: &str = "X-Lab-Key";            // key id hex, selects admin vs ro
pub fn request_mac(key: &[u8], nonce: &str, method: &str, target: &str, body: &[u8]) -> [u8; 32];
pub fn response_mac(key: &[u8], nonce: &str, status: u16, body: &[u8]) -> [u8; 32];
pub fn request_mac_hashed(key, nonce, method, target, body_sha256: &[u8; 32]) -> [u8; 32];  // D4 (raw file bodies)
pub fn response_mac_hashed(key, nonce, status, body_sha256: &[u8; 32]) -> [u8; 32];         // D4 (trailer proof)
pub fn event_mac(key: &[u8], nonce: &str, seq: u64, event_json_without_mac: &str) -> [u8; 16]; // D4 (S-F9)
pub struct NonceStore { .. } impl NonceStore { pub fn new(cap: usize, ttl: Duration) -> Self;
    pub fn issue(&mut self, now: Instant) -> io::Result<String>; pub fn take(&mut self, nonce: &str, now: Instant) -> bool; }

// labproto::sys  (hand-written FFI; port of lab-init sys.rs). Functions return io::Result. Representative:
pub fn mount(src: &str, target: &str, fstype: &str, flags: u64, data: Option<&str>) -> io::Result<()>;
pub fn umount(target: &str, flags: i32) -> io::Result<()>;
pub fn reboot(cmd: RebootCmd) -> io::Result<()>;  pub enum RebootCmd { Restart, PowerOff, Halt, Kexec }
pub fn finit_module(path: &Path, params: &str) -> io::Result<()>;
pub fn ioctl_ptr(fd: RawFd, req: u64, arg: *mut u8) -> io::Result<i32>;
pub fn if_up(name: &str) -> io::Result<()>;  pub fn if_flags(name: &str) -> io::Result<u32>;
pub fn uptime_ms() -> u64;
pub fn getrandom_blocking(buf: &mut [u8]) -> io::Result<()>;    // D4
pub fn flock(fd: RawFd, op: i32) -> io::Result<()>;              // D4
pub fn openat2_beneath(root: &Path, rel: &Path, resolve_flags: u64) -> io::Result<File>;  // D4 (C22), STUB fails closed
// D4 (F-F7): the full wrapper list P2 delivers in its FIRST push is in the sys.rs module doc (tty/process,
// block/file, sockets, console/misc). Until a wrapper lands a lane may keep crate-private FFI in `crate::ffi`.

// labproto::session  (D4, C21; owner P1) sans-IO; frames are full Ethernet frames, tags = canonical stack
pub enum Action { Send(Vec<u8>), Request{req_id, cmd, body, role}, Response{req_id, status, body},
                  StreamData{req_id, chan, data}, StreamEnd{req_id, chan}, Canceled{req_id}, Opened{role, hostname}, Closed{reason} }
pub struct SessionLimits { frag, window, idle, max_req, max_resp, per_session_bytes }   // Default = PROTOCOL values
impl ClientSession { pub fn new(client, server, tags, key: &Key, limits, now) -> Self;
    pub fn send_req(&mut self, cmd: u16, body: &[u8], now) -> Result<u32, FrameError>;
    pub fn send_data(&mut self, req_id, chan, data, fin, now) -> bool; pub fn cancel(&mut self, req_id, now);
    pub fn on_frame(&mut self, frame: &[u8], tags, now) -> Vec<Action>; pub fn poll(&mut self, now) -> Vec<Action>;
    pub fn next_deadline(&self) -> Option<Instant>; }
impl ServerSessions { pub fn new(server_mac, limits) -> io::Result<Self>;
    pub fn on_frame(&mut self, keys: &KeySet, frame, tags, now) -> Vec<Action>;   // per-MAC penalty on HELLO path only
    pub fn respond(&mut self, req_id, status, body, now) -> Vec<Action>;          // cached for idempotent retransmit
    pub fn stream_data(&mut self, req_id, chan, data, fin, now) -> (bool /*accepted*/, Vec<Action>);
    pub fn poll(&mut self, now) -> Vec<Action>; pub fn session_count(&self) -> usize; }

// labproto::netlink  (D4, F-F9; owner P2): get_links get_addrs get_routes add_addr del_addr add_route del_route
//   link_set_up set_mtu add_vlan(parent, vid) -> ifindex, del_link; LinkInfo/AddrInfo/RouteInfo structs
// labproto::cmdline  (D4, F-F13; owner P2): tokenize(&str) -> Vec<String>; i7lab_args(&str) -> Vec<(k, v)>
// labproto::local    (D4, F-F11; owner P1): PATH, encode_request(cmd, argv), decode_request, encode_reply(status,
//   exit, body), decode_reply. Frames: u32 BE len | u16 cmd | argv  /  u32 BE len | u16 status | i32 exit | body
```

### 4.2 labprobe

Rules: `fn probe(ctx: &ProbeCtx, ..) -> Result<T, ProbeError>`; pure `parse_*` helpers take `&str`/`&[u8]`; every
top-level report carries `"v":1`; JSON keys = Rust field names (snake_case); units in the key suffix (`_bytes`,
`_kib`, `_mhz`, `_c` degrees Celsius as float, `_rpm`, `_mv`, `_mw`, `_ms`, `_us`); absent values are `null`, never
omitted; arrays never null (empty). Every string from hardware is stored raw and sanitised at display time (labtui,
i7labctl, SPA). New fields may be added; renaming or retyping a field bumps `v`.

```rust
pub struct ProbeCtx { pub root: PathBuf, pub budget: Duration, pub privileged: bool,      // root "/" or a fixture tree
                      pub boot_partuuid: Option<String>, pub boot_disk: Option<(u32,u32)> } // D4: cached at daemon start
impl ProbeCtx { pub fn live() -> Self; pub fn fixture(root: impl Into<PathBuf>) -> Self; }
pub enum ProbeError { Io(io::Error), Parse(String), Timeout, Unsupported, NotFound(String) }

#[derive(Clone, Copy)] pub enum Section { System, Cpu, Mem, Dmi, Pci, Usb, Block, Net, Thermal, Firmware, Smart, Kmsg }
impl Section { pub const ALL: &'static [Section]; pub fn name(self) -> &'static str; pub fn parse(s: &str) -> Option<Section>; }
pub struct Inventory { pub v: u64, pub sections: Vec<(Section, Result<String /*section JSON*/, ProbeError>)> }
pub fn inventory(ctx: &ProbeCtx, sections: &[Section]) -> Inventory;   // each section isolated: error -> {"error":..}

// one module per probe, each with its report struct + probe fn:
system::probe(ctx)   -> SystemInfo  { v, hostname, kernel, cmdline, uptime_s, load: [f64;3], boot_id, boot_mode, image_build }
cpu::probe(ctx)      -> CpuInfo     { v, vendor, model_name, family, model, stepping, microcode, sockets, cores, threads,
                                      flags_summary: Vec<String>, freq_mhz: Option<f64>, caches: Vec<Cache>, vulnerabilities: Vec<(String,String)> }
mem::probe(ctx)      -> MemInfo     { v, total_kib, available_kib, swap_kib, dimms: Vec<Dimm>, ecc: Option<String>, edac: Vec<EdacMc> }
dmi::probe(ctx)      -> DmiInfo     { v, sys_vendor, product_name, product_serial, product_uuid, board_vendor, board_name,
                                      board_serial, bios_vendor, bios_version, bios_date, chassis_type, chassis_serial }
pci::probe(ctx, &PciOpts) -> PciReport { v, iommu_enabled, devices: Vec<PciDevice> }
  PciDevice { bdf, parent: Option<String>, vendor: u16, device: u16, subsys_vendor: u16, subsys_device: u16, class: u32,
              revision: u8, class_name, vendor_name: Option<String>, device_name: Option<String>, driver: Option<String>,
              link: Option<PcieLink>, iommu_group: Option<u32>, numa_node: Option<i32>, aer: Option<AerCounters>,
              bars: Vec<Bar>, caps: Vec<String>, config_hex: Option<String> }
  PcieLink { cur_gen: Option<u8>, cur_width: Option<u8>, max_gen: Option<u8>, max_width: Option<u8>, degraded: bool }
  impl PciReport { pub fn unbound_nics(&self) -> Vec<&PciDevice>; }   // D4 (F-F34) class 0x02, no driver
  PciOpts { verbose: bool, filter_id: Option<(u16,u16)>, filter_class: Option<u8> }
usb::probe(ctx)      -> UsbReport   { v, devices: Vec<UsbDevice{ path, busnum, devnum, vid, pid, class, speed_mbps,
                                      manufacturer, product, serial, driver: Vec<String>, parent } > }
net::probe(ctx)      -> NetReport   { v, ifaces: Vec<NetIface{ name, mac, perm_mac, driver, bus_info, operstate, carrier,
                                      speed_mbps, duplex, mtu, ipv4: Vec<String>, ipv6: Vec<String>, vlan_of: Option<String>,
                                      rx_bytes, tx_bytes, rx_errors, tx_errors, carrier_changes } > }
thermal::probe(ctx)  -> ThermalReport { v, zones: Vec<Zone{name,type_,temp_c,crit_c}>, hwmon: Vec<Hwmon{name, temps, fans, volts, power}>, alarms: Vec<String> }
firmware::probe(ctx) -> FirmwareInfo { v, boot_mode: "uefi"|"bios", secure_boot: Option<bool>, setup_mode: Option<bool>,
                                      boot_current: Option<u16>, boot_order: Vec<u16>, boot_entries: Vec<BootEntry>, boot_next: Option<u16> }
firmware::internal_os_entry(&FirmwareInfo) -> Option<u16>; firmware::set_boot_next(ctx, u16); firmware::set_os_indications(ctx, u64) // D4 (F-F17)
net::ethtool_phys_id(iface, seconds) -> io::Result<()>                                                            // D4 (identify)
kmsg::read(ctx, &KmsgOpts) -> KmsgReport { v, lines: Vec<KmsgLine{seq, level, ts_us, text, tags: Vec<String>}> }

// block (owner: block lane)
block::probe(ctx, all: bool) -> BlockReport { v, devices: Vec<BlockDevice> }
  BlockDevice { name, devno: (u32,u32), size_bytes, logical_block, physical_block, kind: DiskKind, model, vendor, serial,
                serial_source: Option<SerialSource> /* D4: Nvme|Virtio|Vpd80|Ata|Usb, F-F23 */, wwid, firmware_rev, rotational, removable, read_only, partition_table: Option<PartTable>,
                partitions: Vec<Partition>, signatures: Vec<Signature>, mounts: Vec<String>, holders: Vec<String>,
                boot_media: bool, write_safety: WriteSafety }
  DiskKind { Nvme, Sata, Scsi, Usb, Virtio, Mmc, Other }
  WriteSafety { verdict: Verdict /* Safe | NeedsOverride | Refused */, absolute: Vec<Reason>, overridable: Vec<Reason> }
block::parse_gpt(lba0_1: &[u8], block: u32) -> Option<PartTable>;  block::detect_signatures(head: &[u8]) -> Vec<Signature>;
block::resolve_boot_disk(ctx, partuuid) -> Option<(u32,u32)>;                       // D4: once at daemon start

// write gate: the ONLY way to obtain a writable handle to a block device in this project
pub struct WriteRequest { pub dev: String, pub destructive: bool, pub serial: Option<String>, pub actor: String }
pub enum Reason { NotDestructive, SerialMissing, SerialMismatch, NoSerial, BootMedia, BacksRunningSystem, Mounted(String),
                  Held(String), Swap, Busy, ReadOnly, UnderTest, PartitionTable(String), Signature(String), NotFound, NotADisk }
impl Reason { pub fn overridable(&self) -> bool; pub fn code(&self) -> &'static str; }
pub struct Refusal { pub reasons: Vec<Reason> }
pub struct WriteGuard { .. }   // owns O_RDWR|O_EXCL|O_DIRECT fd + "under test" lock; Drop releases
impl WriteGuard { pub fn acquire(ctx: &ProbeCtx, req: &WriteRequest) -> Result<WriteGuard, Refusal>;  // D4: lock first (section 6)
                  pub fn device(&self) -> &BlockDevice; pub fn file(&self) -> &File;
                  pub fn reread_partitions(&self) -> io::Result<()>; }                         // D4: BLKRRPART
pub fn assess(ctx: &ProbeCtx, dev: &BlockDevice) -> WriteSafety;
pub fn decide(dev: &BlockDevice, req: &WriteRequest) -> Result<(), Refusal>;   // D4: pure policy, host tests
pub const LOCK_DIR: &str = "/run/i7lab/blk"; pub const AUDIT_LOG: &str = "/run/i7lab/audit.log";  // D4 (F-F14)
pub fn audit_write(line: &str) -> io::Result<()>;                               // D4: O_APPEND, used by i7labd and i7labsh

// block test engine
pub enum TestMode { Read, Write, Verify }
pub enum Pattern { Seeded(u64), Zeros, Ones, Aa55 }        // Seeded: w = splitmix64(seed ^ (offset/8)) per 8-byte word
pub struct Region { pub name: String, pub offset: u64, pub len: u64 }
pub struct TestSpec { pub dev: String, pub mode: TestMode, pub regions: Vec<Region>, pub bs: u32, pub direct: bool, pub pattern: Pattern }
impl TestSpec { pub fn default_regions(size_bytes: u64, mb: u64) -> Vec<Region>; }   // start / mid / end
pub struct Progress { pub region: String, pub done_bytes: u64, pub total_bytes: u64, pub mib_s: f64 }
pub struct RegionResult { pub name: String, pub offset: u64, pub len: u64, pub mib_s: f64, pub lat_max_us: u64,
                          pub io_errors: u64, pub mismatches: u64, pub first_mismatch: Option<u64> }
pub struct TestReport { pub v: u32, pub dev: String, pub serial: Option<String>, pub mode: TestMode, pub seed: Option<u64>,
                        pub regions: Vec<RegionResult>, pub ok: bool }
pub fn run_test(ctx: &ProbeCtx, spec: &TestSpec, guard: Option<&WriteGuard>,
                progress: &mut dyn FnMut(&Progress), cancel: &AtomicBool) -> Result<TestReport, ProbeError>;
// Write mode with guard == None returns Err(Unsupported) immediately: no write path exists without the gate.

smart::probe_all(ctx) -> SmartAll { v, devices: Vec<SmartReport> }   // the `smart` inventory section
smart::probe(ctx, dev: &str) -> SmartReport { v, dev, kind: "ata"|"nvme"|"unsupported", verdict: "pass"|"warn"|"fail"|"unknown",
                                               reasons, temperature_c, power_on_hours, attrs: Vec<SmartAttr>, nvme: Option<NvmeHealth> }
```

### 4.3 labtui

As in TUI.md "Renderer API", reduced to what v1 needs: `RawTerm`, `Cell`, `Color`, `Attr`, `Style`, `Rect`,
`Buffer` (`new resize set put_str fill to_text`), `Screen` (`new buffer present invalidate`), widgets (`frame tabs list
table text gauge sparkline dialog`), `BorderSet { Unicode, Ascii }`, `Theme` (`dark()`, `mono()`), `input::Decoder`
(`feed(byte) -> Option<Key>`, `flush_escape() -> Option<Key>`), `Key` enum, `Event`, `EventLoop`. Strings passed to
widgets go through `labproto::text::sanitize` inside `put_str` (cannot be bypassed). Pure over `Buffer`, golden tests
via `Buffer::to_text()`.

### 4.4 i7labd

```rust
// i7labd::registry: one command function per catalogue entry, shared by ether, http, console TUI and local socket
pub enum Source { Ether { mac: Mac, vlan: Option<u16>, iface: String }, Http { peer: SocketAddr }, Console { tty: String }, Local }
pub trait Sink: Send {                            // streaming output for the current request
    fn data(&mut self, chan: Chan, bytes: &[u8]) -> io::Result<()>;   // Stdout/Stderr/File; blocks for backpressure
    fn event(&mut self, json: &str) -> io::Result<()>;                // progress events, NDJSON object
    fn input(&mut self) -> Option<Receiver<Vec<u8>>>;                 // Stdin / File upload / Ctl for exec, put, shell
}
pub struct Ctx<'a> { pub daemon: &'a Daemon, pub source: Source, pub role: Role, pub actor: String,
                     pub args: Vec<String>, pub sink: &'a mut dyn Sink, pub cancel: Arc<AtomicBool> }
pub struct Reply { pub status: Status, pub body: Vec<u8>, pub content: Content }   // body JSON or raw
pub enum Content { Json, Bytes, ExecResult }                                        // ExecResult: i32 BE exit + JSON
impl Reply { pub fn json(s: String) -> Reply; pub fn ok_empty() -> Reply; pub fn error(status: Status, msg: &str) -> Reply;
             pub fn refused(reasons_json: &str, msg: &str) -> Reply; }   // body {"error":{code,message,reasons}}
pub struct NullSink; pub struct CollectSink { stdout, stderr, file, events }      // Sink impls for tests / console
pub fn path_policy(role: Role, op: PathOp, path: &str) -> Result<String /*normalised*/, &'static str>; // D4 (C22)
pub fn normalize(path: &str) -> Option<String>; pub fn ro_path_allowed(path: &str) -> bool;            // D4 helpers
pub type Handler = fn(&mut Ctx) -> Reply;
pub struct Command { pub spec: &'static CmdSpec, pub handler: Handler }
pub struct Registry { .. }
impl Registry {
    pub fn standard() -> Registry;                                 // every CATALOG entry; missing handler => UNSUPPORTED stub
    pub fn get(&self, name: &str) -> Option<&Command>; pub fn by_id(&self, id: u16) -> Option<&Command>;
    pub fn dispatch(&self, ctx: &mut Ctx, cmd: &Command) -> Reply; // D4 order: KeyPolicy::effective, planned => UNSUPPORTED,
                                                                   // role, path_policy (args[0] rewritten), limits, handler, audit
    pub fn commands(&self) -> impl Iterator<Item = &Command>;
}
pub struct Daemon { pub registry: Registry, pub keys: RwLock<KeySet>, pub config: Config, pub boot_id: [u8; 8],
                    pub audit: Audit, pub jobs: Jobs, pub state: RwLock<HostState>,
                    pub policy: KeyPolicy, pub snapshot: Snapshots, pub events: EventBus }      // D4
pub struct KeyPolicy { pub demo: bool, pub vm: bool }                                         // D4 (C20)
impl KeyPolicy { pub fn detect(&KeySet) -> Self; pub fn effective(&self, Role) -> Role; pub fn banner(&self) -> Option<&str>; }
// i7labd::events (D4, F-F8; owner P6a, consumers P5 P6b P7)
pub struct Snapshot { taken_ms, overview_json, attention: Vec<String>, state, links, sessions, stats_json }
pub struct Snapshots { /* Arc<Snapshot> swapped every 2 s */ pub console_frame: Mutex<String> }  impl { get() -> Arc<Snapshot>; set(Snapshot) }
pub enum Event { Audit(String), Job{id, json}, Msg(String), TuiTab(Option<String>), Identify(Duration), Link(String) }
pub struct EventBus; impl EventBus { pub fn subscribe(&self) -> Receiver<Event>; pub fn publish(&self, Event); } // bounded, never blocks
pub struct Config { pub http_port: Option<u16>, pub beacon_compat: bool, pub accept_v1_hint: bool /* D4 default false */,
                    pub ether_allow: Vec<String> /* D4 */, pub ether_deny: Vec<String>, pub http_bind: Option<String> /* D4 */,
                    pub console: ConsoleMode, pub image_build: String, pub hostname: String }
impl Config { pub fn load(etc: &Path, cmdline: &str) -> Config; pub fn apply(&mut self, k: &str, v: &str); }
impl Daemon { pub fn new(config: Config) -> io::Result<Daemon>; pub fn key_summary(&self) -> String; }
pub enum ConsoleMode { Open, Locked, Off }   // Config also has tui, serial_tty, ascii, boot_partuuid, key_dir, audit_log
pub struct Audit { .. } impl Audit { pub fn record(&self, source: &Source, actor: &str, cmd: &str, args: &[String], status: Status); }

// modules (one owner each, section 12): cmds/{core,probe,blk,net,exec,files,power,svc,logs,console,keys,jobs}.rs,
// ether.rs (drives labproto::session::ServerSessions over Link), beacon.rs, http.rs, web.rs (include_str!("../web/index.html")),
// exec.rs (spawn, pty, process groups), netcfg.rs + dhcp.rs (over labproto::netlink), console.rs (TUI app, F10 -> i7labsh),
// events.rs (D4), localsock.rs (labproto::local), jobs.rs
pub fn run(daemon: Arc<Daemon>) -> !;                            // spawns all duties, never returns
```

Binary: `i7labd` (no args) = the agent. `i7labd --check` = load config/keys and exit 0/1 (used by the image build).

### 4.5 i7lab-init (no public lib API)

Stages: mount proc/sys/devtmpfs/devpts/tmpfs(/run,/tmp)/efivarfs(ro); console fds; `i7lab.*` cmdline; load
`/lib/modules/modules.order` (built-in drivers cover boot, this is for Wi-Fi/extras); settle; hostname from DMI
(`i7lab-<board serial tail>`); arm watchdog if present and `i7lab.watchdog!=0`; supervise `/sbin/i7labd` (backoff
1 s -> 30 s); if i7labd fails 5 times in 60 s and console is not `locked`, spawn `/bin/i7labsh -l` on tty1/ttyS0 as
fallback; reaper; SIGTERM reboot, SIGUSR1 halt, SIGUSR2 poweroff. Never exits; panics caught per duty.
D4 additions: cmdline via `labproto::cmdline` (F-F13). Once i7labd reports the TUI up (`/run/i7lab/tui.up`), init sets
the console loglevel to 1 (`klogctl(SYSLOG_ACTION_CONSOLE_LEVEL)`; debug entry keeps 7; F-F16). If the fallback
`i7labsh` owns tty1 and i7labd later starts cleanly, init restarts i7labd with `I7LAB_TUI=off` so the two never fight
over tty1 (F-F37). The watchdog is armed in v0.1 when a driver exposes `/dev/watchdog0` (section 15 fixed).
Kernel args: `i7lab.console=open|locked|off`, `i7lab.tui=off`, `i7lab.http=PORT|off`, `i7lab.ascii=1`,
`i7lab.boot=PARTUUID=..`, `i7lab.watchdog=0`, `i7lab.serial=ttyS0` (TUI also on serial), `i7lab.debug=1`,
D4: `i7lab.ether=IFACE,..|all`, `i7lab.http_bind=IFACE|ADDR|all`, `i7lab.accept_v1_hint=1` (opt-in).

### 4.6 i7labsh

```rust
pub struct Shell { pub env: Vec<(String, String)>, pub cwd: PathBuf, pub last_status: i32, pub interactive: bool }
impl Shell { pub fn new(interactive: bool) -> Shell; pub fn run_line(&mut self, line: &str) -> i32; pub fn repl(&mut self) -> i32; }
pub struct BuiltinSpec { pub name: &'static str, pub usage: &'static str, pub run: fn(&mut Shell, &[String], &mut Io) -> i32 }
pub struct Io { pub stdin: RawFd, pub stdout: RawFd, pub stderr: RawFd }
pub fn builtins() -> &'static [BuiltinSpec];
pub fn parse(line: &str) -> Result<Pipeline, ParseError>;   // words, quotes, $VAR, |, <, >, >>, 2>&1, ;, &&, ||
```
Builtins v1: `cd pwd echo export unset env exit help true false sleep ls cat cp mv rm mkdir rmdir ln touch head tail wc
grep(substring) hexdump sha256sum mount umount ip(addr/link/route show; link set up/down; addr add/del) dmesg ps kill free
df uptime uname date sync reboot poweroff halt lsmod insmod lspci lsblk lsusb sensors probe(<section>) blk(ls/read; write
only through labprobe::WriteGuard) lab(<cmd> args via /run/i7lab/ctl.sock)`. Line editing: minimal (backspace, ^U, ^C,
up-arrow history). Non-builtin words are exec'd from `PATH=/sbin:/bin`.

### 4.7 i7labctl

```rust
pub mod cli;        // hand-written parser over a static subcommand table (same table drives help + completions)
pub mod keys;       // key discovery (section 5) + key init/show/export/import
pub mod hosts;      // registry ~/.cache/i7labctl/hosts.json (version 2, lab-proxy compatible)
pub mod ether;      // client session over labproto::Link: handshake, REQ/RESP, streams, retransmit
pub mod http;       // std TcpStream client with nonce HMAC and proof check
pub mod discover;   // beacon listener / probe / hints
pub mod output;     // human tables, --json envelope, NDJSON events, sanitised output
pub trait Transport { fn call(&mut self, cmd: &CmdSpec, args: &[String], io: &mut dyn ClientIo) -> Result<CallResult, ClientError>; }
pub struct CallResult { pub status: Status, pub body: Vec<u8>, pub exit_code: Option<i32>, pub rtt_ms: f64 }
pub enum ClientError { Usage(String), Transport(String), Timeout, Auth(String), NoHost(String), Ambiguous(Vec<String>), Safety(String) }
impl ClientError { pub fn exit_code(&self) -> i32; }                       // I7LABCTL.md section 5
pub fn main_with_args(args: Vec<String>) -> i32;
```
Test-only global option `--link udp:<local>:<remote>` (point-to-point) or `--link mcast:<group>:<port>` (shared
segment, D4) selects `UdpLink` instead of AF_PACKET (QEMU dgram, section 14). The client drives
`labproto::session::ClientSession` (C21); it writes no session logic of its own.

**v1 subcommand list (D4, F-F29)**; everything else in I7LABCTL.md answers `UNSUPPORTED (planned vX.Y)`:

* discovery/inventory: `discover ls ping id inv pcie usb thermal logs net blk`
* execution/files: `exec sh` (alias of `exec -- i7labsh -c`) `shell put get fs jobs`
* power/lifecycle: `reboot` (incl. `--to-os` UEFI, `--uefi`) `poweroff wait identify msg tui` (`tab`, `dump`) `time-set`
* keys/test: `key init|show|verify|import|export`, `ether cmds|probe|hello|sniff|frame|replay` (`replay` and
  `I7LABCTL_TEST_REPLAY=1` are test hooks that resend a captured REQ verbatim, F-F26)
* help/output: `api help version completions bash`; `help boot-keys`
* host aliases: `~/.config/i7labctl/aliases` (`m900 = 00:1f:..`), resolved by the host selector (F-F37)

`help` lists every `CATALOG` entry; planned ones are marked `(planned vX.Y)` from `CmdSpec::since`. Exit codes: a
target whose beacon `kid` matches no local key exits 5 (`E_AUTH`) without sending; a HELLO with no CHALLENGE exits 4
with the hint "no CHALLENGE: wrong key set or host unreachable" (F-F20). Raw `--cmd` never pre-validates (the server
gate must be exercised). When `exec` argv[0] is an i7labsh builtin with no such file in PATH, the client prints the
`sh` hint (F-F21).

---

## 5. Keys

Simple, baked in, documented, discoverable without flags. **No real key is ever in a tracked file, and real keys
never leave the operator machine** (C19).

| material | generated by | operator copy | on the stick / in the image | used for |
|---|---|---|---|---|
| `admin.key` (32 B, `i7k1:admin:<hex>`) | `scripts/gen-keys` (or `i7labctl key init`) | `~/.config/i7labctl/keys/admin.key` 0600 | ESP `/i7lab/keys.cpio` -> `/etc/i7lab/keys/admin.key` 0600 | ether + HTTP, all commands |
| `ro.key` | same | `~/.config/i7labctl/keys/ro.key` 0600 | same archive, `ro.key` | read-only commands; beacon tag key derives from it |
| `KEYSET-ID` | `gen-keys` | both dirs | same archive | human label: date + fingerprints |
| `ssh_host_ed25519_key`, `operator_ed25519` | `gen-keys` via host `ssh-keygen` (later) | `~/.config/i7labctl/ssh/` | not shipped in v1 (C9) | future optional sshd |

**Operator flow (the whole thing, README QUICKSTART):**

```
scripts/gen-keys                     # once: ./keys/ (gitignored, 0700) + ~/.config/i7labctl/keys/
scripts/install-ctl                  # builds i7labctl on the build host, installs ~/bin/i7labctl, setcap cap_net_raw
scripts/build-usb-drive /dev/sdX --serial <stick serial>   # build keyless image on the build host, write, bake keys
i7labctl discover                    # hosts booted from the stick appear within seconds
```

* **Where keys enter the image (C19).** The image from the build host is keyless and identical for every operator; it carries
  a placeholder `/i7lab/keys.cpio` (empty newc archive) so a keyless stick still boots and its TUI says "NO KEYS:
  run scripts/bake-keys". `scripts/bake-keys` (operator machine) writes the real `keys.cpio` onto a written stick
  (sudo mount of the ESP; the operator machine has no mtools), into a `.img`, or into an `.iso` (`xorriso -boot_image any keep -map`,
  present on the operator machine) for JetKVM upload. `build-usb-drive` calls it after `dd`.
* **i7labctl key lookup order** (first hit wins, per role): `--key FILE`, `$I7LABCTL_KEY`, `$I7LABCTL_KEYDIR/<role>.key`,
  `~/.config/i7labctl/keys/<role>.key` (under sudo: the invoking user's home via `SUDO_USER`), `./keys/<role>.key`.
  Role: `--role`, else admin if found, else ro. With no key at all the CLI says exactly which command creates one.
* Matching: hosts advertise `kid=a:<fp>,r:<fp>` in beacons; `i7labctl ls` marks hosts whose kid does not match any local
  key (`other-keyset`), and a command to such a host exits 5 without sending (F-F20).
* **Rotate (v1):** `scripts/gen-keys --force` (old set moved to `keys/old/<date>/`), then `scripts/bake-keys --device
  /dev/sdX --serial S` per stick (one file rewritten, no rebuild). **`key.set` is not served in v1** (S-F5, F-F32):
  it would send a key in clear and a persisted key would outlive the baked one. Planned v0.3 form: the new key is
  wrapped (`new XOR HMAC-SHA256(SK, "i7c-keywrap\0" | req_id | ctr)` keystream + tag over the plaintext); a persisted
  key may only **add** a key and must be signed by the baked admin key with a monotonic counter; the baked keys
  always win; `id`/TUI/beacon show "persisted key present"; build opt-in `allow_persist_keys=0` by default.
* **Demo keys (C20):** `scripts/gen-keys --demo` / `bake-keys --demo` use the documented well-known set
  `K = SHA256("i7lablinux-demo-<role>")`, public by construction. `build-image`/`bake-keys` refuse them unless
  `ALLOW_DEMO_KEYS=1`. At run time i7labd treats every demo-key request as **ro on real hardware**; full admin with
  demo keys exists only in a VM. The beacon carries `demo=1`, the TUI and `id` show a red DEMO banner, i7labctl warns.
* **Key hygiene:** `Key`'s `Debug`/`Display` print only role + fingerprint (tested); `i7labd --check` prints
  fingerprints; `key show --secret` is the single intentional disclosure (asks first); build scripts never run
  `set -x` around key files; `scripts/remote` keeps `--exclude keys --exclude out`.
* **Threat statement (KEYS.md, build lane):** anyone holding a stick or a baked image has the keys (FAT ESP is
  readable). One key set per operator; per-host derived keys are future work. The ro key is shareable: it cannot read
  key files or other processes' memory (C22). The admin key is root on every host booted from that key set
  (exec, block writes, reboot; kexec of an unsigned kernel when kexec lands in v0.4: S-F15). With an IP, the HTTP
  API is reachable from anything routed to the host; on L2 the ether listener answers on every NIC unless
  `i7lab.ether=` narrows it (C23). Control traffic is authenticated, not encrypted.

---

## 6. Safety model (block write gate)

Implemented once in `labprobe::block` (`WriteGuard::acquire` + the pure `decide`), the only constructor of a writable
block handle in the workspace (enforced by review + a test that greps for `O_RDWR`/`OpenOptions::write` on `/dev`
paths outside `labprobe/src/block/`). Used by i7labd (`blk.write`, all transports), the TUI and `i7labsh blk`
(which works with i7labd dead).

Default is read-only: `blk.read`, `blk.verify`, `blk.ls`, `blk.smart` never open for write.

A write is allowed only if **all** hold:

| check | on failure | overridable by `--destructive --serial S` |
|---|---|---|
| `--destructive` given | `NotDestructive` | n/a (it is the flag) |
| `--serial` given and equals the resolved serial (or WWID if no serial; neither => refuse) | `SerialMissing` / `SerialMismatch` / `NoSerial` | no |
| not boot media: devno equals the boot disk cached at daemon start, or any partition carries the `i7lab.boot` PARTUUID (labels are never trusted) | `BootMedia` | **never** |
| does not back `/`, `/run/i7lab`, swap | `BacksRunningSystem` / `Swap` | **never** |
| no mounted partition (mountinfo), no holders (md/dm), `O_EXCL` open succeeds | `Mounted` / `Held` / `Busy` | **never** (unmount first) |
| device not read-only (`ro` sysfs, BLKROGET, CD-ROM `sr*`) | `ReadOnly` | never |
| not already under a test (cross-process flock) | `UnderTest` | never |
| no partition table (GPT/MBR), no filesystem/RAID/LVM/LUKS/swap signature in first 1 MiB + known offsets + last 1 MiB | `PartitionTable(..)` / `Signature(..)` | **yes**: allowed only with both flags present and serial matching |

**Order inside `acquire` (lock first, then decide from the locked fd; S-F4):**

1. `valid_dev_name`, whole disk only (else `NotADisk`/`NotFound`).
2. `flock(LOCK_EX|LOCK_NB)` on `/run/i7lab/blk/<name>.lock` (cross-process with i7labsh; F-F14) => else `UnderTest`.
3. `open("/dev/<name>", O_RDWR|O_EXCL|O_DIRECT|O_CLOEXEC)`: the kernel's exclusive claim fails with EBUSY while any
   partition is mounted, held or swapped on => `Busy`; EROFS/EACCES/BLKROGET => `ReadOnly`.
4. With the claim held: re-read partition table and signatures **from this fd**, and mountinfo / holders / swaps /
   boot identity.
5. `decide(&dev, &req)` (pure, host-tested table); 6. `audit_write` the outcome (refusals too) with O_APPEND to the
   shared `/run/i7lab/audit.log`; 7. return the guard. The fd that backed the decision is the fd that is written.

After a write that destroyed a partition table, `blk.write` calls `reread_partitions` (BLKRRPART) so `blk.ls` reflects
the disk (F-F21). `blk.ls` shows the verdict per disk (`Safe`, `NeedsOverride` with the reasons, `Refused` with the
reasons) so the operator sees it before typing the serial. Every write attempt (allowed or refused) is in the audit
log with actor (key id + source MAC/IP or `console`), device, serial, regions and seed. Write tests write a seeded
position-dependent pattern (misdirected writes detected), `fsync` + `BLKFLSBUF`, re-read with `O_DIRECT`. One write
test per host at a time. The console TUI write dialog asks for the **full** serial, pre-filled from the probe but not
auto-confirmed (F-F38), so "device serial given" holds from the console too.

**Serial resolution** (`BlockDevice::serial_source`, F-F23): NVMe `device/serial` (trimmed; NVMe pads to 20), virtio
`serial`, SCSI VPD 0x80 (trimmed), ATA IDENTIFY via SAT, then the iSerial of the ancestor USB device. WWID stays a
separate field. `blk ls` shows the source; scripts and e2e select disks **by serial, never by name** (F-F22).

**What it protects (S-F18, documented in SAFETY.md):** the never-overridable boot-media rule protects the
i7lablinux stick (and JetKVM virtual media: same PARTUUID; CD mode `sr0` is read-only). The host's **internal OS disk
is protected only by the partition-table/signature override gate**: wiping it requires `--destructive --serial`.

**USB writer.** `build-usb-drive` applies the same table on the operator machine, where overwriting is its whole
purpose: it requires `--serial` and a typed confirmation, accepts USB-transport devices (sysfs path through a USB host
controller) whatever `removable` says, requires `--internal` for any non-USB transport (F-F5), and refuses the disk
holding `/` or any mounted partition. Local sudo is needed only for `dd`, `sgdisk -e` and the ESP mount of
`bake-keys`.

---

## 7. Kernel, initramfs, image and USB layout

**Kernel**: Linux **6.18 LTS**, pinned `configs/kernel/VERSION` (`6.18.63` + sha256 `81764a54...1d71`, signature checked
when `gpg` + kernel.org keys are available, sha256 always). `make defconfig` + `merge_config.sh` fragments in order,
`olddefconfig`, then a check that every requested `CONFIG_X=y/m` survived (build fails otherwise); **every NIC driver
of the hardware list must be `=y`** (a silent drop of R8169/IGC makes a lab host unreachable; F-F18). The resolved
`.config` is written to `out/kernel/config-<ver>` (and committed as `configs/kernel/config-<ver>.resolved` for review).
Essentials built in: EFI stub, efivarfs, DEVTMPFS, PACKET, VLAN_8021Q, NVMe/AHCI/USB storage/UAS/virtio, ISO9660 +
SR (JetKVM CD mode), NICs (e1000/e1000e/igb/igc/ixgbe/r8169/tg3/bnxt/virtio-net/USB NICs r8152, ax88179_178a,
cdc_ether/ncm), xHCI/EHCI/HID, 8250 + VT + fbcon + SYSFB_SIMPLEFB/DRM_SIMPLEDRM/DRM_FBDEV_EMULATION (FB_EFI off) +
VGA_CONSOLE + `FONT_TER16x32`, hwmon/coretemp/k10temp/NVME_HWMON/drivetemp, MSR/CPUID, IPMI, watchdogs, SG/BSG,
FAT/ext4/iso9660. `CONFIG_MODULES=y` (Wi-Fi and big HBAs as modules), no module signing, `DEBUG_INFO_NONE`.
Optional `CONFIG_NETCONSOLE=y` with an `i7lab.netconsole=` passthrough (F-F37). Budget 3 to 5 config iterations on
the build host. Reproducibility env: `KBUILD_BUILD_TIMESTAMP`, `KBUILD_BUILD_USER=i7lab`, `KBUILD_BUILD_HOST=i7lab`,
`SOURCE_DATE_EPOCH`.

**Initramfs** (`out/initramfs.cpio.zst`, newc, zstd -19, sorted, uid/gid 0, mtime `SOURCE_DATE_EPOCH`; device nodes
`/dev/console` `/dev/null` via the root-less `cpio_node` appended archive from prior art). **Keyless** (C19):

```
/init                      -> i7lab-init (static musl)
/sbin/i7labd  /bin/i7labsh
/etc/i7lab/i7lab.conf      baked defaults
/etc/i7lab/BUILD           build id, kernel ver, git sha
/etc/i7lab/MANIFEST        sha256 of every file (selftest)
/etc/{passwd,group,hostname,os-release}
/lib/modules/<ver>/...     modules + modules.order (only those in configs/image/modules.list)
/lib/firmware/...          per FIRMWARE= set, with WHENCE
/usr/share/i7lab/LICENSES  kernel GPL-2.0 notice + firmware licences
```
`/etc/i7lab/keys/{admin,ro}.key` and `KEYSET-ID` come from the second archive `/i7lab/keys.cpio` (uncompressed newc,
0600, written by `bake-keys`). No `/bin/sh` symlink tree, no applets. `i7labsh` is the only shell; there is no POSIX
`/bin/sh`, so `#!/bin/sh` scripts do not run (KEYS/REMOTE-BOOT docs say so; F-F36).

**Disk image** `out/i7lablinux-<ver>-<sha7>.img` (GPT, 1 MiB aligned, **target <= 256 MiB, expected ~70 MiB**; the
measured size goes into BUILD.md; F-F2):

```
 LBA 0           protective MBR with GRUB boot.img (root-less BIOS stage, C10); entry marked active (PMBR_ACTIVE=1)
 p1   1 MiB      BIOS boot   type EF02  name i7lab-bios     (GRUB core.img)
 p2  64 MiB      ESP         type EF00  name i7lab-esp      FAT32 (mkfs.vfat -F32 -s 1) label I7LABESP
                   EFI/BOOT/BOOTX64.EFI   (grub, standalone, embeds prefix /boot/grub, all_video)
                   boot/grub/grub.cfg  boot/grub/i386-pc/*  boot/grub/x86_64-efi/* (as needed)
                   i7lab/bzImage  i7lab/initramfs.cpio.zst  i7lab/keys.cpio (placeholder until bake-keys)
                   i7lab/IMAGE-ID  i7lab/BUILD  i7lab/SHA256SUMS
 no data partition in v0.1 (C13). Backup GPT at image end; build-usb-drive relocates it (sgdisk -e) after writing.
```
**ISO** `out/i7lablinux-<ver>-<sha7>.iso`: `grub-mkrescue` BIOS+UEFI hybrid (El Torito) from the same ESP tree, for
JetKVM CD-ROM mode; `bake-keys --iso` adds the keys (xorriso on the operator machine). i7labd never writes to boot
media.

**`build-usb-drive /dev/sdX --serial S [--image FILE | --no-build] [--build-host the build host|local] [--internal] [--yes]`**
(operator machine; F-F1):
1. `scripts/remote -l usb -- scripts/build-image` (skipped with `--no-build`/`--image`), 2. `rsync` `out/*.img` back,
3. local safety checks (section 6), 4. `dd`, 5. `sgdisk -e`, 6. `bake-keys --device /dev/sdX --serial S`
(sudo mount of the ESP, copy `keys.cpio`, umount), 7. read back and verify `SHA256SUMS` + keys fingerprint.

Tools (build host only, never in the image): `sgdisk`, `mkfs.vfat`, `grub-mkimage`/`grub-mkstandalone`/`grub-mkrescue`,
`xorriso`, `cpio` (or the bash `cpio_node` writer), `zstd`.

---

## 8. Boot flow

**UEFI**: firmware -> removable-media path `\EFI\BOOT\BOOTX64.EFI` (GRUB x86_64-efi with `all_video`, unsigned) ->
`grub.cfg` (`set gfxpayload=keep`) -> `linux /i7lab/bzImage` + `initrd /i7lab/initramfs.cpio.zst /i7lab/keys.cpio` ->
kernel -> `/init`. Console video: `SYSFB_SIMPLEFB` + `DRM_SIMPLEDRM` + `DRM_FBDEV_EMULATION`, `FB_EFI` off,
`VGA_CONSOLE=y` for BIOS text mode (F-F15). No NVRAM boot entry is created (stick works on
any host). **Secure Boot must be off** (v1; shim/MOK is roadmap v0.9). `firmware` probe reports Secure Boot state.

**BIOS / CSM**: BIOS -> MBR `boot.img` -> core.img in the EF02 partition (modules `part_gpt fat search_fs_file
normal linux echo serial terminal configfile`) -> same `grub.cfg` -> same kernel/initramfs. Kernel uses `vesafb`/VGA text
console instead of efifb.

`grub.cfg` entries (2 s timeout, serial + console terminals, finds the ESP by `search --fs-uuid`/`--file /i7lab/IMAGE-ID`):

1. `i7lablinux` (default): `console=tty0 console=ttyS0,115200n8 i7lab.boot=PARTUUID=<p2> panic=10 loglevel=4`
2. `i7lablinux (serial TUI, ASCII)`: + `i7lab.serial=ttyS0 i7lab.ascii=1`
3. `i7lablinux (locked console)`: + `i7lab.console=locked`
4. `i7lablinux (debug: no TUI, verbose)`: + `i7lab.tui=off i7lab.debug=1 loglevel=7`
5. `Boot the internal disk`: UEFI `exit` (firmware continues with the next BootOrder entry); BIOS `chainloader` of hd1.

In the OS: init -> i7labd -> NICs up, beacon starts within ~2 s of link (target: beacon visible < 15 s after the GRUB
menu on QEMU) -> DHCP in background -> console TUI on tty1.

---

## 9. Remote-boot procedure (docs/REMOTE-BOOT.md, written by the build lane from this section)

Three ways to get a host into i7lablinux when you are not at it. The person at the machine needs no knowledge
beyond the script you read them. Reading of the brief ("remove the drive and power cycle, the host boots lab linux"):
**remove the internal OS drive** so the firmware falls back to the USB stick (open decision 9 asks the operator to
confirm).

**A. Stick lives in the machine (preferred for lab hosts).** Once, with someone at the host or via JetKVM:
set USB first in the firmware boot order (and disable "fast boot"/"USB skip" options so USB is enumerated). The host
then boots i7lablinux on every power cycle. To return to the installed OS for one boot: `i7labctl reboot <host> --to-os`
(UEFI: writes `BootNext` to the internal OS entry, **v0.1**; BIOS hosts return to their OS only by pulling the stick
until v0.4 `grubenv next_entry`). Power cycling with hwlab/PDU therefore always lands in i7lablinux.

**B. Ad hoc (operator instructs a person).** Script to read to them:

B1 (default, matches the brief: remove the drive):
1. "Shut the machine down completely (hold power 5 s if it does not respond)."
2. "Plug the i7lablinux USB drive into a USB port on the back of the machine (motherboard ports, not a hub or front panel if you can)."
3. "With the power off, remove (or unplug) the internal drive." (NVMe M.2 needs a screwdriver.) "Then press the power
   button." The firmware finds no internal OS and falls back to the USB drive.
4. "When you see a blue/white text screen titled i7lablinux with the machine name, you are done; leave it running.
   You may remove the USB drive now if I ask you to." (Safe: everything runs from RAM.)
5. Operator: `i7labctl wait --state ready` (or `i7labctl discover --watch`), then `i7labctl id <host>`; use
   `i7labctl msg <host> "..."` to put instructions on the screen and `i7labctl identify <host>` to make them find it.
   Inverse: `i7labctl poweroff <host>`, "reinsert the internal drive, remove the USB drive, power on".

B2 (if they can work a boot menu): steps 1-2, then "press the power button and immediately tap the boot-menu key
repeatedly" (table below), "choose the entry that names the USB drive", then steps 4-5. Does not touch the disks.

**C. JetKVM virtual media (no stick at all; F-F2).** Upload `i7lablinux-*.iso` (CD-ROM mode) or `.img` (Disk mode),
baked with `bake-keys`, mount it, power cycle with a one-time boot to the virtual device, wait for the beacon:
`i7labctl lab-boot --jetkvm HOST --image PATH` drives **hwlabd** (which owns PDU and JetKVMs on the operator machine) through its CLI/API,
setting `HWLAB=`; it never talks JetKVM JSON-RPC directly (open decision 8). The first real virtual-media run is part
of acceptance (never exercised on a real device yet).

**No control path (F-F34).** A host whose only NIC has no driver is unreachable on ether and HTTP. The TUI Overview
shows a red "NO CONTROL PATH: no usable NIC (unbound: 10ec:8126 at 03:00.0)" banner and the console shell stays
open; REMOTE-BOOT.md tells the person to plug in a USB Ethernet adapter (r8152, ax88179_178a, cdc_ether/ncm are
built in). BUILD.md lists the supported NICs.

One-time boot menu keys (most common): Dell F12, HP F9 (Esc then F9), Lenovo F12 (ThinkCentre/ThinkPad; Novo button on
some), Intel NUC F10, ASUS F8 (desktop) / Esc (laptop), MSI F11, Gigabyte F12, ASRock F11, Supermicro F11, Acer F12 (must be
enabled in setup), Microsoft Surface: hold Volume-Down while pressing power. `i7labctl help boot-keys` prints this table.

Caveats (printed in REMOTE-BOOT.md):
* **Secure Boot** must be disabled, otherwise the firmware silently skips the stick (or shows a security violation).
* **BitLocker / TPM-sealed disks**: changing boot order or booting another OS can trigger BitLocker recovery on the next
  Windows boot. Have the recovery key, or use the one-time boot menu (does not change NVRAM order on most firmware).
* Some firmware drops a missing USB device from BootOrder and does not re-add it; "fast boot" may skip USB entirely.
* **BIOS host refuses the stick**: some legacy BIOSes need an active MBR entry (default `PMBR_ACTIVE=1`); if a host
  refuses an image built that way, rebuild with `PMBR_ACTIVE=0`.
* Removing the internal drive: only when power is off.
* Front-panel and hub ports sometimes are not bootable; USB 3 sticks on old xHCI firmware: try a USB 2 port.
* After boot, `blk.ls` shows the internal disk as `NeedsOverride` (partition table) and the stick as `Refused` (boot media).
* Extra tools (`lspci -vvv`-level dumps, `nvme-cli`, `fio`, `stress-ng` style): `i7labctl put H ./static-tool
  /run/bin/tool --mode 0755` then `i7labctl exec H -- /run/bin/tool ...`. The busybox ban applies to such toolboxes
  too (`check-no-busybox --dir DIR`). There is no `/bin/sh` (F-F36).

---

## 10. Web UI decision

**Vanilla JS single-file SPA** (`crates/i7labd/web/index.html`, embedded with `include_str!`, no build step, no CDN, no
web fonts, target < 100 KB), as WEB.md decided, with the auth change of C3. v1 pages: Overview, PCIe, Storage (incl.
read test; write test form with serial confirmation), Network, USB, Sensors, Log, Actions, About. Hash routing, all
hardware strings via `textContent`. Light/dark via `prefers-color-scheme`, works at phone width. The SPA asks for a key
line, **defaulting to the ro key** (`i7k1:ro:...`); loading the admin key is an explicit step on the Actions page
(S-F19). It keeps the line in `sessionStorage`, signs requests with its own JS HMAC and verifies `X-Lab-Proof` and
every stream event `mac`. CSP: `default-src 'self'; script-src 'nonce-<per-boot>'; style-src 'self' 'unsafe-inline'`
(no inline script without the nonce). A render test feeds `<img onerror>`/`<script>` in model/serial/DMI fields and
asserts inert output. No bearer token, no token file, no `#token=` fragment (WEB.md auth text is void). `GET /` and `/api/v1/hello`
are open; everything else is signed. `i7labctl web` (local proxy for ether-only hosts) is v0.5.

---

## 11. Licence

**No LICENSE file until the operator chooses** (options and recommendation in [LICENSE-DECISION.md](LICENSE-DECISION.md)).
Cargo manifests carry `publish = false` and no `license` field. README says "Licence: not yet chosen; all rights reserved
by the author until then". Third-party material in built images (Linux GPL-2.0-only, GRUB GPL-3.0-or-later, firmware
per `WHENCE`) is listed in `docs/THIRD_PARTY.md` (build lane) and in the image under `/usr/share/i7lab/LICENSES`; the
kernel source offer is the pinned tarball URL + our fragments.

---

## 12. Work split

Every lane owns exactly the paths listed; anything else is read-only for it. Shared files (`Cargo.toml` workspace,
`rust-toolchain.toml`, `.gitignore`, `docs/PLAN.md`, `README.md`, the design notes `docs/{PROTOCOL,I7LABCTL,PROBES,
TUI,WEB,EXPANSION}.md` and the reviews) are owned by **D (architect)**; request changes in your report. Inside
`labproto`, `labprobe` and `i7labd` ownership is per module file. Each lane keeps the scaffold signatures (add freely;
changing an existing public item: say so in the report). Cross-lane needs go in the report under OPEN ISSUES.
FFI: use `labproto::sys`; until a wrapper exists keep private FFI in your crate's own `ffi` module (not `pub`) and
migrate later (F-F7).

| lane | model | owns (paths, relative to repo root) | delivers | depends on |
|---|---|---|---|---|
| **P1 proto-core** | opus | `crates/labproto/Cargo.toml`, `crates/labproto/src/{lib,crypto,keys,json,text,status,catalog,args,mac,frame,handshake,session,replay,reliable,beacon,httpauth,local}.rs`, `crates/labproto/src/unsafe_ranges.txt`, `crates/labproto/tests/` | all pure protocol code; **`session` client+server engine** (C21) and acceptance test 2 (loss/reorder over `MemLink`); PROTOCOL.md section 12 vector; RFC 4231 / FIPS vectors; JSON limits tests; sanitiser parity; keywrap design note for v0.3 | - |
| **P2 sys-net + init** | sonnet | `crates/labproto/src/{sys,packet,link,netlink,cmdline}.rs`, `crates/i7lab-init/**` | **first push: the FFI wrapper list in `sys.rs` docs** (F-F7); `openat2_beneath`; AF_PACKET + BPF accepting exactly the `canonical_tags` shapes + auxdata; `UdpLink::multicast`; rtnetlink; PID 1 (port lab-init minus busybox/dropbear/DHCP; loglevel + TUI handoff rules of 4.5) | P1 types only |
| **P3 probes** | sonnet | `crates/labprobe/Cargo.toml`, `crates/labprobe/src/{lib,ctx,inventory,system,cpu,mem,dmi,pci,pciids,usb,net,thermal,firmware,kmsg}.rs`, `crates/labprobe/data/`, `crates/labprobe/tests/fixtures/` (except `fixtures/block/`), `crates/labprobe/tests/probe_*.rs`, `scripts/capture-fixture` | probes with fixture-tree golden tests (fixtures captured read-only on the operator machine Intel + the build host AMD, scrubbed); v0.1 depth: DMI types 0,1,2,3,4,16,17, no ASPM/SR-IOV/ACS decode; `unbound_nics`; `firmware::{internal_os_entry,set_boot_next,set_os_indications}`; `net::ethtool_phys_id` | P1 json, P2 sys |
| **P4 block** | opus | `crates/labprobe/src/block/**`, `crates/labprobe/tests/fixtures/block/`, `crates/labprobe/tests/block_*.rs` | enumeration incl. serial resolution order, GPT/MBR, signatures, **lock-first `acquire`** + `decide`, flock, `audit_write`, `reread_partitions`, `resolve_boot_disk`, test engine, SMART ATA/NVMe. Loop/mount tests are `#[ignore]` tests run explicitly with sudo on the build host; file tests tolerate `O_DIRECT` EINVAL on tmpfs | P1 json, P2 sys |
| **P5 tui** | sonnet | `crates/labtui/**`, `crates/i7labd/src/console.rs`, `crates/i7labd/src/cmds/console.rs` | renderer + key decoder (golden tests); console app consuming `Daemon::snapshot`/`events`; v0.1 pages Overview (incl. attention + NO CONTROL PATH + DEMO banners), PCIe, Storage (read-only), Network, Log, About; Actions = reboot/poweroff/shell via `Registry::dispatch`; F10 shell handoff; handlers `msg`, `tui`, `tui.dump` (from `Snapshots::console_frame`), `identify` (banner + `ethtool_phys_id`) | P1, P3, P6a |
| **P6a agent core** | opus | `crates/i7labd/Cargo.toml`, `crates/i7labd/src/{lib,main,registry,daemon,config,audit,jobs,events,exec,localsock}.rs`, `crates/i7labd/src/cmds/**` except `cmds/console.rs` | registry + every non-console handler (probe, blk, net, exec/shell pty, files with `path_policy` + `openat2_beneath`, power incl. `reboot --to-os` UEFI and `--uefi`, logs incl. `--audit -f`, jobs, `time.set`), snapshot thread, event bus, audit fd, local socket server, `KeyPolicy` wiring, BLKRRPART after destructive writes | P1, P2, P3, P4 |
| **P6b agent net** | sonnet | `crates/i7labd/src/{ether,beacon,netcfg,dhcp}.rs` | ether server driving `ServerSessions` over `PacketLink` (all NICs or `ether_allow`), beacon v2 (`demo=1`, `kid`, `state`, attention), PROBE_REPLY only to unicast sources, rate-limited per destination MAC + per NIC + global (S-F8), hints (I7LR2; I7LR1 only if `accept_v1_hint`, audited, hinted gateway never used for daemon-initiated traffic), DHCP port, static/VLAN netcfg over `labproto::netlink` | P1, P2, P6a |
| **P7 http + web** | sonnet | `crates/i7labd/src/{http,web}.rs`, `crates/i7labd/web/**` | HTTP/1.1 server (`http_bind`), nonce HMAC, `/api/v1/*` to `Registry::dispatch`, per-event-MAC NDJSON + SSE, raw `/api/v1/file` GET/PUT with streaming hash and trailer proof, SPA (ro key default, nonce CSP, render-injection test) | P1, P6a |
| **P8 shell** | sonnet | `crates/i7labsh/**` | parser, executor (pipes, redirects), builtins (lspci/lsblk/lsusb/sensors/probe as thin labprobe wrappers; `ip` over `labproto::netlink`; `blk write` only through `WriteGuard`), `lab` builtin over `labproto::local`, line editor | P1, P2, P3, P4 |
| **P9 ctl** | opus | `crates/i7labctl/**` | the v1 subcommand list of 4.7 with full help (planned marked), key discovery, registry + aliases, discover/probe/hints, ether client driving `ClientSession`, http client (proof + event mac checks), `--link udp:`/`mcast:`, test replay hook, exit-code rules of F-F20, `lab-boot --jetkvm` over hwlabd (`cmds/labboot.rs`, behind `HWLAB=`) | P1, P2 link |
| **P10 build** | sonnet | `configs/**`, `scripts/{gen-keys,bake-keys,install-ctl,build-kernel,build-userland,build-initramfs,build-image,build-usb-drive,check-no-busybox,remote}`, `scripts/lib/**`, `docs/{BUILD,KEYS,REMOTE-BOOT,THIRD_PARTY,SAFETY}.md` | kernel (NIC =y check, video config), keyless initramfs, 64 MiB-ESP GPT image + root-less BIOS stage + PMBR active, hybrid ISO, placeholder `keys.cpio`, `bake-keys` (stick/img/iso, refuses demo keys without `ALLOW_DEMO_KEYS=1`, refuses to run on a host flagged shared), USB writer (section 6), `install-ctl`, gen-keys, busybox guard (`--dir` too), docs incl. the threat statement and measured image size | binaries from P2/P6/P8 (paths only) |
| **P11 e2e + integrator** | sonnet | `scripts/qemu-test`, `tests/e2e/**`, `docs/TESTING.md` | **from day one**: keeps `cargo test --workspace` + the musl build green on the build host after every lane push and runs M0; then the full section 14 e2e with evidence logs | everything |

**Sequencing (F-F28b).** P1, P2, P10 start immediately. **M0 vertical slice** before the wide fan-out finishes: P10
kernel with 00/10 fragments + minimal keyless initramfs + demo `keys.cpio`; P2 init brings `lo` up and execs i7labd;
P6b beacons + `ping`/`id` over `labproto::session`; P9 `discover` + `--ether .. --cmd ping` over `UdpLink`; P11 runs
e2e steps 1-3 in QEMU. P3, P4, P8 run in parallel against the scaffold from the start; P6a, P5, P7 as soon as P1's
crypto/json land (stubbing against scaffold signatures meanwhile); P11 integrates continuously. Builds and tests only on
the build host (`scripts/remote`, per-lane dir `/tmp/i7ll-<lane>`), at most 2 QEMU guests per lane. Real keys are never
built into anything on the build host.

---

## 13. Acceptance tests

Host (the build host, `cargo test --workspace` and `--target x86_64-unknown-linux-musl` build):

1. labproto: SHA-256/HMAC vectors; PROTOCOL.md section 12 frame bytes and tag exactly; replay window table tests;
   reassembler rejects overlong/misaligned/oversized; argv round trip; JSON writer escapes, parser limits; sanitiser
   covers every code point range in `unsafe_ranges.txt` and escapes backslash; beacon v1/v2 parse + tag; hint v2 tag;
   `canonical_tags` for untagged / 1 in-band / 1 auxdata / auxdata+in-band / QinQ / 3 tags (rejected), and session
   key distinct per stack; `format!("{:?}", key)` contains no key hex; `event_mac` changes with seq.
2. Loopback session test (P1): `ClientSession` and `ServerSessions` over `MemLink` with 10 % random loss and reordering
   complete a 1 MiB `get` and a 64 KiB REQ, never deliver a REQ twice, reject a replayed frame and a frame from another
   MAC or another tag stack; 5 bad HELLO tags from a spoofed MAC do not interrupt an established session from that MAC;
   a one-hole-plus-flood stream stays within `window * frag` held bytes.
3. labprobe: golden JSON from fixture trees (one Intel = the operator machine, one AMD = the build host, captured by `capture-fixture`,
   scrubbed); every report has `"v":1`; `unbound_nics` on a fixture with an unbound 0x02 function.
4. Block gate: `decide` table tests (host, pure); on loop devices / files (the build host, sudo, `#[ignore]` run explicitly):
   blank file-backed device -> needs `--destructive --serial`; GPT and ext4 images -> refused without, allowed with
   both; a mounted loop device -> refused even with both (`Busy`/`Mounted` from the O_EXCL claim); a partition mounted
   **between** two `acquire` calls -> refused; the device marked boot media -> refused even with both; a second
   process holding the flock -> `UnderTest`. Write test detects an injected bit flip and a misdirected block.
5. labtui: layouts at 80x25, 132x43, 240x67 golden; key decoder vectors (Linux console + xterm); injection strings rendered inert.
6. i7labsh: parser table tests; builtins on a temp dir; pipeline `echo a | cat` without fork of a shell.
7. i7labd: `path_policy` table (ro `get /proc/1/root/etc/i7lab/keys/admin.key`, `/proc/self/{root,cwd,mem,fd/N}`,
   `/proc/kcore`, efivars, `..` => EPERM; admin `get /etc/i7lab/keys/*` => EPERM; `put`/`fs.rm` under `/run/i7lab`
   => EPERM; PATH not first => BAD_ARGS); `KeyPolicy` demo-on-hardware => admin commands EPERM; planned commands =>
   UNSUPPORTED; config defaults (`accept_v1_hint` off).
8. i7labctl: `help` output covers every catalogue command and marks planned ones; exit-code mapping table incl. the
   kid-mismatch exit 5 and HELLO-timeout exit 4; key lookup order with env overrides.
9. HTTP: request/response/event MAC vectors shared by Rust and the SPA's JS (same test vector file); a modified
   NDJSON event or a seq gap is rejected by the i7labctl client; SPA render test with hostile DMI/SMART strings.
10. `scripts/check-no-busybox` passes on the tree and on the built initramfs (no file named or containing `busybox`
    strings beyond this rule's own text in docs and the guard script itself).

Image/QEMU (section 14) and hardware (manual, `docs/TESTING.md` checklist: M720q/M900 UEFI USB boot, one BIOS-only host
with `PMBR_ACTIVE=1` and `=0`, r8169 + e1000e NICs, SMART on a real SATA and NVMe disk, VLAN 13 trunk control, the first
real JetKVM virtual-media boot in Disk and CD-ROM mode).

---

## 14. End-to-end QEMU test plan (the build host)

`scripts/qemu-test` (P11) runs on the build host with `timeout` on every guest, at most 2 guests, workdir `/tmp/i7ll-e2e`,
evidence in `out/e2e/<timestamp>/`. Image built keyless and baked with demo keys (`ALLOW_DEMO_KEYS=1 bake-keys --demo
--image`); in the guest DMI says QEMU, so `KeyPolicy` grants demo admin. Ports and the multicast group port come from a
per-label hash so lanes running e2e at the same time do not collide. `qemu-test` discovers the firmware files and fails
clearly when missing (the build host: `/usr/share/OVMF/OVMF_CODE_4M.fd` + `OVMF_VARS_4M.fd`; `/usr/share/ovmf/` is empty; F-F19).

**Machine** (q35 + OVMF via pflash; second run SeaBIOS for the BIOS path):
```
cp /usr/share/OVMF/OVMF_VARS_4M.fd $EV/vars.fd
qemu-system-x86_64 -machine q35,accel=kvm:tcg -cpu max -smp 4 -m 2048 -display none \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file=$EV/vars.fd                       # both omitted for the BIOS run
  -serial file:$EV/serial.log  -monitor unix:$EV/mon.sock,server,nowait \
  -device qemu-xhci,id=xhci -drive if=none,id=stick,format=raw,file=$IMG -device usb-storage,bus=xhci.0,drive=stick,serial=I7STICK0001,bootindex=0 \
  -device pcie-root-port,id=rp1,chassis=1,slot=1 -device pcie-root-port,id=rp2,chassis=2,slot=2 \
  -drive if=none,id=nv0,format=raw,file=$EV/nvme-blank.img   -device nvme,bus=rp1,drive=nv0,serial=I7NVME0001 \
  -drive if=none,id=vd0,format=raw,file=$EV/virtio-blank.img -device virtio-blk-pci,bus=rp2,drive=vd0,serial=I7VIRT0001 \
  -drive if=none,id=vd1,format=raw,file=$EV/virtio-gpt.img   -device virtio-blk-pci,drive=vd1,serial=I7VIRT0002 \
  -drive if=none,id=vd2,format=raw,file=$EV/virtio-mnt.img   -device virtio-blk-pci,drive=vd2,serial=I7VIRT0003 \
  -netdev dgram,id=l2,remote.type=inet,remote.host=239.255.71.1,remote.port=$MP \
  -device virtio-net-pci,netdev=l2,mac=52:54:00:17:00:01 \
  -netdev user,id=ip0,hostfwd=tcp:127.0.0.1:$HTTPP-:8080 -device e1000e,netdev=ip0,mac=52:54:00:17:00:02
```
(`virtio-gpt.img` and `virtio-mnt.img`: GPT + ext4 made with `sgdisk` + `mkfs.ext4 -F`; blank images via `truncate`.)

**Ether without root** (F-F25): the multicast `dgram` netdev puts every guest frame on UDP group `239.255.71.1:$MP`;
`i7labctl --link mcast:239.255.71.1:$MP` uses `UdpLink::multicast`, so several i7labctl processes (a `discover --watch`
next to a command) share the segment, and the full stack (beacon, probe, handshake, sessions, fragmentation, streams)
runs without CAP_NET_RAW. In-band `--vlan 13` tagging also works over dgram (the guest sees the 802.1Q tag).
**Ether with AF_PACKET + VLAN** (second scenario, needs `sudo` on the build host, tap removed afterwards): `ip tuntap add
i7ll-e2e0 mode tap user $USER; ip link add link i7ll-e2e0 name i7ll-e2e0.13 type vlan id 13; ip link set ... up`, guest uses
`-netdev tap,id=l2,ifname=i7ll-e2e0,script=no,downscript=no`; run `sudo i7labctl -i i7ll-e2e0 ...` (untagged),
`-i i7ll-e2e0 --vlan 13` (tagged by i7labctl) and `-i i7ll-e2e0.13` (tagged by the kernel); the guest must answer
with the same tag stack.

**Steps and asserts** (each step writes JSON evidence; disks are always selected by **serial** from `blk ls --json`):
1. Serial log shows GRUB menu, kernel, `i7lab-init` as PID 1, `i7labd` start; no "busybox" string anywhere in serial log;
   under OVMF `/sys/class/graphics/fb0` exists (`exec -- i7labsh -c 'ls /sys/class/graphics'`).
2. `i7labctl discover --listen 20` sees `mac=52:54:00:17:00:01` with `state=ready`, `kid` matching the demo set, `demo=1`, `tag_ok`.
3. `i7labctl --ether 52:54:00:17:00:01 --cmd ping` exits 0. With another key set after `discover` (registry knows the
   kid): exit 5 without sending; with `--no-registry`: exit 4 and the "no CHALLENGE" hint. `I7LABCTL_TEST_REPLAY=1`
   resend of a captured REQ produces no second execution (`stats` counter).
4. `pcie --tree --json`: q35 root complex, two `pcie-root-port` bridges, NVMe `1b36:0010` under rp1, virtio-blk under rp2,
   link fields present.
5. `blk ls --json`: `I7NVME0001` (source nvme) Safe-with-flags, `I7VIRT0001` Safe-with-flags, `I7VIRT0002`
   `NeedsOverride` (gpt, ext4), `I7STICK0001` (source usb) `Refused` (boot media).
6. `blk read` on I7NVME0001 and I7VIRT0001: ok, 3 regions. Raw `--cmd blk.write` (no client pre-validation) on
   I7NVME0001 without flags -> exit 7 `NotDestructive`; with `--destructive --serial WRONG` -> exit 7; with the correct
   serial -> ok, seed printed; `blk verify --seed` -> ok; the stick `--destructive --serial I7STICK0001` -> exit 7
   `BootMedia`; I7VIRT0002 with flags -> ok and `blk ls` afterwards shows no partition table (BLKRRPART);
   `sh 'mkdir -p /mnt && mount /dev/<I7VIRT0003>1 /mnt'` then `blk write <I7VIRT0003> --destructive --serial I7VIRT0003`
   -> exit 7 `Busy`/`Mounted`.
7. `exec -- i7labsh -c 'ls /sys/block | wc -l'` returns output and exit 0; `exec -- false` exits 1; ro key
   `get /proc/1/root/etc/i7lab/keys/admin.key` -> EPERM; admin `get /etc/i7lab/keys/admin.key` -> EPERM.
8. `put` 8 MiB random file, `get` it back, sha256 equal (fragmentation and windows), over ether and over HTTP raw file
   endpoints.
9. HTTP: `curl http://127.0.0.1:$HTTPP/api/v1/hello` open; `i7labctl --http 127.0.0.1:$HTTPP inv --json` ok; unsigned
   `POST /api/v1/cmd/reboot` -> 401; `GET /` serves the SPA (contains `<title>i7lablinux`); a streamed `blk.read` over
   HTTP verifies every event mac.
10. TUI: `tui.dump` returns a frame containing the tab bar `Overview` and the host name; `tui tab Storage` then
    `tui.dump` shows `[Storage]`. A serial-TUI boot (test copy of the image with `set default=1`, or
    `-kernel/-initrd/-append`) checks the same through `tui.dump` (F-F24).
11. `reboot --wait 120`: new `boot` id observed in beacons; `reboot --to-os` under OVMF writes BootNext (read back from
    `vars.fd` / `firmware` probe after reboot); then `poweroff`, QEMU exits within 30 s.
12. BIOS run (SeaBIOS, same image; the BIOS stage is mandatory): steps 1, 2, 3 only.
13. ISO as USB CD-ROM (`-device usb-bot,id=cd -device scsi-cd,bus=cd.0,drive=iso`) under OVMF and SeaBIOS: beacon
    arrives, `blk ls` shows `sr0` `Refused` (read-only, boot media).
14. (optional, negative) Secure Boot: `OVMF_CODE_4M.secboot.fd` + `OVMF_VARS_4M.ms.fd`: no kernel start within 60 s in
    the serial log (evidence for "Secure Boot must be off").

---

## 15. Plan to expand

Roadmap versions as ROADMAP.md (v0.1 boots and tells the truth ... v1.0 stable) with these v1 cut lines. The
catalogue's `since` field is the machine-readable form of this list.

* **v0.1 (this build-out)**: everything in section 12 at "works in QEMU" quality: probes (system cpu mem dmi pci usb block
  net thermal firmware smart kmsg), ether protocol + discover/probe/hints, HTTP API + SPA, console TUI (6 pages),
  i7labsh, block read/write/verify with gate, exec/shell/put/get, reboot/poweroff, `reboot --to-os` (UEFI BootNext) and
  `--uefi`, `time.set`, `tui.dump`, watchdog (if a driver exists), keyless image + `bake-keys` + ISO, USB writer,
  UEFI + BIOS boot, `lab-boot --jetkvm` via hwlabd.
* **v0.2**: hardware validation on lab hosts (incl. the first real JetKVM virtual-media boot); `svc`; `net.vlan`
  probing on trunks; `identify` LEDs on more NICs; TUI write dialog (full serial typed); kmsg tail in the beacon.
* **v0.3**: data partition (`build-usb-drive --data`, explicit `data.mount`), persistence of logs/results, `key.set`
  with key wrap and add-only signed persisted keys (section 5), SNTP, `selftest` against MANIFEST, report bundle,
  sensors history, audit ring on the data partition.
* **v0.4**: kexec (audits sha256 of kernel/initrd/cmdline; optional Ed25519 signature against the update key), BIOS
  `--to-os` via `grubenv`, file manager mounts, nettest + L2 blaster, DHCP/PXE probe, LLDP, WoL, log shipping.
* **v0.5**: remote TUI parity over ether/HTTP, screenshot (fb0 -> PNG), pcap capture, IPMI/BMC + SOL, `i7labctl web` proxy.
* **v0.6+**: wipe/secure erase (own gate class), imaging stream, stress + memtest, PCI reset/rescan, vfio readiness,
  A/B self-update with Ed25519-signed manifests, optional ssh add-on, AEAD (`flags.ENC`), per-host keys, Secure Boot
  path (shim/MOK, v0.9), TLS for HTTP (v0.9).

Extension rules: new command = one `CATALOG` entry (new id, never reused, `since` set) + one handler in
`i7labd/src/cmds/` + i7labctl wrapper (optional; the raw `--cmd` form works immediately) + TUI/SPA entry if wanted. New
probe = one labprobe module + `Section` variant + fixture test. Protocol changes follow PROTOCOL.md section 9.

---

## 16. Open decisions for the operator

1. Licence (no LICENSE file until chosen). 2. Public name. 3. Console open by default (C16) acceptable? 4. Optional
ssh add-on ever (would be static dropbear built from source: third-party C, not busybox). 5. Firmware bundling default
(C12). 6. Demo key set published in the repo docs (public by construction; now read-only on real hardware, C20)
acceptable? 7. Privileged ether access on operator machines: `setcap cap_net_raw+ep i7labctl` (default) vs a root relay
daemon. 8. JetKVM driven through hwlabd (recommended) or directly by i7labctl. 9. "Remove the drive and power cycle" =
remove the internal OS drive (assumed, procedure B1) or something else (netboot?). 10. `key.set` stays out of v1
(assumed) or key-wrap is pulled into v0.1. 11. `PMBR_ACTIVE=1` default for legacy BIOS compatibility (assumed).
12. Exposure defaults (C23): HTTP on all addresses and ether on every NIC (assumed, matches "plug in anywhere"), or
HTTP off unless `i7lab.http=PORT`.

---

## Appendix A. Review disposition (D4)

Reviews: `docs/design-history/review-security.md` (D2, "S-Fn") and `docs/design-history/review-feasibility.md` (D3, "F-Fn"). Accepted findings are
applied in the sections named; the scaffold changes are marked `// D4` in section 4.

| finding | verdict | applied in / reason |
|---|---|---|
| S-F1 / F-F31 ro reads admin key via /proc, `..` | accepted | C22, `registry::path_policy` (+ tests), `sys::openat2_beneath`, test 7. Also fixed: dispatch took "first non-dash word" as the path, so `get --offset 0 /etc/shadow` checked `0`; PATH must now be the first word and is rewritten to its normal form |
| S-F2 WEB.md bearer token | accepted | C3, section 10; banner in WEB.md voids its auth text |
| S-F3 demo keys = remote root | accepted (variant) | C20, `daemon::KeyPolicy`: ro on real hardware, admin only in a VM (keeps e2e working); banner + `demo=1` |
| S-F4 gate TOCTOU | accepted | section 6 order, `WriteGuard::acquire` doc, pure `decide`, test 4 |
| S-F5 persisted key backdoor | accepted | `key.set` planned v0.3 (`since`), add-only signed persistence, baked keys win (section 5) |
| S-F6 I7LR1 default on | accepted | `accept_v1_hint` default false (config + `i7lab.conf`) |
| S-F7 penalty box lockout | accepted | `ServerSessions::on_frame` contract, test 2 |
| S-F8 PROBE_REPLY reflection | accepted | P6b deliverables: unicast-source only, per-destination + global rate limits |
| S-F9 streams unauthenticated | accepted | C17, `httpauth::event_mac`, test 9 |
| S-F10 keys on shared the build host | accepted | C19 keyless image + `bake-keys` on the operator machine |
| S-F11 audit deletable/tmpfs | accepted in part | daemon-held O_APPEND fd, write denial under `/run/i7lab` for every role, live `logs --audit -f` off-box; persistence ring v0.3. Admin can still stop local logging via exec: stated, not "fixed" |
| S-F12 QinQ/auxdata | accepted | `frame::canonical_tags`, `RecvMeta::aux_tag`, BPF = same shapes (P2), test 1 |
| S-F13 stream OOO cap | accepted | `SessionLimits` doc + test 2 |
| S-F14 exposure defaults | rejected in part | ether on every NIC and HTTP on all addresses stay default: the brief is "plug any host in and drive it", and lab hosts boot on unknown NICs. Added `i7lab.ether=`, `i7lab.http_bind=`, documented exposure (C23), operator decision 12 |
| S-F15 kexec unsigned | accepted (doc) | section 5 threat statement; kexec is v0.4 with sha256 audit and optional signature |
| S-F16 early RNG | accepted | `crypto::random_bytes` = blocking `getrandom` only |
| S-F17 key in logs | accepted | redacted `Debug`/`Display` + test; `--check` prints fingerprints |
| S-F18 boot media by labels | accepted | C11, `ProbeCtx::{boot_partuuid,boot_disk}` cached at start, section 6 "what it protects" |
| S-F19 SPA admin key + CSP | accepted | section 10: ro default, nonce-only scripts, render test |
| F-F1 build-usb-drive cannot bake keys | accepted | C19, section 7 flow, `scripts/bake-keys` |
| F-F2 JetKVM missing | accepted | 64 MiB ESP, no data partition, ISO, section 9 C, `lab-boot` via hwlabd (decision 8), CD `sr0` refused, e2e 13 |
| F-F3 BIOS stage needs root | accepted | C10 root-less install, mandatory, fallback documented |
| F-F4 PMBR active | accepted | C10, `PMBR_ACTIVE=1` (decision 11) |
| F-F5 removable flag | accepted | section 6 USB writer (`--internal`) |
| F-F6 session engine twice | accepted | C21, `labproto::session`, P1 owns test 2 |
| F-F7 FFI ownership | accepted | sys.rs wrapper list, private `ffi` rule (section 12) |
| F-F8 snapshot/event bus | accepted | `i7labd::events` (frozen types), `Daemon::{snapshot,events}` |
| F-F9 netlink owner | accepted | `labproto::netlink` (P2), `net::ethtool_phys_id` (P3) |
| F-F10 HTTP file streams | accepted | C17 raw file endpoints, `*_hashed` MACs |
| F-F11 local socket | accepted | `labproto::local` codec |
| F-F12 test/fixture ownership | accepted | P3 owns `tests/probe_*.rs` + `scripts/capture-fixture` |
| F-F13 cmdline twice | accepted | `labproto::cmdline`, used by init and config |
| F-F14 in-process lock/audit | accepted | flock in `LOCK_DIR`, `audit_write` |
| F-F15 UEFI video | accepted | section 8, grub.cfg.in (`all_video`, `gfxpayload=keep`), e2e 1 |
| F-F16 kmsg over TUI | accepted | 4.5 |
| F-F17 efivarfs ro vs BootNext | accepted | firmware setters, remount-rw-in-handler rule, `--to-os` UEFI in v0.1 |
| F-F18 kernel fragments | accepted | NIC `=y` check, iteration budget (section 7) |
| F-F19 OVMF path | accepted | section 14 pflash + discovery |
| F-F20 wrong-key exit code | accepted | 4.7 exit rules, e2e 3 |
| F-F21 `exec -- mount` | accepted | `sh` alias, separate `vdc`/I7VIRT0003, BLKRRPART, e2e 6 |
| F-F22 device names | accepted | select by serial everywhere |
| F-F23 serial sources | accepted | `SerialSource`, section 6 order |
| F-F24 TUI over serial | accepted | `tui.dump` (0x0083), `Snapshots::console_frame`, e2e 10 |
| F-F25 shared dgram | accepted | `UdpLink::multicast`, `--link mcast:` |
| F-F26 replay helper | accepted | P9 test hook, raw `--cmd` never pre-validates |
| F-F27 JetKVM / Secure Boot e2e | accepted | e2e 13, 14 |
| F-F28 lane effort | accepted | P6 split into P6a/P6b; P3, P5, P8 scope cuts; P9 v1 list |
| F-F28b no integration milestone | accepted | M0 slice, P11 = integrator from day one |
| F-F29 v1 ctl list | accepted | 4.7 |
| F-F30 help vs UNSUPPORTED | accepted | `CmdSpec::since` / `planned()`, dispatch answers UNSUPPORTED with the version |
| F-F32 key.set in clear | accepted | dropped from v1 (decision 10) |
| F-F33 install path | accepted | `scripts/install-ctl` (P10), QUICKSTART in section 5 |
| F-F34 no NIC driver | accepted | `unbound_nics`, TUI banner, section 9 |
| F-F35 remote-boot reading | accepted | section 9 B1 + decision 9; `--to-os` UEFI v0.1; BIOS limit stated |
| F-F36 non-builtin tools | accepted | section 9 caveats (put + exec toolbox, no /bin/sh) |
| F-F37 conveniences | accepted in part | aliases, `time.set`, init/TUI handoff, optional netconsole in v0.1; kmsg tail in beacon deferred to v0.2 (scope) |
| F-F38 doc drift | accepted | supersession banner under each design note's title; watchdog = v0.1, persistence = v0.3 here; TUI serial rule in section 6 |

Contract changes implementers must know are summarised at the top of section 4 and in the `// D4` markers.
