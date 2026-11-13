//! `help` output: top level, per command (synopsis, options, examples), `help --all` (the manual), `help ether`,
//! `help exit-codes`, `help boot-keys`, `help json`. The text is part of the interface: golden tests in
//! tests/help_golden.rs pin it. Owner: P9.

use std::io::Write;

use labproto::catalog::{Access, CATALOG};

use crate::cli::{self, Sub, EXIT_CODES_TEXT, SUBS};
use crate::output::Paint;
use crate::Env;

pub struct Doc {
    pub name: &'static str,
    pub about: &'static str,
    pub examples: &'static [&'static str],
}

pub const GLOBAL_OPTS: &str = "\
global options (accepted before or after the command; after `--` nothing is parsed)
  -H, --host SEL          host selector: MAC (any NIC), IPv4, board serial, board name, hostname, alias, or a
                          unique MAC prefix of 4+ characters
  --ether MAC             use the ether transport to that NIC MAC (also the host selector)
  --cmd NAME              raw form: send wire command NAME with the remaining words as its argv (no checks);
                          NAME is a catalogue name (help ether) or a numeric id such as 0x0001
  --http IP[:PORT]        use the http transport (port 8080)
  --ssh [USER@]IP         ssh transport (exec, sh, shell only)
  --transport auto|ether|http|ssh
  -i, --iface IF          lab-side interface (repeatable, or comma separated); default: every Ethernet NIC
  --vlan ID[,ID|A-B]      802.1Q tag to send with / listen on (repeatable)
  --role admin|ro         key role (default: admin if its key file exists, else ro)
  --key FILE              explicit key file (wins over --role)
  --timeout SEC           whole-command timeout (default 30; streaming commands: none; 0 = none)
  --retries N             extra full handshake attempts after the session engine's own retries (default 0)
  --json                  machine output (envelope / NDJSON), see: i7labctl help json
  -q, --quiet   -v (trace)   -vv (frame trace)   --no-color (also NO_COLOR)   (pcie has its own --verbose)
  --registry FILE         registry file (default ~/.cache/i7labctl/hosts.json)
  --no-registry           ignore the registry (and its key-set check)
  -y, --yes               do not ask before destructive actions (never skips the serial of blk write)
  --link udp:LOCAL:REMOTE | mcast:GROUP:PORT
                          test transport: Ethernet frames over UDP (QEMU -netdev dgram), no CAP_NET_RAW needed
  -h, --help   -V, --version";

pub const BOOT_KEYS: &str = "\
one-time boot menu keys (to boot the lab linux stick on a machine; the list is a convenience, check the machine)
  Dell F12 | HP Esc then F9 | Lenovo F12 (ThinkCentre) | Intel NUC F10 | ASUS F8 (desktop) or Esc (laptop)
  MSI F11 | Gigabyte F12 | ASRock F11 | Supermicro F11 | Acer F12 | Surface: hold Volume-Down while pressing power
Secure Boot must be off (the image is not signed). Remote boot procedure: docs/REMOTE-BOOT.md.
";

pub const JSON_HELP: &str = "\
--json output
  One JSON document on stdout (NDJSON for streams), nothing else on stdout; diagnostics go to stderr.
  success   {\"ok\":true,\"transport\":\"ether\",\"host\":{\"mac\":..,\"ip\":..,\"vlan\":..,\"serial\":..,\"boot\":..},
             \"cmd\":\"inv\",\"rtt_ms\":0.8,\"data\":<the server's JSON exactly>}
  failure   {\"ok\":false,\"cmd\":\"blk.write\",\"error\":{\"code\":\"REFUSED\",\"status\":5,\"exit\":7,
             \"message\":\"..\",\"reasons\":[\"mounted\",..]}}
  codes     the server status names (EPERM, BAD_ARGS, UNSUPPORTED, BUSY, REFUSED, NOT_FOUND, IO, TIMEOUT, ..)
            plus E_USAGE E_TRANSPORT E_TIMEOUT E_AUTH E_NOHOST E_AMBIGUOUS E_SAFETY E_FAILED
  streams   exec, logs -f, blk read/write/verify, discover --watch print one event per line:
            {\"event\":\"stdout\",\"data\":\"..\"}  ({\"b64\":..} for non-UTF-8)  {\"event\":\"progress\",..}
            and end with {\"event\":\"result\",\"ok\":true,\"exit\":0}
  ls and discover print {\"ok\":true,\"data\":{\"hosts\":[..]}}. MACs are lower case with colons, times unix seconds.
";

pub fn version_text() -> String {
    format!("i7labctl {} (command protocol {}, beacon v2, catalogue {})", labproto::VERSION, labproto::frame::VERSION, labproto::catalog::CURRENT_RELEASE)
}

pub static DOCS: &[Doc] = &[
    Doc { name: "discover", about: "Listen for L2 beacons (ethertype 0x88B5) and probe replies on every Ethernet NIC with carrier, print what was seen, and record it in the registry. Works with no IP at all and on VLANs (802.1Q tags are decoded; --vlan restricts the listen set and tags probes).\n  --listen S    listen window in seconds (default 4)\n  --active      also broadcast PROBE frames (at most 1 per second per NIC, 5 per run) so hosts answer within half a second; with --vlan 1-200 every id is probed on a tagged trunk\n  --watch       run until Ctrl-C and print events: new, lost (silent 15 s), reboot (boot id changed), ip, state\n  --all         include registry entries not seen in this run\n  --assign MAC=IP/PFX[/GW]\n                answer that MAC's address-less beacon with an address hint (I7LR2 signed with the admin key; I7LR1 to old sticks); at most one hint per MAC per 10 s\n  --daemon      keep running and rewrite the registry every second (like --watch without output)\nBeacons whose mac= differs from the Ethernet source are flagged src-mac-mismatch. A beacon tag that fails verification is shown as unverified, never trusted.", examples: &["i7labctl discover", "i7labctl discover --active --listen 3", "i7labctl discover --watch -i eth1 --vlan 13", "i7labctl discover --assign 02:00:00:9d:01:57=192.0.2.195/24/192.0.2.1"] },
    Doc { name: "ls", about: "List the hosts in the registry (no network). live = beacon within 15 s; entries older than 10 minutes are hidden unless --all. The NOTE column flags: src-mac-mismatch, v1, unverified-tag, other-keyset (the host's key set matches none of your keys: commands to it exit 5 without sending), demo.\n  --sort mac|ip|age|board   (default age)\n  --state live|stale|any    (default live and stale)", examples: &["i7labctl ls", "i7labctl ls --state live --json", "i7labctl ls --all --sort board"] },
    Doc { name: "ping", about: "Round trip to the host over the chosen transport; prints RTT min/avg/max and the host's boot id and uptime. Exits 4 if no reply. With the ether transport the first call includes the handshake (one CHALLENGE round trip).\n  -c N     number of pings (default 4)\n  -W S     per-ping timeout (default 3)\n  ECHO     optional text (up to 1024 bytes) the host echoes back", examples: &["i7labctl ping 02:00:00:9d:01:57", "i7labctl ping m900 -c 10", "i7labctl --ether 02:00:00:9d:01:57 --cmd ping"] },
    Doc { name: "id", about: "Identity of the host: beacon fields, protocol and image build id, command groups, key fingerprints (kid), and the role the host granted to your key.", examples: &["i7labctl id 02:00:00:9d:01:57", "i7labctl id m900 --json"] },
    Doc { name: "inv", about: "System inventory (CPU, memory, DMI, PCI, USB, disks with write-safety, NICs, thermal, firmware, SMART). All sections by default; --section takes the probe names: system cpu mem dmi pci usb block net thermal firmware smart kmsg. A section that failed on the host says unavailable and does not hide the others.\n  --section S,S   only these sections\n  --raw           print the server JSON as received (like --json without the envelope)", examples: &["i7labctl inv 02:00:00:9d:01:57", "i7labctl inv m900 --section dmi,cpu", "i7labctl inv --ether 02:00:00:9d:01:57 --json | jq '.data.block.devices[] | {name,model,serial}'"] },
    Doc { name: "pcie", about: "PCIe devices with bus address, ids, class, driver, current/max link speed and width (DEGRADED when below max), IOMMU group. Read-only, local config space only.\n  --tree         indent by bridge topology\n  --id VVVV:DDDD / --class CC   filter\n  --verbose      add BARs and a config-space hex dump", examples: &["i7labctl pcie 02:00:00:9d:01:57", "i7labctl pcie m900 --tree", "i7labctl pcie m900 --class 02 --verbose"] },
    Doc { name: "usb", about: "USB devices: port path, vid:pid, class, speed, manufacturer, product, serial, bound drivers.\n  --tree         topology\n  --id VVVV:PPPP filter", examples: &["i7labctl usb 02:00:00:9d:01:57", "i7labctl usb m900 --id 0781:5581"] },
    Doc { name: "thermal", about: "Temperatures, fans and alarms. --follow keeps streaming until Ctrl-C; --interval S polls every S seconds from the client instead.", examples: &["i7labctl thermal m900", "i7labctl thermal m900 --follow", "i7labctl thermal m900 --interval 5"] },
    Doc { name: "logs", about: "Host logs. Default is the kernel ring buffer (--dmesg, last 200 lines).\n  --dmesg | --init | --daemon | --http | --audit   which log\n  -n N   number of lines\n  -f     follow until Ctrl-C\nThe ro key can read all of them; the audit log is the place to see who wrote to which disk.", examples: &["i7labctl logs m900", "i7labctl logs m900 --audit -n 50", "i7labctl logs m900 --daemon -f"] },
    Doc { name: "net", about: "Network interfaces and configuration.\n  net ls <host> [IFACE]                       R: NICs, addresses, VLANs, counters\n  net set <host> IFACE (--dhcp | --ip A.B.C.D/N [--gw A.B.C.D] [--dns A,B]) [--mtu N] [--confirm SEC]   W\n  net vlan add <host> IFACE VID [--ip A.B.C.D/N]   |   net vlan del <host> IFACE VID    W\n  net link <host> IFACE up|down               W\n  net confirm <host>                          W: keep a change made with --confirm\n--confirm SEC reverts the change unless confirmed: use it over http so a wrong address does not cut you off. Over ether it is not needed (ether works with any IP state).", examples: &["i7labctl net ls 02:00:00:9d:01:57", "i7labctl net set 02:00:00:9d:01:57 eth0 --ip 192.0.2.195/24 --gw 192.0.2.1", "i7labctl net vlan add m900 eth0 13 --ip 10.13.0.5/24"] },
    Doc { name: "blk", about: "Block devices: enumeration, SMART, read test, write test.\n  blk ls <host> [--all]       name, size, model, SERIAL, table, filesystems, mounted, boot media, and the write-safety verdict (WRITE-SAFE or UNSAFE: reasons)\n  blk smart <host> DEV [--attrs] [--selftest short|long]\n  blk read <host> DEV [--mb N] [--regions start,mid,end | --offset B --len B] [--bs 1m] [--direct]   READ-ONLY (default 256 MiB in three regions)\n  blk write <host> DEV --destructive --serial SERIAL [--mb N] [--regions ..] [--offset B --len B] [--seed N]\n  blk verify <host> DEV --seed N [--mb N] [--regions ..]   read-only compare against a seeded pattern\nSAFETY: blk write is the only command that writes to a disk. It refuses locally without --destructive and --serial (exit 7) and asks for confirmation unless --yes. The host then refuses (exit 7) a disk that is mounted, held, swap, read-only, backing the running system, under test, or the boot media (no override exists for those); a disk with a partition table or filesystem signature needs the same two flags and the real serial (see blk ls). Default is always read-only. The seed is printed (and chosen here when omitted) so blk verify can re-check after a reboot.\nExit 3 when a test finds I/O errors or mismatches or SMART says FAILED.", examples: &["i7labctl blk ls 02:00:00:9d:01:57", "i7labctl blk smart m900 nvme0n1 --attrs", "i7labctl blk read m900 nvme0n1 --mb 1024", "i7labctl blk write m900 sdb --destructive --serial S3Z9NB0K123456 --mb 512", "i7labctl blk verify m900 sdb --seed 8812"] },
    Doc { name: "exec", about: "Run a program on the host (no shell) and stream its output. The exit status of i7labctl is the remote command's (0-254); errors of i7labctl itself (transport, auth, refused) exit 255 here. The command words must come after `--`.\n  --timeout S   remote timeout (default 300, 0 = none)    --env K=V (repeatable)    --cwd DIR\n  --stdin FILE|-   send a file or this terminal's stdin to the program\n  --tty         run on a pty with this terminal's size\n  --detach      start as a job and print the job id (see: jobs)\nShell builtins of i7labsh (ls, cat, mount, ...) are not programs: use `sh` or `exec -- i7labsh -c '...'`.", examples: &["i7labctl exec 02:00:00:9d:01:57 -- dmesg", "i7labctl exec m900 --timeout 60 -- /run/test.elf --self-check", "i7labctl exec m900 --stdin script.sh -- /bin/i7labsh"] },
    Doc { name: "sh", about: "Run a command line through the in-image shell (i7labsh): pipes, redirections, ; && ||, and its builtins (ls cat cp mv rm mkdir mount umount ip dmesg ps kill ...). Same as `exec -- i7labsh -c 'LINE'`. Exit status is the remote status.", examples: &["i7labctl sh m900 'dmesg | tail -20'", "i7labctl sh m900 'mkdir -p /mnt && mount /dev/vdc1 /mnt && ls /mnt'"] },
    Doc { name: "shell", about: "Interactive i7labsh on a pty, over ether (no IP needed). The terminal goes raw; window size changes are forwarded. Local escapes after a newline: `~.` leave, `~r` reboot the host after you typed it again, `~?` list, `~~` a literal tilde (--escape CHAR changes the character, --escape '' disables).\n  --term T   TERM for the remote shell (default: yours)\n  --via ether|ssh   ssh needs a host that runs sshd", examples: &["i7labctl shell 02:00:00:9d:01:57", "i7labctl shell m900 --escape '^'"] },
    Doc { name: "put", about: "Upload a file. Chunked, SHA-256 checked on both ends, written to <remote>.part and renamed at the end. --resume asks the host how much of the .part exists and continues there. The host's path policy applies (no writes under /etc/i7lab or /run/i7lab).\n  --mode 0644   --mkdirs   --resume", examples: &["i7labctl put m900 ./test.elf /run/test.elf --mode 0755", "i7labctl put m900 big.img /run/big.img --resume"] },
    Doc { name: "get", about: "Download a file to <local>.part, verify the SHA-256, rename. --resume continues a partial download. With the ro key only /var/log, /run/i7lab, /proc, /sys and /etc/os-release are readable.\n  --resume", examples: &["i7labctl get m900 /var/log/messages ./messages", "i7labctl get m900 /proc/cpuinfo ./cpuinfo"] },
    Doc { name: "fs", about: "Remote files.\n  fs ls <host> PATH [-l]       fs stat <host> PATH       fs rm <host> PATH [-r]\nThe same path limits as get apply to the ro key.", examples: &["i7labctl fs ls m900 /var/log -l", "i7labctl fs stat m900 /etc/os-release", "i7labctl fs rm m900 /run/test.elf"] },
    Doc { name: "jobs", about: "Detached jobs started with `exec --detach` (output in /run/i7lab/jobs/<id>).\n  jobs <host> [ls]     jobs <host> kill ID     jobs <host> out ID [-f]", examples: &["i7labctl jobs m900", "i7labctl jobs m900 out 3 -f"] },
    Doc { name: "reboot", about: "Reboot the host. Asks for confirmation on a terminal unless --yes.\n  --uefi    reboot into firmware setup\n  --to-os   boot the installed OS once (UEFI BootNext)\n  --force   skip the host's orderly shutdown\n  --delay S wait S seconds first\n  --wait [S] afterwards wait (default 300 s) until the boot id in the host's beacon changes", examples: &["i7labctl reboot 02:00:00:9d:01:57 --wait 120", "i7labctl reboot m900 --to-os -y"] },
    Doc { name: "poweroff", about: "Power the host off (confirmation on a terminal unless --yes). --delay S waits first.", examples: &["i7labctl poweroff m900 -y"] },
    Doc { name: "kexec", about: "Load and exec another kernel from uploaded files. Planned for v0.4: answers UNSUPPORTED.", examples: &["i7labctl kexec m900 --kernel /run/k --initrd /run/i"] },
    Doc { name: "wait", about: "Wait for a host to appear, disappear, become ready or reboot, by listening for its beacons (no session needed). Exit 4 on timeout (default 300 s).\n  --state up|down|ready|reboot   (default up; down = silent for 15 s or state=shutdown; reboot = the boot id changed)\n  --boot-id ID   baseline for reboot (default: the one seen first)", examples: &["i7labctl wait 02:00:00:9d:01:57 --state ready --timeout 120", "i7labctl wait m900 --state reboot"] },
    Doc { name: "identify", about: "Find a machine in a rack: blink the keyboard LEDs and the NIC LED and fill the console with the host name for N seconds (default 30). --stop ends it.", examples: &["i7labctl identify 02:00:00:9d:01:57 --seconds 60"] },
    Doc { name: "msg", about: "Show a message on the host's console TUI for the person standing there (for example during a remote boot).", examples: &["i7labctl msg m900 \"Remove the USB stick now, then press the power button\""] },
    Doc { name: "time-set", about: "Set the host clock (audit log timestamps are wrong before time is set). `now` uses this machine's clock.", examples: &["i7labctl time-set m900 now", "i7labctl time-set m900 1794000000"] },
    Doc { name: "svc", about: "Start/stop agent services (http, beacon, ether). Planned for v0.2: answers UNSUPPORTED.", examples: &["i7labctl svc m900 http status"] },
    Doc { name: "tui", about: "Control the TUI on the host's console.\n  tui tab <host> NAME     switch the tab (Overview, Storage, ..)\n  tui reset <host>        back to the default tab\n  tui dump <host>         text screenshot of the console frame", examples: &["i7labctl tui tab m900 Storage", "i7labctl tui dump m900"] },
    Doc { name: "key", about: "Key management. Keys are `i7k1:<role>:<64 hex>` files, mode 0600. They are found without flags in this order: --key, $I7LABCTL_KEY, $I7LABCTL_KEYDIR/<role>.key, ~/.config/i7labctl/keys/<role>.key, ./keys/<role>.key.\n  key init [--dir DIR] [--force] [--demo]   create admin.key, ro.key, KEYSET-ID in ~/.config/i7labctl/keys and ./keys (or DIR only); refuses to overwrite without --force, then keeps the old set in old/<date>-<ts>/\n  key show [--role R] [--secret]            fingerprints and paths; --secret prints the key line after asking\n  key verify <host>                         authenticate to the host and print the granted role\n  key export [--role ro] [--file F] [-y]    print/copy a key line; the admin key needs --yes (it is root on every host of the set)\n  key import <file> [--force]               install a key line\n  key rotate                                not in v1: scripts/gen-keys --force, then scripts/bake-keys per stick\n--demo creates the PUBLIC demo keys: never use them on real hardware.", examples: &["i7labctl key init", "i7labctl key show", "i7labctl key verify m900", "i7labctl key export --role ro --file ro.key"] },
    Doc { name: "ether", about: "Raw protocol tools.\n  ether cmds <mac>        the host's supported commands (the cmds wire command)\n  ether probe             broadcast PROBE and print replies (like discover --active, registry untouched)\n  ether hello <mac>       handshake only: session parameters, role and RTT\n  ether sniff [--decode] [--count N]   print lab frames (headers only; bodies are never shown)\n  ether frame <hex>       decode a captured frame offline\n  ether replay <mac> NAME [args..]   send a request and resend its captured REQ frames verbatim (test hook: the host must not run it twice)\nThe raw form `i7labctl --ether MAC --cmd NAME [params..]` sends any wire command without checks so the server's gate can be exercised.", examples: &["i7labctl ether cmds 02:00:00:9d:01:57", "i7labctl ether sniff -i eth0 --decode", "i7labctl --ether 02:00:00:9d:01:57 --cmd blk.ls --all"] },
    Doc { name: "api", about: "Authenticated raw HTTP request to the host's API (nonce HMAC, reply proof checked). PATH is relative to the host, e.g. /api/v1/cmd/ping. --data takes JSON or @file.", examples: &["i7labctl api 192.0.2.195 GET /api/v1/hello", "i7labctl api m900 POST /api/v1/cmd/ping --data '{\"args\":[]}'"] },
    Doc { name: "ssh", about: "Run the system ssh to a host that runs sshd (the v0.1 image does not; this is for a later sshd add-on or other machines). Host keys are pinned in ~/.cache/i7labctl/known_hosts, agent and port forwarding are off, BatchMode is on, the identity is ~/.config/i7labctl/ssh/operator_ed25519 if present. Needs an address in the registry. The exit status is ssh's.\n  --user U (default root)   --no-start (accepted; svc sshd is planned)", examples: &["i7labctl ssh m900 uname -a", "i7labctl ssh 192.0.2.195 --user root -- -p 2222 id"] },
    Doc { name: "lab-boot", about: "Boot a host from lab linux with no stick: upload the image to the host's JetKVM, mount it as virtual media, power cycle, and wait for the host's beacon. Everything goes through hwlabd (which owns the PDU and JetKVM): set HWLAB to the hwlab CLI command (default hwlabctl) and HWLAB_TOKEN_FILE for its token. This never talks JetKVM JSON-RPC itself.\n  --jetkvm HOST   hwlab host name\n  --image PATH    .iso (CD-ROM mode) or .img (disk mode)\n  --mode cdrom|disk   (default by extension)\n  --wait S        beacon wait (default 300)\n  --dry-run       print the hwlab commands and stop\nThe virtual-media subcommand of hwlabctl has not been exercised on a real device yet: the first real run is part of the acceptance.", examples: &["i7labctl lab-boot --jetkvm nova --image out/i7lablinux.iso --dry-run", "HWLAB=hwlabctl i7labctl lab-boot --jetkvm nova --image out/i7lablinux.iso"] },
    Doc { name: "image", about: "Thin wrappers around the build scripts (run from the source tree, or set I7LABCTL_SCRIPTS):\n  image build [args]         scripts/build-image (keyless image + ISO into out/, on the build host)\n  image write DEV [args]     scripts/build-usb-drive DEV ... (compile, write, bake keys; asks first)\n  image bake [args]          scripts/bake-keys ... (put your keys into an image, ISO or written stick)\n  image keys [args]          scripts/gen-keys ...\n  image test [args]          scripts/qemu-test ...\n  image info|verify          planned\nArguments after the verb go to the script unchanged. image write never skips the script's own safety checks.", examples: &["i7labctl image build", "i7labctl image write /dev/sdX --serial 4C530001230507123214", "i7labctl image bake --iso out/i7lablinux.iso -o out/with-keys.iso"] },
    Doc { name: "web", about: "Local web UI gateway. Planned for v0.5: answers UNSUPPORTED (the host serves its own SPA on its HTTP port today).", examples: &["i7labctl web --listen 127.0.0.1:8081"] },
    Doc { name: "completions", about: "Print a completion script generated from the same command table that drives help: subcommands, options, verbs, and host selectors from the registry (MACs, hostnames, aliases).", examples: &["eval \"$(i7labctl completions bash)\"", "i7labctl completions zsh > ~/.zfunc/_i7labctl", "i7labctl completions fish > ~/.config/fish/completions/i7labctl.fish"] },
    Doc { name: "help", about: "help               command list\n  help <command>   synopsis, options, examples of one command\n  help --all       the whole manual\n  help ether       the wire commands (offline copy; live list: ether cmds)\n  help exit-codes | boot-keys | json", examples: &["i7labctl help blk", "i7labctl help --all | less"] },
    Doc { name: "version", about: "Print the version, the command protocol version and the catalogue release.", examples: &["i7labctl version"] },
];

pub fn doc(name: &str) -> Option<&'static Doc> {
    DOCS.iter().find(|d| d.name == name)
}

fn transports_text(t: &str) -> String {
    let mut s = String::new();
    for c in ['E', 'H', 'S', 'L'] {
        s.push(if t.contains(c) { c } else { '.' });
    }
    s
}

pub fn top(all: bool, p: Paint) -> String {
    let mut s = String::new();
    s.push_str(&format!("{}\n\n", p.bold("i7labctl: drive i7lablinux hosts over Ethernet frames (no IP needed) or HTTP")));
    s.push_str("usage: i7labctl [global options] <command> [args]\n       i7labctl --ether <mac> --cmd <wire-command> [params..]\n       i7labctl help <command>\n\n");
    s.push_str("quick start\n  i7labctl key init                      create your keys (found automatically from then on)\n  scripts/build-usb-drive /dev/sdX       build, write and key a stick (see docs/BUILD.md); boot a host from it\n  sudo setcap cap_net_raw+ep $(command -v i7labctl)    once, so raw Ethernet works without root\n  i7labctl discover                      hosts booted from the stick appear within seconds\n  i7labctl inv <mac>                     hardware inventory;  i7labctl shell <mac>  for a shell\n\n");
    s.push_str("commands   (transports: E ether, H http, S ssh, L local; role: R read-only key, W admin key)\n");
    for c in SUBS {
        let planned = cli::planned(c).map(|v| format!(" (planned {})", v)).unwrap_or_default();
        s.push_str(&format!("  {:<12} {} {:<3} {}{}\n", c.name, transports_text(c.transports), c.role, c.summary, planned));
        if all {
            s.push_str(&format!("               usage: i7labctl {}\n", c.synopsis));
        }
    }
    s.push('\n');
    s.push_str(GLOBAL_OPTS);
    s.push_str("\n\n");
    s.push_str(EXIT_CODES_TEXT);
    s.push_str("\nmore: i7labctl help <command> | help --all | help ether | help exit-codes | help boot-keys | help json\n");
    s
}

pub fn sub_help(c: &Sub, p: Paint) -> String {
    let mut s = String::new();
    let planned = cli::planned(c).map(|v| format!("  (planned {}: answers UNSUPPORTED, exit 10)", v)).unwrap_or_default();
    s.push_str(&format!("{}{}\n  {}\n\nusage: i7labctl {}\ntransports: {}   role: {}\n", p.bold(&format!("i7labctl {}", c.name)), planned, c.summary, c.synopsis, transports_help(c.transports), role_help(c.role)));
    if let Some(d) = doc(c.name) {
        s.push_str(&format!("\n{}\n", d.about));
        if !d.examples.is_empty() {
            s.push_str("\nexamples\n");
            for e in d.examples {
                s.push_str(&format!("  {}\n", e));
            }
        }
    }
    if let Some(w) = c.wire.and_then(labproto::catalog::by_name).filter(|_| c.verbs.is_empty()) {
        s.push_str(&format!("\nwire command: {} (0x{:04x}) {}\n", w.name, w.id, w.usage));
    }
    s.push_str("\nglobal options and exit codes: i7labctl help\n");
    s
}

fn transports_help(t: &str) -> String {
    let mut v = Vec::new();
    for (c, n) in [('E', "ether"), ('H', "http"), ('S', "ssh"), ('L', "local")] {
        if t.contains(c) {
            v.push(n);
        }
    }
    v.join(", ")
}

fn role_help(r: &str) -> &'static str {
    match r {
        "R" => "read-only key is enough",
        "W" => "admin key",
        "R/W" => "read-only key for reads, admin key for changes",
        _ => "none",
    }
}

pub fn help_ether() -> String {
    let mut s = String::from("wire commands: i7labctl --ether <mac> --cmd NAME [params..]   (offline copy; live list: i7labctl ether cmds <mac>)\n  id      name         role arguments / summary\n");
    for c in CATALOG {
        let role = match c.access {
            Access::Ro => "R",
            Access::Admin => "W",
            Access::RoLimitedPaths => "R/W",
        };
        let planned = if c.planned() { format!(" (planned {})", c.since) } else { String::new() };
        s.push_str(&format!("  0x{:04x}  {:<12} {:<3}  {}{}\n{}", c.id, c.name, role, c.summary, planned, if c.usage.is_empty() { String::new() } else { format!("                           {}\n", c.usage) }));
    }
    s
}

pub fn manual(p: Paint) -> String {
    let mut s = top(true, p);
    for c in SUBS {
        s.push_str("\n----------------------------------------------------------------------\n");
        s.push_str(&sub_help(c, p));
    }
    s.push_str("\n----------------------------------------------------------------------\n");
    s.push_str(&help_ether());
    s.push('\n');
    s.push_str(JSON_HELP);
    s.push('\n');
    s.push_str(BOOT_KEYS);
    s
}

/// `<command> --help`: the command's own page (even for `ether`, whose `help ether` topic is the wire list).
pub fn run_cmd_help(env: &mut Env, name: &str, p: Paint) -> i32 {
    match cli::find(name) {
        Some(c) => {
            let _ = write!(env.out, "{}", sub_help(c, p));
            0
        }
        None => run_help(env, &[name.to_string()], p),
    }
}

pub fn run_help(env: &mut Env, args: &[String], p: Paint) -> i32 {
    let w = |env: &mut Env, t: &str| {
        let _ = write!(env.out, "{}", t);
    };
    match args.first().map(String::as_str) {
        None => w(env, &top(false, p)),
        Some("--all") => w(env, &manual(p)),
        Some("ether") => w(env, &help_ether()),
        Some("exit-codes") => w(env, EXIT_CODES_TEXT),
        Some("boot-keys") => w(env, BOOT_KEYS),
        Some("json") => w(env, JSON_HELP),
        Some(cmd) => match cli::find(cmd) {
            Some(c) => w(env, &sub_help(c, p)),
            None => {
                let _ = writeln!(env.err, "i7labctl: no help for '{}' (try: i7labctl help)", cmd);
                return 2;
            }
        },
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_has_docs_and_examples() {
        for c in SUBS {
            let d = doc(c.name).unwrap_or_else(|| panic!("no help text for {}", c.name));
            assert!(d.about.len() > 30, "{} help too short", c.name);
            assert!(!d.examples.is_empty(), "{} needs examples", c.name);
            for e in d.examples {
                assert!(e.contains("i7labctl") || e.starts_with("HWLAB") || e.starts_with("eval"), "{}: {}", c.name, e);
            }
        }
        for d in DOCS {
            assert!(cli::find(d.name).is_some(), "docs for unknown command {}", d.name);
        }
    }

    #[test]
    fn manual_lists_every_command_and_every_wire_command() {
        let m = manual(Paint { on: false });
        for c in SUBS {
            assert!(m.contains(&format!("i7labctl {}", c.name)), "{}", c.name);
        }
        for c in CATALOG {
            assert!(m.contains(c.name), "{}", c.name);
        }
        assert!(m.contains("(planned v0.4)"), "planned commands are marked");
        assert!(!m.to_ascii_lowercase().contains("busybox"));
    }

    #[test]
    fn every_catalogue_command_has_a_front_or_is_raw_only() {
        let fronted: std::collections::HashSet<&str> = SUBS.iter().filter_map(|s| s.wire).collect();
        // wire commands reached through a verb of a group command or only via --cmd
        let via_verbs = ["blk.smart", "blk.read", "blk.write", "blk.verify", "net.set", "net.vlan", "net.link", "net.confirm", "fs.stat", "fs.rm", "tui.dump"];
        let raw_only = ["cmds", "stats", "key.set"];
        for c in CATALOG {
            assert!(fronted.contains(c.name) || via_verbs.contains(&c.name) || raw_only.contains(&c.name), "no i7labctl front for wire command {}", c.name);
        }
    }
}
