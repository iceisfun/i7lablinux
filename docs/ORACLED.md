# i7oracled: the Windows oracle daemon

`i7oracled.exe` runs on a real Windows 10 machine (22H2) and lets the lab control it over the LAN while it goes through
power states: S3 sleep, S4 hibernate, Modern Standby (S0ix), lid, AC/battery changes, brightness. It records every power
event it can see in a durable log, runs small Win32 probe programs (`win10_*probe.exe`) unattended, and announces itself
with a UDP beacon so nobody needs to know its DHCP address. It exists to record what *real* Windows does, so the lab's
own power code can be compared against it.

One static Rust binary (about 700 KB), no dependencies, hand-written FFI. Crypto, JSON and the HTTP authentication are
compiled from `crates/labproto/src/{crypto,json,httpauth}.rs` (`#[path]`), so the wire bytes are exactly the lab's.
`labproto` as a whole is Linux-only, hence the path includes instead of a crate dependency.

Contents: [Build](#build) | [Install](#install-on-the-windows-machine) | [Modes](#modes-and-which-one-records-what) |
[Keys](#keys) | [API](#api) | [Event log](#event-log-format) | [Beacon](#discovery-beacon) | [Config](#configuration) |
[Power recipes](#power-recipes) | [Verified and not verified](#verified-and-not-verified)

## Build

On the build host (never on a small machine):

```
rustup target add x86_64-pc-windows-gnu          # mingw-w64 provides the linker (x86_64-w64-mingw32-gcc)
cargo build --release -p i7oracled --target x86_64-pc-windows-gnu
# -> target/x86_64-pc-windows-gnu/release/i7oracled.exe
```

`i7oracled` is a workspace member but **not a default member**: a plain `cargo build` or `cargo test` skips it, and
`scripts/build-userland` (musl) is unaffected. `cargo build --release --target x86_64-unknown-linux-musl --workspace`
does build it (as a Linux stub: pure logic plus an API that answers everything except power control), which is also
what lets the unit tests run natively: `cargo test -p i7oracled`.

No Windows binary is ever committed. Copy the `.exe` to the machine by whatever means you have (USB stick, SMB share).

## Install on the Windows machine

Elevated Command Prompt or PowerShell, as Administrator:

```
mkdir C:\oracle
copy i7oracled.exe C:\oracle\
mkdir C:\oracle\probes
copy win10_*probe.exe C:\oracle\probes\               # the probes you want to run
mkdir C:\ProgramData\i7oracled\keys
copy admin.key C:\ProgramData\i7oracled\keys\          # see Keys below; from your machine, never from git
copy ro.key    C:\ProgramData\i7oracled\keys\
C:\oracle\i7oracled.exe install
```

`install` does, and prints each step: create `C:\oracle\{probes,results}` and the data directories; register the service
`i7oracled` (auto start, LocalSystem, recovery: restart after 5 s, 5 s, 30 s, counter reset daily); add the firewall rule
`i7oracled API` (`netsh advfirewall`, inbound TCP 8765, all profiles); restrict `...\keys` to SYSTEM and Administrators
(`icacls`); start the service. Re-running it reconfigures an existing service. The beacon is outbound UDP and needs no rule.

Optional but recommended for the unattended probe runs that need a desktop, and to record window-only events (see
[Modes](#modes-and-which-one-records-what)), run once as the user who will be logged on, elevated:

```
C:\oracle\i7oracled.exe install-agent
```

That creates the logon task `i7oracled-agent` (highest privileges) and starts it.

Remove everything (`sc delete`, the task, the firewall rule) with `C:\oracle\i7oracled.exe uninstall`. The log, the results
and the keys are left alone.

Other commands: `i7oracled.exe console` (foreground, for testing), `agent`, `run` (service entry, started by the SCM),
`version`. Global flags: `--root DIR` (default `C:\oracle`), `--data DIR` (default `C:\ProgramData\i7oracled`),
`--port N`, `--collector HOST:PORT`.

Also worth doing on the laptop before a power-state session: disable automatic Windows Update restarts, and note whether
`powercfg /a` offers "Standby (S3)" or only "Standby (S0 Low Power Idle)" (`POST /powercfg {"action":"available-states"}`
does this remotely and saves nothing; `sleepstudy` and `batteryreport` save HTML into the results).

## Modes and which one records what

| Mode | Started by | Session | API + beacon | Event sources (`src`) |
|---|---|---|---|---|
| `service` | `i7oracled.exe run` from the SCM (`install`) | 0, LocalSystem | yes | `service-ctl` (SERVICE_CONTROL_POWEREVENT, SESSIONCHANGE, SHUTDOWN), `service-cb` (suspend/resume callback), `service-win` (hidden window, may see nothing in session 0), `sampler`, `diag`, `api`, `sweep`, `daemon` |
| `agent` | logon task (`install-agent`) | the logged-on user | no: forwards to the service on 127.0.0.1:8767 | `agent-win` (WM_POWERBROADCAST, WM_QUERYENDSESSION, WM_ENDSESSION, WM_DISPLAYCHANGE, power settings), `agent-cb` |
| `console` | by hand, or a logon task | the logged-on user | yes | `console-win`, `console-cb`, `sampler`, `diag`, `api`, ... |

Why both a service and an agent: a service survives logoff and starts before anyone logs on, and it receives power
events through its control handler (`SERVICE_ACCEPT_POWEREVENT`), which is the supported channel. But session 0 has no
interactive desktop, so display-related window messages (`WM_DISPLAYCHANGE`, `WM_ENDSESSION` for the user session) and
anything that needs a real desktop (GUI probes) belong to the interactive session. Every record carries its `src`, so
the same PBT arriving through two channels shows up twice and the log itself answers which channel saw what. If the
service-side window turns out to receive nothing, that is a finding, not a bug (see [Verified](#verified-and-not-verified)).

If you only want one process and the machine auto-logs-on, run `console` from a logon task instead of installing the
service: probes then also get a real desktop. Do not run `console` and the service at the same time (port clash).

`/run` in service mode starts probes in session 0 (no visible desktop, window stations differ). GUI-dependent probes
should be run in `console` mode.

## Keys

Same keys, same scheme as `i7labd`'s HTTP API (docs/KEYS.md, docs/PROTOCOL.md): `admin.key` and `ro.key`, one line each,
`i7k1:<role>:<64 hex>`. Put the two files into `C:\ProgramData\i7oracled\keys\`. Use your own lab key set, or make a
throwaway one with `scripts/gen-keys --out DIR --throwaway` for a test. Never commit them; never put them on a shared
host. The daemon starts without keys (it records and answers `/health`) but then refuses every authenticated route.
The key bytes are never sent: requests carry a 4-byte key id and an HMAC. Unlike `i7labd` there is no unix permission
check; the installer restricts the directory by ACL instead.

Authentication: `GET /nonce` returns a single-use 30 s nonce; each request carries

```
X-Lab-Key:   hex(first4(SHA256("i7c-keyid" | K)))
X-Lab-Nonce: <nonce>
X-Lab-Auth:  hex(HMAC-SHA256(K, "lp-req\n" nonce "\n" METHOD "\n" TARGET "\n" hex(SHA256(body))))
```

`TARGET` is the request target as sent (`/events?since=5` including the query). The reply carries
`X-Lab-Proof: hex(HMAC-SHA256(K, "lp-resp\n" nonce "\n" status "\n" hex(SHA256(reply body))))`, so a client knows the
answer came from a key holder. Authentication failures (401, 429) have no proof. Ten failures from one address in a
minute lock that address for the rest of the minute (429). `ro` may read; `POST` routes need `admin` (403 otherwise).
There is no TLS: anyone on the LAN can read open endpoints and sniff replies; nobody without a key can act or forge.

## API

Default port 8765. All bodies are JSON. Paths may carry the `i7labd` prefix `/api/v1`.

| Route | Auth | What |
|---|---|---|
| `GET /health` (also `/`) | open | `{ok, service, version, mode, host, boot, up_s, seq, kid}` |
| `GET /nonce` | open | `{nonce, ttl_s}` |
| `GET /info` | ro | machine identity: DMI from `HKLM\HARDWARE\DESCRIPTION\System\BIOS` (manufacturer, product, family, SKU, BIOS vendor/version/date, baseboard), OS (`ProductName`, `DisplayVersion`, `CurrentBuild`, `UBR`), power config (`HibernateEnabled`, `CsEnabled`, `PlatformAoAcOverride`, `HiberbootEnabled`, `hiberfil.sys` present), session id, user, battery presence, power status, the SYSTEM_POWER_CAPABILITIES table, counters |
| `GET /sample` | ro | live power sample now |
| `GET /events?since=SEQ&limit=N` | ro | records with `seq > SEQ` (default limit 500, max 5000) plus `next` to pass back |
| `POST /run` | admin | `{"name":"win10_x_probe.exe","args":["a"],"timeout_s":60,"async":false}` runs a file from `C:\oracle\probes` (`.exe`, `.bat`, `.cmd`, `.ps1`; plain file name only). Reply: `exit_code`, `timed_out`, `duration_ms`, `stdout`, `stderr`, `saved_as`. Saved to `C:\oracle\results\<utc>-<name>.txt`. Output capped at 4 MiB each; on timeout the process tree is killed. `async:true` returns 202 at once; poll `/events` for `run_end` |
| `GET /probes` | ro | files in the probes directory |
| `GET /results`, `GET /results/<file>` | ro | list / fetch saved results and reports |
| `POST /power` | admin | `{"action":"sleep\|hibernate\|shutdown\|reboot\|modern-standby-hint","wake_after_s":N,"wake_method":"timer\|task\|both","delay_s":2}` |
| `POST /powercfg` | admin | whitelisted `powercfg` / registry operations, below |
| `POST /sweep` | admin | run every `*.exe` in the probes directory in sorted order |

### /power

Answers 202 immediately and acts after `delay_s` (default 2) so you get the reply. `request_seq` in the reply is the
seq of the `power_request` event; follow with `GET /events?since=<request_seq - 1>`. The HTTP connection naturally drops
while the machine sleeps; `oracled-curl.py --follow` just retries.

* `sleep`: `SetSuspendState(FALSE, TRUE, FALSE)` (the call `rundll32 powrprof.dll,SetSuspendState 0,1,0` makes). Which state
  that is (S3 or Modern Standby) is the platform's choice; see `GET /info` `capabilities.s3` and `aoac_modern_standby`.
* `hibernate`: `SetSuspendState(TRUE, TRUE, FALSE)`. Needs `powercfg /hibernate on` first (`POST /powercfg`).
* `shutdown`, `reboot`: `InitiateSystemShutdownExW`, forced, reason "planned/other", 3 s timeout.
* `modern-standby-hint`: broadcasts SC_MONITORPOWER off. Windows has no API that *enters* Modern Standby on demand; the
  display-off plus the idle timers (and `POST /powercfg` timeouts) are what get an S0ix machine there. A hint, nothing more.
* `wake_after_s` (5 to 604800): arms the wake source before the transition. `timer` (default) is a waitable timer with
  `fResume=TRUE` held by a waiting thread; `task` registers a one-shot Task Scheduler task with `WakeToRun` at now+N
  (local time, XML in `C:\oracle\wake-task.xml`, task `i7oracled-wake`, runs as SYSTEM); `both` does both. Wake timers only
  work if the power plan allows them (`{"action":"wake-timers","on":true}`) and, on a Modern Standby machine, are
  subject to the platform's timer policy; wake from hibernate needs firmware RTC wake. The result is in the log:
  `wake_timer_fired`, then `pbt` `PBT_APMRESUMEAUTOMATIC` and a `clock_jump`.

Every request is logged (`power_request`, `power_call`, `power_returned` or `power_error`) before and after the blocking call.

### /powercfg

Body `{"action": ...}`; nothing from the request reaches a command line except integers and fixed words.

| action | parameters | runs |
|---|---|---|
| `hibernate` | `on` (bool), optional `type` full\|reduced | `powercfg /hibernate on\|off`, `/hibernate /type ...` |
| `timeouts` | any of `standby_ac standby_dc hibernate_ac hibernate_dc monitor_ac monitor_dc disk_ac disk_dc` (minutes, 0 = never) | `powercfg /change <name>-timeout-<ac\|dc> N` |
| `lid-action` | `ac`, `dc`: nothing\|sleep\|hibernate\|shutdown | `/setac\|dcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION n`, `/setactive` |
| `wake-timers` | `on` (bool) | `/setac\|dcvalueindex SCHEME_CURRENT SUB_SLEEP RTCWAKE 0\|1`, `/setactive` |
| `modern-standby` | `enable` (bool) | `reg add\|delete HKLM\SYSTEM\CurrentControlSet\Control\Power /v PlatformAoAcOverride` (0 disables Modern Standby, exposing S3 where the firmware has it; needs a reboot) |
| `available-states` | | `powercfg /a` |
| `requests`, `lastwake`, `wake-armed`, `list` | | `powercfg /requests`, `/lastwake`, `/devicequery wake_armed`, `/list` |
| `sleepstudy`, `batteryreport`, `energy` | optional `duration` | `powercfg /sleepstudy\|/batteryreport\|/energy /output C:\oracle\results\<utc>-<name>.html` (fetch with `GET /results/<file>`) |

The reply lists, per command, `exit_code`, `output`, `stderr` and `saved_as`.

### Probes and the first-boot sweep

On the first start after install (marker `C:\oracle\first-boot-sweep.done`), after `sweep_delay_s` (30 s) and only if the
probes directory has `.exe` files, the daemon runs every `*.exe` in sorted order with `sweep_timeout_s` (120 s), saves each
result, writes `sweep_start`/`run_*`/`sweep_end` events and, when `collector` is set in `config.json`, POSTs the summary
JSON to `http://<collector>/oracle-hello` (unauthenticated by design: the collector is optional and the body is a summary
line; a failed post is only logged, as `collector_post`). Delete the marker to repeat; `POST /sweep` does it on demand.

## Event log format

`C:\oracle\power-events.jsonl`, one JSON object per line, UTF-8, appended and **fsynced after every record**, so a power
cut or a hibernate loses nothing already reported. `seq` starts at 1 and increases by 1; it survives restarts and reboots
(the daemon reads the last complete line on start). A torn last line is skipped by readers and fenced off by a newline
before the next record. Read the file directly or through `GET /events?since=SEQ`; resume by passing back `next`.

```
{"seq":42,"src":"service-ctl","kind":"pbt","utc":"2026-11-12T10:20:30.1234567Z","wall_100ns":134386...,
 "qpc":8123456789,"qpc_hz":10000000,"tick_ms":123456,"unb_100ns":1234560000,"int_100ns":1234567890,
 "data":{"channel":"SERVICE_CONTROL_POWEREVENT","pbt":"PBT_APMSUSPEND","code":4,"since_last_sample":{"wall_ms":812.4,...}}}
```

Timestamps on every record: `utc`/`wall_100ns` (GetSystemTimePreciseAsFileTime, 100 ns since 1601), `qpc` +
`qpc_hz` (QueryPerformanceCounter), `tick_ms` (GetTickCount64), `unb_100ns` (QueryUnbiasedInterruptTime: does not count
time asleep), `int_100ns` (QueryInterruptTime: does count it). The differences between these clocks across a suspend are
the point: `clock_jump` events and `since_last_sample` give the deltas (`wall_ms`, `qpc_ms`, `tick_ms`, `unbiased_ms`,
`interrupt_ms`) between consecutive samples.

| `kind` | when | `data` |
|---|---|---|
| `start` | process start | version, mode, boot id, host, OS, pid, key fingerprints, full `/info` (capabilities table included) |
| `monitor_ready` | after registration | per power-setting GUID registration error code (0 = ok), suspend/resume callback result |
| `previous_shutdown` | start (Windows) | `wevtutil` summary of System events 41, 1074, 6005, 6006, 6008, 42, 107, 109, 506, 507 and Power-Troubleshooter 1, plus a classification of the latest shutdown marker |
| `pbt` | WM_POWERBROADCAST, service power event, suspend/resume callback | `pbt` name and code, `channel`, `since_last_sample` clock deltas |
| `power_setting` | PBT_POWERSETTINGCHANGE | `setting` {guid, setting name, raw hex, `value`, `meaning`}: AC/DC source, lid, battery percentage, console display state, monitor on, away mode, session display status, user presence, power scheme personality, energy saver, battery saver, idle background task |
| `wm_queryendsession`, `wm_endsession`, `wm_displaychange` | window messages | flags, resolution |
| `service_control`, `session_change`, `service_stopped` | SCM | control code, WTS session event |
| `sample` | on every event, when the battery or power status changes, and every `heartbeat_s` (10 s) | `status` (GetSystemPowerStatus: AC line, battery flag/percent/life/full life, battery saver), `battery` (SYSTEM_BATTERY_STATE: capacity, rate, estimate), `power_info` (SYSTEM_POWER_INFORMATION) |
| `clock_jump` | the 1 s sampler sees the clocks disagree or step | `delta` as above |
| `after_resume` | 3 s after a resume | `transition` (last wake/sleep time, execution state) and the capabilities table again |
| `powercfg` | start and after each resume | output of `powercfg /requests` (what is keeping the machine awake) and `/lastwake` |
| `power_request`, `power_call`, `power_returned`, `power_error`, `wake_timer_fired` | `/power` | see above |
| `run_start`, `run_end`, `sweep_*`, `collector_post`, `api_listening`, `error` | housekeeping | |

Counters: `/info` has `suspends_seen`, `resumes_seen`, `runs`. The Windows kernel's own transition times are in
`after_resume.transition.last_wake_time_100ns` / `last_sleep_time_100ns`. The log is never rotated; copy and truncate it
between sessions if it gets large (a day of heartbeats is a few MB).

## Discovery beacon

UDP broadcast to port 8766 every 5 s, from every adapter that has an IPv4 address, to `255.255.255.255` and the subnet
broadcast. Text, no secrets:

```
I7ORACLE1
host=DESKTOP-ABC123
ip=192.0.2.40
mac=02:00:00:ab:cd:ef
api=8765
kid=a:11223344,r:55667788
os=Windows 10 Home 22H2 build 19045.4046
mode=service
boot=76109143b8e19654
up=412
seq=17
tag=<32 hex>
```

`kid` lists the key-id fingerprints so you can tell whether the machine has your key set. `tag` is
`hex(first16(HMAC(K_beacon, "i7oracle-beacon\0" | all lines before tag)))` with `K_beacon = HMAC(K_ro, "i7c-beacon-key")`:
a verifier holding the ro key can check the datagram came from a machine given that key set; it is replayable (`up` and
`seq` show staleness) and, as everywhere in the lab, an address learned from a beacon is never sent a secret.
Find it with `python3 -c` or any UDP listener on 8766, or `tools/oracled-curl.py` against the printed `ip`.

## Configuration

Optional `C:\ProgramData\i7oracled\config.json`; unknown keys are ignored, wrong types refuse to start:

```
{"port":8765, "bind":"0.0.0.0", "beacon":true, "beacon_port":8766, "beacon_interval_s":5, "agent_port":8767,
 "oracle_dir":"C:\\oracle", "collector":"192.0.2.7:8080", "sweep_on_first_boot":true, "sweep_timeout_s":120,
 "sweep_delay_s":30, "heartbeat_s":10}
```

## tools/oracled-curl.py

Standard-library Python 3 signer that works from any machine (no `i7labctl` needed):

```
tools/oracled-curl.py --host 192.0.2.40 --key-file admin.key GET /info
tools/oracled-curl.py --host 192.0.2.40 --key-file ro.key --role ro GET '/events?since=100'
tools/oracled-curl.py --host 192.0.2.40 --key-file admin.key POST /run '{"name":"win10_foo_probe.exe","args":["--x"],"timeout_s":60}'
tools/oracled-curl.py --host 192.0.2.40 --key-file admin.key POST /power '{"action":"sleep","wake_after_s":30}'
tools/oracled-curl.py --host 192.0.2.40 --key-file ro.key --role ro --follow --since 0     # live event stream
```

It prints the status and whether the reply proof verified on stderr and the body on stdout; exit 0 only for a 2xx with a
valid proof. Without a signer, the protocol is: `curl /nonce`, compute the MAC above, send the three headers.

## Power recipes

| Goal | Steps |
|---|---|
| Is this an S3 or an S0ix machine? | `GET /info`: `capabilities.s3`, `aoac_modern_standby`; `POST /powercfg {"action":"available-states"}`; `GET /info` `power_config.CsEnabled` |
| Force S3 on a Modern Standby laptop (if the firmware supports it) | `{"action":"modern-standby","enable":false}`, reboot, re-check `available-states` |
| Sleep and come back by itself | `{"action":"wake-timers","on":true}`, then `/power {"action":"sleep","wake_after_s":30}`; watch `pbt` `PBT_APMSUSPEND`, `wake_timer_fired`, `PBT_APMRESUMEAUTOMATIC`, `clock_jump` |
| Hibernate and resume | `{"action":"hibernate","on":true}`; `/power {"action":"hibernate","wake_after_s":120,"wake_method":"both"}`; the log shows `previous_shutdown` only after a real power loss, not after a hibernate |
| Lid | close and open the lid by hand; `power_setting` `GUID_LIDSWITCH_STATE_CHANGE`, `lid-action` via `/powercfg` decides what happens |
| What kept it awake | `powercfg` events (`/requests`) after each resume; `{"action":"sleepstudy"}` for Modern Standby drains |
| Reboot reason of the last stop | the `previous_shutdown` event in the first records after boot |

## Verified and not verified

Verified on the Linux build host (`cargo test -p i7oracled`, 61 tests):
event-log record format, durable append, resume by seq, torn-tail handling; the HMAC request and proof MACs against
independently computed vectors and the labproto RFC 4231 / FIPS 180-4 vectors that compile into this crate; nonce reuse,
tampered body, role checks and lockout; HTTP request parsing (split reads, limits, malformed input); JSON; probe name
rules and results store; process capture and timeout (Linux processes); the `powercfg` whitelist; power-request
parsing; GUID layout and power-setting decoding; byte decoders for the Windows power structures; `wevtutil` text parsing;
the beacon format and tag; service/firewall/task command lines; and the signed client against a live daemon (Linux stub). The Windows binary builds
and links with `x86_64-pc-windows-gnu` and imports only system DLLs (kernel32, user32, advapi32, iphlpapi, ws2_32, ntdll).

Verified on a real Windows 10 22H2 (build 19045.2965, Home) guest under QEMU/KVM (the lab's Win10 oracle base image,
`pc` machine, SeaBIOS, std VGA, throwaway overlay; the guest is not the laptop, so this proves the daemon, not the laptop's
firmware): `console` mode and `service` + `agent` mode both start; `install` runs clean (service created with the
recovery actions, firewall rule, ACL, service started); `/health`, `/info` (DMI from the registry shows the QEMU
firmware strings, OS build, capabilities table, battery absent), signed `/events`, `/run` of a mingw-built probe (exit code,
stdout, saved result), `/powercfg` (`available-states`, `hibernate on`) work through the Python signer with valid response
proofs; the power-setting registrations were made on every channel and the 10 settings that apply to that guest (AC/DC source, console display, monitor, session display, global and session user presence, idle background task, scheme personality, battery saver, lid-open power state) each delivered their initial value; battery percentage, lid switch, away mode and energy saver delivered nothing, as expected without a battery or lid.
A real **S4 hibernate round trip** was recorded in both modes (`/power hibernate`, QEMU exits as the guest powers off, the
same overlay is booted again and Windows resumes the processes): `PBT_APMSUSPEND`, `PBT_APMRESUMEAUTOMATIC` and
`PBT_APMRESUMESUSPEND` arrived on **every** channel, including the hidden window inside the session-0 service
(`service-win`) next to the control handler (`service-ctl`), the callback (`service-cb`) and the agent (`agent-win`,
`agent-cb`); display off/monitor off/user presence changes preceded the suspend; the durable log kept seq 1..N without a
gap across the power-off; `clock_jump` showed wall time and `QueryInterruptTime` advancing by the hibernate duration
while `QueryUnbiasedInterruptTime` advanced by 1 to 8 s (QPC also advanced in that guest); `wake_timer_fired` came
right after the resume (the timer is overdue when the guest wakes: QEMU cannot RTC-wake itself, so the guest was started
by hand); `after_resume` diagnostics, `powercfg /requests` and `/lastwake` were captured; the agent's loopback forwarding
delivered its events into the service's log (spool/replay after a refused connection is covered by a unit test only). `/power sleep` on this guest fails cleanly with `SetSuspendState failed: 50`
(`powercfg /a`: S3 "disabled by Graphics", the basic display driver) and is logged as `power_error`: the error path works,
S3 itself could not be exercised.

Reading the log after a resume: records are appended in the order they were *received*, not in time order. After a resume
every channel is delivered late and in different threads, so a record with a higher `seq` can carry an earlier `utc`.
Sort by `wall_100ns` (or `qpc`) when you want the timeline, by `seq` when you want to resume reading. Each transition shows
up several times (once per channel); that is intended, the `src` field tells them apart.

Not verified, because it needs the real laptop: S3 sleep and Modern Standby (S0ix) entry, resume and their events;
lid and battery power-setting changes (the guest has neither); `wake_after_s` actually waking a real machine (timer
and task methods, from S3 and from hibernate; the `task` method was not run at all); brightness events; `modern-standby` registry override effect; whether Modern Standby machines deliver `PBT_APMSUSPEND` at all (they use a different notification, the display-state and `GUID_SYSTEM_AWAYMODE`-style settings, which are recorded); the exact numbers in the
`SYSTEM_BATTERY_STATE` / `SYSTEM_POWER_CAPABILITIES` decoders on real firmware (the raw hex is logged next to the capabilities
so a mislabelled field can be re-read); the full list of power-setting GUIDs (an unknown GUID registers without error and
just never fires; the per-GUID registration result is in `monitor_ready`); the service restart-on-failure behaviour; `install-agent` (the scheduled task; the guest test started the agent by hand); the first-boot sweep and
the collector POST on Windows (unit-tested with a local listener only).

Known limits: no TLS; loopback port 8767 accepts event records from any local process (the oracle machine is disposable
and single-user, so this is accepted); `.bat`/`.cmd` probes are run through `cmd /c`, so an admin-key holder can run
anything cmd can (admin already means arbitrary code on this machine); one request per connection, no streaming (poll
`/events`); the log is never rotated.
