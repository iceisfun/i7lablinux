# Web UI and HTTP API

Current state of the HTTP side of `i7labd`. The design reasoning is in [PLAN.md](PLAN.md) section 10 and C3/C4/C17; the
original proposal is archived in [design-history/web-design.md](design-history/web-design.md) (its bearer-token auth text
is void). The page's own developer notes: `crates/i7labd/web/README.md`.

## Decision: a single embedded page, no framework

The web UI is **one vanilla-JS HTML file** (`crates/i7labd/web/index.html`, about 78 KB), embedded into `i7labd` with
`include_str!` and served from memory at `GET /`. No build step, no npm, no CDN, no web fonts, no external requests: it
works offline from the host itself, which is the only place it is needed. A framework-based SPA was rejected because
the image has no Node, the page must keep working on a machine with nothing else, and a 100 KB file is easy to audit.

Pages: Overview, PCIe, Storage (partition bar, write-gate verdicts, read and write test launcher), Network, USB, Sensors,
Log, Terminal, Actions, About. Every data tab has Copy as Markdown and Copy as JSON buttons (clipboard API, with a
hidden-textarea fallback for plain-HTTP origins). Light and dark follow the OS; it works from phone width up.

## Listening

`i7labd` answers HTTP on port 80 and on port 8080 (kept for older clients and scripts; same handler, same auth, one shared connection budget) on every address once the host has an IP (DHCP). Narrow it with the kernel argument
`i7lab.http_bind=IFACE|ADDR` move the primary port with `i7lab.http=PORT` (an explicit value drops the 8080 listener unless `i7lab.http_alt=PORT` is also given; `i7lab.http_alt=off` drops only 8080) or turn HTTP off with `i7lab.http=off i7lab.http_alt=off`. A port that cannot bind is logged and skipped; the beacon `http=` field advertises the first port that bound (80). Every request is signed, so plain HTTP on port 80 adds no unauthenticated capability (see [PLAN.md](PLAN.md) C23). There is no TLS.

## Routes (all under `/api/v1`)

| method and path | auth | purpose |
|---|---|---|
| `GET /` | open | the page |
| `GET /api/v1/hello` | open | identity: hostname, version, build, state |
| `GET /api/v1/nonce` | open | single-use nonce, valid 30 s |
| `GET /api/v1/openapi.json` | open | generated from the command catalogue |
| `POST /api/v1/cmd/<name>` | signed | run a catalogue command, body `{"args":["--mb","256"]}`; `?stream=1` for NDJSON |
| `GET /api/v1/probe/<section>` | signed | same as `inv --section <section>` |
| `GET /api/v1/overview` | signed | snapshot JSON |
| `GET /api/v1/events` | signed | server-sent events: snapshots, audit, jobs |
| `GET /api/v1/file`, `PUT /api/v1/file` | signed | raw download and upload |
| `POST /api/v1/shell/open[?cols=&rows=]` | signed, admin | start i7labsh on a pty, returns `{"id"}` |
| `GET /api/v1/shell/<id>/out` | signed, admin | sealed SSE: `{"event":"out","b64":..}` chunks, ends with `{"event":"exit","reason":..,"code":..}` |
| `POST /api/v1/shell/<id>/in` | signed, admin | keystrokes: base64 text body, or raw bytes with `Content-Type: application/octet-stream`; at most 64 KiB |
| `POST /api/v1/shell/<id>/resize` | signed, admin | `?cols=N&rows=N` or JSON `{"cols":N,"rows":N}`, 1..1000 |
| `POST /api/v1/shell/<id>/close` | signed, admin | end the shell |
| `GET /vendor/xterm.js`, `xterm.css`, `addon-fit.js` | open | embedded xterm.js 5.5.0 + fit addon 0.10.0 (MIT), loaded by the Terminal tab only |

## Authentication

One scheme for every transport, using the same two keys as the Ethernet protocol ([KEYS.md](KEYS.md)). The raw key never
crosses the wire and there is no token file.

1. `GET /api/v1/nonce`.
2. Send `X-Lab-Key` (key id), `X-Lab-Nonce` and `X-Lab-Auth = HMAC-SHA256(K, "lp-req\n" nonce "\n" METHOD "\n" target "\n" sha256(body))`.
3. The reply carries `X-Lab-Proof`, an HMAC over nonce, status and body hash. The client must verify it. Stream events carry
   a per-event `mac` and a sequence number.

`i7labctl --http HOST[:PORT] ...` (port 80 unless given) does all of this. The page does it in about 100 lines of JS (WebCrypto is unavailable on
plain-HTTP origins). The page asks for a key line and defaults to the **read-only** key; the admin key is loaded explicitly
on the Actions page and kept in `sessionStorage` for the tab only.

## Web terminal

A shell in the browser without WebSocket: `shell/open` starts `/bin/i7labsh` as session leader on a pty; the page reads
`shell/<id>/out` (the same sealed SSE as `events`: per-event `seq` + `mac`, so a forged or reordered byte of terminal
output is rejected) and writes keystrokes with signed `shell/<id>/in` posts. Requests and responses are signed exactly
like every other call; the key never leaves the page.

* **Admin key only.** The read-only key gets 403 `EPERM` on every shell route (audited as a denied attempt), and the page
  shows the tab disabled with an explanation.
* **Limits.** 2 concurrent shells (503 `BUSY` beyond); 10 minutes without a keystroke or resize closes the shell
  (`reason":"idle"`); a shell whose out stream is not attached within 60 s is dropped; closing the out stream (tab
  closed, network gone) closes the shell; one output stream per shell; output is buffered at most 256 KiB and a slow
  browser makes the shell block on the pty (backpressure, nothing dropped); one input post is at most 64 KiB.
* **Audit.** `shell.open` and `shell.close` (with the reason: `closed`, `idle`, `disconnect`, `unattached`, `exit N`) go
  through the normal audit log and `logs --audit -f`; a refused or failed open is audited too.
* **No encryption.** There is no TLS: everything typed and everything shown is readable on the network. The tab carries a
  permanent warning ("unencrypted HTTP ... use only on a trusted LAN"). An admin shell is root on the host: keep it on a lab
  LAN, or use the ether protocol (`i7labctl shell`) which is also unencrypted but needs L2 adjacency.
* **CSP.** `script-src 'nonce-..' 'self'`: `'self'` is there for `/vendor/*.js`, which is embedded in the binary.

## Hardening of the page

Content-Security-Policy `default-src 'self'; script-src 'nonce-<per-boot>' 'self'; style-src 'self' 'unsafe-inline'`, no inline
event handlers, every hardware string inserted with `textContent` and sanitised, and a render test feeds `<img onerror>` and
`<script>` through the model, serial and DMI fields. The write-test form is UX only: the host re-decides in the write gate.

## Decision still open

Whether `i7labctl web` (a local proxy so the page can reach hosts that have no IP) is built: planned for v0.5, see
[ROADMAP.md](ROADMAP.md).
