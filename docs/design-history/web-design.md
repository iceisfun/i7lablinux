# WEB: HTTP API and the embedded UI

> **Superseded by docs/PLAN.md (authoritative) on:** PLAN.md C3 (**no bearer token, token file, `#token=` fragment or ts-signing**: auth is nonce HMAC with the admin/ro keys only), C4 (`POST /api/v1/cmd/<name>` with an argv list), C6 (no confirm tokens), C17 (per-event MACs on NDJSON/SSE, raw file endpoints), section 10 (ro key default, nonce-only script CSP, `web/index.html`). Read PLAN.md first; where this note disagrees, PLAN.md wins.


Status: design (R4). Served by `i7labd` (std-only HTTP/1.1 server, no TLS in v0.x).

## Decision

**A tiny embedded single-page app, vanilla JS, one HTML file, no build step, served by `i7labd`
from memory (`include_str!`/`include_bytes!`), talking to the same JSON API that `i7labctl` uses.**

Options considered:

| option | verdict |
|--------|---------|
| Server-rendered HTML (Rust formats pages) | Simple and works with no JS, but every refresh re-sends full pages, live data (progress, logs, graphs) needs polling or a meta refresh, and every screen is Rust string-building that duplicates the API formatting. Two presentation paths to maintain (HTML and JSON). Rejected as the primary UI. Kept only for the two fallback pages below. |
| Framework SPA (React/Vue/Svelte + bundler) | Needs node, a build step and dependencies, an unreproducible build and large assets (hundreds of KB) in the initramfs. Violates the no-dependencies spirit. Rejected. |
| **Vanilla JS SPA, one file** | One source of truth (the JSON API). Embedded in the binary, 40-80 KB uncompressed. Browsers do the rendering; the host spends nearly nothing. No build, reviewable, diffable. Works on any modern browser including old lab laptops. Chosen. |

Fallbacks:

- `GET /` always works even if JS is disabled: the page contains a `<noscript>` block and a plain
  `<pre>` of `/api/v1/probe/all` rendered server-side as text (cheap `to_text()` that already exists for
  the shell). `GET /text/<probe>` returns `text/plain` for `curl`.
- The binary also serves `GET /report.html` (static, the same SPA renderer fed by an embedded snapshot).

## Transport and auth

- HTTP/1.1 on TCP port 8080 by default (`i7lab.http=PORT`), bound to all interfaces when an IP
  exists. `Connection: close` and keep-alive for the SPA. Thread per connection from a small
  pool (max 16), 64 KiB header limit, 1 MiB body limit except upload endpoints, 10 s read timeout.
- No TLS in v0.x. State this honestly in docs: requests are authenticated, not encrypted. TLS is a v0.9 item.
- **Auth (PLAN.md C3, the only scheme):** `GET /api/v1/nonce` (single use, 30 s), then `X-Lab-Key: <key id>`,
  `X-Lab-Nonce`, `X-Lab-Auth = HMAC(K, "lp-req" | nonce | method | target | sha256(body))` with the same admin/ro keys
  as ether; the server answers with `X-Lab-Proof`; stream events carry `seq` + `mac` (`labproto::httpauth`). No secret
  ever crosses the wire. **There is no bearer token, no token file and no URL-fragment auth.**
- Unauthenticated endpoints: `GET /` (the SPA shell, contains no data), `GET /api/v1/hello` (same data an L2 beacon
  already broadcasts), `GET /api/v1/nonce`. Everything else is signed. A bad signature gets 401 after a constant
  200 ms delay; 20 failures from one address lock that address for 60 s.
- CORS off. `Content-Security-Policy: default-src 'self'; script-src 'nonce-<per boot>'; style-src 'self' 'unsafe-inline'`
  (scripts only with the nonce; PLAN.md section 10).
- All strings coming from hardware go through HTML escaping in the SPA (`textContent`, never
  `innerHTML` for probe data). Same hostile-product-string reasoning as the TUI.

## API shape (v1)

JSON everywhere, UTF-8, `"v":1`. Errors: `{"error":{"code":"...","message":"..."}}` with the right HTTP status.

| method + path | meaning |
|---------------|---------|
| GET `/api/v1/hello` | identity, version, boot id (no auth) |
| GET `/api/v1/probe` | list of probe names |
| GET `/api/v1/probe/<name>` | probe result (pci, block, net, usb, cpu, mem, thermal, dmi, acpi, firmware, tpm, gpu, input, serial, ipmi, wol, inventory, system) |
| GET `/api/v1/probe/all` | everything |
| GET `/api/v1/overview` | Overview page data (same as the TUI) |
| GET `/api/v1/log?since=SEQ&level=N&follow=0` | kernel + lab log; with `follow=1` a streaming response (chunked, newline-delimited JSON) |
| GET `/api/v1/events` | Server-Sent Events: `snapshot` (every 2 s), `log`, `job` progress, `link` changes |
| POST `/api/v1/cmd` | body `{"cmd":"disktest","args":{...},"confirm":"token"}`: the same command set as the L2 `--cmd` interface and the shell. Returns result or a `job` id |
| GET `/api/v1/jobs`, `/api/v1/jobs/<id>`, DELETE `/api/v1/jobs/<id>` | long-running tests (disktest, stress, nettest, memtest, capture) with progress + cancel |
| GET/PUT `/api/v1/fs/<path>` | remote file manager: list, download, upload (Range supported), checksum in `X-Sha256` |
| GET `/api/v1/capture/<if>` | live pcap stream |
| GET `/api/v1/screenshot` | PNG of the framebuffer |
| GET `/api/v1/report` | the report bundle |
| GET/PUT `/api/v1/inventory` | tags + notes |
| GET `/api/v1/audit` | audit log |
| POST `/api/v1/update/...` | stick update (v0.7) |
| GET `/api/v1/openapi.json` | machine readable description (generated from the command table) |

The command table (`labproto::commands`) is the single registry feeding: shell builtin help, `i7labctl help`,
L2 dispatch, HTTP `cmd`, TUI Actions menu and the OpenAPI document, so a new command is added once.

Confirmation tokens work as in PROBES.md: Class D commands answer 409 with
`{"confirm":"<token>","summary":"..."}` and succeed on the repeat call carrying the token.

## Pages in the SPA

Hash-routed (`#/overview`), one `<main>` element swapped by small render functions. Mirrors the TUI so
operators learn one structure.

1. **Overview**: identity, health badges (attention list), CPU/mem gauges, NIC table, disk table, temperature sparkline.
2. **PCIe**: collapsible topology tree with degraded-link highlight, detail drawer (BARs, AER, IOMMU group).
3. **Storage**: disks, partition table graphic (proportional bar), signatures, SMART table, test runner form
   (device, mode, pattern, seed, region), live progress chart, results history; destructive confirm modal repeating the serial.
4. **Network**: NICs, stats, rate graph, DHCP discover button + offer table, LLDP neighbours, ping/nettest.
5. **USB**: tree.
6. **Sensors**: live graphs from the SSE stream (inline SVG polyline; no chart library).
7. **Log**: virtualised log viewer, follow, filter, tag chips, download.
8. **Console**: the live TUI screen mirrored (ANSI to HTML renderer of about 150 lines) with key input, plus a
   shell terminal over a WebSocket-less long-poll pair (`POST /api/v1/shell/<id>/in`, `GET .../out` stream) so
   there is no WebSocket dependency. Optional PNG screenshot tab.
9. **Files**: remote file manager with upload/download.
10. **Actions**: boot next / reboot / poweroff / kexec / wipe / WoL / set time / stress, using the same
    confirmation flow.
11. **Fleet** (v0.8): when the operator opens the SPA from a controller host, a list of discovered hosts
    (from L2 beacons relayed by the local `i7labd` or `i7labctl serve`) with a tile each and one-click open.
12. **About**: version, build id, kernel config hash, key fingerprints, update slot status, licence notices.

Implementation constraints: HTML + CSS + JS in a single `ui.html` under `crates/i7labd/ui/`, target
under 100 KB, gzip-embedded at build time with `Content-Encoding: gzip` (the Rust side stores the pre-compressed bytes
produced by `build.rs` using a tiny own "stored deflate" fallback if no gzip tool is available, so the build never
needs an external tool). Light and dark via `prefers-color-scheme`. Layout works at phone width. No external
requests (no CDN, no web fonts), since the lab network may be isolated. A small unit-less test: a headless
check on the build host that loads `ui.html` with a minimal DOM stub (node is not required; the SPA's pure
functions, such as the formatters, are tested through a tiny test page executed by a browser in a later CI job).

## Server details that matter

- One listener thread, accept, hand off to workers. Worker never runs a probe longer than its budget:
  slow probes run as jobs.
- Static assets carry `ETag` from the build id; `Cache-Control: no-cache` for the API.
- `Range` for file download and image reads.
- Graceful with half-up hardware: a probe failing returns its partial result with `warnings:[]`
  instead of HTTP 500.
- Access log lines go into the audit ring (method, path, status, actor key id, source).
- Rate limit on commands of Class D: one per second per actor.
- Binding: `i7lab.http=off` disables the server entirely (L2 + console only).

## Future (not v0.x)

- TLS with a pinned self-signed cert generated at stick build time; the fingerprint is printed by the build.
- WebAuthn is not planned. Token plus HMAC suffices for a lab tool.
- A service-worker offline mode for the report viewer.
