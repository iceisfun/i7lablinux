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
Log, Actions, About. Light and dark follow the OS; it works from phone width up.

## Listening

`i7labd` answers HTTP on port 8080 on every address once the host has an IP (DHCP). Narrow it with the kernel argument
`i7lab.http_bind=IFACE|ADDR` or turn it off with `i7lab.http=off` (see [PLAN.md](PLAN.md) C23). There is no TLS.

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

## Authentication

One scheme for every transport, using the same two keys as the Ethernet protocol ([KEYS.md](KEYS.md)). The raw key never
crosses the wire and there is no token file.

1. `GET /api/v1/nonce`.
2. Send `X-Lab-Key` (key id), `X-Lab-Nonce` and `X-Lab-Auth = HMAC-SHA256(K, "lp-req\n" nonce "\n" METHOD "\n" target "\n" sha256(body))`.
3. The reply carries `X-Lab-Proof`, an HMAC over nonce, status and body hash. The client must verify it. Stream events carry
   a per-event `mac` and a sequence number.

`i7labctl --http HOST:PORT ...` does all of this. The page does it in about 100 lines of JS (WebCrypto is unavailable on
plain-HTTP origins). The page asks for a key line and defaults to the **read-only** key; the admin key is loaded explicitly
on the Actions page and kept in `sessionStorage` for the tab only.

## Hardening of the page

Content-Security-Policy `default-src 'self'; script-src 'nonce-<per-boot>'; style-src 'self' 'unsafe-inline'`, no inline
event handlers, every hardware string inserted with `textContent` and sanitised, and a render test feeds `<img onerror>` and
`<script>` through the model, serial and DMI fields. The write-test form is UX only: the host re-decides in the write gate.

## Decision still open

Whether `i7labctl web` (a local proxy so the page can reach hosts that have no IP) is built: planned for v0.5, see
[ROADMAP.md](ROADMAP.md).
