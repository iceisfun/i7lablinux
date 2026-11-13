# i7labd web UI (`index.html`)

One file, vanilla JS, no build step, no external request (no CDN, no web fonts), works offline from the host itself.
About 78 KB. Embedded by `src/web.rs` with `include_str!`. Pages: Overview, PCIe (topology tree + detail drawer),
Storage (partition bar, write-gate verdicts, SMART, block-test launcher), Network (live rates), USB (tree), Sensors
(live SVG graphs, polling), Log (filter, tags, follow, download), Actions (confirm dialogs), About.
Dark/light follows the OS with a toggle; layout works from 390 px to wide screens; landmarks, labels, focus
rings, `aria-live` regions, native `<dialog>` for modals, `prefers-reduced-motion` respected.

## Serving contract (for `http.rs`)

* `GET /` returns this file with every `__I7LAB_NONCE__` replaced by the per-boot CSP nonce and the header
  `Content-Security-Policy: default-src 'self'; script-src 'nonce-<nonce>'; style-src 'self' 'unsafe-inline'`.
  The page has exactly two `<script nonce=...>` blocks (`#core` pure functions, `#app`), no inline event handlers.
  Served without the replacement the scripts will not run under that CSP.
* `GET /api/v1/hello` and `GET /api/v1/nonce` are open; everything else is signed (PLAN.md C3).

## Auth (what the SPA does)

The page asks for a key line `i7k1:ro:<64 hex>` (the ro key by default; "Use the documented demo read-only key" builds
`SHA256("i7lablinux-demo-ro")` locally). The admin key is loaded only on the Actions page, verified with an `id` call
(the host may downgrade it: the SPA then says so). Keys live in `sessionStorage` for the tab and are never sent.
Own JS SHA-256/HMAC (WebCrypto is unavailable on plain-HTTP origins). Per request:

1. `GET /api/v1/nonce`, answered as `{"nonce":"<hex>"}` (a bare text nonce is also accepted).
2. `X-Lab-Key: <hex first4(SHA256("i7c-keyid"|K))>`, `X-Lab-Nonce`, `X-Lab-Auth = hex HMAC(K, "lp-req\n"+nonce+"\n"+METHOD+"\n"+target+"\n"+hex(sha256(body)))`
   where `target` is path + query exactly as requested, `body` is the raw request body (empty for GET).
3. The response must carry `X-Lab-Proof = hex HMAC(K, "lp-resp\n"+nonce+"\n"+status+"\n"+hex(sha256(body)))`;
   a missing proof on a 2xx or a mismatch shows a red "Verification failed" error and the data is discarded.
4. Streams (NDJSON and SSE): every event carries `"seq":N` (0, 1, ...) and `"mac"`. The mac must be the **last**
   member of the event text; it is `hex(first16(HMAC(K, "lp-evt\n"+nonce+"\n"+seq+"\n"+<event text with the ,"mac":"..." member removed>)))`.
   A bad mac, missing mac or seq gap aborts the stream with the same error. SSE uses the nonce of the `GET /api/v1/events` request.

## JSON API consumed

| call | used by | expected |
|---|---|---|
| `GET /api/v1/hello` (open) | login, header | `{hostname, version?, build?, state?, demo?: bool}` (all optional; `demo:true` shows the DEMO KEYS badge) |
| `GET /api/v1/probe/<a,b,..>` | all data pages | `{"v":1, "<section>": <labprobe report> or {"error","message"}}`, sections = `system cpu mem dmi pci usb block net thermal smart kmsg firmware` (PLAN 4.2 field names; extra fields ignored; a failed section is shown inline, not fatal) |
| `POST /api/v1/cmd/id` / `cmds` / `ping` | login check, Actions, About | the PLAN catalogue handlers (`role`, `version`, `kid`, ...; `cmds` entries `{name, access, streams, usage, summary}`, optional `planned: true` and `since` which grey the command out) |
| `POST /api/v1/cmd/<name>` body `{"args":[..]}` | Actions: `identify msg time.set tui reboot poweroff` (admin) | JSON reply, errors `{"error":{"code","message","reasons"?}}` with the HTTP status |
| `POST /api/v1/cmd/blk.read\|blk.verify\|blk.write?stream=1` | Storage | NDJSON: `{"event":"progress","region","done_bytes","total_bytes","mib_s"}` ... `{"event":"result","ok":bool,"exit":N,"report":<TestReport>}`; `blk.write` args `DEV --destructive --serial S [--mb N] [--regions ..] [--seed N]`, refusals as 409 with `error.reasons` |
| `POST /api/v1/cmd/logs?stream=1` args `--audit\|--daemon\|--init -n 400` | Log | NDJSON `{"event":"stdout","data":".."}` (or `b64`) then `result` |
| `GET /api/v1/events` (SSE) | Overview | events `{"event":"snapshot","state":"..","attention":["..",..],...}`; optional, the page works without it (indicator "live feed: off") |

Polling: Overview 8 s, Network and Sensors 2 s, Log 3 s (tab hidden: paused). PCIe, USB and Storage load on open and on Refresh.
Hardware strings are always inserted with `textContent` and also pass through the same sanitiser as `labproto::text`
(control, bidi, zero-width, private-use, tag characters shown as `\u{XXXX}`, backslash doubled). There is no `innerHTML` in the page.

## Write-test safety UI

Read tests never send `--destructive`. The write button is disabled until all of: admin key loaded, device not
boot media / mounted / held / read-only / refused by the host, a serial or WWID exists, the full serial has been typed
(never pre-filled), the data-loss box is ticked when the verdict is `needs_override`; then a modal repeats device,
model, size and serial and needs the serial typed once more. This is UX only: `labprobe::block::WriteGuard` re-decides on the host.

## Development and tests (no cargo needed)

```
python3 web/dev/mock-server.py --port 8080     # prints the demo key lines; open http://127.0.0.1:8080/
node web/dev/test-core.js                      # 89 unit checks of the pure functions (SHA-256/HMAC vs node:crypto, RFC 4231,
                                               #   MAC layouts, stream checks, sanitiser, tree/partition/gate logic)
node web/dev/browser-check.js [chrome]         # headless Chrome over DevTools: 78 checks, drives the mock end to end
```

`mock-server.py` implements the real auth (single-use nonces, request check with the demo keys, proof, event macs,
nonce CSP) and a fixture host with hostile strings (`<img onerror>`, `<script>`, ESC sequences, bidi) in model, serial, DMI, USB and kmsg.
`MOCK_BAD_PROOF=1` makes it a host that fails verification (used by the browser check).

## Assumptions to confirm with `http.rs` (P7)

1. The nonce endpoint answers JSON `{"nonce":..}` or plain text.
2. The mac is the last member of every NDJSON/SSE event and is computed over the line with it removed (as in the mock).
3. Probe sections are addressable as a comma list (`/api/v1/probe/pci,net`), equivalent to `inv --section pci,net`.
4. The final `result` event of `blk.*` may carry the `TestReport` as `report` (or inline as `regions`); otherwise the raw event is shown.
5. A `/api/v1/openapi.json` link is shown on About; `/text/all` is the noscript fallback.
