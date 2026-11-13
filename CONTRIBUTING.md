# Contributing

## Ground rules

* **No busybox.** Every userland tool in the image is our own Rust: a builtin of `i7labsh`, or a small own binary. The
  build must not fetch or compile busybox and no document may list it as a dependency. `scripts/check-no-busybox` enforces it.
* **No dependencies.** Rust 2021, std plus the hand-written FFI in each crate's `ffi.rs` or `labproto::sys`. Ask before
  adding even a tiny well-known crate; the answer is usually a small module instead.
* **No secrets in the tree.** Never commit keys, tokens or passwords. `keys/` and `out/` are gitignored. Only public
  material (the demo key derivation) and documentation of the scheme may be tracked.
* **Safety of writes.** Anything that can write a block device goes through `labprobe::block::WriteGuard`. Do not add a
  second path around it. Tests that write use loop files or QEMU disks, never a real device.
* **Host-testable.** Put logic in pure functions with unit tests; keep syscalls behind thin wrappers. Real-hardware or QEMU
  results go in [docs/E2E-RESULTS.md](docs/E2E-RESULTS.md) with an honest NOT RUN list.

## Layout

See the architecture table in the [README](README.md) and [docs/PLAN.md](docs/PLAN.md) section 3. Docs index:
[docs/README.md](docs/README.md).

## Build and test

```sh
make check          # fmt --check, clippy -D warnings, tests, shellcheck, busybox guard (what CI runs)
make test           # cargo test --workspace
make musl           # release build of the image binaries for x86_64-unknown-linux-musl
make image          # full keyless image on the build host: kernel, userland, initramfs, GPT image + ISO
make e2e            # QEMU end-to-end run on the build host
```

The Rust toolchain is pinned in `rust-toolchain.toml`; `Cargo.lock` is committed. On a small machine do not run cargo or QEMU
locally: `scripts/remote -l <label> -- cargo test --workspace` runs it on the build host. QEMU guests are 4 GB each; run at
most two at once and always under `timeout`.

## Adding things

* **A command**: one `CATALOG` entry in `labproto` (new id, never reused, `since` set), one handler in `i7labd`, optionally an
  `i7labctl` wrapper (the raw `--cmd` form works immediately), a TUI or web entry if wanted, a test, and a line in
  [docs/I7LABCTL.md](docs/I7LABCTL.md). Protocol changes follow [docs/PROTOCOL.md](docs/PROTOCOL.md) section 9.
* **A probe**: one `labprobe` module, a `Section` variant and a fixture test (`scripts/capture-fixture` records one from a
  real host; scrub serial numbers and MAC addresses first).
* **A kernel option**: edit a fragment in `configs/kernel/fragments/`, add critical symbols to `configs/kernel/must-be-y.list`,
  rebuild and boot-test.

## Style

`cargo fmt`, `cargo clippy -D warnings`, no `unwrap` on input-derived data, bounded buffers and loops on anything read from
the network or a device, `unsafe` only inside the FFI modules with a comment on the invariant. Shell scripts are
`bash`, `set -euo pipefail` via `scripts/lib/common.sh`, clean under `shellcheck`.

## Docs

Keep [docs/PLAN.md](docs/PLAN.md) and the reference docs current when behaviour changes. Working notes, reviews and
recon belong in [docs/design-history/](docs/design-history/README.md), not in the main docs. Update
[CHANGELOG.md](CHANGELOG.md). `make docs-check` verifies that relative links resolve.

## Commits

No sign-off trailers are required. The licence is undecided ([docs/LICENSE-DECISION.md](docs/LICENSE-DECISION.md)), so
do not contribute code you cannot license to the maintainer.
