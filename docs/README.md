# Documentation index

Start with the [project README](../README.md). Then pick by what you are doing.

## Use it

| doc | what |
|---|---|
| [QUICKSTART.md](QUICKSTART.md) | stick to first command, and what to do when it does not come up |
| [I7LABCTL.md](I7LABCTL.md) | the operator CLI: every command, options, exit codes, key lookup |
| [KEYS.md](KEYS.md) | the baked keys: generate, bake, rotate, test keys, threat statement |
| [REMOTE-BOOT.md](REMOTE-BOOT.md) | getting a host you are not at to boot lab linux (stick, instructed person, JetKVM) |
| [TUI.md](TUI.md) | the console UI, pages and keys |
| [WEB.md](WEB.md) | HTTP API, authentication and the web page |

## Build it

| doc | what |
|---|---|
| [BUILD.md](BUILD.md) | pipeline, build host, variables, what is not yet proven |
| [E2E-RESULTS.md](E2E-RESULTS.md) | the recorded QEMU end-to-end run, sizes, failures, NOT RUN list ([transcript](e2e/transcript-20261113.txt), [TUI capture](e2e/tui-vga-uefi.png)) |
| [../tests/e2e/README.md](../tests/e2e/README.md) | how the end-to-end scripts work |
| [BRIEF-CHECKLIST.md](BRIEF-CHECKLIST.md) | every operator-brief bullet: PASS / PARTIAL / MISSING with evidence; gaps in [EXPANSION.md](EXPANSION.md) |

## Reference and design

| doc | what |
|---|---|
| [PLAN.md](PLAN.md) | the authoritative design: contracts, safety model, image layout, boot flow, decisions |
| [PROTOCOL.md](PROTOCOL.md) | wire protocols: frames, sessions, catalogue, beacons, test vectors, threat model |
| [PROBES.md](PROBES.md) | what is probed and how, the block test engine |
| [ROADMAP.md](ROADMAP.md) | versions and open items |
| [THIRD_PARTY.md](THIRD_PARTY.md) | third-party material in built images |
| [../SECURITY.md](../SECURITY.md) | threat model and reporting |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | how to work on it |

## Archive

[design-history/](design-history/README.md): recon notes, the adversarial reviews, the original web and expansion
proposals, the integration log. Kept for the reasoning; where they disagree with PLAN.md, PLAN.md wins.
