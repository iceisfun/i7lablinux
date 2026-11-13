# Licence decision (operator)

There is **no LICENSE file on purpose**. Until one is added, all rights are reserved by the author: nobody else may use,
copy or modify the code. Cargo manifests have no `license` field and `publish = false`. This page lays out the choice;
adding a file and the manifest field is a two-minute change once decided.

## What the licence covers

Only our own source: the seven crates, scripts, configs, docs. The image that the scripts build also contains
third-party material under its own licences, which stays as it is whatever we choose ([THIRD_PARTY.md](THIRD_PARTY.md)).
The project has no crates.io dependencies, so no dependency forces a choice.

## Options

| option | what it means | for | against |
|---|---|---|---|
| `MIT OR Apache-2.0` (recommended) | the Rust ecosystem default; users pick either | maximum reuse; Apache-2.0 brings a patent grant and MIT brings simplicity and GPLv2 compatibility | anyone can take it into a closed product |
| MIT | short permissive | simplest to read | no patent grant |
| Apache-2.0 | permissive with patent grant and contribution terms | explicit patent and contribution clauses | incompatible with GPLv2-only code in one binary (irrelevant here, the kernel is a separate component) |
| GPL-2.0-only or GPL-3.0 | copyleft | forces modifications to stay open; GPL-2.0 matches the kernel | blocks use in non-GPL tools; GPL-3.0 does not mix with GPL-2.0-only code |
| AGPL-3.0 | copyleft including network use | covers the agent being run as a service | unusual for a lab tool, deters contributors |
| source-available or no licence (status quo) | stays private | full control | nobody can legally contribute or reuse it |

## Related choices

* **Contributions**: with a permissive licence, "inbound = outbound" (contributors license under the project licence) needs
  no CLA. A copyleft or relicensing plan wants a CLA or DCO sign-off decided now, while there are few contributors.
* **Prior art**: the earlier lab-init and lab-proxy code was copied in and adapted. Those are the operator's own code, so the
  operator may license the result however they like.
* **The demo keys** are public by design and are not a licence matter ([KEYS.md](KEYS.md)).
* **Name**: the public name (`i7lablinux`) is a separate open decision.

## To apply a decision

1. Add `LICENSE` (or `LICENSE-MIT` and `LICENSE-APACHE`).
2. Set `license = "..."` in `[workspace.package]` of `Cargo.toml`, `license.workspace = true` in each crate, drop the "no
   licence yet" comment lines, and remove `publish = false` only if publishing is intended.
3. Update the Licence section of [README.md](../README.md) and the licence line in [PLAN.md](PLAN.md) section 11.
4. Add SPDX headers if wanted. Mention the choice in [CHANGELOG.md](../CHANGELOG.md).
