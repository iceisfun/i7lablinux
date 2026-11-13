# e2e tests (owner: P11)

Driven by `scripts/qemu-test` on the build host; plan and asserts in docs/PLAN.md section 14.

`scripts/e2e` (integrator, X1) boots the built image in QEMU (BIOS and UEFI) and checks beacon, L2 commands without an IP,
HTTP, the block write gate, exec and the TUI; see docs/E2E-RESULTS.md for a recorded run. `tuicap.py` drives the serial
console (needs `pyte`) and prints the screen after each step.
