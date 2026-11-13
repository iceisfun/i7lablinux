# Common targets. Heavy work (kernel, image, QEMU) runs on the build host via scripts/; plain cargo runs where you are.
# On a small machine use `make remote-test` instead of `make test`.
SHELL := /bin/bash
MUSL  := x86_64-unknown-linux-musl
LABEL ?= $(shell whoami)

.PHONY: help build test fmt fmt-check clippy check musl shellcheck no-busybox docs-check keys ctl image usb e2e qemu-test release remote-test clean

help:
	@echo "build         cargo build --workspace"
	@echo "test          cargo test --workspace"
	@echo "check         fmt-check clippy test shellcheck no-busybox docs-check (what CI runs)"
	@echo "musl          release build of the image binaries ($(MUSL))"
	@echo "keys          scripts/gen-keys (once; keys stay out of git)"
	@echo "ctl           install i7labctl to ~/bin"
	@echo "image         keyless image + ISO on the build host (out/image)"
	@echo "usb DEV=...   build and write a stick: make usb DEV=/dev/sdX SERIAL=<serial>"
	@echo "e2e           QEMU end-to-end run (on the build host)"
	@echo "qemu-test     QEMU boot smoke test (on the build host)"
	@echo "release       keyless release bundle"
	@echo "remote-test   cargo test --workspace on the build host (LABEL=$(LABEL))"

build:
	cargo build --workspace --all-targets

test:
	cargo test --workspace

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

musl:
	cargo build --release --locked --target $(MUSL) -p i7lab-init -p i7labd -p i7labsh

shellcheck:
	find scripts -type f -exec grep -lE "^#!.*(bash|sh)" {} + | xargs shellcheck -x

no-busybox:
	scripts/check-no-busybox --repo

docs-check:
	scripts/check-doc-links

check: fmt-check clippy test shellcheck no-busybox docs-check

keys:
	scripts/gen-keys

ctl:
	scripts/install-ctl

image:
	scripts/build-image --full

usb:
	@test -n "$(DEV)" || { echo "usage: make usb DEV=/dev/sdX SERIAL=<serial>"; exit 2; }
	scripts/build-usb-drive $(DEV) $(if $(SERIAL),--serial $(SERIAL))

e2e:
	scripts/e2e

qemu-test:
	scripts/qemu-test --both

release:
	scripts/make-release

remote-test:
	scripts/remote -l $(LABEL) -- cargo test --workspace

clean:
	cargo clean
