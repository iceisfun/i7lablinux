# Shared helpers for i7lablinux scripts (owner: P10). Source with: . "$(dirname "$0")/lib/common.sh"
# shellcheck shell=bash
# No busybox anywhere: every tool used here is a normal GNU/util-linux/grub/mtools package on the BUILD host.
set -euo pipefail
umask 077
export PATH="$PATH:/usr/sbin:/sbin:$HOME/.cargo/bin"
I7_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
I7_OUT="${I7_OUT:-$I7_ROOT/out}"
# Big caches (kernel tarball, finished kernels) live outside the tree so `scripts/remote` rsyncs stay small.
# /tmp is the default (a tmpfs /tmp on a big build host is fast and roomy).
I7_CACHE="${I7_CACHE:-/tmp/i7ll-cache-$(id -un)}"
# Build host: $I7LL_HOST, else the first line of ~/.config/i7lablinux/build-host (kept out of the repo on purpose:
# no host names in tracked files). Only needed when a heavy step has to run elsewhere.
I7_HOST="${I7LL_HOST:-$(head -n1 "$HOME/.config/i7lablinux/build-host" 2>/dev/null || true)}"
need_build_host() { [ -n "$I7_HOST" ] || die "no build host: set I7LL_HOST=user@host, or put the host in ~/.config/i7lablinux/build-host (or build locally with --build-host local / I7_BUILD_HOST=local)"; }
I7_ME="$(basename "$0")"

die() { echo "$I7_ME: $*" >&2; exit 1; }
warn() { echo "$I7_ME: WARNING: $*" >&2; }
info() { echo "$I7_ME: $*" >&2; }
not_implemented() { echo "$I7_ME: not implemented yet (owner: P10, see docs/PLAN.md section 12)" >&2; exit 2; }

need() { # need TOOL... : fail once, listing every missing tool with the Ubuntu package hint
  local t miss=()
  for t in "$@"; do command -v "$t" >/dev/null 2>&1 || miss+=("$t"); done
  [ ${#miss[@]} -eq 0 ] && return 0
  echo "$I7_ME: missing tools: ${miss[*]}" >&2
  echo "  Ubuntu: sudo apt-get install -y build-essential flex bison bc cpio xz-utils zstd libelf-dev libssl-dev" >&2
  echo "          xorriso dosfstools mtools gdisk parted rsync grub-pc-bin grub-efi-amd64-bin grub-common kmod curl" >&2
  echo "          (docs/BUILD.md lists what each script needs)" >&2
  exit 1
}

sha256_file() { sha256sum "$1" | cut -d' ' -f1; }

# conf_get FILE KEY : value of a `key=value` line (comments and blanks ignored); empty if absent.
conf_get() { sed -n "s/^$2[[:space:]]*=[[:space:]]*//p" "$1" | head -n1; }

# ---- kernel flavour and image variant (operator decision 2026-11-13) --------------------------------------------------------
# I7_KERNEL: stable (default: newest stable release) | lts (fallback: pinned longterm). I7_VARIANT: lean (default, < 256 MiB, small
# firmware subset, JetKVM-friendly) | full (every driver family + linux-firmware, for a real USB stick). Scripts take --kernel /
# --variant and call i7_select_*; remote runs forward both variables.
I7_KERNEL="${I7_KERNEL:-stable}"
I7_VARIANT="${I7_VARIANT:-lean}"
i7_select_kernel() { # NAME : stable|lts, re-reads configs/kernel/VERSION.<NAME>
  case "$1" in stable|lts) ;; *) die "--kernel takes stable or lts (got '$1')";; esac
  I7_KERNEL="$1"; I7_VERSION_FILE="$I7_ROOT/configs/kernel/VERSION.$I7_KERNEL"
  [ -s "$I7_VERSION_FILE" ] || die "$I7_VERSION_FILE missing"
  I7_KVER="$(conf_get "$I7_VERSION_FILE" version)"
  SOURCE_DATE_EPOCH="${I7_EPOCH_OVERRIDE:-$(conf_get "$I7_VERSION_FILE" epoch)}"; SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1767225600}"
  export I7_KERNEL SOURCE_DATE_EPOCH
}
i7_select_variant() { case "$1" in lean|full) I7_VARIANT="$1"; export I7_VARIANT;; *) die "--variant takes lean or full (got '$1')";; esac; }
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-}"; I7_EPOCH_OVERRIDE="$SOURCE_DATE_EPOCH"
i7_select_kernel "$I7_KERNEL"; i7_select_variant "$I7_VARIANT"

i7_sha7() { git -C "$I7_ROOT" rev-parse --short=7 HEAD 2>/dev/null || echo nogit; }
# used in file names: i7lablinux-<kver>-<sha7>.img (lean) and i7lablinux-<kver>-<sha7>-full.img
i7_image_id() { echo "${I7_KVER}-$(i7_sha7)$([ "$I7_VARIANT" = full ] && echo -full || true)"; }
# i7_check_kernel_matches DIR : the kernel in DIR (out/kernel) must be the one --kernel/I7_KERNEL selects, or the image id lies.
i7_check_kernel_matches() {
  local have; have="$(sed -n 's/^kernel=//p' "$1/BUILD-INFO" 2>/dev/null)"
  [ "$have" = "$I7_KVER" ] || die "$1 holds kernel '${have:-?}' but --kernel $I7_KERNEL selects $I7_KVER: run scripts/build-kernel --kernel $I7_KERNEL"
}

# ---- key material helpers (formats: docs/PLAN.md section 5, crates/labproto/src/keys.rs) --------------------------------
is_hex64() { [[ "$1" =~ ^[0-9a-f]{64}$ ]]; }
hex2bin() { # hex string on $1 -> raw bytes on stdout (pure bash + printf, NUL safe)
  [[ "$1" =~ ^([0-9a-f][0-9a-f])*$ ]] || die "hex2bin: bad hex"
  # shellcheck disable=SC2059
  printf "$(printf '%s' "$1" | sed 's/../\\x&/g')"
}
# Key fingerprint = first 4 bytes of SHA256("i7c-keyid" | K), hex (labproto Key::fingerprint).
key_fp() { { printf 'i7c-keyid'; hex2bin "$1"; } | sha256sum | cut -c1-8; }
# key_line_hex FILE ROLE : print the 64-hex secret of an `i7k1:<role>:<hex>` key file, or fail.
key_line_hex() {
  local line prefix role hex
  line="$(tr -d ' \t\r\n' < "$1")" || return 1
  IFS=: read -r prefix role hex <<<"$line"
  [ "$prefix" = i7k1 ] && [ "$role" = "$2" ] && is_hex64 "$hex" || return 1
  printf '%s' "$hex"
}
# make_throwaway_keys DIR : a fresh RANDOM key set for one test run (scripts/gen-keys --out DIR --throwaway). Never touches
# ./keys or ~/.config/i7labctl. DIR must not exist yet.
make_throwaway_keys() { "$I7_ROOT/scripts/gen-keys" --out "$1" --throwaway --quiet; }

# ---- newc cpio helpers (root-less device nodes from the prior art, kept here so every script can test them) --------
# Character device without root: a newc header we write ourselves. A second archive appended to the first is
# unpacked in order by the kernel, so these nodes can follow the `cpio -o` archive.
cpio_node() { # name mode(octal incl. S_IFCHR) major minor ino
  local name=$1 nlen=$(( ${#1} + 1 ))
  printf '070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X' "$5" "$((8#$2))" 0 0 1 "$SOURCE_DATE_EPOCH" 0 0 0 "$3" "$4" "$nlen" 0
  printf '%s\0' "$name"
  head -c $(( (4 - (110 + nlen) % 4) % 4 )) /dev/zero
}
cpio_trailer() {
  printf '070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X' 0 0 0 0 1 0 0 0 0 0 0 11 0
  printf 'TRAILER!!!\0'
  head -c $(( (4 - (110 + 11) % 4) % 4 )) /dev/zero
}
# newc_dir DIR > archive : deterministic archive of DIR's content (sorted, root:root, fixed mtime).
newc_dir() {
  ( cd "$1" && find . -mindepth 1 -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} + \
      && find . -mindepth 1 | LC_ALL=C sort | sed 's|^\./||' | cpio -o -H newc --quiet --owner 0:0 --reproducible )
}

# make_keys_cpio KEYDIR OUT : the key overlay /i7lab/keys.cpio (PLAN C19). KEYDIR holds admin.key ro.key [KEYSET-ID].
# With KEYDIR = "" it writes the empty placeholder archive (just a trailer) used by the keyless image.
make_keys_cpio() {
  local kdir=$1 out=$2 t
  if [ -z "$kdir" ]; then cpio_trailer > "$out"; return 0; fi
  [ -s "$kdir/admin.key" ] && [ -s "$kdir/ro.key" ] || die "$kdir needs admin.key and ro.key (run scripts/gen-keys)"
  key_line_hex "$kdir/admin.key" admin >/dev/null || die "$kdir/admin.key is not an i7k1:admin:<64 hex> key"
  key_line_hex "$kdir/ro.key" ro >/dev/null || die "$kdir/ro.key is not an i7k1:ro:<64 hex> key"
  t="$(mktemp -d)"
  mkdir -p "$t/etc/i7lab/keys"; chmod 755 "$t/etc" "$t/etc/i7lab"; chmod 700 "$t/etc/i7lab/keys"
  install -m 0600 "$kdir/admin.key" "$kdir/ro.key" "$t/etc/i7lab/keys/"
  [ -s "$kdir/KEYSET-ID" ] && install -m 0600 "$kdir/KEYSET-ID" "$t/etc/i7lab/keys/KEYSET-ID"
  newc_dir "$t" > "$out"
  rm -rf "$t"
}

# ---- build host selection ----------------------------------------------------------------------------------------------
# Heavy steps (kernel, cargo, QEMU) run on the build host. When a script is started on a small machine it
# re-runs itself there through scripts/remote and fetches out/<sub>. Inside such a run I7_ON_BUILD_HOST=1 is set.
on_build_host() { [ "${I7_ON_BUILD_HOST:-0}" = 1 ] || [ "$(nproc)" -ge 64 ] || [ "${I7_BUILD_HOST:-}" = local ]; }
# remote_run LABEL CMD... : run CMD in the synced tree on the build host
remote_run() {
  local label=$1; shift
  need_build_host
  "$I7_ROOT/scripts/remote" -l "$label" -H "$I7_HOST" -- env I7_ON_BUILD_HOST=1 "I7_KERNEL=$I7_KERNEL" "I7_VARIANT=$I7_VARIANT" "$@"
}
# remote_fetch LABEL SUBDIR : copy <build host tree>/out/SUBDIR back to $I7_OUT/SUBDIR (a file or a directory)
remote_fetch() {
  local label=$1 sub=$2
  need_build_host
  mkdir -p "$I7_OUT/$(dirname "$sub")"
  rsync -a --delete "$I7_HOST:/tmp/i7ll-$label/out/$sub" "$I7_OUT/$(dirname "$sub")/"
}
