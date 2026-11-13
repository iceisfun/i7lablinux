# Firmware helpers for i7lablinux scripts (owner: P10). Source after common.sh. Nothing here ships blobs: it selects them from the
# pinned linux-firmware tree in the build host's cache (scripts/fetch-firmware) and stages them zstd-compressed for the initramfs.
# shellcheck shell=bash

FW_VERSION_FILE="$I7_ROOT/configs/firmware/VERSION"
FW_TAG="$(conf_get "$FW_VERSION_FILE" tag)"
FW_TREE="$I7_CACHE/firmware-$FW_TAG/tree"

# fw_manifest TREE > TSV : what linux-firmware's own copy-firmware.sh would install, from WHENCE.
#   "F<TAB>path"                 a firmware file (File:/RawFile:)
#   "L<TAB>path<TAB>target"      a symlink (Link: path -> target), target normalised relative to the tree root
fw_manifest() {
  awk '
    function norm(p,   n,a,i,o,k) { n=split(p,a,"/"); k=0
      for (i=1;i<=n;i++) { if (a[i]=="" || a[i]==".") continue; if (a[i]=="..") { if (k>0) k--; continue } o[++k]=a[i] }
      p=""; for (i=1;i<=k;i++) p=p (i>1?"/":"") o[i]; return p }
    /^(Raw)?File: / { f=$0; sub(/^(Raw)?File: */,"",f); gsub(/^"|"$/,"",f); print "F\t" f; next }
    /^Link: .* -> / { l=$0; sub(/^Link: */,"",l); i=index(l," -> "); p=substr(l,1,i-1); t=substr(l,i+4); gsub(/^"|"$/,"",p); gsub(/^"|"$/,"",t)
      d=p; if (sub(/\/[^\/]*$/,"",d)==0) d=""; print "L\t" p "\t" norm((d==""?"":d "/") t) }
  ' "$1/WHENCE" | LC_ALL=C sort -u
}

# fw_globs FILE : the patterns of a list/exclude file (comments and blanks dropped), one per line
fw_globs() { grep -hvE '^[[:space:]]*(#|$)' "$1" | sed 's/[[:space:]]*$//'; }

# fw_pick VARIANT PATFILE < MANIFEST > PICKED : the selection itself. Patterns are shell-style globs on installed names (* crosses /).
#   lean: entries matching a pattern of the list; full: every entry NOT matching a pattern of the exclude file.
#   "@latest N GLOB" (either file): among the selected entries matching GLOB that end in -<number>.<ext> (or -c<number>, as iwlwifi-sc-*-c108.ucode), keep only the N highest
#   numbers per family (iwlwifi-cc-a0-77.ucode: the kernel asks for the newest API it knows and falls back, older ones are dead weight).
#   A selected link pulls in its target (chains followed). Output: the manifest lines that are kept.
fw_pick() {
  awk -F'\t' -v variant="$1" -v patfile="$2" '
    function rx(g,   o,i,c) { o="^"; for (i=1;i<=length(g);i++) { c=substr(g,i,1)
        if (c=="*") o=o ".*"; else if (c=="?") o=o "."; else if (c ~ /[][(){}.+^$|\\]/) o=o "\\" c; else o=o c } return o "$" }
    function hit(p,   i) { for (i=1;i<=np;i++) if (p ~ re[i]) return 1; return 0 }
    BEGIN { while ((getline g < patfile) > 0) { sub(/[ \t]+$/,"",g); if (g=="" || g ~ /^#/) continue
        if (g ~ /^@latest /) { split(g,q," "); nl_++; keepn[nl_]=q[2]; lre[nl_]=rx(q[3]); continue }
        re[++np]=rx(g) } }
    { kind[NR]=$1; path[NR]=$2; tg[NR]=$3; if ($1=="L") tgt[$2]=$3 }
    END {
      for (i=1;i<=NR;i++) { h=hit(path[i]); if (variant=="full") h=!h; sel[i]=h }
      for (d=1; d<=nl_; d++) {
        delete vs
        for (i=1;i<=NR;i++) if (sel[i] && path[i] ~ lre[d] && match(path[i], /-[a-z]?[0-9]+\.[^.\/]+$/)) {
          base=substr(path[i],1,RSTART-1); ver=substr(path[i],RSTART+1); sub(/\..*$/,"",ver); sub(/^[a-z]/,"",ver); ver+=0
          gf[i]=base; v[i]=ver; if (!((base SUBSEP ver) in vs)) { vs[base SUBSEP ver]=1; vl[base]=vl[base] " " ver } }
        for (i=1;i<=NR;i++) if (i in gf) { n=split(vl[gf[i]],a," "); r=0; for (j=1;j<=n;j++) if (a[j]+0 > v[i]) r++
          if (r >= keepn[d]) sel[i]=0 }
        delete gf; delete v; delete vl
      }
      for (i=1;i<=NR;i++) if (sel[i]) { if (kind[i]=="F") want[path[i]]=1; else lnk[path[i]]=tg[i] }
      do { ch=0
        for (k in lnk) { t=lnk[k]
          if (t in tgt) { if (!(t in lnk)) { lnk[t]=tgt[t]; ch=1 } }
          else if (!(t in want)) { want[t]=1; ch=1 } }
      } while (ch)
      for (k in want) print "F\t" k
      for (k in lnk) print "L\t" k "\t" lnk[k]
    }' | LC_ALL=C sort
}

# fw_select VARIANT TREE OUTDIR : copy the selected firmware (zstd -19 each, symlinks kept) into OUTDIR (which becomes /lib/firmware).
#   lean : only what configs/firmware-lean.list names; full : every WHENCE entry except configs/firmware-full.exclude.
# Prints "files=N links=M bytes=B" on stdout.
fw_select() {
  local variant=$1 tree=$2 out=$3 man picked pf kind p t n nl=0
  man="$(mktemp)"; picked="$(mktemp)"
  fw_manifest "$tree" > "$man"
  if [ "$variant" = lean ]; then pf="$I7_ROOT/configs/firmware-lean.list"; else pf="$I7_ROOT/configs/firmware-full.exclude"; fi
  fw_pick "$variant" "$pf" < "$man" > "$picked"
  mkdir -p "$out"
  # compress in parallel (only files that exist in the tree); the kernel (FW_LOADER_COMPRESS_ZSTD) looks for NAME.zst
  awk -F'\t' '$1=="F"{print $2}' "$picked" | ( cd "$tree" && while IFS= read -r f; do [ -f "$f" ] && printf '%s\n' "$f"; done ) > "$man"
  ( cd "$tree" && xargs -d '\n' -P "$(nproc)" -n 16 sh -c 'o=$0; for f; do mkdir -p "$o/$(dirname "$f")"; zstd -q -19 -f -o "$o/$f.zst" "$f"; done' "$out" < "$man" )
  n=$(wc -l < "$man")
  while IFS=$'\t' read -r kind p t; do
    [ "$kind" = L ] || continue
    [ -f "$out/$t.zst" ] || [ -L "$out/$t.zst" ] || continue
    mkdir -p "$out/$(dirname "$p")"
    ln -sfn "$(realpath -m --relative-to="$out/$(dirname "$p")" "$out/$t.zst")" "$out/$p.zst"; nl=$((nl+1))
  done < "$picked"
  rm -f "$man" "$picked"
  echo "files=$n links=$nl bytes=$(du -sb "$out" | cut -f1)"
}
