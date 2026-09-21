#!/usr/bin/env bash
# Move every tracked pin to its upstream head, together: each sources.yml ref
# (a source block carrying url + a 40-hex ref) and the GoDFIR-toolz submodule
# gitlink. The caller reviews and commits the resulting diff.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
sources="$repo/sources.yml"

# Materialize the (source, url) pin list before any rewrite touches the file.
pins=()
while IFS=$'\t' read -r name url; do
  pins+=("$name"$'\t'"$url")
done < <(awk '
  /^[a-z0-9_-]+:$/ { block = substr($0, 1, length($0) - 1) }
  $1 == "url:" { url[block] = $2 }
  $1 == "ref:" && url[block] != "" && $2 ~ /^[0-9a-f]{40}$/ { print block "\t" url[block] }
' "$sources")

# Every pinned source -> its upstream default-branch head.
for pin in "${pins[@]}"; do
  name=${pin%%$'\t'*}
  url=${pin#*$'\t'}
  head="$(git ls-remote "$url" HEAD | cut -f1)"
  [ -n "$head" ] || { echo "sync-pins: no HEAD for $name ($url)" >&2; exit 1; }
  tmp="$(mktemp)"
  awk -v name="$name" -v sha="$head" '
    /^[a-z0-9_-]+:$/ { block = substr($0, 1, length($0) - 1) }
    block == name && $1 == "ref:" { sub(/[0-9a-f]{40}/, sha) }
    { print }
  ' "$sources" > "$tmp" && mv "$tmp" "$sources"
  echo "$name -> $head"
done

# GoDFIR-toolz gitlink -> its upstream default-branch head.
sub="$repo/docker/GoDFIR-toolz"
git -C "$sub" fetch --quiet origin
git -C "$sub" checkout --quiet "$(git -C "$sub" ls-remote origin HEAD | cut -f1)"
echo "godfir-toolz -> $(git -C "$sub" rev-parse HEAD)"
