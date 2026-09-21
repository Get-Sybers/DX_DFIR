#!/usr/bin/env bash
# Move every tracked pin to its upstream head, together: each sources.yml ref
# (a source block carrying url + a 40-hex ref) and the GoDFIR-toolz submodule
# gitlink. The caller reviews and commits the resulting diff — CI (pin-sync)
# opens it as a PR, where checks/smoke validate the bumped pair.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
sources="$repo/sources.yml"

# sources.yml: every pinned source -> its upstream default-branch head.
while IFS=$'\t' read -r name url; do
  head="$(git ls-remote "$url" HEAD | cut -f1)"
  [ -n "$head" ] || { echo "sync-pins: no HEAD for $name ($url)" >&2; exit 1; }
  awk -v name="$name" -v sha="$head" '
    /^[a-z0-9_-]+:$/ { block = substr($0, 1, length($0) - 1) }
    block == name && $1 == "ref:" { sub(/[0-9a-f]{40}/, sha) }
    { print }
  ' "$sources" > "$sources.tmp" && mv "$sources.tmp" "$sources"
  echo "$name -> $head"
done < <(awk '
  /^[a-z0-9_-]+:$/ { block = substr($0, 1, length($0) - 1) }
  $1 == "url:" { url[block] = $2 }
  $1 == "ref:" && url[block] != "" && $2 ~ /^[0-9a-f]{40}$/ { print block "\t" url[block] }
' "$sources")

# GoDFIR-toolz gitlink -> its upstream default-branch head.
sub="$repo/docker/GoDFIR-toolz"
git -C "$sub" fetch --quiet origin
git -C "$sub" checkout --quiet "$(git -C "$sub" ls-remote origin HEAD | cut -f1)"
echo "godfir-toolz -> $(git -C "$sub" rev-parse HEAD)"
