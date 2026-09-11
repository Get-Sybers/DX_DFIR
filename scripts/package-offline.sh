#!/bin/bash
# ==============================================================================
# Build a self-contained offline package for an air-gapped DX_DFIR analysis host.
#
# Run this on an ONLINE host that can reach Docker Hub, PyPI and Ansible Galaxy.
# It assembles ONE portable bundle containing everything the offline host needs:
#
#   images/       the hardened dxdfir/* tool images (built + docker-saved) plus the
#                 one unbuildable image (the .NET runtime), as tars
#   wheels/       the dxdfir CLI and every Python dependency, as wheels
#                 (pip download — installed offline with --no-index)
#   collections/  the pinned ansible collections (community.docker, ansible.posix)
#   repo.tar      a clean archive of the repository at HEAD (code, playbooks,
#                 roles, docs, the data_store skeleton) — no evidence, no .git
#   deps.tar      data_store/dependencies/ — the signature rulesets (YARA,
#                 Suricata, Hayabusa incl. its binary), the Volatility ISF
#                 symbol cache and the EvtxECmd release: everything the
#                 detection lanes need that git prunes from the skeleton and
#                 that an air-gapped host cannot fetch
#   MANIFEST.sha256   a checksum of every file above
#   setup-offline.sh  a copy, so the bundle installs itself
#
# The result is `dxdfir-offline-<version>-<arch>.tar.gz` (or a directory with
# --no-tar). Carry it to the air-gapped host and run setup-offline.sh.
#
# Usage:
#   scripts/package-offline.sh [--out DIR] [--build] [--no-tar] [--no-images]
#
#   --build      (re)build the dxdfir/* images before saving (else they must exist)
#   --fetch-rules provision the pinned DetectRaptor YARA set first if the rules
#                dir is empty (online-side convenience for a fresh checkout)
#   --no-tar     leave the staged bundle as a directory, don't compress it
#   --no-images  skip the (large) image tarballs — code/wheels/collections only
#   --out DIR    where to write the bundle (default: ./dist)
# ==============================================================================

set -o pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
REPO="$(realpath "$SCRIPT_DIR/..")"
OUT_DIR="$REPO/dist"
DO_BUILD=0
DO_FETCH=0
DO_TAR=1
DO_IMAGES=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out) OUT_DIR="$(realpath -m "$2")"; shift ;;
        --build) DO_BUILD=1 ;;
        --fetch-rules) DO_FETCH=1 ;;
        --no-tar) DO_TAR=0 ;;
        --no-images) DO_IMAGES=0 ;;
        -h|--help) sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "❌ Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

die() { echo "❌ $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required tool not on PATH: $1"; }

need python3; need tar; need sha256sum; need git
[[ "$DO_IMAGES" -eq 1 ]] && { need docker; need ansible-playbook; }

# Resolve a python that HAS pip (system python often ships without it).
PIP=""
if python3 -m pip --version >/dev/null 2>&1; then PIP="python3 -m pip"
elif command -v pip3 >/dev/null 2>&1; then PIP="pip3"
else die "no pip available (need python3 -m pip or pip3 to download the CLI wheels). Try: python3 -m ensurepip, or run inside a venv."; fi

VERSION="$(python3 -c "import tomllib,sys; print(tomllib.load(open('$REPO/python/pyproject.toml','rb'))['project']['version'])" 2>/dev/null || echo "0.0.0")"
ARCH="$(uname -m)"
NAME="dxdfir-offline-${VERSION}-${ARCH}"
STAGE="$OUT_DIR/$NAME"

echo "📦 Packaging DX_DFIR $VERSION ($ARCH) for offline install"
echo "   staging: $STAGE"
rm -rf "$STAGE"; mkdir -p "$STAGE"/{images,wheels,collections}

# ---- 1. the repository (clean archive at HEAD: no evidence, no .git) ---------
echo "📁 Archiving the repository at HEAD ..."
git -C "$REPO" archive --format=tar HEAD -o "$STAGE/repo.tar" \
    || die "git archive failed (commit your work, or run from a clean checkout)."

# ---- 1b. the Go front-end modules (vendored for a reproducible offline build) -
# git archive only carries tracked files, so go/vendor (gitignored) is shipped
# separately. The offline installer extracts it and builds with -mod=vendor.
if command -v go >/dev/null 2>&1; then
    echo "🐹 Vendoring the Go front-end modules ..."
    ( cd "$REPO/go" && GOFLAGS= go mod vendor ) || die "go mod vendor failed."
    tar -C "$REPO/go" -cf "$STAGE/go-vendor.tar" vendor \
        || die "failed to package go/vendor."
    ( cd "$REPO/go" && rm -rf vendor )   # keep the working tree clean
    echo "   $(du -sh "$STAGE/go-vendor.tar" | cut -f1) of Go modules vendored."
else
    echo "⚠️  go not found; skipping Go module vendoring (the offline host will need"
    echo "    the Go toolchain + network for the modules, or a prebuilt dxdfir binary)."
fi

# ---- 2. the dxdfir CLI + all Python deps as wheels ---------------------------
echo "🐍 Building the dxdfir CLI and downloading Python dependencies as wheels ..."
# `pip wheel` BUILDS the local project into a wheel AND resolves every
# dependency into wheels — the project itself is what `pip download` omits.
# --constraint pins them to python/constraints.txt, the SAME lock
# setup-environment.sh uses, so the offline bundle carries the exact tested versions.
$PIP wheel --wheel-dir "$STAGE/wheels" --constraint "$REPO/python/constraints.txt" "$REPO/python" >/dev/null \
    || die "pip wheel of the CLI failed."
# bootstrap wheels so the offline venv can upgrade its own pip
$PIP download --dest "$STAGE/wheels" pip setuptools wheel >/dev/null 2>&1 || true

# ---- 2b. the detection dependencies (signature rules, symbols, tools) --------
DEPS="$REPO/data_store/dependencies"
if [[ "$DO_FETCH" -eq 1 ]]; then
    echo "🧲 Provisioning the pinned DetectRaptor YARA set (--fetch-rules) ..."
    PYTHONPATH="$REPO/python" python3 -m get_sybers_dxdfir.signatures \
        --output-dir "$(mktemp -d)" --repo-root "$REPO" --only yara \
        --yara-sources files --fetch >/dev/null 2>&1 || true
fi
if [[ -d "$DEPS" ]] && [[ -n "$(find "$DEPS" -type f -print -quit 2>/dev/null)" ]]; then
    echo "🧩 Archiving data_store/dependencies (signature rules, Hayabusa, symbols, EvtxECmd) ..."
    tar -C "$REPO/data_store" -cf "$STAGE/deps.tar" dependencies \
        || die "failed to archive data_store/dependencies."
    echo "   $(du -sh "$STAGE/deps.tar" | cut -f1) of detection dependencies packaged."
else
    echo "⚠️  data_store/dependencies is empty — the bundle will carry NO signature"
    echo "    rules / Hayabusa / symbols. Provision them first (see docs/Signature-Rules.md)"
    echo "    or pass --fetch-rules for the pinned DetectRaptor set."
fi

# ---- 3. the pinned ansible collections ---------------------------------------
echo "📚 Downloading the pinned ansible collections ..."
REQS="$REPO/ansible/collections/get_sybers.dxdfir/requirements.yml"
if command -v ansible-galaxy >/dev/null 2>&1; then
    ansible-galaxy collection download -r "$REQS" -p "$STAGE/collections" >/dev/null \
        || die "ansible-galaxy collection download failed."
else
    echo "⚠️  ansible-galaxy not found; skipping collection download (the offline host will need them another way)."
fi

# ---- 4. the images ----------------------------------------------------------
if [[ "$DO_IMAGES" -eq 1 ]]; then
    echo "🐳 Saving the container images ..."
    build_arg=(); [[ "$DO_BUILD" -eq 1 ]] && build_arg=(--build)
    DXDFIR_IMAGE_DIR="$STAGE/images" "$SCRIPT_DIR/save-docker-images.sh" "${build_arg[@]}" \
        || die "image save failed."
else
    echo "⏭️  Skipping images (--no-images)."
    rmdir "$STAGE/images" 2>/dev/null || true
fi

# ---- 5. self-contained installer + manifest ---------------------------------
cp "$SCRIPT_DIR/setup-offline.sh" "$STAGE/setup-offline.sh"
chmod +x "$STAGE/setup-offline.sh"

echo "🔏 Writing MANIFEST.sha256 ..."
( cd "$STAGE" && find . -type f ! -name MANIFEST.sha256 -print0 \
    | sort -z | xargs -0 sha256sum > MANIFEST.sha256 )

# ---- 6. compress ------------------------------------------------------------
if [[ "$DO_TAR" -eq 1 ]]; then
    echo "🗜️  Compressing the bundle ..."
    ( cd "$OUT_DIR" && tar -czf "$NAME.tar.gz" "$NAME" ) || die "tar failed."
    SIZE="$(du -sh "$OUT_DIR/$NAME.tar.gz" | cut -f1)"
    rm -rf "$STAGE"
    echo ""
    echo "🎉 Offline package: $OUT_DIR/$NAME.tar.gz  ($SIZE)"
    echo "   On the air-gapped host:"
    echo "     tar -xzf $NAME.tar.gz && cd $NAME && ./setup-offline.sh"
else
    SIZE="$(du -sh "$STAGE" | cut -f1)"
    echo ""
    echo "🎉 Offline bundle (uncompressed): $STAGE  ($SIZE)"
    echo "   On the air-gapped host: cd $STAGE && ./setup-offline.sh"
fi
