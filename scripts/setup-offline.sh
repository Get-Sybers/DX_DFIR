#!/bin/bash
# ==============================================================================
# Set up DX_DFIR on an AIR-GAPPED host from an offline package.
#
# Run this from inside an extracted offline bundle (produced by
# scripts/package-offline.sh). With no network it:
#
#   1. verifies every file against MANIFEST.sha256 (tamper / corruption check)
#   2. unpacks the repository to the target dir (default: ./DX_DFIR), then
#      restores data_store/dependencies from deps.tar — the signature rulesets
#      (YARA/Suricata/Hayabusa), the Volatility symbol cache and EvtxECmd
#   3. loads the container images and runs the hardened-inventory guard
#   4. installs the dxdfir CLI into a venv from the bundled wheels (no PyPI)
#   5. installs the pinned ansible collections from the bundle (no Galaxy)
#   6. prints how to run the pipeline
#
# Nothing here reaches the network. Prerequisites on the offline host: docker,
# python3 (+ venv), tar, sha256sum — all normally present on an analysis box.
#
# Usage:
#   ./setup-offline.sh [--target DIR] [--venv DIR] [--skip-images]
#
#   --target DIR   where to unpack the repo   (default: ./DX_DFIR)
#   --venv DIR     where to create the CLI venv (default: <target>/.venv)
#   --skip-images  don't load images (code/CLI only)
# ==============================================================================

set -o pipefail

BUNDLE="$(dirname "$(readlink -f "$0")")"
TARGET=""
VENV=""
SKIP_IMAGES=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$(realpath -m "$2")"; shift ;;
        --venv) VENV="$(realpath -m "$2")"; shift ;;
        --skip-images) SKIP_IMAGES=1 ;;
        -h|--help) sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "❌ Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

TARGET="${TARGET:-$PWD/DX_DFIR}"
VENV="${VENV:-$TARGET/.venv}"

die() { echo "❌ $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required tool not on PATH: $1"; }

need python3; need tar; need sha256sum
[[ "$SKIP_IMAGES" -eq 0 ]] && need docker

# ---- 1. integrity -----------------------------------------------------------
echo "🔏 Verifying MANIFEST.sha256 ..."
[[ -f "$BUNDLE/MANIFEST.sha256" ]] || die "MANIFEST.sha256 missing — is this a DX_DFIR offline bundle?"
( cd "$BUNDLE" && sha256sum --quiet -c MANIFEST.sha256 ) \
    || die "checksum verification FAILED — the bundle is corrupt or was tampered with. Aborting."
echo "✅ All files verified against the manifest."

# ---- 2. repository ----------------------------------------------------------
echo "📁 Unpacking the repository to $TARGET ..."
mkdir -p "$TARGET"
tar -xf "$BUNDLE/repo.tar" -C "$TARGET" || die "failed to unpack repo.tar"

if [[ -f "$BUNDLE/deps.tar" ]]; then
    echo "🧩 Restoring detection dependencies (signature rules, Hayabusa, symbols, EvtxECmd) ..."
    tar -xf "$BUNDLE/deps.tar" -C "$TARGET/data_store" || die "failed to unpack deps.tar"
    for d in yara-rules suricata-rules hayabusa volatility3-symbols evtxecmd; do
        [[ -d "$TARGET/data_store/dependencies/$d" ]] \
            && echo "   ✅ dependencies/$d"
    done
else
    echo "⚠️  No deps.tar in the bundle — the signature lanes have no rules until you provision data_store/dependencies by hand."
fi

# ---- 3. images + inventory guard --------------------------------------------
DOCKER_CMD=""
if [[ "$SKIP_IMAGES" -eq 0 ]]; then
    if docker info >/dev/null 2>&1; then DOCKER_CMD="docker"
    elif command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then DOCKER_CMD="sudo docker"
    fi
    [[ -n "$DOCKER_CMD" ]] || die "Docker daemon not reachable (start it, or pass --skip-images)."
    if [[ -d "$BUNDLE/images" ]]; then
        echo "🐳 Loading container images ..."
        loaded=0
        for tarfile in "$BUNDLE"/images/*.tar; do
            [[ -e "$tarfile" ]] || continue
            $DOCKER_CMD load -i "$tarfile" >/dev/null \
                && { echo "   ✅ ${tarfile##*/}"; loaded=$((loaded + 1)); } \
                || die "failed to load ${tarfile##*/}"
        done
        echo "✅ Loaded $loaded image tarball(s)."
    else
        echo "ℹ️  No images/ in the bundle (packaged with --no-images); skipping load."
    fi
fi

# ---- 4. the dxdfir CLI, offline ---------------------------------------------
echo "🐍 Installing the dxdfir CLI into $VENV (offline) ..."
python3 -m venv "$VENV" || die "could not create the venv (need python3-venv)."
"$VENV/bin/pip" install --quiet --no-index --find-links "$BUNDLE/wheels" \
    --upgrade pip >/dev/null 2>&1 || true
"$VENV/bin/pip" install --quiet --no-index --find-links "$BUNDLE/wheels" \
    get_sybers_dxdfir || die "offline install of the CLI failed (missing wheels?)."
# The Python console script installs as dxdfir-py (a fallback + the reference the
# Go front-end mirrors).
DXDFIR_PY="$VENV/bin/dxdfir-py"
ln -sf "$DXDFIR_PY" /usr/local/bin/dxdfir-py 2>/dev/null || true
echo "✅ dxdfir-py (Python fallback) installed: $("$DXDFIR_PY" --version 2>/dev/null || echo dxdfir-py)"

# ---- 4b. the Go/termui front-end, offline (from vendored modules) -----------
if command -v go >/dev/null 2>&1 && [[ -f "$BUNDLE/go-vendor.tar" ]]; then
    echo "🐹 Building the dxdfir Go front-end (offline, -mod=vendor) ..."
    tar -xf "$BUNDLE/go-vendor.tar" -C "$TARGET/go" || die "failed to unpack go-vendor.tar"
    ( cd "$TARGET/go" && GOFLAGS= GOTOOLCHAIN=local GOPROXY=off go build -mod=vendor -o dxdfir ./cmd/dxdfir ) \
        || die "offline build of the Go front-end failed."
    if ln -sf "$TARGET/go/dxdfir" /usr/local/bin/dxdfir 2>/dev/null; then
        DXDFIR="/usr/local/bin/dxdfir"
    else
        DXDFIR="$TARGET/go/dxdfir"
        echo "ℹ️  Could not symlink into /usr/local/bin; use $DXDFIR (or add $TARGET/go to PATH)."
    fi
    echo "✅ dxdfir (Go front-end) installed: $("$DXDFIR" --version 2>/dev/null || echo dxdfir)"
else
    echo "ℹ️  No Go toolchain or go-vendor.tar in the bundle — using the Python CLI as 'dxdfir'."
    if ln -sf "$DXDFIR_PY" /usr/local/bin/dxdfir 2>/dev/null; then
        DXDFIR="/usr/local/bin/dxdfir"
    else
        DXDFIR="$DXDFIR_PY"
    fi
fi

# ---- 5. the pinned ansible collections, offline -----------------------------
if [[ -d "$BUNDLE/collections" ]] && ls "$BUNDLE"/collections/*.tar.gz >/dev/null 2>&1; then
    echo "📚 Installing the pinned ansible collections (offline) ..."
    COLL_DEST="$TARGET/ansible/collections/get_sybers.dxdfir/.ansible/collections"
    mkdir -p "$COLL_DEST"
    # `ansible-galaxy collection download` wrote a requirements.yml that names the
    # tarballs by RELATIVE filename, so the install must run FROM that dir to be
    # offline; installing all tarballs together also lets inter-collection deps
    # resolve among them (community.docker needs library_inventory_filtering).
    if ( cd "$BUNDLE/collections" && "$VENV/bin/ansible-galaxy" collection install \
            -r requirements.yml -p "$COLL_DEST" >/dev/null 2>&1 ); then
        echo "✅ Collections installed under $COLL_DEST"
    else
        die "offline collection install failed — check $BUNDLE/collections."
    fi
fi

# ---- 6. verify the hardened inventory + report ------------------------------
if [[ "$SKIP_IMAGES" -eq 0 && -n "$DOCKER_CMD" ]]; then
    echo "🔒 Verifying the hardened image inventory ..."
    if "$DXDFIR" verify-images; then :; else
        die "image inventory verification FAILED — the loaded images are not the expected hardened set."
    fi
fi

echo ""
echo "🎉 DX_DFIR is set up offline."
echo "   Repo:  $TARGET"
echo "   CLI:   $DXDFIR"
echo "   Try:   cd $TARGET && $DXDFIR --help"
echo "          $DXDFIR verify-images        # re-check the image inventory any time"
