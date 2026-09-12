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
#   3. unpacks the external Byakugan engine (byakugan.tar — the CAR lane) next
#      to the repo ($BYAKUGAN_ROOT, else <target>/../byakugan: where the CAR
#      lane resolves it) and the piiat-mem tree (piiat-mem.tar — the volatility
#      lane) into <target>/third_party/. Bundles from before these tarballs
#      existed install with a warning: those two lanes are then unavailable
#      offline until provisioned by hand, everything else still works
#   4. loads the container images and runs the hardened-inventory guard
#   5. installs the get_sybers_dxdfir processors + ansible into a venv from the
#      bundled wheels (no PyPI)
#   6. installs the pinned ansible collections from the bundle (no Galaxy)
#   7. prints how to run the pipeline
#
# Nothing here reaches the network. Prerequisites on the offline host: docker,
# python3 (+ venv), tar, sha256sum — all normally present on an analysis box.
#
# Usage:
#   ./setup-offline.sh [--target DIR] [--venv DIR] [--skip-images]
#
#   --target DIR   where to unpack the repo   (default: ./DX_DFIR)
#   --venv DIR     where to create the venv (default: <target>/.venv)
#   --skip-images  don't load images (code only)
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
        -h|--help) sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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

# ---- 2b. the external Byakugan engine (the CAR lane) ------------------------
# repo.tar carries NO submodule/engine content (git archive drops gitlinks), so
# the engine ships as its own tarball. It unpacks to where the CAR lane
# (get_sybers_dxdfir.mitrecar) resolves it: $BYAKUGAN_ROOT when set, else the
# `byakugan` directory NEXT TO the repo — a sibling, deliberately outside
# $TARGET. If you set $BYAKUGAN_ROOT here, keep it exported for every dxdfir
# run too, or the runtime falls back to the sibling default and misses it.
# An older bundle without the tarball is a warning, not a death: the rest of
# the bundle still works, only build-car / verify-car are unavailable offline.
BYAKUGAN_DEST="${BYAKUGAN_ROOT:-$(dirname "$TARGET")/byakugan}"
if [[ -f "$BUNDLE/byakugan.tar" ]]; then
    echo "🔭 Unpacking the Byakugan engine to $BYAKUGAN_DEST ..."
    mkdir -p "$BYAKUGAN_DEST" || die "could not create $BYAKUGAN_DEST"
    tar -xf "$BUNDLE/byakugan.tar" -C "$BYAKUGAN_DEST" || die "failed to unpack byakugan.tar"
    echo "✅ Byakugan engine at $BYAKUGAN_DEST (pinned commit recorded in $TARGET/byakugan.ref)"
else
    echo "⚠️  No byakugan.tar in the bundle (packaged before the engine shipped) —"
    echo "    the CAR lane (build-car / verify-car) is unavailable offline until a"
    echo "    recursive engine checkout is provisioned at $BYAKUGAN_DEST by hand"
    echo "    (a bundle this old predates byakugan.ref; take the pinned commit from"
    echo "    a current DX_DFIR checkout's byakugan.ref, or use the engine repo:"
    echo "    https://github.com/Get-Sybers/byakugan)."
fi

# ---- 2c. the vendored piiat-mem tree (the volatility lane) ------------------
# Same gitlink drop: third_party/piiat-mem never reached older bundles either.
# The tarball is rooted `piiat-mem`, so it lands as $TARGET/third_party/piiat-mem
# — exactly where the volatility lane resolves it relative to the repo.
if [[ -f "$BUNDLE/piiat-mem.tar" ]]; then
    echo "🧠 Unpacking third_party/piiat-mem ..."
    mkdir -p "$TARGET/third_party"
    tar -xf "$BUNDLE/piiat-mem.tar" -C "$TARGET/third_party" || die "failed to unpack piiat-mem.tar"
else
    echo "⚠️  No piiat-mem.tar in the bundle (packaged before it shipped) — the"
    echo "    volatility lane is unavailable offline until third_party/piiat-mem"
    echo "    is provisioned by hand."
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

# ---- 4. the get_sybers_dxdfir package (+ ansible), offline ------------------
echo "🐍 Installing the get_sybers_dxdfir package into $VENV (offline) ..."
python3 -m venv "$VENV" || die "could not create the venv (need python3-venv)."
"$VENV/bin/pip" install --quiet --no-index --find-links "$BUNDLE/wheels" \
    --upgrade pip >/dev/null 2>&1 || true
# The package declares ansible-core, so this one install also delivers
# ansible-playbook into the venv. The Go front-end resolves it next to the
# python its DXDFIR_PYTHON names (else PATH) — the verify step below sets
# DXDFIR_PYTHON to the venv's python so the resolution lands here.
"$VENV/bin/pip" install --quiet --no-index --find-links "$BUNDLE/wheels" \
    get_sybers_dxdfir || die "offline install of the package failed (missing wheels?)."
# Expose the venv's ansible tools on PATH (as setup-environment.sh does) so a
# later `dxdfir` run — and a human — resolves ansible-playbook. Best-effort:
# the verify step below also pins the resolution via DXDFIR_PYTHON.
for _ans in ansible ansible-playbook ansible-galaxy; do
    [[ -x "$VENV/bin/$_ans" ]] && ln -sf "$VENV/bin/$_ans" "/usr/local/bin/$_ans" 2>/dev/null
done
echo "✅ get_sybers_dxdfir (+ ansible) installed into $VENV"

# ---- 4b. the Go/termui front-end, offline (from vendored modules) -----------
# The build pins GOTOOLCHAIN=local GOPROXY=off, so the host's toolchain must
# satisfy go.mod's floor (Go >= 1.24) by itself — an older Go (e.g. the 1.22.x
# an earlier setup-environment.sh installed) cannot build and, air-gapped,
# cannot upgrade; it falls through to the no-front-end path instead of dying.
_go_ok=0
if command -v go >/dev/null 2>&1; then
    _gominor="$(go version 2>/dev/null | grep -oE 'go1\.[0-9]+' | head -1 | cut -d. -f2)"
    [[ "$_gominor" =~ ^[0-9]+$ ]] && (( _gominor >= 24 )) && _go_ok=1
fi
if (( _go_ok )) && [[ -f "$BUNDLE/go-vendor.tar" ]]; then
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
    # Best-effort man page, as setup-environment.sh installs online.
    install -Dm644 "$TARGET/go/man/dxdfir.1" /usr/local/share/man/man1/dxdfir.1 2>/dev/null || true
    echo "✅ dxdfir (Go front-end) installed: $("$DXDFIR" --version 2>/dev/null || echo dxdfir)"
else
    # There is no Python fallback front-end any more (the Typer CLI is retired):
    # without a Go >= 1.24 toolchain + vendored modules, no `dxdfir` binary can
    # be built offline. The pipeline is still fully drivable — the collection
    # playbooks run directly with the venv's ansible-playbook (exactly what
    # dxdfir shells out to), and the verify step below does just that.
    echo "ℹ️  No Go >= 1.24 toolchain or no go-vendor.tar in the bundle — no dxdfir front-end installed."
    echo "    Drive the collection playbooks directly with the venv's ansible-playbook, e.g.:"
    echo "      cd $TARGET && ANSIBLE_ROLES_PATH=$TARGET/ansible/collections/get_sybers.dxdfir/roles \\"
    echo "        $VENV/bin/ansible-playbook -i localhost, -c local ansible/collections/get_sybers.dxdfir/playbooks/dxdfir-process-zeek.yml"
    DXDFIR=""
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
    if [[ -n "$DXDFIR" ]]; then
        # DXDFIR_PYTHON steers the front-end's ansible-playbook resolution to
        # the venv (it looks next to that python, then PATH — the bare host has
        # neither the venv on PATH nor a system ansible).
        if DXDFIR_PYTHON="$VENV/bin/python3" "$DXDFIR" verify-images; then :; else
            die "image inventory verification FAILED — the loaded images are not the expected hardened set."
        fi
    else
        # No front-end: run the same audit play the `dxdfir verify-images` verb
        # fronts, directly with the venv's ansible-playbook.
        if ( cd "$TARGET" && ANSIBLE_ROLES_PATH="$TARGET/ansible/collections/get_sybers.dxdfir/roles" \
                "$VENV/bin/ansible-playbook" -i localhost, -c local \
                "$TARGET/ansible/collections/get_sybers.dxdfir/playbooks/dxdfir-verify-images.yml" ); then :; else
            die "image inventory verification FAILED — the loaded images are not the expected hardened set."
        fi
    fi
fi

echo ""
echo "🎉 DX_DFIR is set up offline."
echo "   Repo:  $TARGET"
if [[ -n "$DXDFIR" ]]; then
    echo "   CLI:   $DXDFIR"
    echo "   Try:   cd $TARGET && $DXDFIR --help"
    echo "          $DXDFIR verify-images        # re-check the image inventory any time"
else
    echo "   Front-end: none (no Go toolchain) — drive the playbooks with:"
    echo "          $VENV/bin/ansible-playbook -i localhost, -c local ansible/collections/get_sybers.dxdfir/playbooks/<play>.yml"
fi
