#!/bin/bash
# ==============================================================================
# Save / load the DX_DFIR analysis images as tarballs for offline hosts.
#
# The runtime tool images (dxdfir/*) are BUILT in-repo
# (`ansible-playbook playbooks/dxdfir-build-images.yml`), not pulled — so this
# script `docker save`s the local builds. Only the one image that cannot be
# built from source is pulled first: the stock .NET runtime for evtxecmd's
# operator-supplied mode. (The Elastic-native analysis backend, docker/elastic,
# is compose-managed — its images are not part of this set.)
#
# This is the image half of the offline lifecycle. For a complete portable
# bundle (images + the dxdfir CLI wheels + the ansible collections + the repo),
# use scripts/package-offline.sh, which calls this script.
#
# Usage:
#   scripts/save-docker-images.sh              save every image to a tarball
#   scripts/save-docker-images.sh --build      build the dxdfir/* images first, then save
#   scripts/save-docker-images.sh --load       load every tarball in the image dir
#   scripts/save-docker-images.sh --verify     load, then assert the hardened inventory
#   scripts/save-docker-images.sh --list       show the images this manages
#   scripts/save-docker-images.sh --help
#
# The image directory defaults to data_store/docker_images/ and is overridable
# with $DXDFIR_IMAGE_DIR (the offline packager points it at the bundle staging).
# ==============================================================================

set -o pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
REPO_ROOT_DIR="$(realpath "$SCRIPT_DIR/..")"
DOCKER_TAR_DIR="${DXDFIR_IMAGE_DIR:-$REPO_ROOT_DIR/data_store/docker_images}"

# Runtime tool images — BUILT in-repo (or from the EZTools-Docker submodule),
# never pulled. Keep in sync with dxdfir_images_set (the image-build role).
BUILT_IMAGES=(
    "get-sybers/yara:latest"
    "get-sybers/suricata:latest"
    "get-sybers/zeek:latest"
    "get-sybers/volatility:latest"
    "get-sybers/plaso:latest"
    "get-sybers/evtxecmd:latest"
    # Eric Zimmerman tool family (EZTools-Docker submodule, eztool/Dockerfile).
    "get-sybers/recmd:latest"
    "get-sybers/mftecmd:latest"
    "get-sybers/amcacheparser:latest"
    "get-sybers/appcompatcacheparser:latest"
    "get-sybers/lecmd:latest"
    "get-sybers/jlecmd:latest"
    "get-sybers/sbecmd:latest"
    "get-sybers/sqlecmd:latest"
    "get-sybers/rbcmd:latest"
    "get-sybers/wxtcmd:latest"
    # Linux-native Go substitutes for the Windows-bound EZ tools.
    "get-sybers/prefetch:latest"
    "get-sybers/esedump:latest"
)
# Unbuildable images — pulled from a registry (online side only).
PULL_IMAGES=(
    "mcr.microsoft.com/dotnet/runtime:9.0"
)
ALL_IMAGES=("${BUILT_IMAGES[@]}" "${PULL_IMAGES[@]}")

MODE="save"
BUILD_FIRST=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build) BUILD_FIRST=1 ;;
        --load) MODE="load" ;;
        --verify) MODE="verify" ;;
        --list) MODE="list" ;;
        -h|--help)
            sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "❌ Unknown option: $1" >&2
            echo "   Usage: $0 [--build] [--load] [--verify] [--list] [--help]" >&2
            exit 1
            ;;
    esac
    shift
done

die() { echo "❌ $*" >&2; exit 1; }

if [[ "$MODE" == "list" ]]; then
    echo "Built in-repo (docker save):"
    printf '   • %s\n' "${BUILT_IMAGES[@]}"
    echo "Pulled (unbuildable):"
    printf '   • %s\n' "${PULL_IMAGES[@]}"
    echo "Image directory: $DOCKER_TAR_DIR"
    exit 0
fi

################################################################################
# Resolve how to talk to the daemon: prefer the unprivileged socket, fall back
# to sudo, say plainly when neither answers.
DOCKER_CMD=""
if docker info >/dev/null 2>&1; then
    DOCKER_CMD="docker"
elif command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
    DOCKER_CMD="sudo docker"
    echo "ℹ️  Talking to the Docker daemon via sudo (group membership needs a new login session)."
fi
[[ -n "$DOCKER_CMD" ]] || die "The Docker daemon is not reachable. Start it with: sudo systemctl start docker"

image_to_filename() { echo "$1" | tr '/' '_' | tr ':' '_'; }

# The hardened-inventory guard, used by --verify after a load.
verify_inventory() {
    local py="$REPO_ROOT_DIR/python"
    if PYTHONPATH="$py" python3 -c "import get_sybers_dxdfir.images" 2>/dev/null; then
        echo "🔒 Verifying the hardened image inventory..."
        PYTHONPATH="$py" python3 -m get_sybers_dxdfir.images --audit >/dev/null \
            && echo "✅ Inventory clean — all hardened tool images present, nothing unexpected." \
            || die "Image inventory verification FAILED (see: python3 -m get_sybers_dxdfir.images --audit)."
    else
        echo "ℹ️  get_sybers_dxdfir not importable here; skipping the inventory guard (run 'dxdfir verify-images' after installing the CLI)."
    fi
}

################################################################################
if [[ "$MODE" == "load" || "$MODE" == "verify" ]]; then
    shopt -s nullglob
    TARBALLS=("$DOCKER_TAR_DIR"/*.tar)
    shopt -u nullglob
    [[ ${#TARBALLS[@]} -gt 0 ]] || die "No tarballs found in $DOCKER_TAR_DIR"

    echo "📦 Loading Docker images from $DOCKER_TAR_DIR:"
    failed=0
    for tarfile in "${TARBALLS[@]}"; do
        echo "📦 Loading ${tarfile##*/}..."
        if $DOCKER_CMD load -i "$tarfile"; then
            echo "✅ Loaded ${tarfile##*/}"
        else
            echo "❌ Error loading ${tarfile##*/}"
            failed=$((failed + 1))
        fi
    done
    [[ $failed -eq 0 ]] || die "$failed tarball(s) failed to load."
    echo "✨ Finished loading Docker images"
    [[ "$MODE" == "verify" ]] && verify_inventory
    exit 0
fi

################################################################################
# MODE=save.
if [[ "$BUILD_FIRST" -eq 1 ]]; then
    echo "🐳 Building the hardened dxdfir/* images first..."
    ( cd "$REPO_ROOT_DIR" && ansible-playbook \
        ansible/collections/get_sybers.dxdfir/playbooks/dxdfir-build-images.yml \
        -i localhost, -c local ) || die "Image build failed."
fi

mkdir -p "$DOCKER_TAR_DIR"
echo "💾 Saving Docker images to $DOCKER_TAR_DIR..."
echo ""
failed=0

# Built images: must already exist locally (never pulled).
for image in "${BUILT_IMAGES[@]}"; do
    if ! $DOCKER_CMD image inspect "$image" >/dev/null 2>&1; then
        echo "❌ $image is not built. Run: ansible-playbook playbooks/dxdfir-build-images.yml (or pass --build)"
        failed=$((failed + 1)); continue
    fi
    fn="$(image_to_filename "$image")"
    echo "💾 Saving (built) $image -> $fn.tar"
    $DOCKER_CMD save "$image" -o "$DOCKER_TAR_DIR/$fn.tar" \
        && echo "✅ $fn.tar" || { echo "❌ save failed: $image"; failed=$((failed + 1)); }
done

# Pulled images: fetch then save.
for image in "${PULL_IMAGES[@]}"; do
    echo "🔄 Pulling $image..."
    if ! $DOCKER_CMD pull "$image"; then
        echo "❌ Failed to pull $image"; failed=$((failed + 1)); continue
    fi
    fn="$(image_to_filename "$image")"
    echo "💾 Saving (pulled) $image -> $fn.tar"
    $DOCKER_CMD save "$image" -o "$DOCKER_TAR_DIR/$fn.tar" \
        && echo "✅ $fn.tar" || { echo "❌ save failed: $image"; failed=$((failed + 1)); }
done

[[ $failed -eq 0 ]] || die "$failed operation(s) failed."
echo ""
echo "🎉 All images saved to: $DOCKER_TAR_DIR"
echo "   Load them on the offline host with: scripts/save-docker-images.sh --verify"
