#!/bin/bash
# ==============================================================================
# Save / load the DX_DFIR analysis images as tarballs for offline hosts.
#
# THE image engine of the offline lifecycle — both offline entry points call
# it: scripts/package-offline.sh (online side, save into the bundle) and
# scripts/setup-offline.sh (air-gapped side, load from the bundle). It also
# runs standalone to seed a host that already has the repo and docker.
#
# Two image sets, no hardcoded lists:
#   built  — the hardened get-sybers/* tool images from the repo-root
#            images.yml manifest; BUILT by `dxdfir build-docker` (the
#            dxdfir_images role), never pulled, so this script `docker save`s
#            the local builds (--build first runs that build).
#   pulled — the Elastic analysis stack (docker/elastic): the official
#            docker.elastic.co images at ELASTIC_VERSION, derived from the
#            compose file + .env.example. The stack IS the analysis backend,
#            so an offline bundle without it could process but never analyse.
#
# Usage:
#   scripts/save-docker-images.sh              save every image to a tarball
#   scripts/save-docker-images.sh --build      build the get-sybers/* images first, then save
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

# Runtime tool images — BUILT from the GoDFIR-toolz submodule, never pulled.
# Derived from the repo-root images.yml manifest (the single source of truth
# the Python guard and the dxdfir_images build role also read), so a new image
# is added in ONE place.
_ns="$(awk -F': *' '/^namespace:/{print $2; exit}' "$REPO_ROOT_DIR/images.yml")"
mapfile -t BUILT_IMAGES < <(awk -v ns="${_ns:-get-sybers}" '
    $1=="images:"{f=1; next}
    /^[^[:space:]]/{f=0}
    f && $1=="-" && $2=="name:"{print ns "/" $3 ":latest"}
' "$REPO_ROOT_DIR/images.yml")

# Pulled images — the Elastic analysis stack (docker/elastic), part of the
# offline set now that it is THE analysis backend. Derived from the compose
# file's image: lines with ELASTIC_VERSION resolved from .env.example (falling
# back to the compose default), so neither the list nor the version has a
# second copy here to drift. (The retired .NET runtime for evtxecmd's
# operator-supplied mode is gone with that mode — goevtx replaced it.)
_elastic_dir="$REPO_ROOT_DIR/docker/elastic"
_ever="$(awk -F'=' '$1=="ELASTIC_VERSION"{print $2; exit}' "$_elastic_dir/.env.example" 2>/dev/null)"
if [[ -z "$_ever" ]]; then
    _ever="$(grep -oE '\$\{ELASTIC_VERSION:-[^}]+\}' "$_elastic_dir/docker-compose.yml" | head -1 | sed 's/.*:-//; s/}$//')"
fi
mapfile -t PULL_IMAGES < <(awk -F'"' '/^[[:space:]]*image:/{print $2}' "$_elastic_dir/docker-compose.yml" \
    | sed "s/\${ELASTIC_VERSION:-[^}]*}/$_ever/" | sort -u)

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
            # The help IS the header block: everything between the opening and
            # closing `# ===` rules, so it never drifts from a hardcoded range.
            awk 'NR < 3 { next } /^# =+$/ { exit } { sub(/^# ?/, ""); print }' "$0"
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
    echo "Built in-repo (images.yml → dxdfir build-docker; docker save):"
    printf '   • %s\n' "${BUILT_IMAGES[@]}"
    echo "Pulled (the Elastic stack, docker/elastic @ ${_ever:-?}):"
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
    echo "🐳 Building the hardened get-sybers/* images first (dxdfir_images role)..."
    # dxdfir build-docker IS the build path; the raw playbook invocation below
    # is the same role, for a host where the Go front-end is not installed yet.
    if command -v dxdfir >/dev/null 2>&1; then
        dxdfir build-docker || die "Image build failed (dxdfir build-docker)."
    else
        ( cd "$REPO_ROOT_DIR" && ansible-playbook \
            ansible/collections/get_sybers.dxdfir/playbooks/dxdfir-build-images.yml \
            -i localhost, -c local ) || die "Image build failed."
    fi
fi

mkdir -p "$DOCKER_TAR_DIR"
echo "💾 Saving Docker images to $DOCKER_TAR_DIR..."
echo ""
failed=0

# Built images: must already exist locally (never pulled).
for image in "${BUILT_IMAGES[@]}"; do
    if ! $DOCKER_CMD image inspect "$image" >/dev/null 2>&1; then
        echo "❌ $image is not built. Run: dxdfir build-docker (or pass --build)"
        failed=$((failed + 1)); continue
    fi
    fn="$(image_to_filename "$image")"
    echo "💾 Saving (built) $image -> $fn.tar"
    $DOCKER_CMD save "$image" -o "$DOCKER_TAR_DIR/$fn.tar" \
        && echo "✅ $fn.tar" || { echo "❌ save failed: $image"; failed=$((failed + 1)); }
done

# Pulled images (the Elastic stack): fetch then save.
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
