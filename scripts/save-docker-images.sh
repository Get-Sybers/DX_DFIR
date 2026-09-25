#!/bin/bash
# ==============================================================================
# Save / load the DX_DFIR analysis images as tarballs for offline hosts.
#
# THE offline image mechanism, in one place. Two image sets, no hardcoded lists:
#
#   built  — the hardened get-sybers/* tool images from the repo-root images.yml
#            manifest. BUILT by the existing playbook (dxdfir-build-images.yml,
#            the dxdfir_images role — the same thing `dxdfir build-docker`
#            runs), never pulled; --build invokes it before saving.
#   pulled — the Elastic analysis stack: the docker.elastic.co
#            images at the inventory's dxdfir_elastic_version, derived from
#            .env.example. The stack IS the analysis backend, so an offline
#            host without it could process but never analyse.
#
# Run it on a connected host (--build), carry data_store/docker_images/ across,
# and either run --load there or simply run scripts/setup-environment.sh, which
# falls back to loading these tarballs when it finds no internet.
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
# with $DXDFIR_IMAGE_DIR.
# ==============================================================================

set -o pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
REPO_ROOT_DIR="$(realpath "$SCRIPT_DIR/..")"
DOCKER_TAR_DIR="${DXDFIR_IMAGE_DIR:-$REPO_ROOT_DIR/data_store/docker_images}"

die() { echo "❌ $*" >&2; exit 1; }

# Runtime tool images — BUILT in-repo (or from the GoDFIR-toolz submodule), never
# pulled. Derived from the repo-root images.yml manifest (the single source of
# truth the Python guard and the dxdfir_images build role also read), so a new
# image is added in ONE place.
_ns="$(awk -F': *' '/^namespace:/{print $2; exit}' "$REPO_ROOT_DIR/images.yml")"
mapfile -t BUILT_IMAGES < <(awk -v ns="${_ns:-get-sybers}" '
    $1=="images:"{f=1; next}
    /^[^[:space:]]/{f=0}
    f && $1=="-" && $2=="name:"{print ns "/" $3 ":latest"}
' "$REPO_ROOT_DIR/images.yml")
# Pulled images — the Elastic analysis stack. The version comes from the
# inventory layer's one pin (dxdfir_elastic_version in the playbooks'
# group_vars) and the image list from the dxdfir_stack role's image map
# (docker.elastic.co/... lines), so neither has a second copy here to drift.
_group_vars="$REPO_ROOT_DIR/ansible/collections/get_sybers.dxdfir/playbooks/group_vars/all.yml"
_stack_defaults="$REPO_ROOT_DIR/ansible/collections/get_sybers.dxdfir/roles/dxdfir_stack/defaults/main.yml"
_ever="$(awk -F': *' '$1=="dxdfir_elastic_version"{gsub(/"/, "", $2); print $2; exit}' "$_group_vars" 2>/dev/null)"
mapfile -t PULL_IMAGES < <(grep -oE 'docker\.elastic\.co/[a-z-]+/[a-z-]+:' "$_stack_defaults" \
    | sed "s|\$|$_ever|" | sort -u)

# Fail closed: an unreadable manifest/inventory or an unresolvable version
# must not silently shrink the offline set the header promises.
[[ ${#BUILT_IMAGES[@]} -gt 0 ]] \
    || die "No images derived from $REPO_ROOT_DIR/images.yml — manifest missing or unreadable."
[[ -n "$_ever" ]] \
    || die "Could not resolve dxdfir_elastic_version from $_group_vars."
[[ ${#PULL_IMAGES[@]} -gt 0 ]] \
    || die "No docker.elastic.co image lines found in $_stack_defaults — cannot derive the Elastic set."

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

if [[ "$MODE" == "list" ]]; then
    echo "Built in-repo (images.yml → dxdfir-build-images.yml; docker save):"
    printf '   • %s\n' "${BUILT_IMAGES[@]}"
    echo "Pulled (the Elastic stack @ ${_ever:-?}):"
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

# The hardened-inventory guard, used by --verify after a load. $DXDFIR_PYTHON
# lets a caller with a ready venv (setup-environment.sh's offline fallback)
# run the audit with it; bare python3 otherwise, degrading to a skip-notice
# when the package is not importable there.
verify_inventory() {
    local py="$REPO_ROOT_DIR/python" pybin="${DXDFIR_PYTHON:-python3}"
    if PYTHONPATH="$py" "$pybin" -c "import get_sybers_dxdfir.images" 2>/dev/null; then
        echo "🔒 Verifying the hardened image inventory..."
        PYTHONPATH="$py" "$pybin" -m get_sybers_dxdfir.images --audit >/dev/null \
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
    echo "🐳 Building the hardened get-sybers/* images first (dxdfir-build-images.yml)..."
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
