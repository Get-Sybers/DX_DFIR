#!/bin/bash
# ==============================================================================
# Save / load the DX_DFIR analysis images as tarballs for offline hosts.
#
# THE offline image mechanism — and this script is only its LAUNCHER: the
# image sets, the pulls, the exports and the loads are Ansible tasks
# (dxdfir-images-save.yml / dxdfir-images-load.yml, the dxdfir_images role),
# with the sets defined in ONE place each: the repo-root images.yml manifest
# for the built get-sybers/* tool images (never pulled; --build invokes
# dxdfir-build-images.yml first) and the inventory layer's
# dxdfir_elastic_images for the Elastic stack set.
#
# Run it on a connected host (--build), carry data_store/docker_images/
# across, and either run --load there or simply run
# scripts/setup-environment.sh, which falls back to loading these tarballs
# when it finds no internet.
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
PLAYBOOKS="$REPO_ROOT_DIR/ansible/collections/get_sybers.dxdfir/playbooks"

die() { echo "❌ $*" >&2; exit 1; }

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

# setup-environment.sh symlinks the venv's ansible into /usr/local/bin; fall
# back to the venv directly for a PATH that lacks it.
if ! command -v ansible-playbook >/dev/null 2>&1; then
    _venv="${DXDFIR_VENV:-/opt/dxdfir/venv}"
    if [[ -x "$_venv/bin/ansible-playbook" ]]; then
        PATH="$_venv/bin:$PATH"
    else
        die "ansible-playbook not found — run scripts/setup-environment.sh first."
    fi
fi

# Extra vars the playbooks take from this launcher: only the dir override.
EXTRA_VARS=()
[[ -n "${DXDFIR_IMAGE_DIR:-}" ]] && EXTRA_VARS+=(-e "dxdfir_images_tar_dir=$DXDFIR_IMAGE_DIR")

run_playbook() {
    ( cd "$REPO_ROOT_DIR" && "${RUNNER[@]}" ansible-playbook "$PLAYBOOKS/$1" "${@:2}" "${EXTRA_VARS[@]}" )
}

if [[ "$MODE" == "list" ]]; then
    RUNNER=()
    run_playbook dxdfir-images-save.yml -e dxdfir_images_list_only=true \
        || die "Could not list the image sets."
    exit 0
fi

# Resolve how to talk to the daemon: prefer the unprivileged socket, fall
# back to running the playbook under sudo (PATH preserved so the venv's
# ansible survives), say plainly when neither answers.
RUNNER=()
if ! docker info >/dev/null 2>&1; then
    if command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
        RUNNER=(sudo -E env "PATH=$PATH")
        echo "ℹ️  Talking to the Docker daemon via sudo (group membership needs a new login session)."
    else
        die "The Docker daemon is not reachable. Start it with: sudo systemctl start docker"
    fi
fi

case "$MODE" in
    load)
        run_playbook dxdfir-images-load.yml || die "Image load failed."
        ;;
    verify)
        run_playbook dxdfir-images-load.yml || die "Image load failed."
        echo "🔒 Verifying the hardened image inventory (dxdfir-verify-images.yml)..."
        run_playbook dxdfir-verify-images.yml \
            || die "Image inventory verification FAILED (see: dxdfir verify-images)."
        ;;
    save)
        if [[ "$BUILD_FIRST" -eq 1 ]]; then
            echo "🐳 Building the hardened get-sybers/* images first (dxdfir-build-images.yml)..."
            run_playbook dxdfir-build-images.yml || die "Image build failed."
        fi
        run_playbook dxdfir-images-save.yml || die "Image save failed."
        ;;
esac
