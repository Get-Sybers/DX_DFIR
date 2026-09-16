#!/bin/bash
# ==============================================================================
# DX_DFIR — molecule scenarios, containerised
#
# Runs the collection's molecule scenarios inside a purpose-built container
# (python + molecule + a STATIC docker CLI), so molecule never has to be
# installed on the host. The scenarios use the delegated driver: the role under
# test runs its tool containers (the hardened get-sybers/* images — build them first
# with playbooks/dxdfir-build-images.yml,
# ...) against the HOST docker daemon through the mounted socket. For that to
# work, the repo and /tmp are mounted at IDENTICAL paths inside the molecule
# container — every bind path the role hands the daemon must be valid on the
# host.
#
#   ./.github/tests/run-molecule.sh                  run the default scenario set
#   ./.github/tests/run-molecule.sh dxdfir_zeek ...    run specific roles only
#
# Operator-supplied fixtures (large/binary; not shipped) come from env vars —
# a scenario whose fixture is absent is SKIPPED with a note, not failed:
#   MOLECULE_SAMPLE_EVTX      .evtx log            (dxdfir_evtx)
#   MOLECULE_SAMPLE_IMAGE     raw/E01 disk image   (dxdfir_plaso)
#   MOLECULE_SAMPLE_MEMORY    memory image         (dxdfir_volatility)
#
# Exit code is non-zero if any executed scenario fails, so this can gate CI
# (on a runner with the docker socket and the tool images available).
# ==============================================================================
set -o pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
REPO_ROOT="$(realpath "$SCRIPT_DIR/../..")"
ROLES_DIR="$REPO_ROOT/ansible/collections/get_sybers.dxdfir/roles"
IMAGE="${MOLECULE_IMAGE:-get-sybers/molecule:latest}"

# Roles whose scenarios validate real behaviour.
DEFAULT_ROLES=(dxdfir_signatures dxdfir_zeek dxdfir_evtx dxdfir_plaso dxdfir_volatility)
ROLES=("${@:-${DEFAULT_ROLES[@]}}")

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 127; }

# --- the molecule image (built once, cached) ---------------------------------
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "⬇️  building $IMAGE ..."
    docker build -t "$IMAGE" -f - "$REPO_ROOT" <<'DOCKERFILE' || exit 1
FROM python:3.12-slim
# static docker CLI only — the daemon is the host's, via the mounted socket
ADD https://download.docker.com/linux/static/stable/x86_64/docker-27.5.1.tgz /tmp/docker.tgz
RUN tar -xzf /tmp/docker.tgz -C /tmp && mv /tmp/docker/docker /usr/local/bin/docker \
    && rm -rf /tmp/docker /tmp/docker.tgz
# requests + docker SDK: community.docker's modules import them (the
# dxdfir_images scenario builds images through that collection)
RUN pip install --no-cache-dir molecule ansible-core requests docker
DOCKERFILE
fi

# --- per-role fixture requirements ------------------------------------------
extra_args() { # role -> ansible -e args for its operator-supplied fixtures, or rc 1 to skip
    case "$1" in
        dxdfir_evtx)
            [[ -f "${MOLECULE_SAMPLE_EVTX:-}" ]] || return 1
            echo "-e molecule_sample_evtx=$MOLECULE_SAMPLE_EVTX" ;;
        dxdfir_plaso)
            [[ -f "${MOLECULE_SAMPLE_IMAGE:-}" ]] || return 1
            echo "-e molecule_sample_image=$MOLECULE_SAMPLE_IMAGE" ;;
        dxdfir_volatility)
            [[ -f "${MOLECULE_SAMPLE_MEMORY:-}" ]] || return 1
            echo "-e molecule_sample_memory=$MOLECULE_SAMPLE_MEMORY" ;;
        *)  echo "" ;;
    esac
}

FAILED=0; RAN=0; SKIPPED=0
for role in "${ROLES[@]}"; do
    [[ -d "$ROLES_DIR/$role/molecule/default" ]] || { echo "✗ $role: no molecule scenario" >&2; FAILED=$((FAILED+1)); continue; }
    if ! args="$(extra_args "$role")"; then
        echo "– $role: skipped (operator-supplied fixture not provided — see header)"
        SKIPPED=$((SKIPPED+1)); continue
    fi
    echo "▶ $role: molecule test"
    # shellcheck disable=SC2086
    if docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$REPO_ROOT":"$REPO_ROOT" \
        -v /tmp:/tmp \
        -w "$ROLES_DIR/$role" \
        "$IMAGE" molecule test ${args:+-- $args}; then
        echo "✓ $role"
        RAN=$((RAN+1))
    else
        echo "✗ $role FAILED" >&2
        FAILED=$((FAILED+1))
    fi
done

echo
echo "molecule: $RAN passed, $SKIPPED skipped (missing fixtures), $FAILED failed"
[[ "$FAILED" -eq 0 ]]
