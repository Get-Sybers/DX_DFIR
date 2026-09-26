#!/bin/bash
# ==============================================================================
# The collection's molecule scenarios, containerised (delegated driver against
# the HOST daemon — repo and /tmp mounted at IDENTICAL paths so every bind the
# role hands the daemon is valid on the host). Args pick roles; fixtures come
# from MOLECULE_SAMPLE_EVTX / _IMAGE / _MEMORY env vars — an absent fixture
# SKIPS its scenario with a note, never fails it.
# ==============================================================================
set -o pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
REPO_ROOT="$(realpath "$SCRIPT_DIR/../..")"
ROLES_DIR="$REPO_ROOT/ansible/collections/get_sybers.dxdfir/roles"
IMAGE="${MOLECULE_IMAGE:-get-sybers/molecule:latest}"

# roles whose scenarios validate real behaviour
DEFAULT_ROLES=(dxdfir_signatures dxdfir_zeek dxdfir_evtx dxdfir_plaso dxdfir_memory)
ROLES=("${@:-${DEFAULT_ROLES[@]}}")

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 127; }

# --- the molecule image (built once, cached) ---------------------------------
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "⬇️  building $IMAGE ..."
    docker build -t "$IMAGE" -f - "$REPO_ROOT" <<'DOCKERFILE' || exit 1
FROM python:3.12-slim
# static docker CLI only — the daemon is the host's
ADD https://download.docker.com/linux/static/stable/x86_64/docker-27.5.1.tgz /tmp/docker.tgz
RUN tar -xzf /tmp/docker.tgz -C /tmp && mv /tmp/docker/docker /usr/local/bin/docker \
    && rm -rf /tmp/docker /tmp/docker.tgz
# requests + docker SDK: community.docker's modules import them
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
        dxdfir_memory)
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
