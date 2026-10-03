#!/bin/bash
# ==============================================================================
# The collection's molecule scenarios, containerised — and this script is only
# the LAUNCHER: the runner-image build and every container run are Ansible
# tasks (playbooks/dxdfir-molecule.yml; only ansible interacts with the
# containers). Args pick roles; fixtures come from MOLECULE_SAMPLE_EVTX /
# _IMAGE / _MEMORY env vars — an absent fixture SKIPS its scenario with a
# note, never fails it.
# ==============================================================================
set -o pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
REPO_ROOT="$(realpath "$SCRIPT_DIR/../..")"
PLAYBOOKS="$REPO_ROOT/ansible/collections/get_sybers.dxdfir/playbooks"

command -v ansible-playbook >/dev/null 2>&1 || { echo "ansible-playbook is required" >&2; exit 127; }

EXTRA=()
if [[ $# -gt 0 ]]; then
    roles_json="$(printf '"%s",' "$@")"
    EXTRA+=(-e "{\"dxdfir_molecule_roles\": [${roles_json%,}]}")
fi
[[ -n "${MOLECULE_SAMPLE_EVTX:-}" ]]   && EXTRA+=(-e "dxdfir_molecule_sample_evtx=$MOLECULE_SAMPLE_EVTX")
[[ -n "${MOLECULE_SAMPLE_LINUX:-}" ]]  && EXTRA+=(-e "dxdfir_molecule_sample_linux=$MOLECULE_SAMPLE_LINUX")
[[ -n "${MOLECULE_SAMPLE_IMAGE:-}" ]]  && EXTRA+=(-e "dxdfir_molecule_sample_image=$MOLECULE_SAMPLE_IMAGE")
[[ -n "${MOLECULE_SAMPLE_MEMORY:-}" ]] && EXTRA+=(-e "dxdfir_molecule_sample_memory=$MOLECULE_SAMPLE_MEMORY")
[[ -n "${MOLECULE_IMAGE:-}" ]]         && EXTRA+=(-e "dxdfir_molecule_image=$MOLECULE_IMAGE")

cd "$REPO_ROOT" || exit 1
exec ansible-playbook "$PLAYBOOKS/dxdfir-molecule.yml" "${EXTRA[@]}"
