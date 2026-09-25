#!/bin/bash
# ==============================================================================
# Prepare a host to run the DX_DFIR scripts.
#
# Installs Docker and the handful of userland tools the processing scripts
# shell out to, puts the invoking user in the docker group, and sets
# ownership/permissions on the repository.
#
# The analysis images are BUILT, not pulled — the dxdfir-build-images.yml
# playbook (what `dxdfir build-docker` runs) is the one build mechanism, and
# scripts/save-docker-images.sh --build calls it and saves the results as
# tarballs for transport. When this script finds no route to the internet it
# falls back to loading those pre-seeded tarballs (see "Analysis images"
# below). That fallback covers the IMAGES only: the earlier steps (apt, the
# Docker repo, submodules, pip, collections) still need the network on a FIRST
# run, so the offline path assumes a host provisioned online first — set up
# connected, save the tarballs, move/disconnect, re-run.
#
# Each guard below encodes a way the previous revision of this script failed on
# a clean machine:
#
#   - `sudo` is NOT assumed to exist. The previous revision hardcoded it in 11
#     places and died on its first line ("sudo: command not found") on any
#     minimal container image, which is exactly where a fresh analyst
#     environment gets built. We are usually already root there, so the
#     escalation prefix is resolved once, up front, and may legitimately be
#     empty.
#   - Every prompt degrades to a default when stdin is not a TTY. `read` on a
#     closed stdin returns non-zero immediately, so the old prompts silently
#     took the "no" branch and the script reported success having installed
#     nothing. --yes makes that explicit and non-interactive runs assume it.
#   - The Docker apt repository is derived from /etc/os-release, not hardcoded
#     to Debian. The old URL installed a Debian repo on Ubuntu hosts, which
#     resolves but then fails to find the packages.
#   - apt-get runs with -y. Without it the install blocks on a confirmation
#     prompt that non-interactive runs can never answer.
#   - Permissions are u=rwX,g=rX (capital X), not 744. 744 clears the execute
#     bit on DIRECTORIES for the group, so members of the docker group the
#     script had just created could not traverse into the very repository it
#     had just given them. Capital X applies +x to directories and to files
#     that are already executable, leaving the .sh files runnable and data
#     files alone.
#   - unzip is installed, not merely hoped for. dev-scripts/fetch-samples.sh
#     unpacks zip fixtures with it and the old script never mentioned it.
#
# Usage: scripts/setup-environment.sh [--yes] [--no-color] [--help]
# ==============================================================================

set -o pipefail

################################################################################
# Establish DX_DFIR repo filepath
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
REPO_ROOT_DIR="$(realpath "$SCRIPT_DIR/..")"

# Userland tools the pipeline shells out to. python3 runs the get_sybers_dxdfir
# package, unzip backs dev-scripts/fetch-samples.sh, tar backs the image
# tarballs written by save-docker-images.sh, curl fetches sample fixtures.
# ca-certificates and gnupg are needed to add the Docker repo itself.
APT_DEPS=(ca-certificates curl git gnupg unzip python3 python3-venv tar)
REQUIRED_CMDS=(curl git python3 unzip tar realpath readlink)

ASSUME_YES=false

# ------------------------------------------------------------------------------
# Output styling — the DX_DFIR "Sunset" palette in ANSI, matching the dxdfir TUI.
# Colour is applied ONLY on a real terminal; piped/logged output, NO_COLOR, a
# dumb TERM, or --no-color all fall back to plain ASCII, so the script stays bare
# bones and its logs stay greppable. Status markers are ASCII (no emoji, no
# Unicode) for the same reason the progress spinner is: they must survive a
# C/POSIX locale on a clean machine.
# ------------------------------------------------------------------------------
USE_COLOR=true
setup_colors() {
    if [[ "$USE_COLOR" == true && -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != dumb ]]; then
        local e=$'\033'
        C_RESET="${e}[0m"; C_BOLD="${e}[1m"
        C_ACCENT="${e}[38;5;214m" # marigold  — actions / commands / focus
        C_OK="${e}[38;5;172m"     # amber     — done / present
        C_WARN="${e}[38;5;173m"   # ochre     — warning
        C_FAIL="${e}[38;5;167m"   # vermilion — failure
        C_TITLE="${e}[38;5;230m"  # cream     — headings
        C_FRAME="${e}[38;5;94m"   # bronze    — brackets / rules
        C_DIM="${e}[38;5;245m"    # grey      — secondary detail
    else
        C_RESET= C_BOLD= C_ACCENT= C_OK= C_WARN= C_FAIL= C_TITLE= C_FRAME= C_DIM=
    fi
}
setup_colors

# _status COLOUR TAG MESSAGE… — an aligned "[ tag ]" (bronze brackets, coloured
# 4-char tag) then the message. ok/step/info → stdout; warn/fail → stderr.
_status() { local c="$1" t="$2"; shift 2; printf '%s[%s%s%s]%s %s\n' "$C_FRAME" "$c" "$t" "$C_FRAME" "$C_RESET" "$*"; }
ok()   { _status "$C_OK"     " ok " "$@"; }
step() { _status "$C_ACCENT" " >> " "$@"; }
info() { _status "$C_DIM"    " .. " "$@"; }
warn() { _status "$C_WARN"   "warn" "$@" >&2; }
fail() { _status "$C_FAIL"   "fail" "$@" >&2; }

# detail — a dimmed continuation line, indented under the [tag].
detail() { printf '       %s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }

# section — a cream heading over a bronze rule.
section() {
    printf '\n%s%s%s%s\n%s%s%s\n\n' \
        "$C_BOLD" "$C_TITLE" "$1" "$C_RESET" \
        "$C_FRAME" "----------------------------------------------------" "$C_RESET"
}

# banner — the GE-SYBERS wordmark as a warm sunset gradient (marigold → crimson),
# echoing the TUI; plain when colour is off.
banner() {
    _band() { if [[ -n "$C_RESET" ]]; then printf '\033[38;5;%sm%s\033[0m\n' "$1" "$2"; else printf '%s\n' "$2"; fi; }
    printf '\n'
    _band 214 ' ██████╗ ███████╗████████╗   ███████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗'
    _band 214 '██╔════╝ ██╔════╝╚══██╔══╝   ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝'
    _band 172 '██║  ███╗█████╗     ██║█████╗███████╗ ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗'
    _band 173 '██║   ██║██╔══╝     ██║╚════╝╚════██║  ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║'
    _band 167 '╚██████╔╝███████╗   ██║      ███████║   ██║   ██████╔╝███████╗██║  ██║███████║'
    _band 160 ' ╚═════╝ ╚══════╝   ╚═╝      ╚══════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝'
    printf '\n'
}

################################################################################
# Argument parsing
while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--yes) ASSUME_YES=true ;;
        --no-color|--no-colour) USE_COLOR=false; setup_colors ;;
        -h|--help)
            sed -n '2,42p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            fail "Unknown option: $1"
            detail "Usage: $0 [--yes] [--no-color] [--help]" >&2
            exit 1
            ;;
    esac
    shift
done

# A non-interactive run cannot answer a prompt, so it takes the documented
# defaults rather than failing every `read` and pretending that was a choice.
if [[ ! -t 0 ]] && [[ "$ASSUME_YES" != true ]]; then
    info "stdin is not a TTY — running non-interactively (implies --yes)."
    ASSUME_YES=true
fi

die() { fail "$*"; exit 1; }

# Build invocation-scoped safe.directory flags (into GIT_SAFE_FLAGS) trusting
# ONE checkout root — never `git config --global`, which would be a persistent,
# accumulating change to the operator's own git config. Recursive submodule
# operations walk into nested submodule repos whose paths cannot be
# pre-enumerated, so the root entry alone is not enough: git >= 2.46
# understands a trailing "/*" leading-path match that scopes trust to the root
# and everything under it; older gits only match exact paths or the global
# "*", so there the invocation-scoped wildcard remains the fallback (still
# per-command, never persisted).
git_safe_flags() {
    local root="$1" major minor
    IFS=. read -r major minor _ <<< "$(git --version 2>/dev/null | awk '{print $3}')"
    major="${major//[^0-9]/}"; minor="${minor//[^0-9]/}"
    if [[ -n "$major" && -n "$minor" ]] \
        && (( major > 2 || (major == 2 && minor >= 46) )); then
        GIT_SAFE_FLAGS=(-c "safe.directory=$root" -c "safe.directory=$root/*")
    else
        GIT_SAFE_FLAGS=(-c "safe.directory=$root" -c "safe.directory=*")
    fi
}

confirm() {
    local prompt="$1"
    if [[ "$ASSUME_YES" == true ]]; then
        info "$prompt [assuming yes]"
        return 0
    fi
    local reply
    read -r -p "$(printf '%s?%s %s (y/n) ' "$C_ACCENT" "$C_RESET" "$prompt")" reply
    echo
    [[ "$reply" =~ ^[Yy]$ ]]
}

# Run a long command while keeping the terminal informed, so a multi-minute step
# is not a dead prompt. The command runs in the background; this prints a live
# elapsed-time heartbeat — a redrawn spinner on a TTY, a line every 10s when
# output is piped to a log. Returns the command's exit code, so callers keep
# their `|| echo ...` fallbacks. Sudo credentials are refreshed up front (a
# no-op when $SUDO is empty or already primed) so the backgrounded privileged
# command never blocks on a password prompt it cannot display. The spinner is
# deliberately ASCII: braille/unicode frames break ${#var}/substring math under
# a C/POSIX locale, exactly the clean-machine case this script targets.
run_with_progress() {
    local label="$1"; shift
    [[ -n "$SUDO" ]] && $SUDO -v 2>/dev/null
    "$@" &
    local pid=$! start=$SECONDS last=-1 elapsed
    local frames='|/-\' nframes i=0
    nframes=${#frames}
    while kill -0 "$pid" 2>/dev/null; do
        elapsed=$((SECONDS - start))
        if [[ -t 1 ]]; then
            printf '\r%s %s  %ds ' "$label" "${frames:i%nframes:1}" "$elapsed"
            i=$((i + 1))
        elif (( elapsed >= 10 && elapsed != last && elapsed % 10 == 0 )); then
            printf '%s … still working (%ds elapsed)\n' "$label" "$elapsed"
            last=$elapsed
        fi
        sleep 1
    done
    wait "$pid"; local rc=$?
    elapsed=$((SECONDS - start))
    if [[ -t 1 ]]; then
        printf '\r%s … done in %ds%*s\n' "$label" "$elapsed" 12 ''
    else
        printf '%s … done in %ds\n' "$label" "$elapsed"
    fi
    return "$rc"
}

################################################################################
banner
info "Repository: $REPO_ROOT_DIR"

################################################################################
# Resolve the privilege prefix ONCE.
#
# Running as root is normal in a container and is not, by itself, a mistake —
# but it is worth one confirmation on a workstation, because the chown at the
# end rewrites ownership across the whole repository.
RUN_USER="$(id -un)"

if [[ "$EUID" -eq 0 ]]; then
    SUDO=""
    cat << "EOF"
        ⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⣤⣤⣤⣤⣤⣤⣤⣀⡀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⢀⣴⣿⣿⣿⠿⠟⠛⠉⠉⠀⠀⠉⠙⠻⢿⣷⣦⡀⠀⠀⠀
        ⠀⠀⠀⢠⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⢿⣆⠀⠀
        ⠀⠀⢠⣿⠋⠀⠀⠀⣠⣶⣶⣶⣶⣶⣦⣄⠀⠀⠀⠀⠀⠀⠈⣿⣆⠀
        ⠀⢀⣿⠁⠀⠀⠀⠘⠛⠋⠁⠀⠀⠈⠉⠛⠀⠀⠀⠀⠀⠀⠀⢹⣿⠀
        ⠀⢸⣿⠀⠀⠀⢀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠀⠀⠀⣿⡇
        ⠀⠈⢿⣧⠀⢀⡿⠛⠛⠃⠀⠀⠀⠀⠀⠀⠀⠘⠿⠟⠛⠂⠀⣼⡟⠀
        ⠀⠀⠀⠙⢿⣮⣅⣀⣀⣀⣀⣀⠀⠀⠀⠀⢀⣀⣀⣠⣤⣴⡾⠋⠀⠀

EOF
    warn "RUNNING AS ROOT"
    detail "Normal in a container, worth a second look on a workstation —" >&2
    detail "the final step rewrites ownership across the repository." >&2
    echo
    confirm "Continue as root?" || die "Aborted at the root check."
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    die "Not root and sudo is not installed. Re-run as root, or install sudo first."
fi

################################################################################
# Docker presence probe — the ENGINE ITSELF is provisioned by ansible now
# (dxdfir-bootstrap.yml -> the dxdfir_stack role's docker_ensure entry
# point: Docker's apt repository, engine + plugins, daemon, docker group and
# operator membership — the same idempotent state tasks `dxdfir deploy
# stack` runs), once ansible exists below. Only the fact is read here, for
# the plan and the final notes; the shell copy of that provisioning is gone.
DOCKER_WAS_INSTALLED=true
command -v docker >/dev/null 2>&1 || DOCKER_WAS_INSTALLED=false

################################################################################
# Install the userland tools the processing scripts need.
#
# The old script installed none of these. Nothing in the pipeline runs without
# python3, and the sample fetcher exits on a missing unzip — each one an error
# the analyst hit halfway through an ingest instead of here.
MISSING_DEPS=()
for cmd in "${REQUIRED_CMDS[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 || MISSING_DEPS+=("$cmd")
done

section "Userland tools"
if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
    step "Installing missing tools: ${MISSING_DEPS[*]}"
    $SUDO apt-get update || die "apt-get update failed."
    $SUDO apt-get install -y "${APT_DEPS[@]}" || die "Failed to install: ${MISSING_DEPS[*]}"
    ok "Userland tools installed."
else
    ok "Required tools present: ${REQUIRED_CMDS[*]}"
fi

################################################################################
# Present user with what this script will do
section "Setup plan"
ok   "1. Install required userland tools"
step "2. Initialise the git submodules (recursively)"
step "3. Set ownership and permissions on the DX_DFIR repository"
step "4. Install the Python package + Ansible (venv) and the pinned collections"
step "5. Ensure the Docker engine, daemon and group via ansible (dxdfir-bootstrap.yml)"
detail "the Byakugan CAR engine is no longer a host checkout — it is built into"
detail "the get-sybers/byakugan image by 'dxdfir build-docker'"
echo

confirm "Do you wish to proceed?" || { info "Setup cancelled."; exit 1; }

################################################################################
# Pull the git submodules — RECURSIVELY.
#
# The remaining submodule is docker/GoDFIR-toolz: the Go tool family, goevtx
# and the anamnesis memory image build. --recursive is kept on principle: it
# means any submodule that DOES nest content checks out complete instead of
# silently empty — the failure mode that bit the CAR engine while it was vendored
# here. (The Byakugan engine is no longer a submodule; it is provisioned as an
# external checkout in the next step, and anamnesis is fused into the
# get-sybers/anamnesis image.) Runs before the chown/chmod below so the freshly
# checked-out files inherit them too.
section "Git submodules"
if [[ -f "$REPO_ROOT_DIR/.gitmodules" ]]; then
    step "Initialising git submodules (recursive) ..."
    # safe.directory is scoped to THIS invocation with `-c` (the repo may be owned
    # by a different user until the chown below); git_safe_flags trusts the repo
    # root — and, on git >= 2.46, only the paths beneath it.
    git_safe_flags "$REPO_ROOT_DIR"
    GIT_SAFE=("${GIT_SAFE_FLAGS[@]}")
    git "${GIT_SAFE[@]}" -C "$REPO_ROOT_DIR" submodule sync --recursive >/dev/null 2>&1 || true
    git "${GIT_SAFE[@]}" -C "$REPO_ROOT_DIR" submodule update --init --recursive \
        || die "Failed to initialise git submodules recursively (need network + git access)."
    ok "Submodules checked out (docker/GoDFIR-toolz)."
else
    info "No .gitmodules found — skipping submodule init."
fi

################################################################################
# Set ownership and permissions for DX_DFIR.
#
# u=rwX,g=rX — capital X applies the execute bit to directories and to files
# that already carry one, so directories stay traversable by the docker group
# and the .sh files stay runnable, while evidence files are left non-executable.
# The old `chmod -R 744` cleared group execute on directories and locked the
# docker group out of the tree the script had just handed it.
section "Repository ownership + permissions"
step "Setting ownership to $RUN_USER:docker and permissions on the repository ..."
detail "Recursive over the whole checkout; a populated data_store/ makes this a"
detail "large walk that can take a while — live progress is shown below."
if [[ -d "$REPO_ROOT_DIR" ]]; then
    run_with_progress "   -> ownership  ($RUN_USER:docker)" \
        $SUDO chown -R "$RUN_USER:docker" "$REPO_ROOT_DIR" \
        || warn "Some ownership changes were skipped"
    run_with_progress "   -> permissions (u=rwX,g=rX,o=)" \
        $SUDO chmod -R u=rwX,g=rX,o= "$REPO_ROOT_DIR" \
        || warn "Some permission changes were skipped"
fi

################################################################################
# Install the get_sybers_dxdfir processor package. A dedicated venv keeps it off
# the system Python (PEP 668) and — this is the point — delivers ansible-playbook
# right next to the processors the roles invoke, which is exactly where the Go
# `dxdfir` front-end (built below) resolves it (the front-end drives the Ansible
# collection). ansible-core is a declared dependency of the package, so this one
# install gives a working `dxdfir process/build-car/verify-car/build-docker`.
#
# --editable is REQUIRED, not a preference. The package still resolves paths
# RELATIVE TO ITS OWN FILES (walking up from __file__): images.py reads the
# GoDFIR-toolz submodule's images.yml (the tool-image inventory, at
# docker/GoDFIR-toolz/images.yml),
# and carcheck.py defaults its --car-dir under the repo's data_store. A plain
# copying install puts the package under the venv's site-packages, whose ancestors
# hold no submodule manifest or data_store/ — the guard and lanes then fail to find them
# even though the repo IS present (above).
# Editable keeps the installed module IN the repo tree, so every _REPO_ROOT-
# relative path resolves. (The Byakugan CAR engine is no longer a host checkout —
# it is cloned + built into the get-sybers/byakugan image, so mitrecar/carcheck
# only shell that image.)
################################################################################
section "Python package + Ansible"
DXDFIR_VENV="${DXDFIR_VENV:-/opt/dxdfir/venv}"
step "Installing the get_sybers_dxdfir package (+ ansible) into $DXDFIR_VENV ..."
$SUDO python3 -m venv "$DXDFIR_VENV" || die "Failed to create the venv (need python3-venv)."
$SUDO "$DXDFIR_VENV/bin/pip" install --quiet --upgrade pip || die "pip upgrade in the venv failed."
# --constraint pins the exact, tested dependency versions from python/constraints.txt
# (pyproject carries the ">=" floors; the lock is the single source of truth this
# installer consumes). Without it a fresh install pulls
# whatever ansible-core / docker-SDK / PyYAML is newest and can shift the pipeline
# under itself; with it there are no version literals to drift in this script.
$SUDO "$DXDFIR_VENV/bin/pip" install --quiet --editable "$REPO_ROOT_DIR/python" \
    --constraint "$REPO_ROOT_DIR/python/constraints.txt" \
    || die "Failed to install the get_sybers_dxdfir package (and its pinned dependencies)."

# ansible-core (a declared dependency, installed with the package above) puts
# ansible-playbook / ansible / ansible-galaxy in the SAME venv bin. dxdfir resolves
# ansible-playbook from there itself, but a HUMAN — including the dxdfir-build-images
# step this script prints at the end — needs them on PATH too, or `ansible-playbook
# ...` is "command not found" on a fresh shell despite ansible being installed.
# Expose them beside dxdfir, exactly as the Go front-end is exposed below.
for _ans in ansible ansible-playbook ansible-galaxy; do
    [[ -x "$DXDFIR_VENV/bin/$_ans" ]] \
        || die "Expected $_ans in $DXDFIR_VENV/bin after installing ansible-core."
    $SUDO ln -sf "$DXDFIR_VENV/bin/$_ans" "/usr/local/bin/$_ans" \
        || die "Failed to expose $_ans on PATH (/usr/local/bin)."
done
ok "ansible on PATH: $(/usr/local/bin/ansible-playbook --version 2>/dev/null | head -1 || echo 'ansible-playbook')"

################################################################################
# Build + install the Go/termui `dxdfir` front-end (go/). It is the primary
# `dxdfir` on PATH; it re-implements no processing — it drives the Ansible
# collection and the get_sybers_dxdfir processors by shelling out. Go is not in
# APT_DEPS (not all distros carry a new enough toolchain), so install the pinned
# upstream toolchain when absent OR older than go.mod's floor (Go >= 1.24): the
# build below pins GOTOOLCHAIN=local, which deliberately refuses toolchain
# auto-upgrades, so a host provisioned by an earlier release of this script
# (which pinned 1.22.x) must be re-provisioned here rather than fail the build.
################################################################################
section "Go toolchain + dxdfir front-end"
GO_VERSION="${GO_VERSION:-1.24.7}"
GO_MIN_MINOR=24
GO_BIN_DIR="${GO_BIN_DIR:-/opt/dxdfir/bin}"
_go_ok=0
if command -v go >/dev/null 2>&1; then
    _gominor="$(go version 2>/dev/null | grep -oE 'go1\.[0-9]+' | head -1 | cut -d. -f2)"
    [[ "$_gominor" =~ ^[0-9]+$ ]] && (( _gominor >= GO_MIN_MINOR )) && _go_ok=1
fi
if (( ! _go_ok )); then
    command -v go >/dev/null 2>&1 \
        && info "Found Go $(go version 2>/dev/null | awk '{print $3}') — older than go.mod's 1.${GO_MIN_MINOR} floor; replacing it."
    step "Installing the Go toolchain ($GO_VERSION) ..."
    case "$(uname -m)" in
        x86_64)        _garch=amd64 ;;
        aarch64|arm64) _garch=arm64 ;;
        *) die "unsupported architecture for the Go toolchain: $(uname -m)" ;;
    esac
    _gotar="go${GO_VERSION}.linux-${_garch}.tar.gz"
    curl -fsSL "https://go.dev/dl/${_gotar}" -o "/tmp/${_gotar}" \
        || die "Failed to download the Go toolchain (${_gotar})."
    # Supply-chain: verify the tarball against Go's published SHA-256 BEFORE
    # extracting it as root over /usr/local/go. Refuse to install on a mismatch.
    #
    # The checksum comes from the go.dev release index (?mode=json), the canonical
    # machine-readable source. The old per-file "<tarball>.sha256" sidecar URLs
    # were retired: go.dev now answers them with an HTTP 200 HTML redirect page,
    # so `curl -f` succeeded, the HTML landed in $_gosha, and sha256sum died with
    # "no properly formatted checksum lines found" — surfacing as a bogus checksum
    # mismatch on every run. python3 is guaranteed here (a REQUIRED_CMD installed
    # above), so parse the JSON with it rather than a format-fragile grep;
    # include=all so a pinned older release is covered, not just the latest few.
    _gosha="$(curl -fsSL "https://go.dev/dl/?mode=json&include=all" \
        | python3 -c 'import sys, json; d = json.load(sys.stdin); print(next((f["sha256"] for v in d for f in v["files"] if f.get("filename") == sys.argv[1]), ""))' \
            "${_gotar}")" \
        || die "Failed to fetch the Go toolchain checksum from the go.dev release index."
    [[ "$_gosha" =~ ^[0-9a-f]{64}$ ]] \
        || die "No SHA-256 for ${_gotar} in the go.dev release index (looked up go${GO_VERSION}) — check the pinned GO_VERSION names a real release."
    printf '%s  %s\n' "$_gosha" "/tmp/${_gotar}" | sha256sum -c --status - \
        || die "Go toolchain checksum mismatch for ${_gotar} — refusing to install."
    detail "Verified go${GO_VERSION} (${_garch}) against the go.dev published SHA-256."
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf "/tmp/${_gotar}" || die "Failed to extract the Go toolchain."
    rm -f "/tmp/${_gotar}"
    $SUDO ln -sf /usr/local/go/bin/go /usr/local/bin/go
    export PATH="/usr/local/go/bin:$PATH"
fi
step "Building the dxdfir Go front-end ($(go version 2>/dev/null | awk '{print $3}')) ..."
$SUDO mkdir -p "$GO_BIN_DIR"

# Build from a CLEAN, EPHEMERAL cache — a throwaway dir (module cache, build
# cache and HOME all inside it) removed as soon as the build finishes. Every run
# therefore resolves the dependency set from a SOURCE OF TRUTH — the in-tree
# go/vendor/ if present (an air-gapped host can pre-vendor with
# 'cd go && go mod vendor' on a connected one), else the module proxy —
# instead of trusting whatever a previous run left on disk.
# A rebuild is honest (it never silently depends on stale cached modules) and
# nothing is cached under the install prefix or the invoking user's ~/go; the
# cost is a cold module fetch each run, which is the intent. GOTOOLCHAIN=local
# keeps the pinned Go from auto-upgrading (go.mod's deps are held at the go 1.24
# floor on purpose — e.g. modernc.org/sqlite is pinned to its last 1.24 tag).
_gotmp="$(mktemp -d)"
_goclean() { [[ -n "$_gotmp" ]] && { $SUDO chmod -R u+w "$_gotmp" 2>/dev/null; $SUDO rm -rf "$_gotmp"; }; }
_goenv=( PATH="$PATH" HOME="$_gotmp" GOTOOLCHAIN=local
         GOCACHE="$_gotmp/build" GOMODCACHE="$_gotmp/mod" )
_gomod="-mod=mod"
[[ -f "$REPO_ROOT_DIR/go/vendor/modules.txt" ]] && _gomod="-mod=vendor"
if ! ( cd "$REPO_ROOT_DIR/go" \
        && $SUDO env "${_goenv[@]}" go build "$_gomod" -o "$GO_BIN_DIR/dxdfir" ./cmd/dxdfir ); then
    if [[ "$_gomod" == "-mod=vendor" ]]; then
        # A vendored tree captured before a dependency changed would fail an
        # update; fall back to the proxy rather than wedge on stale vendoring.
        warn "Vendored modules look stale — fetching through the module proxy instead."
        ( cd "$REPO_ROOT_DIR/go" \
            && $SUDO env "${_goenv[@]}" go build -mod=mod -o "$GO_BIN_DIR/dxdfir" ./cmd/dxdfir ) \
            || { _goclean; die "Failed to build the dxdfir Go front-end (module proxy unreachable? re-vendor on a networked host: 'cd go && go mod vendor')."; }
    else
        _goclean
        die "Failed to build the dxdfir Go front-end (need network for the module proxy, or vendor the modules for an air-gapped install: 'cd go && go mod vendor')."
    fi
fi
_goclean
$SUDO ln -sf "$GO_BIN_DIR/dxdfir" /usr/local/bin/dxdfir
# `man dxdfir` (README / Get-Started) must work on a provisioned host, so the
# manual installs beside the binary. Best-effort: no man tree is not fatal.
$SUDO install -Dm644 "$REPO_ROOT_DIR/go/man/dxdfir.1" /usr/local/share/man/man1/dxdfir.1 2>/dev/null \
    || warn "Could not install the man page — read it in-tree: man ./go/man/dxdfir.1"
ok "dxdfir (Go front-end) installed: $(/usr/local/bin/dxdfir --version 2>/dev/null || echo "$GO_BIN_DIR/dxdfir")"

################################################################################
# Install the collection's pinned Ansible dependencies (requirements.yml — never
# :latest, never a branch). They go to a fixed shared path that the repo-root
# ansible.cfg puts on collections_path, so every user's runs resolve the same
# pinned versions: community.docker (the deploy roles) and ansible.posix (the
# profile_tasks audit-timing callback).
################################################################################
section "Ansible collections"
DXDFIR_COLLECTIONS="${DXDFIR_COLLECTIONS:-/opt/dxdfir/collections}"
step "Installing pinned Ansible collections into $DXDFIR_COLLECTIONS ..."
$SUDO "$DXDFIR_VENV/bin/ansible-galaxy" collection install \
    -r "$REPO_ROOT_DIR/ansible/collections/get_sybers.dxdfir/requirements.yml" \
    -p "$DXDFIR_COLLECTIONS" --force \
    || die "Failed to install the pinned Ansible collections (requirements.yml)."

# The GoDFIR-toolz BUILD galaxy (get_sybers.godfir_toolz): the image inventory
# and the godfir_build role dxdfir_images delegates to. Its pin is the
# GITLINK, so it is imported from the submodule initialised above; when the
# submodule content is absent anyway (a tarball checkout, an init that could
# not reach out), it is imported straight from the source the repo root
# declares — the .gitmodules URL at the gitlink revision — never from a
# hardcoded location. --no-deps: its dependency set is exactly the pins
# installed above.
TOOLZ_PATH="docker/GoDFIR-toolz"
if [[ -f "$REPO_ROOT_DIR/$TOOLZ_PATH/galaxy.yml" ]]; then
    TOOLZ_SRC="$REPO_ROOT_DIR/$TOOLZ_PATH"
    step "Importing the GoDFIR-toolz build galaxy from the submodule ..."
else
    TOOLZ_URL=$(git config -f "$REPO_ROOT_DIR/.gitmodules" "submodule.$TOOLZ_PATH.url" 2>/dev/null) \
        || die "GoDFIR-toolz is neither checked out at $TOOLZ_PATH nor declared in .gitmodules — cannot import the build galaxy."
    TOOLZ_SRC="git+${TOOLZ_URL}"
    if TOOLZ_SHA=$(git -C "$REPO_ROOT_DIR" rev-parse "HEAD:$TOOLZ_PATH" 2>/dev/null); then
        TOOLZ_SRC="${TOOLZ_SRC},${TOOLZ_SHA}"
        step "Importing the GoDFIR-toolz build galaxy from $TOOLZ_URL at the gitlink pin ${TOOLZ_SHA:0:12} ..."
    else
        warn "No git metadata to read the gitlink pin — importing the build galaxy from $TOOLZ_URL (default branch)."
    fi
fi
$SUDO "$DXDFIR_VENV/bin/ansible-galaxy" collection install "$TOOLZ_SRC" \
    -p "$DXDFIR_COLLECTIONS" --force --no-deps \
    || die "Failed to import the GoDFIR-toolz build galaxy (get_sybers.godfir_toolz)."
ok "Collections installed: $("$DXDFIR_VENV/bin/ansible-galaxy" collection list -p "$DXDFIR_COLLECTIONS" 2>/dev/null | grep -cE '^[a-z]' || echo '?') pinned"

################################################################################
# Docker engine + group — ansible, not shell: the same state tasks the deploy
# uses (dxdfir_stack docker_ensure). This script used to carry its own shell
# copy of exactly this provisioning; there is ONE implementation now, and
# rerunning it on a healthy host is a no-op.
################################################################################
section "Docker engine (ansible)"
step "Ensuring the Docker engine, daemon and group (dxdfir-bootstrap.yml) ..."
( cd "$REPO_ROOT_DIR" && $SUDO ansible-playbook \
    ansible/collections/get_sybers.dxdfir/playbooks/dxdfir-bootstrap.yml ) \
    || die "Docker engine bootstrap failed (dxdfir-bootstrap.yml)."
ok "Docker engine present, daemon running, group membership ensured."

################################################################################
# Offline fallback: the analysis images are BUILT (dxdfir-build-images.yml) and
# building needs the network (base images, apt, pinned clones). When the host
# has no route out, fall back to the tarballs a connected host pre-seeded with
# scripts/save-docker-images.sh --build. With internet this section stays
# silent and the images are built normally (the commands printed below).
################################################################################
if ! curl -fsI --connect-timeout 4 --max-time 8 https://download.docker.com/ >/dev/null 2>&1; then
    section "Analysis images (offline fallback)"
    _tars="${DXDFIR_IMAGE_DIR:-$REPO_ROOT_DIR/data_store/docker_images}"
    if compgen -G "$_tars/*.tar" >/dev/null; then
        step "No internet — loading + verifying the pre-seeded image tarballs from $_tars ..."
        # --verify loads every tarball THEN runs the hardened-inventory audit
        # (both as playbooks; the venv's ansible was symlinked onto PATH
        # above), so a missing or corrupt tarball fails here, not at first
        # pipeline use.
        "$SCRIPT_DIR/save-docker-images.sh" --verify \
            || die "Offline image load/verify failed (scripts/save-docker-images.sh --verify)."
        ok "Analysis images loaded and the hardened inventory verified."
    else
        warn "No internet and no image tarballs in $_tars — the analysis images cannot be provisioned."
        detail "On a connected host: scripts/save-docker-images.sh --build, then carry data_store/docker_images/ across."
    fi
fi

################################################################################
# cmd — a marigold command line, indented under a step, with a dim aside.
cmd() { printf '       %s%s%s  %s%s%s\n' "$C_ACCENT" "$1" "$C_RESET" "$C_DIM" "${2:-}" "$C_RESET"; }

section "Setup complete"
if [[ "$DOCKER_WAS_INSTALLED" == false ]]; then
    warn "Log out and back in for the Docker group change to take effect."
else
    ok "Docker was already present; if the bootstrap just added you to the docker group, log out and back in once."
fi
echo

step "Build the hardened tool containers (everything the pipeline runs):"
cmd "ansible-playbook ansible/collections/get_sybers.dxdfir/playbooks/dxdfir-build-images.yml"
echo
step "Pre-seed the analysis images as tarballs for an offline host:"
cmd "scripts/save-docker-images.sh --build" "(connected host: build + save every image)"
cmd "scripts/save-docker-images.sh --load" "(offline host: load tarballs — or just re-run this script)"
echo
step "Run DX_DFIR:"
cmd "dxdfir --help" "(process evidence, build + verify CAR, deploy the analysis stack — see README.md)"
echo
