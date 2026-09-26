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
#   - Nothing this script installs depends on a PATH edit taking effect. The
#     previous revision put the dxdfir binary under /opt/dxdfir/bin and the
#     ansible venv under /opt/dxdfir/venv, reachable only through an
#     /etc/profile.d drop-in — which login shells read and nothing else does
#     (`su user`, a desktop terminal, tmux, sudo's secure_path, the very shell
#     the script ran in), so the closing "dxdfir --help" was command-not-found
#     until a full re-login, and sometimes after it. Now the binary is a real
#     file in /usr/local/bin (on every default PATH, sudo's included), the venv
#     lives INSIDE the checkout at .venv (gitignored) where dxdfir resolves it
#     by relation to the repo it just found, and the script proves the result
#     from a fresh non-login shell before it says "done".
#
# Usage: scripts/setup-environment.sh [--yes] [--no-color] [--help]
# ==============================================================================

set -o pipefail

################################################################################
# Establish DX_DFIR repo filepath
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
REPO_ROOT_DIR="$(realpath "$SCRIPT_DIR/..")"

# userland tools the pipeline shells out to
APT_DEPS=(ca-certificates curl git gnupg unzip python3 python3-venv tar)
REQUIRED_CMDS=(curl git python3 unzip tar realpath readlink)

ASSUME_YES=false

# Output styling — the Sunset palette, TTY-only; status markers and spinner
# frames are ASCII so they survive a C/POSIX locale (docs: Design decisions).
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

# _status COLOUR TAG MESSAGE… — ok/step/info → stdout; warn/fail → stderr
_status() { local c="$1" t="$2"; shift 2; printf '%s[%s%s%s]%s %s\n' "$C_FRAME" "$c" "$t" "$C_FRAME" "$C_RESET" "$*"; }
ok()   { _status "$C_OK"     " ok " "$@"; }
step() { _status "$C_ACCENT" " >> " "$@"; }
info() { _status "$C_DIM"    " .. " "$@"; }
warn() { _status "$C_WARN"   "warn" "$@" >&2; }
fail() { _status "$C_FAIL"   "fail" "$@" >&2; }

# detail — a dimmed continuation line
detail() { printf '       %s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }

# section — a heading over a rule
section() {
    printf '\n%s%s%s%s\n%s%s%s\n\n' \
        "$C_BOLD" "$C_TITLE" "$1" "$C_RESET" \
        "$C_FRAME" "----------------------------------------------------" "$C_RESET"
}

# banner — the wordmark; plain when colour is off
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

# non-interactive runs take the documented defaults
if [[ ! -t 0 ]] && [[ "$ASSUME_YES" != true ]]; then
    info "stdin is not a TTY — running non-interactively (implies --yes)."
    ASSUME_YES=true
fi

die() { fail "$*"; exit 1; }

# invocation-scoped safe.directory flags, never --global; >=2.46 gets the
# root/* leading-path match, older gits the GLOBAL "*" wildcard — global for
# that one invocation only, never persisted (docs: Design decisions)
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

# run a long command behind a live heartbeat; sudo refreshed up front so the
# backgrounded command never blocks on a hidden prompt (docs: Design decisions)
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
# Resolve the privilege prefix once; root gets one confirmation on a workstation
# (the closing chown rewrites ownership across the repo).
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
# Docker presence probe — the engine itself is provisioned by ansible
# (dxdfir-bootstrap.yml -> docker_ensure); only the fact is read here.
DOCKER_WAS_INSTALLED=true
command -v docker >/dev/null 2>&1 || DOCKER_WAS_INSTALLED=false

################################################################################
# Install the userland tools the processing scripts need — here, not halfway
# through an ingest.
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
step "4. Install the pinned Ansible layer (repo-local .venv) and the pinned collections"
step "5. Ensure the Docker engine, daemon and group via ansible (dxdfir-bootstrap.yml)"
detail "the Byakugan CAR engine is no longer a host checkout — it is built into"
detail "the get-sybers/byakugan image by 'dxdfir build-docker'"
echo

confirm "Do you wish to proceed?" || { info "Setup cancelled."; exit 1; }

################################################################################
# Pull the git submodules — recursively, on principle (a nesting submodule
# checks out complete instead of silently empty); before the chown/chmod so
# fresh files inherit them.
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
# Ownership and permissions: u=rwX,g=rX — capital X keeps dirs traversable
# and scripts runnable while evidence files stay non-executable.
section "Repository ownership + permissions"
# On a fresh host the docker group does not exist yet (docker itself is
# installed by the bootstrap playbook, a later step) — pre-create it so the
# chown below can reference it; daemon + membership stay the playbook's job.
# The chown SPEC follows what actually exists: should the pre-create fail,
# ownership falls back to the user alone instead of failing wholesale and
# leaving the checkout root-owned.
getent group docker >/dev/null 2>&1 || $SUDO groupadd --system docker || true
if getent group docker >/dev/null 2>&1; then
    OWN_SPEC="$RUN_USER:docker"
else
    OWN_SPEC="$RUN_USER"
    warn "docker group unavailable — ownership falls back to $RUN_USER only (the bootstrap playbook manages the group)"
fi
step "Setting ownership to $OWN_SPEC and permissions on the repository ..."
detail "Recursive over the whole checkout; a populated data_store/ makes this a"
detail "large walk that can take a while — live progress is shown below."
if [[ -d "$REPO_ROOT_DIR" ]]; then
    run_with_progress "   -> ownership  ($OWN_SPEC)" \
        $SUDO chown -R "$OWN_SPEC" "$REPO_ROOT_DIR" \
        || warn "Some ownership changes were skipped"
    run_with_progress "   -> permissions (u=rwX,g=rX,o=)" \
        $SUDO chmod -R u=rwX,g=rX,o= "$REPO_ROOT_DIR" \
        || warn "Some permission changes were skipped"
fi

################################################################################
# Install the pinned ansible layer into the checkout's own venv (PEP 668).
# There is no host python package any more — the engine logic lives in
# get-sybers/byakugan and the detections in GoDFIR-toolz, both inside
# images; requirements.txt is the one pip surface left (ansible-core + the
# docker SDK the collection's modules import on the controller).
#
# The venv is <repo>/.venv, NOT a system prefix: the dxdfir front-end
# resolves it by relation to the repo it just located (no PATH edit, profile
# drop-in or re-login in between), `. .venv/bin/activate` is the convention
# every python user already knows for direct ansible use, .gitignore already
# covers it, and it is created by the invoking user — no root-owned pip
# caches or venv files. $DXDFIR_VENV overrides the location (dxdfir and
# save-docker-images.sh honour the same variable).
################################################################################
section "Ansible (pinned)"
# /opt/dxdfir is the RETIRED prefix: an override still naming it (a stale
# export from an earlier release's shell, a forgotten ~/.bashrc line) would
# recreate exactly the layout this script retires — ignore it, loudly.
for _legacy in DXDFIR_VENV DXDFIR_COLLECTIONS DXDFIR_BIN_DIR; do
    if [[ "${!_legacy:-}" == /opt/dxdfir || "${!_legacy:-}" == /opt/dxdfir/* ]]; then
        warn "Ignoring $_legacy=${!_legacy} — /opt/dxdfir is the retired prefix; everything lives in the checkout now."
        unset "$_legacy"
    fi
done
DXDFIR_VENV="${DXDFIR_VENV:-$REPO_ROOT_DIR/.venv}"
step "Installing the pinned ansible layer into $DXDFIR_VENV ..."
python3 -m venv "$DXDFIR_VENV" || die "Failed to create the venv (need python3-venv)."
"$DXDFIR_VENV/bin/pip" install --quiet --upgrade pip || die "pip upgrade in the venv failed."
# requirements.txt pins the tested versions (the lock is the single source of truth)
"$DXDFIR_VENV/bin/pip" install --quiet -r "$REPO_ROOT_DIR/requirements.txt" \
    || die "Failed to install the pinned ansible layer (requirements.txt)."

# hold the venv to its contract: the front-end and the scripts call these by
# absolute path, so they must exist here
for _ans in ansible ansible-playbook ansible-galaxy; do
    [[ -x "$DXDFIR_VENV/bin/$_ans" ]] \
        || die "Expected $_ans in $DXDFIR_VENV/bin after installing ansible-core."
done
ok "ansible in the venv: $("$DXDFIR_VENV/bin/ansible-playbook" --version 2>/dev/null | head -1 || echo 'ansible-playbook')"
# The legacy system-prefix venv of earlier releases: nothing reads it any more
# (dxdfir resolves the repo venv, the profile.d drop-in below is rewritten
# without it), so retire it rather than leave a stale ansible around.
if [[ -d /opt/dxdfir/venv ]]; then
    $SUDO rm -rf /opt/dxdfir/venv && detail "Retired legacy venv /opt/dxdfir/venv"
fi
# The rest of THIS script run sees the venv directly (child launchers
# included); sudo steps keep invoking the venv binaries by absolute path.
export PATH="$DXDFIR_VENV/bin:$PATH"

################################################################################
# Build + install the Go/termui front-end; the pinned toolchain is
# (re)installed when absent or under go.mod's floor — GOTOOLCHAIN=local
# refuses auto-upgrades (docs: Design decisions).
################################################################################
section "Go toolchain + dxdfir front-end"
GO_VERSION="${GO_VERSION:-1.24.7}"
GO_MIN_MINOR=24
# a real file on a directory every default PATH already carries (sudo's
# secure_path included) — no shim, no drop-in, nothing to re-login for
DXDFIR_BIN_DIR="${DXDFIR_BIN_DIR:-/usr/local/bin}"
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
    # /usr/local/go/bin joins PATH for this run here and for login shells via
    # the /etc/profile.d drop-in written below (a rebuild convenience only —
    # nothing at runtime needs `go`).
    export PATH="/usr/local/go/bin:$PATH"
fi
step "Building the dxdfir Go front-end ($(go version 2>/dev/null | awk '{print $3}')) ..."

# build UNPRIVILEGED from a clean, ephemeral cache: deps resolve from
# go/vendor/ or the proxy every run, never a previous run's leftovers (docs:
# Design decisions); only the final install into $DXDFIR_BIN_DIR escalates
_gotmp="$(mktemp -d)"
_goclean() { [[ -n "$_gotmp" ]] && { chmod -R u+w "$_gotmp" 2>/dev/null; rm -rf "$_gotmp"; }; }
_goenv=( PATH="$PATH" HOME="$_gotmp" GOTOOLCHAIN=local
         GOCACHE="$_gotmp/build" GOMODCACHE="$_gotmp/mod" )
_gomod="-mod=mod"
[[ -f "$REPO_ROOT_DIR/go/vendor/modules.txt" ]] && _gomod="-mod=vendor"
if ! ( cd "$REPO_ROOT_DIR/go" \
        && env "${_goenv[@]}" go build "$_gomod" -o "$_gotmp/dxdfir" ./cmd/dxdfir ); then
    if [[ "$_gomod" == "-mod=vendor" ]]; then
        # A vendored tree captured before a dependency changed would fail an
        # update; fall back to the proxy rather than wedge on stale vendoring.
        warn "Vendored modules look stale — fetching through the module proxy instead."
        ( cd "$REPO_ROOT_DIR/go" \
            && env "${_goenv[@]}" go build -mod=mod -o "$_gotmp/dxdfir" ./cmd/dxdfir ) \
            || { _goclean; die "Failed to build the dxdfir Go front-end (module proxy unreachable? re-vendor on a networked host: 'cd go && go mod vendor')."; }
    else
        _goclean
        die "Failed to build the dxdfir Go front-end (need network for the module proxy, or vendor the modules for an air-gapped install: 'cd go && go mod vendor')."
    fi
fi
# a stale symlink from a legacy install would otherwise be followed
[[ -L "$DXDFIR_BIN_DIR/dxdfir" ]] && $SUDO rm -f "$DXDFIR_BIN_DIR/dxdfir"
$SUDO install -Dm755 "$_gotmp/dxdfir" "$DXDFIR_BIN_DIR/dxdfir" \
    || { _goclean; die "Failed to install dxdfir into $DXDFIR_BIN_DIR."; }
_goclean
# the legacy prefix binary of earlier releases (reachable only via the old
# drop-in): retire it so two dxdfir versions never coexist on a host
if [[ -f /opt/dxdfir/bin/dxdfir ]]; then
    $SUDO rm -f /opt/dxdfir/bin/dxdfir && $SUDO rmdir /opt/dxdfir/bin 2>/dev/null
    detail "Retired legacy binary /opt/dxdfir/bin/dxdfir"
fi
# the manual installs beside the binary; best-effort
$SUDO install -Dm644 "$REPO_ROOT_DIR/go/man/dxdfir.1" /usr/local/share/man/man1/dxdfir.1 2>/dev/null \
    || warn "Could not install the man page — read it in-tree: man ./go/man/dxdfir.1"

# One managed /etc/profile.d drop-in — a CONVENIENCE for login shells only
# (`go` for rebuilds, a bare `ansible-playbook` for hand-driven plays); dxdfir
# itself needs none of it. Venv bin APPENDED so the system python/pip keep
# winning. Written with an explicit mode: /etc/profile skips a drop-in it
# cannot read, and a strict umask under sudo would leave it 0600.
# Legacy shims from earlier releases are retired (docs: Design decisions).
step "Writing the PATH drop-in (/etc/profile.d/dxdfir.sh) and retiring legacy shims ..."
_dropin="$(mktemp)"
printf '%s\n' \
    "# Managed by DX_DFIR scripts/setup-environment.sh — a convenience for login" \
    "# shells: the pinned Go toolchain (rebuilds) and the repo venv's ansible*" \
    "# (hand-driven plays), venv appended so the system python/pip keep winning." \
    "# dxdfir itself lives in $DXDFIR_BIN_DIR and resolves the venv on its own." \
    "export PATH=\"/usr/local/go/bin:\$PATH:$DXDFIR_VENV/bin\"" > "$_dropin"
$SUDO install -m0644 "$_dropin" /etc/profile.d/dxdfir.sh \
    || { rm -f "$_dropin"; die "Failed to write /etc/profile.d/dxdfir.sh."; }
rm -f "$_dropin"
for _shim in dxdfir go ansible ansible-playbook ansible-galaxy; do
    if [[ -L "/usr/local/bin/$_shim" ]]; then
        case "$(readlink "/usr/local/bin/$_shim")" in
            /opt/dxdfir/*|"$DXDFIR_VENV/bin/"*|/usr/local/go/bin/*)
                $SUDO rm -f "/usr/local/bin/$_shim"
                detail "Retired legacy shim /usr/local/bin/$_shim" ;;
        esac
    fi
done
export PATH="/usr/local/go/bin:$PATH:$DXDFIR_VENV/bin"
ok "dxdfir (Go front-end) installed: $("$DXDFIR_BIN_DIR/dxdfir" --version 2>/dev/null || echo "$DXDFIR_BIN_DIR/dxdfir") -> $DXDFIR_BIN_DIR/dxdfir"

################################################################################
# Install the pinned Ansible dependencies (requirements.yml) into the
# checkout's own collection tree — .ansible/collections, gitignored, the
# first entry of ansible.cfg's collections_path — as the invoking user, like
# the venv: nothing of the pipeline lives under a system prefix any more.
################################################################################
section "Ansible collections"
# ansible's state home (ansible.cfg `home`): its local temp — where
# ansible-galaxy stages the downloaded tarballs — galaxy cache/token and
# persistent-connection sockets in the checkout, never ~/.ansible; the
# export makes that hold even where the repo-root ansible.cfg is not read
# (an ANSIBLE_CONFIG in the caller's shell, a world-writable checkout)
export ANSIBLE_HOME="$REPO_ROOT_DIR/.ansible"
# a timestamp to audit ~/.ansible against at the end: anything under it newer
# than this was written by this run, whether or not the directory predates it
_ansible_stamp=$(mktemp) || die "mktemp failed."
DXDFIR_COLLECTIONS="${DXDFIR_COLLECTIONS:-$REPO_ROOT_DIR/.ansible/collections}"
step "Installing pinned Ansible collections into $DXDFIR_COLLECTIONS ..."
"$DXDFIR_VENV/bin/ansible-galaxy" collection install \
    -r "$REPO_ROOT_DIR/ansible/collections/get_sybers.dxdfir/requirements.yml" \
    -p "$DXDFIR_COLLECTIONS" --force \
    || die "Failed to install the pinned Ansible collections (requirements.yml)."

# The build galaxy: the gitlink is the pin, the primary path installs
# NOTHING (roles_path resolves the submodule); only an absent submodule gets
# the galaxy imported from the .gitmodules source (docs: Design decisions).
TOOLZ_PATH="docker/GoDFIR-toolz"
if [[ -f "$REPO_ROOT_DIR/$TOOLZ_PATH/galaxy.yml" ]]; then
    ok "GoDFIR-toolz build galaxy resolves in place from the submodule (nothing installed)"
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
    "$DXDFIR_VENV/bin/ansible-galaxy" collection install "$TOOLZ_SRC" \
        -p "$DXDFIR_COLLECTIONS" --force --no-deps \
        || die "Failed to import the GoDFIR-toolz build galaxy from $TOOLZ_URL."
fi
ok "Collections installed: $("$DXDFIR_VENV/bin/ansible-galaxy" collection list -p "$DXDFIR_COLLECTIONS" 2>/dev/null | grep -cE '^[a-z]' || echo '?') pinned"
# the retired prefix, once its last tenant (the collections) has moved in-tree
if [[ -d /opt/dxdfir ]]; then
    $SUDO rm -rf /opt/dxdfir && detail "Retired legacy prefix /opt/dxdfir (nothing of the pipeline lives there any more)"
fi

################################################################################
# Docker engine + group — ansible, not shell (one implementation, shared with
# the deploy); a healthy host is a no-op.
################################################################################
section "Docker engine (ansible)"
step "Ensuring the Docker engine, daemon and group (dxdfir-bootstrap.yml) ..."
# the venv binary by ABSOLUTE path (as the collections step above): sudo's
# secure_path never carries the venv — a bare `sudo ansible-playbook` is
# command-not-found on exactly the fresh host this bootstrap exists for
# ANSIBLE_HOME through sudo (its env reset would otherwise send root's run to
# /root/.ansible): the same in-tree state home as the collections step
( cd "$REPO_ROOT_DIR" && $SUDO env ANSIBLE_HOME="$ANSIBLE_HOME" "$DXDFIR_VENV/bin/ansible-playbook" \
    ansible/collections/get_sybers.dxdfir/playbooks/dxdfir-bootstrap.yml ) \
    || die "Docker engine bootstrap failed (dxdfir-bootstrap.yml)."
ok "Docker engine present, daemon running, group membership ensured."

################################################################################
# Offline fallback: no route out -> load the pre-seeded tarballs; online
# hosts build normally and this section stays silent.
################################################################################
if ! curl -fsI --connect-timeout 4 --max-time 8 https://download.docker.com/ >/dev/null 2>&1; then
    section "Analysis images (offline fallback)"
    _tars="${DXDFIR_IMAGE_DIR:-$REPO_ROOT_DIR/data_store/docker_images}"
    if compgen -G "$_tars/*.tar" >/dev/null; then
        step "No internet — loading + verifying the pre-seeded image tarballs from $_tars ..."
        # --verify loads every tarball THEN runs the hardened-inventory audit
        # (both as playbooks; the launcher resolves the venv's ansible on its
        # own), so a missing or corrupt tarball fails here, not at first
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
# cmd — a command line with a dim aside
cmd() { printf '       %s%s%s  %s%s%s\n' "$C_ACCENT" "$1" "$C_RESET" "$C_DIM" "${2:-}" "$C_RESET"; }

section "Setup complete"
# Prove the install from a FRESH, NON-LOGIN shell with the default PATH — the
# case the profile.d drop-in never covered (`su user`, a desktop terminal,
# tmux) — rather than assert it. A failure here is the script's bug, not the
# operator's shell.
_probe="$(env -i HOME="$HOME" bash -c 'command -v dxdfir' 2>/dev/null)"
if [[ "$_probe" == "$DXDFIR_BIN_DIR/dxdfir" ]]; then
    ok "dxdfir resolves from a fresh non-login shell: $_probe (no re-login needed)"
else
    die "dxdfir does not resolve from a fresh shell (got '${_probe:-nothing}', expected $DXDFIR_BIN_DIR/dxdfir) — is $DXDFIR_BIN_DIR on the default PATH?"
fi
# ...and that the binary finds the venv's ansible on its own: the landing
# dashboard's readiness line, from the same clean environment.
_ap="$(env -i HOME="$HOME" NO_COLOR=1 bash -c "dxdfir --repo-root '$REPO_ROOT_DIR' --no-tui" 2>/dev/null \
    | grep -E '^ *\[[^]]*\] +ansible ' | head -1 | sed 's/^ *//')"
case "$_ap" in
    "[ok]"*) ok "dxdfir readiness: $_ap" ;;
    "")      warn "Could not read dxdfir's ansible readiness line — check 'dxdfir --no-tui'." ;;
    *)       die "dxdfir does not resolve the venv's ansible: $_ap" ;;
esac
# ...and that ansible kept its state in the checkout: anything under
# ~/.ansible written since the collections step (the directory itself, if the
# run created it) means the in-tree state home (ansible.cfg `home`,
# ANSIBLE_HOME) was not honoured somewhere — the script's regression, not the
# operator's. A ~/.ansible older than the run (an earlier release's, another
# ansible project's) is not the script's to judge, only to leave untouched.
_written=$(find "$HOME/.ansible" -newer "$_ansible_stamp" -print -quit 2>/dev/null)
rm -f "$_ansible_stamp"
if [[ -n "$_written" ]]; then
    die "This run wrote under $HOME/.ansible ($_written) — ansible's state belongs in $REPO_ROOT_DIR/.ansible (ansible.cfg 'home')."
elif [[ -e "$HOME/.ansible" ]]; then
    ok "ansible state (temp, galaxy cache) stays in $REPO_ROOT_DIR/.ansible — the pre-existing $HOME/.ansible was not written to"
else
    ok "ansible state (temp, galaxy cache) stays in $REPO_ROOT_DIR/.ansible — nothing under $HOME/.ansible"
fi

# The docker group is the ONE thing a re-login is genuinely needed for, and
# only when the membership is newer than the shell: compare the account's
# groups (the file) with the running process's.
if [[ "$EUID" -ne 0 ]] && id -nG "$RUN_USER" 2>/dev/null | tr ' ' '\n' | grep -qx docker \
    && ! id -nG | tr ' ' '\n' | grep -qx docker; then
    warn "Your docker-group membership is new — this shell does not carry it yet."
    detail "Run 'newgrp docker' here, or log out and back in once; dxdfir itself needs neither."
elif [[ "$DOCKER_WAS_INSTALLED" == false ]]; then
    ok "Docker engine installed."
fi
echo

step "Run DX_DFIR (works in this shell as it is):"
cmd "dxdfir --help" "(process evidence, build + verify CAR, deploy the analysis stack — see README.md)"
echo
step "Build the hardened tool containers (everything the pipeline runs):"
cmd "dxdfir build-docker" "(runs dxdfir-build-images.yml with the venv's ansible)"
echo
step "Drive ansible by hand (the venv is the repo's own):"
cmd ". $DXDFIR_VENV/bin/activate" "(login shells also get it from /etc/profile.d/dxdfir.sh)"
echo
step "Pre-seed the analysis images as tarballs for an offline host:"
cmd "scripts/save-docker-images.sh --build" "(connected host: build + save every image)"
cmd "scripts/save-docker-images.sh --load" "(offline host: load tarballs — or just re-run this script)"
echo
