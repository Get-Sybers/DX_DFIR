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
step "4. Install the Python package + Ansible (venv) and the pinned collections"
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
# Install the pinned ansible layer into a dedicated venv (PEP 668). There is
# no host python package any more — the engine logic lives in
# get-sybers/byakugan and the detections in GoDFIR-toolz, both inside
# images; requirements.txt is the one pip surface left (ansible-core + the
# docker SDK the collection's modules import on the controller).
################################################################################
section "Ansible (pinned)"
DXDFIR_VENV="${DXDFIR_VENV:-/opt/dxdfir/venv}"
step "Installing the pinned ansible layer into $DXDFIR_VENV ..."
$SUDO python3 -m venv "$DXDFIR_VENV" || die "Failed to create the venv (need python3-venv)."
$SUDO "$DXDFIR_VENV/bin/pip" install --quiet --upgrade pip || die "pip upgrade in the venv failed."
# requirements.txt pins the tested versions (the lock is the single source of truth)
$SUDO "$DXDFIR_VENV/bin/pip" install --quiet -r "$REPO_ROOT_DIR/requirements.txt" \
    || die "Failed to install the pinned ansible layer (requirements.txt)."

# ansible lands in the same venv bin; PATH picks it up via /etc/profile.d
# below (no symlink shims) — here just
# hold the venv to its contract.
for _ans in ansible ansible-playbook ansible-galaxy; do
    [[ -x "$DXDFIR_VENV/bin/$_ans" ]] \
        || die "Expected $_ans in $DXDFIR_VENV/bin after installing ansible-core."
done
ok "ansible in the venv: $("$DXDFIR_VENV/bin/ansible-playbook" --version 2>/dev/null | head -1 || echo 'ansible-playbook')"
# The rest of THIS script run sees the venv directly (child launchers
# included); new shells get it from the profile.d drop-in written below, and
# sudo steps keep invoking the venv binaries by absolute path regardless.
export PATH="$DXDFIR_VENV/bin:$PATH"

################################################################################
# Build + install the Go/termui front-end; the pinned toolchain is
# (re)installed when absent or under go.mod's floor — GOTOOLCHAIN=local
# refuses auto-upgrades (docs: Design decisions).
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
    # No symlink shim: /usr/local/go/bin joins PATH for this run here and for
    # every shell via the /etc/profile.d drop-in written below.
    export PATH="/usr/local/go/bin:$PATH"
fi
step "Building the dxdfir Go front-end ($(go version 2>/dev/null | awk '{print $3}')) ..."
$SUDO mkdir -p "$GO_BIN_DIR"

# build from a clean, ephemeral cache: deps resolve from go/vendor/ or the
# proxy every run, never a previous run's leftovers (docs: Design decisions)
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
# the manual installs beside the binary; best-effort
$SUDO install -Dm644 "$REPO_ROOT_DIR/go/man/dxdfir.1" /usr/local/share/man/man1/dxdfir.1 2>/dev/null \
    || warn "Could not install the man page — read it in-tree: man ./go/man/dxdfir.1"

# PATH via one managed /etc/profile.d drop-in — venv bin APPENDED so the
# system python/pip keep winning; legacy shims retired (docs: Design decisions)
step "Writing the PATH drop-in (/etc/profile.d/dxdfir.sh) and retiring legacy shims ..."
printf '%s\n' \
    "# Managed by DX_DFIR scripts/setup-environment.sh — no symlink shims:" \
    "# the real tool locations join PATH. The venv bin is appended so its" \
    "# ansible* resolve while the system python/pip keep winning by order." \
    "export PATH=\"$GO_BIN_DIR:/usr/local/go/bin:\$PATH:$DXDFIR_VENV/bin\"" \
    | $SUDO tee /etc/profile.d/dxdfir.sh >/dev/null \
    || die "Failed to write /etc/profile.d/dxdfir.sh."
for _shim in dxdfir go ansible ansible-playbook ansible-galaxy; do
    if [[ -L "/usr/local/bin/$_shim" ]]; then
        case "$(readlink "/usr/local/bin/$_shim")" in
            "$GO_BIN_DIR/"*|"$DXDFIR_VENV/bin/"*|/usr/local/go/bin/*)
                $SUDO rm -f "/usr/local/bin/$_shim"
                detail "Retired legacy shim /usr/local/bin/$_shim" ;;
        esac
    fi
done
export PATH="$GO_BIN_DIR:/usr/local/go/bin:$PATH:$DXDFIR_VENV/bin"
ok "dxdfir (Go front-end) installed: $("$GO_BIN_DIR/dxdfir" --version 2>/dev/null || echo "$GO_BIN_DIR/dxdfir") — new shells pick PATH up from /etc/profile.d/dxdfir.sh"

################################################################################
# Install the pinned Ansible dependencies (requirements.yml) to the fixed
# shared path ansible.cfg puts on collections_path.
################################################################################
section "Ansible collections"
DXDFIR_COLLECTIONS="${DXDFIR_COLLECTIONS:-/opt/dxdfir/collections}"
step "Installing pinned Ansible collections into $DXDFIR_COLLECTIONS ..."
$SUDO "$DXDFIR_VENV/bin/ansible-galaxy" collection install \
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
    $SUDO "$DXDFIR_VENV/bin/ansible-galaxy" collection install "$TOOLZ_SRC" \
        -p "$DXDFIR_COLLECTIONS" --force --no-deps \
        || die "Failed to import the GoDFIR-toolz build galaxy from $TOOLZ_URL."
fi
ok "Collections installed: $("$DXDFIR_VENV/bin/ansible-galaxy" collection list -p "$DXDFIR_COLLECTIONS" 2>/dev/null | grep -cE '^[a-z]' || echo '?') pinned"

################################################################################
# Docker engine + group — ansible, not shell (one implementation, shared with
# the deploy); a healthy host is a no-op.
################################################################################
section "Docker engine (ansible)"
step "Ensuring the Docker engine, daemon and group (dxdfir-bootstrap.yml) ..."
# the venv binary by ABSOLUTE path (as the collections step above): the
# profile.d drop-in only reaches NEW shells, and sudo's secure_path never
# carries the venv — a bare `sudo ansible-playbook` is command-not-found on
# exactly the fresh host this bootstrap exists for
( cd "$REPO_ROOT_DIR" && $SUDO "$DXDFIR_VENV/bin/ansible-playbook" \
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
if [[ "$DOCKER_WAS_INSTALLED" == false ]]; then
    warn "Log out and back in for the Docker group change to take effect."
else
    ok "Docker was already present; if the bootstrap just added you to the docker group, log out and back in once."
fi
echo

step "Use dxdfir in THIS shell (new logins pick PATH up automatically):"
cmd ". /etc/profile.d/dxdfir.sh" "(the log-out/in above also applies it, along with the docker group)"
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
