#!/bin/bash
# ==============================================================================
# Prepare a host to run the DX_DFIR.

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
step "2. Set ownership and permissions on the DX_DFIR repository"
step "3. Install the pinned Ansible layer (repo-local .venv) and the pinned collections"
detail "get_sybers.godfir_run is imported by URL into .ansible/collections from"
detail "requirements.yml (no submodule)"
step "4. Ensure the Docker engine, daemon and group via ansible (dxdfir-bootstrap.yml)"
detail "the Byakugan CAR engine and every tool image are pulled from the registry"
detail "(ghcr.io/get-sybers/GoDFIR-toolz/<tool>) by 'dxdfir build-docker'"
echo

confirm "Do you wish to proceed?" || { info "Setup cancelled."; exit 1; }

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
    id -nG "$RUN_USER" 2>/dev/null | tr ' ' '\n' | grep -qx docker \
        || $SUDO usermod -aG docker "$RUN_USER" \
        || warn "Could not add $RUN_USER to the docker group — run 'sudo usermod -aG docker $RUN_USER' manually."
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
# The rest of THIS script run sees the venv directly (child launchers
# included); sudo steps keep invoking the venv binaries by absolute path.
export PATH="$DXDFIR_VENV/bin:$PATH"

################################################################################
# Build + install the Go/termui front-end; the pinned toolchain is
# (re)installed when absent or under go.mod's floor — GOTOOLCHAIN=local
# refuses auto-upgrades (docs: Design decisions).
################################################################################
section "Go toolchain + dxdfir front-end"
# The ONE source of the Go toolchain version is go/go.mod's `go` directive
# (standards §2: scripts read the tracked pin, never carry their own copy).
GO_VERSION="$(grep -E '^go [0-9]+\.[0-9]+(\.[0-9]+)?$' "$REPO_ROOT_DIR/go/go.mod" | awk '{print $2}')"
[[ -n "$GO_VERSION" ]] || die "could not read the go directive from go/go.mod"
GO_MIN_MINOR="$(cut -d. -f2 <<<"$GO_VERSION")"
# The Go toolchain and the built dxdfir binary both live inside the checkout
# at .go/ (gitignored), so nothing escapes the repo root.
DXDFIR_GO_ROOT="$REPO_ROOT_DIR/.go"
DXDFIR_BIN_DIR="${DXDFIR_BIN_DIR:-$DXDFIR_GO_ROOT/bin}"
_go_ok=0
if [[ -x "$DXDFIR_GO_ROOT/bin/go" ]]; then
    _gominor="$("$DXDFIR_GO_ROOT/bin/go" version 2>/dev/null | grep -oE 'go1\.[0-9]+' | head -1 | cut -d. -f2)"
    [[ "$_gominor" =~ ^[0-9]+$ ]] && (( _gominor >= GO_MIN_MINOR )) && _go_ok=1
fi
if (( ! _go_ok )); then
    [[ -x "$DXDFIR_GO_ROOT/bin/go" ]] \
        && info "Found Go $("$DXDFIR_GO_ROOT/bin/go" version 2>/dev/null | awk '{print $3}') — older than go.mod's 1.${GO_MIN_MINOR} floor; replacing it."
    step "Installing the Go toolchain ($GO_VERSION) into .go/ ..."
    case "$(uname -m)" in
        x86_64)        _garch=amd64 ;;
        aarch64|arm64) _garch=arm64 ;;
        *) die "unsupported architecture for the Go toolchain: $(uname -m)" ;;
    esac
    _gotar="go${GO_VERSION}.linux-${_garch}.tar.gz"
    curl -fsSL "https://go.dev/dl/${_gotar}" -o "/tmp/${_gotar}" \
        || die "Failed to download the Go toolchain (${_gotar})."
    # Supply-chain: verify the tarball against Go's published SHA-256 BEFORE
    # extracting it into .go/. Refuse to install on a mismatch.
    _gosha="$(curl -fsSL "https://go.dev/dl/?mode=json&include=all" \
        | python3 -c 'import sys, json; d = json.load(sys.stdin); print(next((f["sha256"] for v in d for f in v["files"] if f.get("filename") == sys.argv[1]), ""))' \
            "${_gotar}")" \
        || die "Failed to fetch the Go toolchain checksum from the go.dev release index."
    [[ "$_gosha" =~ ^[0-9a-f]{64}$ ]] \
        || die "No SHA-256 for ${_gotar} in the go.dev release index (looked up go${GO_VERSION}) — check the pinned GO_VERSION names a real release."
    printf '%s  %s\n' "$_gosha" "/tmp/${_gotar}" | sha256sum -c --status - \
        || die "Go toolchain checksum mismatch for ${_gotar} — refusing to install."
    detail "Verified go${GO_VERSION} (${_garch}) against the go.dev published SHA-256."
    rm -rf "$DXDFIR_GO_ROOT"
    mkdir -p "$DXDFIR_GO_ROOT"
    tar -C "$DXDFIR_GO_ROOT" --strip-components=1 -xzf "/tmp/${_gotar}" \
        || die "Failed to extract the Go toolchain into $DXDFIR_GO_ROOT."
    rm -f "/tmp/${_gotar}"
fi
export PATH="$DXDFIR_GO_ROOT/bin:$PATH"
step "Building the dxdfir Go front-end ($("$DXDFIR_GO_ROOT/bin/go" version 2>/dev/null | awk '{print $3}')) ..."

# build UNPRIVILEGED from a clean, ephemeral cache: deps resolve from
# go/vendor/ or the proxy every run, never a previous run's leftovers (docs:
# Design decisions); the binary installs into the in-repo .go/bin/
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
install -Dm755 "$_gotmp/dxdfir" "$DXDFIR_BIN_DIR/dxdfir" \
    || { _goclean; die "Failed to install dxdfir into $DXDFIR_BIN_DIR."; }
_goclean
export PATH="$DXDFIR_GO_ROOT/bin:$PATH:$DXDFIR_VENV/bin"
ok "dxdfir (Go front-end) installed: $("$DXDFIR_BIN_DIR/dxdfir" --version 2>/dev/null || echo "$DXDFIR_BIN_DIR/dxdfir") -> $DXDFIR_BIN_DIR/dxdfir"
detail "man page: man $REPO_ROOT_DIR/go/man/dxdfir.1"

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

# The container-interaction galaxy (get_sybers.godfir_run) is pinned in
# requirements.yml as a git-URL collection and was installed by the step above,
# straight into .ansible/collections — no submodule, no separate import.
ok "Collections installed: $("$DXDFIR_VENV/bin/ansible-galaxy" collection list -p "$DXDFIR_COLLECTIONS" 2>/dev/null | grep -cE '^[a-z]' || echo '?') pinned (incl. get_sybers.godfir_run from its git URL)"

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
# Verify the in-repo binary exists and can find its venv's ansible.
if [[ -x "$DXDFIR_BIN_DIR/dxdfir" ]]; then
    ok "dxdfir binary: $("$DXDFIR_BIN_DIR/dxdfir" --version 2>/dev/null || echo "$DXDFIR_BIN_DIR/dxdfir")"
else
    die "dxdfir binary not found at $DXDFIR_BIN_DIR/dxdfir"
fi
_ap="$(NO_COLOR=1 "$DXDFIR_BIN_DIR/dxdfir" --repo-root "$REPO_ROOT_DIR" --no-tui 2>/dev/null \
    | grep -E '^ *\[[^]]*\] +ansible ' | head -1 | sed 's/^ *//')"
case "$_ap" in
    "[ok]"*) ok "dxdfir readiness: $_ap" ;;
    "")      warn "Could not read dxdfir's ansible readiness line — check '.go/bin/dxdfir --no-tui'." ;;
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