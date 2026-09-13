#!/bin/bash
# ==============================================================================
# Prepare a host to run the DX_DFIR scripts.
#
# Installs Docker and the handful of userland tools the processing scripts
# shell out to, puts the invoking user in the docker group, and sets
# ownership/permissions on the repository.
#
# Pre-seeding the analysis images as offline tarballs is a separate concern
# with its own online/offline lifecycle — it now lives in
# scripts/save-docker-images.sh. The processing scripts pull their images on
# first use, so a host with registry access needs nothing further here.
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
#   - unzip is installed, not merely hoped for. the velociraptor lane hard
#     exits without it and the old script never mentioned it.
#
# Usage: scripts/setup-environment.sh [--yes] [--help]
# ==============================================================================

set -o pipefail

################################################################################
# Establish DX_DFIR repo filepath
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
REPO_ROOT_DIR="$(realpath "$SCRIPT_DIR/..")"

# Userland tools the pipeline shells out to. python3 runs the get_sybers_dxdfir
# package, unzip backs the velociraptor lane, tar backs the image tarballs
# written by save-docker-images.sh, curl fetches sample fixtures.
# ca-certificates and gnupg are needed to add the Docker repo itself.
APT_DEPS=(ca-certificates curl git gnupg unzip python3 python3-venv tar)
REQUIRED_CMDS=(curl git python3 unzip tar realpath readlink)

ASSUME_YES=false

################################################################################
# Argument parsing
while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--yes) ASSUME_YES=true ;;
        -h|--help)
            sed -n '2,42p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "❌ Unknown option: $1"
            echo "   Usage: $0 [--yes] [--help]"
            exit 1
            ;;
    esac
    shift
done

# A non-interactive run cannot answer a prompt, so it takes the documented
# defaults rather than failing every `read` and pretending that was a choice.
if [[ ! -t 0 ]] && [[ "$ASSUME_YES" != true ]]; then
    echo "ℹ️  stdin is not a TTY — running non-interactively (implies --yes)."
    ASSUME_YES=true
fi

die() { echo "❌ $*" >&2; exit 1; }

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
        echo "➡️  $prompt [assuming yes]"
        return 0
    fi
    local reply
    read -r -p "$prompt (y/n) " reply
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
echo ""
echo " ██████╗ ███████╗████████╗   ███████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗"
echo "██╔════╝ ██╔════╝╚══██╔══╝   ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝"
echo "██║  ███╗█████╗     ██║█████╗███████╗ ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗"
echo "██║   ██║██╔══╝     ██║╚════╝╚════██║  ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║"
echo "╚██████╔╝███████╗   ██║      ███████║   ██║   ██████╔╝███████╗██║  ██║███████║"
echo " ╚═════╝ ╚══════╝   ╚═╝      ╚══════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝"
echo ""
echo "📂 Repository: $REPO_ROOT_DIR"

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

       🤨  RUNNING AS ROOT
       ⚠️   Normal in a container, worth a second look on a workstation —
            the final step rewrites ownership across the repository.

EOF
    confirm "Continue as root?" || die "Aborted at the root check."
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    die "Not root and sudo is not installed. Re-run as root, or install sudo first."
fi

################################################################################
# Install Docker if not already installed
DOCKER_WAS_INSTALLED=true

if ! command -v docker >/dev/null 2>&1; then
    echo "❌ Docker not found. Installing Docker..."
    DOCKER_WAS_INSTALLED=false

    # Derive the Docker apt repo from the running distro. Derivatives (Mint,
    # Pop!_OS) carry UBUNTU_CODENAME; Docker publishes no repo of their own.
    # shellcheck disable=SC1091
    . /etc/os-release
    case "$ID" in
        debian|ubuntu) DOCKER_DISTRO="$ID" ;;
        *)
            case "$ID_LIKE" in
                *ubuntu*) DOCKER_DISTRO="ubuntu" ;;
                *debian*) DOCKER_DISTRO="debian" ;;
                *) die "Unsupported distro '$ID'. Install Docker manually, then re-run." ;;
            esac
            ;;
    esac
    DOCKER_CODENAME="${UBUNTU_CODENAME:-$VERSION_CODENAME}"
    [[ -n "$DOCKER_CODENAME" ]] || die "Could not determine the distro codename from /etc/os-release."
    echo "   Using Docker repository for $DOCKER_DISTRO/$DOCKER_CODENAME"

    $SUDO apt-get update || die "apt-get update failed."
    $SUDO apt-get install -y "${APT_DEPS[@]}" || die "Failed to install prerequisites."

    $SUDO install -m 0755 -d /etc/apt/keyrings
    $SUDO curl -fsSL "https://download.docker.com/linux/$DOCKER_DISTRO/gpg" \
        -o /etc/apt/keyrings/docker.asc || die "Failed to fetch the Docker signing key."
    $SUDO chmod a+r /etc/apt/keyrings/docker.asc

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$DOCKER_DISTRO $DOCKER_CODENAME stable" \
        | $SUDO tee /etc/apt/sources.list.d/docker.list > /dev/null

    $SUDO apt-get update || die "apt-get update failed after adding the Docker repository."
    $SUDO apt-get install -y docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin || die "Docker installation failed."

    echo "✅ Docker installed successfully!"
else
    echo "✅ Docker already installed: $(docker --version)"
fi

################################################################################
# Install the userland tools the processing scripts need.
#
# The old script installed none of these. The velociraptor lane exits on a
# missing unzip, and nothing in the pipeline runs without python3 — each one
# an error the analyst hit halfway through an ingest instead of here.
MISSING_DEPS=()
for cmd in "${REQUIRED_CMDS[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 || MISSING_DEPS+=("$cmd")
done

if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
    echo "🔧 Installing missing tools: ${MISSING_DEPS[*]}"
    $SUDO apt-get update || die "apt-get update failed."
    $SUDO apt-get install -y "${APT_DEPS[@]}" || die "Failed to install: ${MISSING_DEPS[*]}"
else
    echo "✅ Required tools present: ${REQUIRED_CMDS[*]}"
fi

################################################################################
# Docker group membership.
#
# $USER is empty under `sudo` and in most non-login shells, so the old
# `usermod -aG docker "$USER"` could expand to a no-op that failed loudly or,
# worse, quietly. id -un always answers.
if ! getent group docker > /dev/null; then
    $SUDO groupadd docker
fi

if id -nG "$RUN_USER" | tr ' ' '\n' | grep -qx docker; then
    echo "✅ $RUN_USER is already in the docker group"
else
    $SUDO usermod -aG docker "$RUN_USER" && \
        echo "✅ Added $RUN_USER to the docker group"
fi

################################################################################
# Present user with what this script will do
echo -e "\n================== Setup Actions ==================\n"
echo "1. ✅ Check and install Docker (completed)"
echo "2. ✅ Install required userland tools (completed)"
echo "3. ✅ Set up Docker group permissions (completed)"
echo "4. 🔧 Initialise the git submodules (recursively)"
echo "5. 🔧 Provision the external Byakugan engine at its pinned commit"
echo "     (and build its Go parse binary, once the Go toolchain is in place)"
echo "6. 🔧 Set ownership and permissions on the DX_DFIR repository"
echo -e "\n==================================================\n"

confirm "Do you wish to proceed?" || { echo "Setup cancelled."; exit 1; }

################################################################################
# Pull the git submodules — RECURSIVELY.
#
# The remaining vendored submodule is third_party/piiat-mem: the PIIAT-Mem tree
# the volatility lane (get_sybers_dxdfir.volatility) drives in place. --recursive
# is kept on principle even though piiat-mem nests nothing today: it is a no-op
# then, and it means any submodule that DOES nest content checks out complete
# instead of silently empty — the failure mode that bit the CAR engine while it
# was vendored here. (The Byakugan engine is no longer a submodule; it is
# provisioned as an external checkout in the next step.) Runs before the
# chown/chmod below so the freshly checked-out files inherit them too.
if [[ -f "$REPO_ROOT_DIR/.gitmodules" ]]; then
    echo "🔗 Initialising git submodules (recursive)..."
    # safe.directory is scoped to THIS invocation with `-c` (the repo may be owned
    # by a different user until the chown below); git_safe_flags trusts the repo
    # root — and, on git >= 2.46, only the paths beneath it.
    git_safe_flags "$REPO_ROOT_DIR"
    GIT_SAFE=("${GIT_SAFE_FLAGS[@]}")
    git "${GIT_SAFE[@]}" -C "$REPO_ROOT_DIR" submodule sync --recursive >/dev/null 2>&1 || true
    git "${GIT_SAFE[@]}" -C "$REPO_ROOT_DIR" submodule update --init --recursive \
        || die "Failed to initialise git submodules recursively (need network + git access)."
    echo "✅ Submodules checked out (third_party/piiat-mem)."
else
    echo "ℹ️  No .gitmodules found — skipping submodule init."
fi

################################################################################
# Provision the external Byakugan engine at its pinned commit.
#
# The CAR lane (get_sybers_dxdfir.mitrecar) drives the Byakugan engine from an
# EXTERNAL checkout, resolved exactly as the python seam resolves it:
# $BYAKUGAN_ROOT when set, else the `byakugan` directory next to (a sibling of)
# this repository. The commit is pinned in byakugan.ref at the repo root (the
# first non-comment line) — the version the pipeline is tested against; bump it
# there, then re-run this script.
#
# The engine's OWN nested submodules (third_party/car, third_party/
# attack-datasources) are REQUIRED at runtime — it reconstructs its object
# model live from them — so every path below inits them recursively.
#
# Deliberately NO $SUDO here: the engine lives OUTSIDE the repository in the
# invoking user's space, and the repo-scoped chown below does not cover it —
# a root-owned sibling checkout would be exactly the permissions trap the
# chown exists to avoid.
BYAKUGAN_ROOT="${BYAKUGAN_ROOT:-$(dirname "$REPO_ROOT_DIR")/byakugan}"
BYAKUGAN_URL="https://github.com/Get-Sybers/byakugan"
# Same scoped safe.directory guard as the submodule step above: a re-run under
# a different uid than the one that provisioned the checkout (root vs operator)
# must not die at git's dubious-ownership check with a misleading origin error.
git_safe_flags "$BYAKUGAN_ROOT"
BYA_GIT=(git "${GIT_SAFE_FLAGS[@]}")
BYAKUGAN_REF="$(grep -vE '^[[:space:]]*(#|$)' "$REPO_ROOT_DIR/byakugan.ref" 2>/dev/null | head -1 | tr -d '[:space:]')"
[[ -n "$BYAKUGAN_REF" ]] \
    || die "no pinned engine commit — byakugan.ref at the repo root must carry a sha on its first non-comment line."

if [[ -e "$BYAKUGAN_ROOT/.git" ]]; then
    # An existing checkout: only accept it if origin really is the engine repo
    # (case-insensitive, .git suffix and trailing slash optional — https and
    # ssh remotes both end [/:]owner/repo). Anything else at the resolved path
    # is somebody else's directory; refusing beats silently rebasing it.
    _origin="$("${BYA_GIT[@]}" -C "$BYAKUGAN_ROOT" remote get-url origin 2>/dev/null)"
    _origin_norm="${_origin,,}"; _origin_norm="${_origin_norm%/}"; _origin_norm="${_origin_norm%.git}"
    [[ "$_origin_norm" == *[/:]get-sybers/byakugan ]] \
        || die "$BYAKUGAN_ROOT is a git repo but its origin ('$_origin') is not $BYAKUGAN_URL — move it aside, or point \$BYAKUGAN_ROOT elsewhere."
    if [[ "$("${BYA_GIT[@]}" -C "$BYAKUGAN_ROOT" rev-parse HEAD 2>/dev/null)" == "$BYAKUGAN_REF" ]]; then
        # Already on the pin: skip the fetch so a re-run works offline; the
        # submodule update below is then a local no-op (or a first init).
        echo "🔭 Byakugan engine already at the pinned commit ($BYAKUGAN_ROOT)."
    else
        echo "🔭 Updating the Byakugan engine at $BYAKUGAN_ROOT to the pinned commit ..."
        "${BYA_GIT[@]}" -C "$BYAKUGAN_ROOT" fetch origin \
            || die "failed to fetch the Byakugan engine (need network + git access)."
        "${BYA_GIT[@]}" -C "$BYAKUGAN_ROOT" checkout --quiet "$BYAKUGAN_REF" \
            || die "failed to check out the pinned engine commit $BYAKUGAN_REF."
    fi
    "${BYA_GIT[@]}" -C "$BYAKUGAN_ROOT" submodule update --init --recursive \
        || die "failed to initialise the engine's nested submodules (car + attack-datasources)."
elif [[ -e "$BYAKUGAN_ROOT" ]]; then
    die "$BYAKUGAN_ROOT exists but is not a git checkout — move it aside, or point \$BYAKUGAN_ROOT at the real engine checkout."
else
    echo "🔭 Cloning the Byakugan engine to $BYAKUGAN_ROOT ..."
    git clone "$BYAKUGAN_URL" "$BYAKUGAN_ROOT" \
        || die "failed to clone the Byakugan engine (need network + git access)."
    "${BYA_GIT[@]}" -C "$BYAKUGAN_ROOT" checkout --quiet "$BYAKUGAN_REF" \
        || die "failed to check out the pinned engine commit $BYAKUGAN_REF."
    "${BYA_GIT[@]}" -C "$BYAKUGAN_ROOT" submodule update --init --recursive \
        || die "failed to initialise the engine's nested submodules (car + attack-datasources)."
fi
echo "✅ Byakugan engine provisioned: $BYAKUGAN_ROOT @ $BYAKUGAN_REF"
# NOTE: the engine's Go parse binary (go/bin/byakugan-parse) is built further
# down, AFTER the Go toolchain section — `go` is not guaranteed on PATH here.

################################################################################
# Set ownership and permissions for DX_DFIR.
#
# u=rwX,g=rX — capital X applies the execute bit to directories and to files
# that already carry one, so directories stay traversable by the docker group
# and the .sh files stay runnable, while evidence files are left non-executable.
# The old `chmod -R 744` cleared group execute on directories and locked the
# docker group out of the tree the script had just handed it.
echo "🔧 Setting ownership to $RUN_USER:docker and permissions on the repository..."
echo "   Recursive over the whole checkout; a populated data_store/ makes this a"
echo "   large walk that can take a while — live progress is shown below."
if [[ -d "$REPO_ROOT_DIR" ]]; then
    run_with_progress "   → ownership  ($RUN_USER:docker)" \
        $SUDO chown -R "$RUN_USER:docker" "$REPO_ROOT_DIR" \
        || echo "⚠️  Some ownership changes were skipped"
    run_with_progress "   → permissions (u=rwX,g=rX,o=)" \
        $SUDO chmod -R u=rwX,g=rX,o= "$REPO_ROOT_DIR" \
        || echo "⚠️  Some permission changes were skipped"
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
# RELATIVE TO ITS OWN FILES (_REPO_ROOT = three dirs up from __file__):
# volatility.py locates the vendored piiat-mem tree (third_party/piiat-mem),
# carcheck.py defaults its --car-dir under the repo's data_store, and
# mitrecar.py anchors the Byakugan engine's SIBLING-DIR default (and reads
# byakugan.ref) at that same root. A plain copying install puts the package
# under the venv's site-packages, three dirs up from which is .../lib/pythonX.Y
# with no third_party/, data_store/ or byakugan.ref — the volatility lane dies
# "not initialised" even though the submodule WAS initialised (above), and the
# engine default degrades to a path nothing provisioned. Editable keeps the
# installed module IN the repo tree, so every _REPO_ROOT-relative path resolves.
################################################################################
DXDFIR_VENV="${DXDFIR_VENV:-/opt/dxdfir/venv}"
echo "🐍 Installing the get_sybers_dxdfir package (+ ansible) into $DXDFIR_VENV ..."
$SUDO python3 -m venv "$DXDFIR_VENV" || die "Failed to create the venv (need python3-venv)."
$SUDO "$DXDFIR_VENV/bin/pip" install --quiet --upgrade pip || die "pip upgrade in the venv failed."
# --constraint pins the exact, tested dependency versions from python/constraints.txt
# (pyproject carries the ">=" floors; the lock is the single source of truth this
# installer AND scripts/package-offline.sh consume). Without it a fresh install pulls
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
echo "✅ ansible on PATH: $(/usr/local/bin/ansible-playbook --version 2>/dev/null | head -1 || echo 'ansible-playbook')"

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
        && echo "🐹 Found Go $(go version 2>/dev/null | awk '{print $3}') — older than go.mod's 1.${GO_MIN_MINOR} floor; replacing it."
    echo "🐹 Installing the Go toolchain ($GO_VERSION) ..."
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
    echo "   🔒 Verified go${GO_VERSION} (${_garch}) against the go.dev published SHA-256."
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf "/tmp/${_gotar}" || die "Failed to extract the Go toolchain."
    rm -f "/tmp/${_gotar}"
    $SUDO ln -sf /usr/local/go/bin/go /usr/local/bin/go
    export PATH="/usr/local/go/bin:$PATH"
fi
echo "🐹 Building the dxdfir Go front-end ($(go version 2>/dev/null | awk '{print $3}')) ..."
$SUDO mkdir -p "$GO_BIN_DIR"

# Build from a CLEAN, EPHEMERAL cache — a throwaway dir (module cache, build
# cache and HOME all inside it) removed as soon as the build finishes. Every run
# therefore resolves the dependency set from a SOURCE OF TRUTH — the in-tree
# go/vendor/ (air-gapped installs, packaged by scripts/package-offline.sh), else
# the module proxy — instead of trusting whatever a previous run left on disk.
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
        echo "⚠️  Vendored modules look stale — fetching through the module proxy instead."
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
    || echo "⚠️  Could not install the man page — read it in-tree: man ./go/man/dxdfir.1"
echo "✅ dxdfir (Go front-end) installed: $(/usr/local/bin/dxdfir --version 2>/dev/null || echo "$GO_BIN_DIR/dxdfir")"

################################################################################
# Build the Byakugan engine's OWN Go parse binary (go/bin/byakugan-parse).
#
# The engine's file ingestion REQUIRES it: `python -m byakugan` refuses to parse
# evidence and prints build instructions when the binary is missing, so an
# engine checkout that is provisioned but unbuilt fails on the analyst's first
# build-car instead of here. This is a build of the ENGINE's module
# (github.com/get-sybers/byakugan/go), not of this repo's go/ front-end.
#
# It runs HERE, not next to the engine checkout above, purely because of script
# order: the checkout step happens before the Go toolchain is installed, and
# `go` is only guaranteed on PATH from this point on. $BYAKUGAN_ROOT and
# $BYAKUGAN_REF are still in scope from that step.
#
# Deliberately NO $SUDO — same reason the checkout above has none: the engine
# lives OUTSIDE the repository in the invoking user's space, and a root-owned
# build artefact there is exactly the permissions trap the repo chown avoids.
# GOTOOLCHAIN=local matches the front-end build: never auto-download a newer Go.
#
# The command below mirrors `make -C "$BYAKUGAN_ROOT/go" build` exactly (same
# package, same output path) without making `make` a dependency of this script.
################################################################################
[[ -d "$BYAKUGAN_ROOT/go" ]] \
    || die "the Byakugan engine at $BYAKUGAN_ROOT has no go/ directory — the pinned commit ($BYAKUGAN_REF) predates the Go parse binary, or the checkout is incomplete. Bump byakugan.ref, or re-provision the engine."
echo "🐹 Building the Byakugan engine's Go parse binary ($(go version 2>/dev/null | awk '{print $3}')) ..."
# HOME="${HOME:-/root}" for the same reason the front-end build above sets it:
# `go build` needs a writable HOME for its build cache and dies without one.
( cd "$BYAKUGAN_ROOT/go" \
    && env HOME="${HOME:-/root}" GOTOOLCHAIN=local \
        go build -o bin/byakugan-parse ./cmd/byakugan-parse ) \
    || die "failed to build the Byakugan engine's parse binary (equivalent: make -C \"$BYAKUGAN_ROOT/go\" build) — the engine's file ingestion requires go/bin/byakugan-parse."
[[ -x "$BYAKUGAN_ROOT/go/bin/byakugan-parse" ]] \
    || die "the engine build reported success but $BYAKUGAN_ROOT/go/bin/byakugan-parse is missing or not executable."
echo "✅ Byakugan parse binary built: $BYAKUGAN_ROOT/go/bin/byakugan-parse"

################################################################################
# Install the collection's pinned Ansible dependencies (requirements.yml — never
# :latest, never a branch). They go to a fixed shared path that the repo-root
# ansible.cfg puts on collections_path, so every user's runs resolve the same
# pinned versions: community.docker (the deploy roles) and ansible.posix (the
# profile_tasks audit-timing callback).
################################################################################
DXDFIR_COLLECTIONS="${DXDFIR_COLLECTIONS:-/opt/dxdfir/collections}"
echo "📚 Installing pinned Ansible collections into $DXDFIR_COLLECTIONS ..."
$SUDO "$DXDFIR_VENV/bin/ansible-galaxy" collection install \
    -r "$REPO_ROOT_DIR/ansible/collections/get_sybers.dxdfir/requirements.yml" \
    -p "$DXDFIR_COLLECTIONS" --force \
    || die "Failed to install the pinned Ansible collections (requirements.yml)."
echo "✅ Collections installed: $("$DXDFIR_VENV/bin/ansible-galaxy" collection list -p "$DXDFIR_COLLECTIONS" 2>/dev/null | grep -cE '^[a-z]' || echo '?') pinned"

################################################################################
echo ""
echo "🎉 Setup complete!"
echo ""
if [[ "$DOCKER_WAS_INSTALLED" == false ]]; then
    echo "⚠️  IMPORTANT: Please log out and back in for Docker group changes to take effect."
else
    echo "✅ Docker group permissions should already be active."
fi
echo ""
echo "🐳 Build the hardened tool containers (everything the pipeline runs):"
echo "     ansible-playbook ansible/collections/get_sybers.dxdfir/playbooks/dxdfir-build-images.yml"
echo ""
echo "📦 To pre-seed the analysis images as tarballs for an offline host, run:"
echo "     scripts/save-docker-images.sh          (online host: pull + save)"
echo "     scripts/save-docker-images.sh --load   (offline host: load tarballs)"
echo ""
echo "🚀 You can now run DX_DFIR — try:  dxdfir --help"
echo "   (process evidence, build + verify CAR, bring up docker/elastic — see README.md)"
