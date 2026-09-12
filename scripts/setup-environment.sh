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
echo "5. 🔧 Set ownership and permissions on the DX_DFIR repository"
echo -e "\n==================================================\n"

confirm "Do you wish to proceed?" || { echo "Setup cancelled."; exit 1; }

################################################################################
# Pull the git submodules — RECURSIVELY.
#
# The CAR lane (get_sybers_dxdfir.mitrecar) drives the vendored PIIAT-MitreCar
# engine in third_party/piiat-mitrecar, which reconstructs its object model LIVE
# from ITS OWN pinned submodules (third_party/car, third_party/attack-datasources).
# A plain `git submodule update --init` leaves those nested modules empty and the
# `dxdfir` CAR/timeline commands then fail, so the init MUST be recursive. Runs
# before the chown/chmod below so the freshly checked-out files inherit them too.
if [[ -f "$REPO_ROOT_DIR/.gitmodules" ]]; then
    echo "🔗 Initialising git submodules (recursive)..."
    # safe.directory is scoped to THIS invocation with `-c` (the repo may be owned
    # by a different user until the chown below) — never `git config --global`,
    # which is a persistent, accumulating change to the operator's own git config.
    GIT_SAFE=(-c "safe.directory=$REPO_ROOT_DIR" -c "safe.directory=*")
    git "${GIT_SAFE[@]}" -C "$REPO_ROOT_DIR" submodule sync --recursive >/dev/null 2>&1 || true
    git "${GIT_SAFE[@]}" -C "$REPO_ROOT_DIR" submodule update --init --recursive \
        || die "Failed to initialise git submodules recursively (need network + git access)."
    echo "✅ Submodules checked out (incl. PIIAT-MitreCar's nested car + attack-datasources)."
else
    echo "ℹ️  No .gitmodules found — skipping submodule init."
fi

################################################################################
# Set ownership and permissions for DX_DFIR.
#
# u=rwX,g=rX — capital X applies the execute bit to directories and to files
# that already carry one, so directories stay traversable by the docker group
# and the .sh files stay runnable, while evidence files are left non-executable.
# The old `chmod -R 744` cleared group execute on directories and locked the
# docker group out of the tree the script had just handed it.
echo "🔧 Setting ownership to $RUN_USER:docker and permissions on the repository..."
if [[ -d "$REPO_ROOT_DIR" ]]; then
    $SUDO chown -R "$RUN_USER:docker" "$REPO_ROOT_DIR" \
        || echo "⚠️  Some ownership changes were skipped"
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
# --editable is REQUIRED, not a preference. get_sybers_dxdfir/mitrecar.py locates the
# vendored PIIAT-MitreCar engine RELATIVE TO ITS OWN FILE (_REPO_ROOT = three dirs
# up from __file__ -> third_party/piiat-mitrecar). A plain copying install puts the
# package under the venv's site-packages, three dirs up from which is .../lib/pythonX.Y
# with no third_party/ — so `dxdfir build-car` can't reach the engine and dies
# "third_party/piiat-mitrecar is not initialised", even though the submodules WERE
# initialised (above) in the repo tree. Editable keeps the installed module IN the
# repo tree, so the engine and its nested car / attack-datasources submodules resolve.
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
    _gosha="$(curl -fsSL "https://go.dev/dl/${_gotar}.sha256")" \
        || die "Failed to fetch the Go toolchain checksum (${_gotar}.sha256)."
    echo "${_gosha}  /tmp/${_gotar}" | sha256sum -c - \
        || die "Go toolchain checksum mismatch for ${_gotar} — refusing to install."
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf "/tmp/${_gotar}" || die "Failed to extract the Go toolchain."
    rm -f "/tmp/${_gotar}"
    $SUDO ln -sf /usr/local/go/bin/go /usr/local/bin/go
    export PATH="/usr/local/go/bin:$PATH"
fi
echo "🐹 Building the dxdfir Go front-end ($(go version 2>/dev/null | awk '{print $3}')) ..."
$SUDO mkdir -p "$GO_BIN_DIR"
# Build offline from vendored modules when present (air-gapped installs, packaged
# by scripts/package-offline.sh), else fetch through the module proxy. Pin the
# toolchain (GOTOOLCHAIN=local) so it never tries to auto-download a newer Go.
GO_BUILD_MODFLAG=""
[[ -d "$REPO_ROOT_DIR/go/vendor" ]] && GO_BUILD_MODFLAG="-mod=vendor"
( cd "$REPO_ROOT_DIR/go" \
    && $SUDO env PATH="$PATH" HOME="${HOME:-/root}" GOTOOLCHAIN=local \
        go build ${GO_BUILD_MODFLAG} -o "$GO_BIN_DIR/dxdfir" ./cmd/dxdfir ) \
    || die "Failed to build the dxdfir Go front-end."
$SUDO ln -sf "$GO_BIN_DIR/dxdfir" /usr/local/bin/dxdfir
# `man dxdfir` (README / Get-Started) must work on a provisioned host, so the
# manual installs beside the binary. Best-effort: no man tree is not fatal.
$SUDO install -Dm644 "$REPO_ROOT_DIR/go/man/dxdfir.1" /usr/local/share/man/man1/dxdfir.1 2>/dev/null \
    || echo "⚠️  Could not install the man page — read it in-tree: man ./go/man/dxdfir.1"
echo "✅ dxdfir (Go front-end) installed: $(/usr/local/bin/dxdfir --version 2>/dev/null || echo "$GO_BIN_DIR/dxdfir")"

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
