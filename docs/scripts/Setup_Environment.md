# Setup Environment Script

## Overview
The `setup-environment.sh` script prepares a host to run the DX_DFIR (Digital
Forensics and Incident Response) scripts. It installs Docker and the userland
tools the processing scripts depend on, adds the invoking user to the Docker
group, and sets ownership and permissions on the repository.

Pre-seeding the analysis Docker images as offline tarballs is a separate
concern and lives in its own script, [`save-docker-images.sh`](#pre-seeding-images-for-offline-hosts).
On a host with registry access nothing further is needed — the individual
processing scripts pull their images on first use.

> **For the `dxdfir` front-end** (the pipeline's entry point): this script also
> builds and installs the Go `dxdfir` binary (`go/`, installing the Go toolchain
> when absent) and installs the pinned ansible layer (`requirements.txt`:
> `ansible-core` + the docker SDK the collection's modules import), so
> `ansible-playbook` lands in the repo's own `.venv` (gitignored), which
> `dxdfir` resolves by itself — see [How It Runs](/README.md#how-it-runs).

## Prerequisites
- A Debian- or Ubuntu-based Linux distribution (the Docker apt repository is
  derived from `/etc/os-release`, so derivatives that declare `ID_LIKE` work too)
- Internet connectivity for installing Docker and the prerequisite packages
- Either run as root, or have `sudo` installed with privileges (the script
  resolves the escalation prefix once and works in both cases)

## What the Script Does

1. **Root/privilege check**: Detects whether it is root or needs `sudo`, and
   asks for confirmation before continuing as root (the final step rewrites
   ownership across the repository). Exits with a clear message if it is
   neither root nor able to use `sudo`.
2. **Docker Setup (via ansible, after step 4)**: runs `dxdfir-bootstrap.yml`
   — the `dxdfir_stack` role's `docker_ensure` entry point, the same state
   tasks `dxdfir deploy stack` uses — which installs the engine if absent
   (Docker's apt repository for the detected Debian/Ubuntu distribution),
   starts and enables the daemon, creates the docker group and adds the
   sudo'ing operator to it. The script carries no shell copy of this.
3. **Userland tools**: Installs the tools the processing scripts shell out to
   (`curl`, `python3`, `unzip`, `tar`, plus `ca-certificates`/`gnupg`), so a
   missing dependency surfaces here rather than halfway through an ingest.
4. **Permission Management**:
   - Sets ownership to the current user and Docker group (the group is pre-created when absent — docker itself arrives later, via the bootstrap playbook)
   - Sets permissions with `u=rwX,g=rX` so directories stay traversable by the
     Docker group and the `.sh` files stay executable

> The Byakugan CAR engine is no longer provisioned on the host: it is cloned +
> built into the hardened `get-sybers/byakugan` image at its Dockerfile's `BYAKUGAN_REF` pin by
> `dxdfir build-docker`, alongside the other tool images.

### Options
- `--yes` / `-y` — assume "yes" to all prompts (also assumed automatically when
  stdin is not a TTY, so the script is safe to run non-interactively)
- `--help` / `-h` — print the script's header documentation and exit

## Usage

### Running the Script
Execute the script from the terminal:

```bash
DX_DFIR/scripts/setup-environment.sh
```

### Script Execution Flow
1. Displays what actions will be performed
2. Prompts for confirmation before proceeding
3. Performs the installation and setup process
4. Provides completion message with next steps

## Pre-seeding Images for Offline Hosts
Image tarball management is handled by `scripts/save-docker-images.sh`, not by
the setup script. On a host with registry access it is optional.

```bash
# On an online host: pull each analysis image and save it as a tarball
scripts/save-docker-images.sh

# List the images this manages and the tarball directory
scripts/save-docker-images.sh --list

# On the offline host: load every tarball back into Docker
scripts/save-docker-images.sh --load
```

The images managed are:
- the `get-sybers/*` hardened tool images from the GoDFIR-toolz `images.yml` — built in-repo by
  `ansible-playbook playbooks/dxdfir-build-images.yml` (see docs/Containers.md)
- the Elastic stack's `docker.elastic.co/*` images at `ELASTIC_VERSION`
  (derived from the inventory's `dxdfir_elastic_version` + the `dxdfir_stack` role's image map) — pulled and
  saved so the analysis backend deploys offline with zero pulls

Tarballs are written to `data_store/docker_images/`.

## Post-Installation
After running the script:

1. `dxdfir` works in the shell you ran the script from and in every other
   one (login or not): it is a real file in `/usr/local/bin`, and it finds
   the ansible venv at `<repo>/.venv` by itself. Nothing to source, no
   re-login.
2. The **docker group** is the one thing a new shell is genuinely needed for,
   and only when the bootstrap just added you: the script says so when that
   is the case — `newgrp docker` in place, or log out and back in once.
3. To drive ansible by hand, `. .venv/bin/activate` (login shells also get
   the venv's `ansible*` and the pinned Go on PATH from
   `/etc/profile.d/dxdfir.sh`, a convenience the front-end never depends on).
4. If you are seeding an offline host, carry the tarballs from
   `data_store/docker_images/` across and run `scripts/save-docker-images.sh --load`
   (equivalent to loading each one manually with `docker load -i`)

## Troubleshooting

- If you encounter permission issues, ensure you are root or have `sudo` privileges
- Docker installation may require additional configuration on some systems
- Network issues might prevent installing Docker; check your connectivity

## Design decisions

The script's non-obvious choices, recorded here so the script itself stays
lean:

- **Status markers and spinner frames are ASCII** (the banner and prose may
  carry Unicode), and colour applies only on a real terminal (`NO_COLOR`, a
  dumb TERM, piped output and `--no-color` all fall back to plain): logs
  stay greppable, and braille/unicode spinner frames break `${#var}`
  substring math under the C/POSIX locale a clean machine runs.
- **Git trust is invocation-scoped, never `--global`**: recursive submodule
  operations walk into nested repos whose paths cannot be pre-enumerated, so
  git ≥ 2.46 gets a trailing `/*` leading-path `safe.directory` match scoped
  to the checkout root; older gits only match exact paths or the global
  `"*"`, so there the fallback is that **global wildcard, confined to the
  single git invocation** (`-c`, never persisted in the operator's config) —
  a wider trust grant for that one command, which is why ≥ 2.46 gets the
  path-scoped form.
- **Long steps run behind a heartbeat** (a redrawn spinner on a TTY, a line
  every 10s piped) with sudo credentials refreshed up front, so a
  backgrounded privileged command never blocks on a password prompt it
  cannot display.
- **Root is confirmed once on a workstation** (normal in a container): the
  closing chown rewrites ownership across the whole repository.
- **The docker engine is provisioned by ansible, not shell**
  (`dxdfir-bootstrap.yml` → `dxdfir_stack`'s `docker_ensure`): one
  implementation, shared with `dxdfir deploy stack`; the script only probes
  the fact for its plan and closing notes.
- **`--recursive` submodule init is kept on principle** — a nesting
  submodule checks out complete instead of silently empty, the failure mode
  that bit the vendored CAR engine.
- **Permissions are `u=rwX,g=rX`**: capital X keeps directories traversable
  by the docker group and `.sh` files runnable while evidence files stay
  non-executable (the old `chmod -R 744` locked the docker group out).
- **The venv holds only the pinned ansible layer** (`requirements.txt` —
  the lock is the single source of truth, no version literals in the
  script); there is no host python package to install any more.
- **The venv lives inside the checkout** (`<repo>/.venv`, gitignored,
  `$DXDFIR_VENV` overrides) and is created by the invoking user, not root.
  It is a per-checkout dependency layer like `go/vendor/`, so it belongs
  with the checkout; the front-end resolves it by relation to the repo it
  just located, which is what makes `dxdfir` work from any shell with no
  PATH edit in between; `. .venv/bin/activate` is the convention every
  python user already knows; and a system-prefix venv brought root-owned
  pip caches and a second install prefix to keep in step with the checkout.
  An earlier release's `/opt/dxdfir/venv` is retired on the next run.
- **The Go toolchain is (re)installed when absent or under go.mod's floor**:
  the build pins `GOTOOLCHAIN=local`, which deliberately refuses
  auto-upgrades, so a host provisioned by an older release re-provisions
  here instead of failing the build. The build itself runs from a **clean,
  ephemeral cache** (module + build cache + HOME in a throwaway dir):
  every run resolves dependencies from a source of truth (the in-tree
  `go/vendor/` if pre-vendored, else the proxy), nothing is cached under
  the install prefix, and a rebuild never silently rides stale modules.
- **`dxdfir` depends on no PATH edit**: the binary is installed as a real
  file in `/usr/local/bin`, a directory every default PATH — and sudo's
  `secure_path` — already carries, and it resolves the venv's ansible on
  its own. An earlier release put it under `/opt/dxdfir/bin`, reachable
  only through the profile.d drop-in, which login shells read and nothing
  else does (`su user`, a desktop terminal, tmux, sudo, the shell the
  script ran in): the closing `dxdfir --help` was command-not-found until
  a full re-login, and after one too when the drop-in had landed
  unreadable under a strict umask. The script now **proves** the result
  from a fresh non-login shell (`env -i bash -c 'command -v dxdfir'`, then
  the dashboard's ansible readiness line) before it reports success.
- **One managed `/etc/profile.d/dxdfir.sh` remains, as a convenience**: the
  pinned Go toolchain (rebuilds) and the venv bin — **appended**, so the
  system python/pip keep winning — for hand-driven `ansible-playbook` in
  login shells. It is written with an explicit `0644` mode (`/etc/profile`
  skips a drop-in it cannot read). Legacy `/usr/local/bin` symlink shims
  from earlier releases are retired on the next run; the binary there now
  is a file, not a shim.
- **The build galaxy's primary path installs nothing** — the gitlink is the
  pin and `roles_path` resolves the submodule in place; only a checkout
  without submodule content has the galaxy imported from the `.gitmodules`
  source at the gitlink revision (`--no-deps`: its dependency set is exactly
  the pins already installed).
