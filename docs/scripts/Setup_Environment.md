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
> when absent) and installs the `get_sybers_dxdfir` processor package —
> `ansible-core` included, so `ansible-playbook` lands in the same venv — see
> [How It Runs](/README.md#how-it-runs).

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
2. **Docker Setup**:
   - Checks if Docker is installed; installs it if not present, using the apt
     repository matching the detected distribution
   - Creates a Docker group if it doesn't exist
   - Adds the current user to the Docker group
3. **Userland tools**: Installs the tools the processing scripts shell out to
   (`curl`, `python3`, `unzip`, `tar`, plus `ca-certificates`/`gnupg`), so a
   missing dependency surfaces here rather than halfway through an ingest.
4. **Permission Management**:
   - Sets ownership to the current user and Docker group
   - Sets permissions with `u=rwX,g=rX` so directories stay traversable by the
     Docker group and the `.sh` files stay executable

> The Byakugan CAR engine is no longer provisioned on the host: it is cloned +
> built into the hardened `get-sybers/byakugan` image at the `sources.yml` pin by
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
# On an online host: build (dxdfir build-docker) + save every image as tarballs
scripts/save-docker-images.sh --build

# List the images this manages and the tarball directory
scripts/save-docker-images.sh --list

# On the offline host: load every tarball back into Docker
scripts/save-docker-images.sh --load
```

The images managed are:
- the `get-sybers/*` hardened tool images from `images.yml` — built in-repo by
  `dxdfir build-docker` (the `dxdfir_images` role; see docs/Containers.md)
- the Elastic stack's `docker.elastic.co/*` images at `ELASTIC_VERSION`
  (derived from `docker/elastic/`'s compose file + `.env.example`) — pulled and
  saved so the analysis backend deploys offline with zero pulls

Tarballs are written to `data_store/docker_images/`.

## Post-Installation
After running the script:

1. **Log out and log back in** to apply the Docker group membership changes
2. If you are seeding an offline host, carry the tarballs from
   `data_store/docker_images/` across and run `scripts/save-docker-images.sh --verify`
   (loads every tarball, then asserts the hardened inventory); for a complete
   air-gapped install use `scripts/package-offline.sh` → the bundle's
   `setup-offline.sh` instead

## Troubleshooting

- If you encounter permission issues, ensure you are root or have `sudo` privileges
- Docker installation may require additional configuration on some systems
- Network issues might prevent installing Docker; check your connectivity
