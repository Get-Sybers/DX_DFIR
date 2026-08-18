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

> **For the `dxdfir` CLI path** (the pipeline front-end): this script installs the
> *scripts'* dependencies, not the CLI's. `dxdfir` additionally needs
> `ansible-playbook` on `PATH` and the Python package installed with
> `pip install ./python` (which provides the `dxdfir` command and Typer) — see
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
- `log2timeline/plaso:latest` — Timeline analysis tools
- `zeek/zeek:latest` — Network traffic analysis
- `mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest` — the Kusto
  emulator (analysis backend)

Tarballs are written to `data_store/docker_images/`.

## Post-Installation
After running the script:

1. **Log out and log back in** to apply the Docker group membership changes
2. If you are seeding an offline host, carry the tarballs from
   `data_store/docker_images/` across and run `scripts/save-docker-images.sh --load`
   (equivalent to loading each one manually with `docker load -i`)

## Troubleshooting

- If you encounter permission issues, ensure you are root or have `sudo` privileges
- Docker installation may require additional configuration on some systems
- Network issues might prevent installing Docker; check your connectivity
