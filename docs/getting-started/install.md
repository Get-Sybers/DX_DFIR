# Install

DX_DFIR installs on a single **Debian or Ubuntu** host (or a derivative that carries a
Debian/Ubuntu codename). One script provisions everything.

## Prerequisites

- A Debian/Ubuntu x86-64 or arm64 host you can `sudo` on (or run as root).
- **Headroom.** No hard minimum, but the [Elastic stack](../architecture/the-stack.md)
  alone reserves a 1 GB JVM heap and processing spins several tool containers — plan for
  **≥ 8 GB RAM** and generous free disk (evidence is copied through
  `raw → processed → car`, so budget a few times the size of your evidence).
- Network access on first install — Docker's apt repo, the pinned Go toolchain, the
  Byakugan engine checkout, and the Python/Ansible dependencies are all fetched.
  (Air-gapped installs: provision connected, save the image tarballs with
  `scripts/save-docker-images.sh`, disconnect — a `setup-environment.sh` re-run
  with no route out loads them instead of building. See the
  [scripts overview](../scripts/Scripts-Overview.md).)

## 1. Clone with submodules

```bash
git clone --recursive https://github.com/Get-Sybers/DX_DFIR.git
cd DX_DFIR
```

`--recursive` matters: the memory lane ([flashback](https://github.com/Get-Sybers/flashback))
and the Go tool family ([GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz)) are
git submodules. Already cloned flat? `git submodule update --init --recursive`.

## 2. Run the setup script

```bash
./scripts/setup-environment.sh --yes        # --yes skips the prompts; drop it to be asked
```

It provisions the host in order — Docker, userland tools, the docker group, the
submodules, the pinned [Byakugan engine](https://github.com/Get-Sybers/byakugan),
repository permissions, the Python + Ansible venv, the Go toolchain and the `dxdfir`
binary, and the pinned Ansible collections. Each step is idempotent and safe to re-run.
The full step-by-step is in **[Architecture → setup flow](../architecture/setup-flow.md)**
(and the older [Setup_Environment walkthrough](../scripts/Setup_Environment.md)).

Output is themed to match the [`dxdfir` UI](the-interface.md); pass `--no-color` (or set
`NO_COLOR`) for plain logs. `--help` prints the usage.

> **Log out and back in once.** The script adds you to the `docker` group, but that only
> takes effect on your next login. Until then, `docker` commands need `sudo`.

## 3. Build the tool images

```bash
dxdfir build-docker                          # build + hardening-verify the get-sybers/* images
```

Every lane runs its tool inside a hardened `get-sybers/*` container. Build them **once
per host before your first `process`**, and again after changing anything under
`docker/`. `dxdfir verify-images` audits the set (it fails if any is missing or
un-hardened). See [tool containers](../Containers.md).

## Verify the install

```bash
dxdfir --version
dxdfir            # on a terminal: the interactive UI; piped: the readiness dashboard
```

Running `dxdfir` with no arguments shows a **readiness dashboard** — green rows mean the
repo, Python, Docker and the Byakugan engine are all in place. Anything amber/red tells
you what's missing.

## Next

- **[First run](first-run.md)** — process your first case.
- **[The interface](the-interface.md)** — drive it from the terminal UI.
