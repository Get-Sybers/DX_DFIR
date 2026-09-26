# Setup flow

`scripts/setup-environment.sh` provisions an online host in ten guarded, idempotent
steps. Each is safe to re-run; a step that finds its work already done reports and moves
on. (The older prose walkthrough is [Setup_Environment.md](../scripts/Setup_Environment.md);
the source is the best reference.)

```mermaid
flowchart LR
    A[1 Docker] --> B[2 Tools] --> C[3 docker group] --> D[4 Submodules]
    D --> E[5 Permissions] --> F[6 Python + Ansible venv]
    F --> G[7 Go + dxdfir] --> H[8 Ansible collections]
```

| # | Step | What it provisions |
|---|---|---|
| 1 | **Docker engine** | `docker-ce`/cli/containerd/buildx/compose-plugin from the distro-derived Docker apt repo (skipped if present). |
| 2 | **Userland tools** | `ca-certificates curl git gnupg unzip python3 python3-venv tar`. |
| 3 | **Docker group** | `groupadd docker` + `usermod -aG` the invoking user. |
| 4 | **Git submodules** | `submodule update --init --recursive` — [anamnesis](https://github.com/Get-Sybers/Anamnesis) (memory lane) and [GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz) (the tool images). |
| 5 | **Permissions** | `chown -R <user>:docker` + `chmod -R u=rwX,g=rX,o=` (capital `X` keeps dirs traversable for the group). |
| 6 | **Ansible (pinned)** | Create `/opt/dxdfir/venv`, `pip install -r requirements.txt` (ansible-core + the docker SDK the collection's modules import — no host python package); the venv's `ansible*` reach PATH through the profile.d drop-in of step 7 — no symlink shims. |
| 7 | **Go + dxdfir** | Install the pinned, SHA-256-verified Go toolchain (if absent/too old), build the `dxdfir` binary from a clean ephemeral cache to `/opt/dxdfir/bin`, install the man page, then write ONE managed `/etc/profile.d/dxdfir.sh` putting the real tool locations on PATH (venv bin appended, so system python/pip keep winning) and retire any legacy `/usr/local/bin` shims a previous install created. |
| 8 | **Ansible collections** | `ansible-galaxy install` the collection's pinned `requirements.yml` into `/opt/dxdfir/collections`. The GoDFIR-toolz **build galaxy** installs NOTHING on the primary path: its roles resolve in place from the submodule (`docker/GoDFIR-toolz/roles` on the repo-root `roles_path`) at the gitlink pin; only a checkout without the submodule has it imported by `ansible-galaxy` from the `.gitmodules` source at the gitlink revision, into the shared path `roles_path` also covers as its degraded-only last entry. |

> The Byakugan CAR engine is **no longer provisioned on the host**. It is cloned + built into the hardened [`get-sybers/byakugan`](https://github.com/Get-Sybers/byakugan) image at the `sources.yml` pin (`docker/GoDFIR-toolz/byakugan/Dockerfile`, parse binary and model sources baked in) by `dxdfir build-docker`, alongside the other tool images — so the CAR lane only shells that image.

## Why these choices

A few guards encode ways an earlier revision failed on a clean machine — they're worth
knowing:

- **`sudo` is resolved once and may be empty.** Minimal container images are often
  already root and carry no `sudo`; hardcoding it died on line one.
- **`--editable` install is required, not a preference.** The Python package resolves
  paths relative to its own files (the `docker/GoDFIR-toolz` submodule — its
  `images.yml` manifest included — and `data_store/`). A copying install would put it under `site-packages` where none of
  those resolve.
- **Capital-`X` permissions.** `u=rwX,g=rX` applies `+x` to directories and to files that
  already carry it — so the `docker` group can traverse the tree and the `.sh` files stay
  runnable, while evidence files stay non-executable.
- **Pinned, verified Go, built clean.** The toolchain tarball is checksum-verified against
  the go.dev release index before extraction, and the build runs from a throwaway module
  cache with `GOTOOLCHAIN=local` so it never silently auto-upgrades or trusts stale
  modules. See [build and test](../reference/build-and-test.md).

## Offline hosts

Air-gapped installs provision connected first, then disconnect: run
`scripts/setup-environment.sh` online (build images, install the toolchain),
save the tarballs with `scripts/save-docker-images.sh`, move/disconnect — a
re-run with no route out falls back to loading those tarballs. See the
[scripts overview](../scripts/Scripts-Overview.md).
