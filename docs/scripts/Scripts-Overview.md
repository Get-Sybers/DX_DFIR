# Scripts Directory (`./scripts`)

This directory contains **host provisioning** scripts: installing the
environment and seeding the analysis container images. Host artefacts are
collected with **the hardened GoDFIR-toolz containers**.

## Provisioning scripts

The analysis container images are catalogued in [Containers](../Containers.md).

| Script | Description |
|---|---|
| `setup-environment.sh` | Bootstraps ansible (userland deps, venv, pinned collections), then provisions the Docker engine THROUGH it (`dxdfir-bootstrap.yml` → the `dxdfir_stack` role's `docker_ensure`); the git submodules; the Python venv, the Go toolchain and the `dx` front-end. The Byakugan CAR engine is cloned + built into the `get-sybers/byakugan` image by `dx build images`, not checked out on the host. Image seeding is split into `save-docker-images.sh`. |
| `save-docker-images.sh` | Save the built hardened `get-sybers/*` images (+ the pulled Elastic-stack images) as tarballs; `--load` / `--verify` restore them and assert the hardened inventory. A launcher only: the sets, pulls, exports and loads are the `dxdfir_images` role's save/load tasks (`dxdfir-images-save.yml` / `dxdfir-images-load.yml`). |
