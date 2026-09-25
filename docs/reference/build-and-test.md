# Build and test

Two harnesses: a fast **check** suite that runs on every push, and a **smoke** test that
runs the real pipeline.

## Checks — static, every push

`.github/tests/run-checks.sh` (also `dxdfir validate`) is static and internal-consistency only —
it does **not** run the pipeline. Wired into CI via `.github/workflows/checks.yml`.

```bash
./.github/tests/run-checks.sh          # or: dxdfir validate   ·   -v for verbose
```

Groups it runs:

- **Shell** — `bash -n` + `shellcheck -S error` over `scripts/`, `dev-scripts/`, `.github/tests/`.
- **Collection requirements** — asserts every collection dep is an exact `X.Y.Z` pin
  covering every `galaxy.yml` dependency, and that `setup-environment.sh` installs it.
- **Ansible lint** — `ansible-lint --profile production`.
- **Python** — `pytest` under the `python/constraints.txt` lock.
- **Go front-end** — `gofmt -l go` must be empty, `go vet ./...`, `go build ./...`,
  `go test ./...` (all guarded on `go` being present; CI installs Go 1.24).
- Plus repo-path resolution, version/doc consistency, evidence-gitignore coverage, secret
  patterns, and documentation links.

`go/Makefile`: `make check` = `gofmt -l` + `go vet` + `go build`; `make` / `make install`
build and install the binary.

## Smoke — the real pipeline

`.github/workflows/smoke.yml` → `.github/tests/smoke-test.sh` runs the pipeline end to end for
correctness: a sha256-pinned Sysmon `.evtx` → the real evtx lane (`get-sybers/goevtx`) →
materialised CAR via the external [Byakugan engine](https://github.com/Get-Sybers/byakugan)
→ asserts every Sysmon-sourced CAR object has rows with the expected fields → the
`verify-car` gate.

Triggers: `workflow_dispatch`, a nightly cron, and PRs that touch the pipeline (the
Python processors, the `dxdfir_images` role,
`.gitmodules`, `docker/GoDFIR-toolz` — the manifest `images.yml` arrives inside it —
or the smoke test). It checks out submodules recursively and builds the
tool images with `dxdfir build-docker`, which clones + builds Byakugan into the
`get-sybers/byakugan` image at its Dockerfile's `BYAKUGAN_REF` pin (parse binary and model sources
baked in).

## Go pins and the ephemeral build

`go/go.mod` holds `go 1.24.0` and pins the dependencies deliberately:

- **`modernc.org/sqlite v1.46.0`** — the pure-Go, cgo-free SQLite driver, **held at
  v1.46.0 to keep the Go 1.24 floor** (a newer sqlite would raise the toolchain
  requirement). Also `spf13/cobra`, `apenella/go-ansible/v2`, `gizak/termui/v3` — all
  pinned.

The [setup script](../architecture/setup-flow.md) installs the pinned Go toolchain
(SHA-256-verified against the go.dev release index) and builds the front-end from a
**clean, throwaway** module cache with **`GOTOOLCHAIN=local`** — it deliberately refuses
toolchain auto-upgrades, so a host provisioned by an earlier release must be
re-provisioned rather than silently upgraded, and the build never trusts stale modules.

## Before you push

```bash
cd go && gofmt -w . && go vet ./... && go test ./...   # Go
./.github/tests/run-checks.sh                                   # everything
```
