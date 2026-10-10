# `dx` — Go front-end

This directory holds the **`dx`** command: a Go front-end, the user-facing entry
point of the DX_DFIR pipeline (the Python Typer CLI it replaced is retired —
this binary is the only front-end). It owns *only* the verbs and their
presentation — the heavy work stays where it belongs:

```
dx (Go)                              this directory — the verbs + plain streaming output
  └─ get_sybers.dxdfir (Ansible)     orchestration: one role per source, preflight → process → verify
```

The grammar is **verb first** — `<verb> <noun>` (`deploy stack`, `register
evidence NAME`, `list evidence`). The evidence verbs also accept a bare NAME in
place of the noun (`select NAME`). `byakugan` is the one noun-first exception: a
tool namespace whose subcommands are its own verbs (`byakugan build`, `byakugan
export-stix`). See [the command reference](../docs/getting-started/dx-cli.md).

The binary never re-implements processing. It shells out to what already exists:

| Verb | Driven by |
|---|---|
| `process` | `ansible-playbook … dxdfir-process-<tool>.yml` (per tool), progress reconstructed by watching output files |
| `build images` | `ansible-playbook … dxdfir-build-images.yml` |
| `byakugan build` / `verify` / `export-timeline` | `ansible-playbook … dxdfir-{build-car,verify-car,car-timeline}.yml` (the `godfir_byakugan` role over the engine + carcheck gate) |
| `byakugan load` | `ansible-playbook … dxdfir-load-car.yml` (the `dxdfir_car_load` role — `byakugan load` into `logs-car.*`, behind the `dxdfir_stack` ensure_running gate) |
| `byakugan export-stix` / `behaviour` / `pull` / `sightings` | `dxdfir-exchange-*.yml` (the `dxdfir_exchange` role — the byakugan image's own exchange sub-tools) |
| `verify images` | `ansible-playbook … dxdfir-verify-images.yml` |
| `register` / `select` / `unselect` / `unregister` / `sort` | native Go (`internal/collection`: the SQLite registry, magic-byte classify, sort/promote/link, and the SHA-1 manifest — no subprocess) |
| `deploy` / `start` / `stop` / `restart` / `status` / `update` `stack` | `ansible-playbook … dxdfir-stack-<action>.yml` (the `dxdfir_stack` role) |
| `purge stack` | `ansible-playbook … dxdfir-stack-destroy.yml` |
| `purge evidence` / `car` / `images` | `ansible-playbook … dxdfir-cleanup.yml` (`--dry-run` maps to `--check`) |
| `list` | native Go (filesystem only) |
| `validate` | `bash .github/tests/run-checks.sh` |

Every `ansible-playbook` argv is built with
[go-ansible](https://github.com/apenella/go-ansible) v2 (typed command options);
extra vars stay ordered, repeated `-e KEY=VALUE` pairs so the user's overrides
keep their last-wins contract. go-ansible only *builds* the command — the
in-repo `internal/run` engine executes it.

## Presentation

There is one presenter. Long-running work (`process`, and collection
`register`/`sort`) streams progress as plain line output on **stderr** —
periodic status lines (`[dx] lanes 2/5 · zeek → conn.log`) plus a bounded,
filtered log-tail from the long-pole lanes — while everything written to
**stdout** stays unstyled, so a redirected stdout is a clean data channel.
Progress is truthful: a gauge/count appears only where a real *i/N* exists
(files landed, bytes hashed); heartbeat lanes (plaso) show growth + elapsed;
spinner lanes (hayabusa, yara) never fake a bar. Colour is used on stderr only,
and disabled automatically when stderr is not a terminal (and under `NO_COLOR` /
`TERM=dumb`). **Ctrl-C** cancels the underlying job cleanly.

Why this matters: under Ansible the subprocess is buffered — nothing prints
until a lane finishes — so a multi-hour run would otherwise show a frozen line.
Watching the deterministic per-item output paths land on disk gives a live,
honest progress signal without un-swallowing the tools' firehose of output.

## Build

```sh
cd go
make            # build ./dx
make link       # build + install dx into ../.go/bin/ (same layout as setup-environment.sh)
make install    # go install to $GOBIN / $GOPATH/bin as `dx`
make check      # gofmt -l, go vet, go build
```

`make link` is the quick way to rebuild after a code change: it builds and
installs the binary into the repo-local `.go/bin/` (gitignored) — the exact
layout `scripts/setup-environment.sh` provisions — so nothing lands outside the
checkout. Override the destination with `make link BIN_DIR=…`. (`make install`
uses `go install`, which lands in `$GOBIN`/`$GOPATH/bin` and only works as a
shortcut if that directory is already on your `PATH`.)

Requires Go per `go.mod`'s `go` directive. Dependencies (cobra, go-ansible,
modernc sqlite) are pinned in `go.mod`.

## Runtime

`dx` locates the repo via `--repo-root`, then `$DFIR_REPO_ROOT`, then by walking
up from the cwd, then from the binary's own directory — the marker is
`ansible/collections/get_sybers.dxdfir`. It then resolves `ansible-playbook` from
the checkout's own venv, `<repo>/.venv/bin` (what `scripts/setup-environment.sh`
installs; `$DXDFIR_VENV` overrides), falling back to PATH only when that venv is
absent — so a provisioned host works from any shell, and a dev host with its own
venv activated keeps working unchanged.

Environment / flags:

- `--repo-root PATH` / `$DFIR_REPO_ROOT` — the DX_DFIR checkout.
- `$DXDFIR_VENV` — the ansible venv to use (else `<repo>/.venv`, then PATH).

A bare `dx` prints a plain landing readout (environment readiness + tracked
collections + staged evidence) on stdout — see
[the interface](../docs/getting-started/the-interface.md).

The external Byakugan CAR engine is no longer a host checkout: it is cloned +
built into the hardened `get-sybers/byakugan` image at its Dockerfile's
`BYAKUGAN_REF` pin by `dx build images`, and the CAR lane just shells that image.

## Module layout

Broken into small, independently-testable packages — nothing imports a terminal
library, so the runner, watchers and repo detection need no terminal:

```
cmd/dx/               thin entry: build the command tree, map exit codes
internal/
  cli/                 cobra verb tree, one file per area (stack, evidence, byakugan, purge, …)
  model/               shared types (Update/Snapshot/Lane) + the Presenter interface
  repo/                repo + interpreter/tool discovery
  run/                 subprocess engine (passthrough, stream, capture)
  lanes/               `process` orchestration: lane specs, output-glob watching, the Job
  collect/             collection orchestration: native register/sort/promote/link + SHA-1 hash (internal/collection), no subprocess
  collection/          native collection layer: SQLite registry, classify, sort/register, hashing
  plain/               the line-output presenter (stderr progress, clean stdout)
  style/               ASCII-safe glyph + colour vocabulary
```

The producers (`lanes`, `collect`) emit a `model.Update` stream that the `plain`
presenter renders, so the subprocess/watch layer stays independent of how
progress is shown.
