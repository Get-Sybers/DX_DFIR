# `dxdfir` — Go / termui front-end

This directory holds the **`dxdfir`** command: a Go [termui](https://github.com/gizak/termui)
front-end, the user-facing entry point of the DX_DFIR pipeline (the Python Typer
CLI it replaced is retired — this binary is the only front-end). It owns *only*
the verbs and their presentation — the heavy work stays where it belongs:

```
dxdfir (Go / termui)                 this directory — verbs + adaptive dashboards
  └─ get_sybers.dxdfir (Ansible)     orchestration: one role per source, preflight → process → verify
       └─ get_sybers_dxdfir (Python) the minimal per-item processors the roles invoke
```

The binary never re-implements processing. It shells out to what already exists:

| Verb group | Driven by |
|---|---|
| `process` | `ansible-playbook … dxdfir-process-<lane>.yml` (per lane), progress reconstructed by watching output files |
| `build-docker` | `ansible-playbook … dxdfir-build-images.yml` |
| `build-car` / `verify-car` / `car-timeline` | `ansible-playbook … dxdfir-{build-car,verify-car,car-timeline}.yml` (the `dxdfir_car` role over the engine + carcheck gate) |
| `verify-images` | `ansible-playbook … dxdfir-verify-images.yml` |
| `register` / `collection …` | native Go (`internal/collection`: the SQLite registry, magic-byte classify, sort/promote/link, and the SHA-1 manifest — no subprocess) |
| `stix …` | `python -m get_sybers_dxdfir.stix …` (data → stdout, summary → stderr) |
| `stack …` | `ansible-playbook … dxdfir-stack-<action>.yml` (the `dxdfir_stack` role) |
| `cleanup …` | `ansible-playbook … dxdfir-cleanup.yml` (`--dry-run` maps to `--check`) |
| `list` | native Go (filesystem only) |
| `validate` | `bash tests/run-checks.sh` |

Every `ansible-playbook` argv is built with
[go-ansible](https://github.com/apenella/go-ansible) v2 (typed command options);
extra vars stay ordered, repeated `-e KEY=VALUE` pairs so the user's overrides
keep their last-wins contract. go-ansible only *builds* the command — the
in-repo `internal/run` engine executes it.

## Adaptive presentation

Presentation adapts to the work and the terminal:

- **Processing progress** (`process`) and **collection creation** (`register`,
  `collection sort`) render a **live termui dashboard** — an overall gauge, a
  per-lane board, a bounded *filtered* log-tail for the long-pole lanes
  (volatility, plaso), and an exceptions panel. Progress is truthful: a gauge
  appears only where a real *i/N* exists (files landed, bytes hashed); heartbeat
  lanes (plaso) show growth + elapsed; spinner lanes (hayabusa, yara) show a
  spinner, never a fake bar.
- Everything else prints concise, colour-coded plain output (the good parts of
  the original layout).
- **Non-interactive** (piped, CI, `DXDFIR_NO_TUI`, a dumb terminal, or a window
  below 60×14) automatically streams the same progress as plain lines. The
  dashboard renders on `/dev/tty`, so a machine-readable stdout stays clean, and
  the durable end-of-run summary is always printed as plain text on exit.

Why this matters: under Ansible the subprocess is buffered — nothing prints until
a lane finishes — so a multi-hour run would otherwise show a frozen line.
Watching the deterministic per-item output paths land on disk gives a live,
honest progress signal without un-swallowing the tools' firehose of output.

## Build

```sh
cd go
make            # build ./dxdfir
make link       # build + put a `dxdfir` shortcut on PATH (rebuild-after-edit; uses sudo when not root)
make install    # go install to $GOBIN / $GOPATH/bin as `dxdfir`
make check      # gofmt -l, go vet, go build
```

`make link` is the quick way to rebuild after a code change and have `dxdfir`
runnable anywhere without the full filepath: it builds, installs the binary to
`/opt/dxdfir/bin/dxdfir`, and symlinks `/usr/local/bin/dxdfir` to it — the exact
layout `scripts/setup-environment.sh` provisions, so it reuses (or creates) the
same shortcut. Override the destinations with `make link GO_BIN_DIR=… LINK_DIR=…`.
(`make install` uses `go install`, which lands in `$GOBIN`/`$GOPATH/bin` and only
works as a shortcut if that directory is already on your `PATH`.)

Requires Go ≥ 1.24. Dependencies (termui, cobra, go-ansible) are pinned in `go.mod`.

## Runtime

`dxdfir` locates the repo like the Python CLI did (`--repo-root`, then
`$DFIR_REPO_ROOT`, then walking up from the cwd, then from the binary's own
directory — the marker is `ansible/collections/get_sybers.dxdfir`). It prepends
`<repo>/python` to `PYTHONPATH` for every child it shells, so the processors are
importable from a bare checkout as well as an installed environment.

Environment / flags:

- `--repo-root PATH` / `$DFIR_REPO_ROOT` — the DX_DFIR checkout.
- `--no-tui` / `$DXDFIR_NO_TUI` / `$CI` / `TERM=dumb` — force plain output.
- `--tui` — force the dashboard even when auto-detection is unsure.
- `$DXDFIR_PYTHON` — the Python interpreter to use (else `python3`/`python`).
- `$BYAKUGAN_ROOT` — the external Byakugan engine checkout the CAR lane drives
  (else `byakugan/` beside the repo; pinned by `byakugan.ref`).

Keys in the dashboard: `q` / `Ctrl-C` abort · `Ctrl-L` redraw.

## Module layout

Broken into small, independently-testable packages (nothing outside `internal/tui`
imports termui, so the runner, watchers and repo detection need no terminal):

```
cmd/dxdfir/            thin entry: build the command tree, map exit codes
internal/
  cli/                 cobra verb tree, one file per verb group
  model/               shared types (Update/Snapshot/Lane) + the Presenter interface
  repo/                repo + interpreter/tool discovery
  run/                 subprocess engine (passthrough, stream, capture, sentinels)
  lanes/               `process` orchestration: lane specs, output-glob watching, the Job
  collect/             collection orchestration: drives `python -m …collection`, parses sentinels
  tui/                 termui presenter (process + collection dashboards, event loop)
  plain/               non-TTY presenter (same channel contract)
  termdetect/          TTY detection + opt-outs
  style/               ASCII-safe glyph + colour vocabulary
```

The two presenters consume the identical `model.Update` stream, so the
subprocess/watch layer is the same in both modes and only the presenter differs.
