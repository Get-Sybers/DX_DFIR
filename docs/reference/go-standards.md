# Go standards

The `dxdfir` front-end (`go/`, module `github.com/get-sybers/dx_dfir/go`, Go 1.24 floor)
re-implements no processing — it builds a plan and shells out. These are its conventions.

## Naming — the `go-thonic` vocabulary

Functions use a small set of **reserved verbs** and read as a phrase at the call site.
There is no `Get*`, and a name never stutters its package.

| Verb | Means | Example |
|---|---|---|
| `Read` | read the contents of a file | `readTimeline(…)`, `readElasticEnv(…)` |
| `Load` | load a module / library / rule | *(reserved)* |
| `Check` | check a state / status | `collection.CheckStatus(…)`, `collection.CheckState(…)` |
| `List` | return a plural collection | `collection.ListLanes(…)` |
| `Run` | execute a command / job | `runProcess(…)`, `runESQL(…)` |
| `Classify` / `Detect` | classify evidence by content | `identify.Classify(…)`, `identify.IsPcap(…)` |

The rule bites hardest at **exported, cross-package** call sites:
`collection.CheckStatus(root)` reads as a phrase, whereas
`collection.GetCollectionStatus(root)` would both use `Get*` and stutter the package —
not the house style. Package-private helpers (`readTimeline`, `runESQL`, `runProcess`)
follow the same verb vocabulary but are called unqualified within their package. This
mirrors the Ansible best-practices the project follows.

## Package layout

Small, independently testable `internal/` packages, one concern each. **Only
`internal/tui` may import termui** — so the runner, watcher and repo detection need no
terminal.

| Package | Concern |
|---|---|
| `cmd/dxdfir/` | Thin entry: build the cobra tree, map exit codes |
| `internal/cli` | The cobra verb tree — one file per verb group |
| `internal/model` | Shared `Update`/`Snapshot`/`Lane` types + the `Presenter` interface — the single channel contract both presenters consume |
| `internal/run` | Subprocess engine (passthrough / stream / capture / plan) |
| `internal/lanes` | Process orchestration: lane specs, output-glob watching, the Job |
| `internal/collection` · `internal/collect` | Native Go collection layer — SQLite registry, magic-byte classify, no subprocess |
| `internal/tui` | The termui presenter — tabs, dashboards, the shell |
| `internal/plain` | The non-TTY presenter — same channel contract |
| `internal/repo` · `identify` · `health` · `fsx` · `termdetect` · `style` | Discovery, classification, readiness, fs helpers, TTY detection, plain-output palette |

The binary shells out via [go-ansible](https://github.com/apenella/go-ansible) (which
only *builds* argv — `internal/run` executes it) or `python -m get_sybers_dxdfir.*`.

## The Sunset theme

`internal/tui/tui.go` holds a single warm 256-colour accent family (marigold → crimson).
Green/blue/cyan were **retired** so nothing competes with the sunset and no pass/fail
hangs on red-vs-green. The rules:

- **Text (including titles) may be near-white; non-text chrome — borders, tabs, gauge
  bars — is warm and never near-white.**
- The frame tone is `colBorder`, selectable via `DXDFIR_THEME` (`ember` = deep bronze,
  default · `dusk` = burnt amber · `driftwood` = tan).
- `ensureTheme()` applies the theme exactly once (`sync.Once`) **before any widget is
  built** — termui copies `ui.Theme` at construction.
- Every state pairs colour with a **glyph or token**, never hue alone. Gauges are
  truthful — a bar only where a real *i/N* exists; load gauges ramp amber→ochre→crimson.
- Dynamic text is **ASCII-only** (so `${#var}` math survives a C/POSIX locale).

The old colour names are kept as **semantic aliases** (`colBlue`=214 marigold/running,
`colGreen`=172 amber/done, …) so views recolour with no edits. The separate plain-output
palette lives in `internal/style` and honours `NO_COLOR` / `TERM=dumb`. The
[setup script](../architecture/setup-flow.md) uses the same palette in ANSI.

## Error handling

Sentinel errors (e.g. `tui.ErrNoTTY`, `errors.New`) let a caller fall back cleanly — the
TUI declines and `internal/plain` renders the identical `model.Update` stream, so only
presentation differs, never the data.

## Enforced by

`gofmt -l` clean, `go vet ./...`, `go build ./...`, `go test ./...` — all in
[the check harness](build-and-test.md).
