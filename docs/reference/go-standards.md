# Go standards

The `dx` front-end (`go/`, module `github.com/Get-Sybers/DX_DFIR/go`, Go 1.24 floor)
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

Small, independently testable `internal/` packages, one concern each. All presentation is
isolated in `internal/plain` — so the runner, watcher and repo detection need no terminal.

| Package | Concern |
|---|---|
| `cmd/dx/` | Thin entry: build the cobra tree, map exit codes |
| `internal/cli` | The cobra verb tree — one file per verb group |
| `internal/model` | Shared `Update`/`Snapshot`/`Lane` types + the `Presenter` interface — the channel contract the presenter consumes |
| `internal/run` | Subprocess engine (passthrough / stream / capture / plan) |
| `internal/lanes` | Process orchestration: lane specs, output-glob watching, the Job |
| `internal/collection` · `internal/collect` | Native Go collection layer — SQLite registry, magic-byte classify, no subprocess |
| `internal/plain` | The line-output presenter — streams progress on stderr, keeps stdout clean |
| `internal/repo` · `identify` · `health` · `fsx` · `style` | Discovery, classification, readiness, fs helpers, plain-output palette |

The binary shells out via [go-ansible](https://github.com/apenella/go-ansible) (which
only *builds* argv — `internal/run` executes it); everything it fronts is
`ansible-playbook`.

## Error handling

Sentinel errors (e.g. `errors.New` values a caller can match on) let a caller react
precisely, and `internal/plain` renders the `model.Update` stream as line output — so
presentation never touches the data.

## Enforced by

`gofmt -l` clean, `go vet ./...`, `go build ./...`, `go test ./...` — all in
[the check harness](build-and-test.md).
