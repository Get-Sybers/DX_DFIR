# The interface

Run `dxdfir` with **no arguments** on a terminal and it launches a persistent,
interactive UI — a tabbed dashboard with one command box at the bottom. Every line you
type runs the same `dxdfir` verbs you'd type at a shell, so you keep driving the whole
pipeline without leaving the UI.

> The previews below are faithful terminal renderings. They render in any Markdown
> viewer; drop real PNG captures into [`docs/images/`](../images/) and swap them in if
> you prefer.

## The command box

The box at the bottom is always live. Type a command, press **Enter**, and its output
streams into the pane above. Built-ins: `clear`, `quit` / `exit`. Everything else
(`list`, `list collections`, `process case-a zeek`, …) runs the real CLI verb.

| Key | Action |
|---|---|
| **Tab** / **→** | next tab |
| **Shift-Tab** / **←** | previous tab (← is reliable; most terminals don't send Shift-Tab) |
| **Enter** | run the current line |
| **Ctrl-C** | cancel a running command or query · quit the shell when idle |

## Pipeline

The streaming output log, plus — while a `process` job runs — a live progress gauge and
a lane/step queue that ticks as evidence lands. State icons: `▸` running, `✓` done,
`✗` failed, `–` skipped, `·` queued.

```
┌ Pipeline ─┬ Containers ─┬ Kibana ─┬ Timeline ──────────────────────────────────┐
│ pipeline                                                                        │
│ ████████████████░░░░░░░░░░░░░░░░░░░░░░  42%  ·  2/5 lanes  ·  zeek → conn.log    │
├ queue ──────────────────────────────────────────────────────────────────────── ┤
│   LANE / STEP        PROGRESS   DETAIL                                           │
│ ✓ zeek               12/12      conn, dns, http, ssl, files…                     │
│ ▸ evtx               3/8        Security.evtx                                    │
│ · volatility         0/1        queued                                           │
│ · plaso              0/1        queued                                           │
│ – godfir-toolz       –          skipped — no disk image                          │
├ output ─────────────────────────────────────────────────────────────────────── ┤
│ [zeek] wrote conn.log — 18,442 records                                           │
│ [evtx] parsing Security.evtx …                                                   │
├ command ────────────────────────────────────────────────────────────────────── ┤
│ > process case-a all_                                                            │
└ type a command, Enter to run · Tab/→ next · Shift-Tab/← prev · Ctrl-C quits ──── ┘
```

## Containers

A `ktop`-style table of the running tool containers with aggregate CPU and memory
gauges. Containers are spawned **per file during a run**, so "none running" is normal at
rest. The load gauges ramp amber → ochre → crimson as usage climbs.

```
┌ Pipeline ─┬ Containers ─┬ Kibana ─┬ Timeline ──────────────────────────────────┐
│ CPU                                                                             │
│ ██████████████████████░░░░░░░░░░░░░░░  58%  ·  Σ 232% over 4 cores              │
│ memory                                                                          │
│ ████████████████████████████████████  91%  ·  3 containers                     │
├ containers (3 running) ──────────────────────────────────────────────────────── ┤
│ NAME             IMAGE                STATUS   CPU    MEM                        │
│ zeek-case-a-01   get-sybers/zeek      Up 6s    128%   512MiB                     │
│ evtx-case-a-01   get-sybers/goevtx    Up 2s    64%    210MiB                     │
│ plaso-case-a-01  get-sybers/plaso     Up 1s    40%    1.1GiB                     │
└─────────────────────────────────────────────────────────────────────────────── ┘
```

## Kibana

The command box becomes an **ES|QL query input**. Type a query, press Enter, and the
result renders as a table. A status header shows the [Elastic stack](../architecture/the-stack.md)
health and the `logs-dxdfir.*` data streams.

```
┌ Pipeline ─┬ Containers ─┬ Kibana ─┬ Timeline ──────────────────────────────────┐
│ ES: green  2 nodes   ·   Kibana: ready  http://127.0.0.1:5601                   │
│ query> FROM logs-dxdfir.* | STATS n = COUNT(*) BY labels.type | SORT n DESC      │
├ results (5 rows) ───────────────────────────────────────────────────────────── ┤
│ labels.type    n                                                                │
│ evtx           18442                                                            │
│ zeek           21959                                                            │
│ volatility     3517                                                             │
└─────────────────────────────────────────────────────────────────────────────── ┘
```

## Timeline

The [Byakugan behaviour timeline](../architecture/car-pipeline.md) read from
`data_store/processed/byakugan`, newest event first — the CAR object events and relationship
edges unioned into one time-ordered stream.

```
┌ Pipeline ─┬ Containers ─┬ Kibana ─┬ Timeline ──────────────────────────────────┐
│ TIME                 KIND    OBJECT   HOST     SUMMARY                          │
│ 2024-01-01T00:00:03  object  flow     HOST1    10.0.0.5:5000 → 93.1.2.3:443 tls │
│ 2024-01-01T00:00:02  edge    →        HOST1    process connected_to flow (pid)  │
│ 2024-01-01T00:00:01  object  process  HOST1    C:\evil.exe  evil.exe -run       │
└─────────────────────────────────────────────────────────────────────────────── ┘
```

## Theming

The frame tone is set by the **`DXDFIR_THEME`** environment variable — part of the warm
"Sunset" palette (marigold running, amber done, ochre warn, vermilion failed, so no
pass/fail rests on red-vs-green alone):

```bash
DXDFIR_THEME=ember dxdfir       # deep bronze frame (default)
DXDFIR_THEME=dusk dxdfir        # burnt amber
DXDFIR_THEME=driftwood dxdfir   # tan
```

Anything unset or unknown falls back to `ember`. See the palette rules in
[Go standards → the Sunset theme](../reference/go-standards.md#the-sunset-theme).

## No terminal? The plain dashboard

If the terminal can't host the UI (piped output, no TTY, or a window below the minimum
size) `dxdfir` falls back to a plain **readiness dashboard**: environment checks,
tracked collections, and staged evidence per lane. Force it with `dxdfir --no-tui`.
