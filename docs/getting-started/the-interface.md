# The interface

`dx` is a plain command-line tool: one `dx <verb> <noun>` per action, with output that
streams as it happens. There is no interactive dashboard — every command is a single,
auditable invocation you can type, script, redirect, or re-run.

## Output model

- **Progress** (processing, collection hashing, sorting) streams as line output on
  **stderr**: periodic status lines (`[dx] lanes 2/5 · zeek → conn.log`) plus the live
  log tail from the tool. Pressing **Ctrl-C** cancels the underlying job cleanly.
- **Machine-readable payloads** go to **stdout** and are never styled, so
  `dx list evidence > staged.txt` and friends stay clean under a pipe or redirect.
- **Colour** is used on stderr for diagnostics only. It is disabled automatically when
  stderr is not a terminal, and honours `NO_COLOR` and `TERM=dumb`.

## The landing readout

Run `dx` with **no arguments** for a point-in-time readout of where the pipeline stands:

```
dx 0.7.0   DX_DFIR forensic pipeline
repo  /opt/cases/DX_DFIR

[x] NOT READY - 2 of 4 gate check(s) failing.
Readiness   (* = optional lane/capability, not a process gate)
  [ok] repo          /opt/cases/DX_DFIR
  [x]  ansible       ansible-playbook not found - run scripts/setup-environment.sh
  [ok] collection    get_sybers.dxdfir (ansible/collections/get_sybers.dxdfir)
  [x]  docker        daemon unreachable - is dockerd running / are you in the docker group?
  [!]  byakugan*     engine image get-sybers/byakugan:latest not built (dx build images)

Collections
  * case-a                 142 file(s)  [pcaps:3, memory:2]  sha1:9f2c1a0b4d7e

Staged evidence   (data_store/raw/ - what `process` reads)
  zeek               3 file(s)  pcaps/
  anamnesis          2 file(s)  memory/
  ...

-> process: dx process <scope>   |   register: dx register <name>   |   help: dx --help
```

Three panels:

- **Readiness** — the environment checks. `[ok]` green, `[!]` an optional lane/capability
  not yet available (a warning, never a process gate), `[x]` a failing gate. The banner
  sums the gate checks.
- **Collections** — registered, detected, and dropzone-candidate collections; the active
  one is starred. The same data as `dx list collections`.
- **Staged evidence** — per-lane file counts over `data_store/raw/`. The same data as
  `dx list evidence`.

The readout is written to stdout, so it is a first-class, greppable payload like any
other list.

## Working the pipeline

Everything you need is a verb away — see the [command reference](commands.md). A typical
session:

```bash
dx build images                 # one-time: pull the hardened tool images
dx register case-a              # track a dropzone folder as a collection
dx sort case-a                  # magic-byte-sort it into lane subdirs
dx process case-a               # run every tool with evidence in the case
dx byakugan build               # normalise the processed tree into CAR
dx byakugan verify              # gate the CAR before trusting it
dx deploy stack                 # bring the Elastic analysis stack up
dx byakugan load                # bulk-load the CAR into the stack
```
