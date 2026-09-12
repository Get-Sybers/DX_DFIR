# get_sybers_dxdfir

The processing logic of the DX_DFIR pipeline as an importable, unit-tested Python
package — the processors plus the `python -m` contract modules the front-end
drives. The heavy per-item work (container runs, JSON reshaping) lives here; the
`get_sybers.dxdfir` Ansible collection orchestrates it one action per task, and
the user-facing **`dxdfir`** front-end is the Go binary built from `go/`.

## Processors
Each source is a module runnable standalone or through its role:
```bash
python -m get_sybers_dxdfir.zeek        --pcap-dir RAW/pcaps --out-dir PROCESSED/zeek
python -m get_sybers_dxdfir.evtx        --evtx-dir RAW/logs/winevt --out-dir PROCESSED/windows_logs --evtxecmd-dir DEPS/evtxecmd
python -m get_sybers_dxdfir.volatility  --memory-dir RAW/memory --out-dir PROCESSED/volatility --symbols-dir DEPS/symbols --renderer … --plugins-dir …
python -m get_sybers_dxdfir.plaso       --input-dir RAW/disk_images --out-dir PROCESSED/log2timeline --module dev-scripts/plaso/l2t_json_dxdfir.py
python -m get_sybers_dxdfir.signatures  --output-dir PROCESSED/signatures --repo-root .
```
Every processor prints a machine-readable JSON summary (`processed`/`skipped`/
`failed`/…) so its role can set an honest `changed_when`.

The CAR lane sits on top of the processed tree: `python -m get_sybers_dxdfir.mitrecar`
drives the vendored [PIIAT-MitreCar](https://github.com/Get-Sybers/PIIAT-MitreCar)
engine (one `car.db` + `car_<object>.jsonl` per source), and
`python -m get_sybers_dxdfir.carcheck` is the correctness gate over what it wrote.
The Elastic detection rules live as data under `get_sybers_dxdfir/detect/rules/`
(`python -m get_sybers_dxdfir.detect.rules_loader` validates them).

## The `dxdfir` front-end (Go)
The verbs live in the Go binary (`go/` — see [its README](../go/README.md)); it
shells out to this package and never re-implements processing:
```bash
dxdfir process zeek --pipeline elastic  # drive the dxdfir_zeek role (preflight → process → verify)
dxdfir process signatures -e '{"dxdfir_signatures_lanes":["yara"]}'
dxdfir build-car                        # normalise every processed source into per-source CAR stores
dxdfir verify-car                       # the CAR correctness gate over the materialised CAR
dxdfir build-docker                     # build (and hardening-verify) every dxdfir/* tool image
dxdfir validate                         # run the check harness
dxdfir list                             # list processable sources
man dxdfir                              # the manual (go/man/dxdfir.1)
```
`process` drives the collection with `ansible-playbook` (the role's one action calls
the matching `python -m get_sybers_dxdfir.<source>` for the tight loop). `build-car` and
`verify-car` drive the CAR lane; the analysis backend is the Elastic-native stack
(`docker/elastic`, brought up with compose), fed from the processed tree.
`validate` runs the repo's check harness (`tests/run-checks.sh`). The repo is
auto-detected (or pass `--repo-root` / `$DFIR_REPO_ROOT`).

## Install
```bash
pip install ./python          # the processor package (+ ansible-core, so ansible-playbook comes with it)
install -Dm644 go/man/dxdfir.1 ~/.local/share/man/man1/dxdfir.1   # optional: man page
```
The package installs no console script — the `dxdfir` command is the Go binary
(`scripts/setup-environment.sh` builds and installs it). In-repo runs need no
install — set `PYTHONPATH=python` (the roles do this via
`dxdfir_<source>_python_path`). Without installing the man page, read it directly with
`man ./go/man/dxdfir.1`.

## Test
```bash
cd python && PYTHONPATH=. python -m pytest        # unit tests (pure logic; no docker)
```
