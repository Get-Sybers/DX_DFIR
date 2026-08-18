# get_sybers_dfir

The processing logic of the DX_DFIR pipeline as an importable, unit-tested Python
package, plus the **`dxdfir`** command-line front-end (Typer) — the top layer of epic
#46. The heavy per-item work (container runs, JSON reshaping) lives here; the
`get_sybers.dfir` Ansible collection orchestrates it one action per task.

## Processors
Each source is a module runnable standalone or through its role:
```bash
python -m get_sybers_dfir.zeek        --pcap-dir RAW/pcaps --out-dir PROCESSED/zeek
python -m get_sybers_dfir.velociraptor --raw-dir RAW/velociraptor --out-dir PROCESSED/velociraptor
python -m get_sybers_dfir.evtx        --evtx-dir RAW/WinEvt --out-dir PROCESSED/windows_logs --evtxecmd-dir DEPS/evtxecmd
python -m get_sybers_dfir.volatility  --memory-dir RAW/memory --out-dir PROCESSED/volatility --symbols-dir DEPS/symbols --renderer … --plugins-dir …
python -m get_sybers_dfir.plaso       --input-dir RAW/disk_images --out-dir PROCESSED/log2timeline --module dev-scripts/plaso/l2t_json_dfir.py
python -m get_sybers_dfir.signatures  --output-dir PROCESSED/signatures --repo-root .
```
Every processor prints a machine-readable JSON summary (`processed`/`skipped`/
`failed`/…) so its role can set an honest `changed_when`.

## The `dxdfir` CLI
```bash
dxdfir process zeek --pipeline adx      # drive the dfir_zeek role (preflight → process → verify)
dxdfir process signatures -e '{"dfir_signatures_lanes":["yara"]}'
dxdfir ingest --only zeek               # load processed output into the ADX emulator
dxdfir deploy                           # stand up + schema-load the emulator
dxdfir validate                         # run the check harness
dxdfir list                             # list processable sources
man dxdfir                              # the manual (man/dxdfir.1)
```
`process` drives the collection with `ansible-playbook` (the role's one action calls
the matching `python -m get_sybers_dfir.<source>` for the tight loop). `ingest` and
`deploy` drive the `dfir_ingest_adx` / `dfir_deploy_adx` roles the same way;
`validate` runs the repo's check harness (`tests/run-checks.sh`). The repo is
auto-detected (or pass `--repo-root` / `$DFIR_REPO_ROOT`).

## Install
```bash
pip install ./python          # provides the `dxdfir` entry point + the package
install -Dm644 man/dxdfir.1 ~/.local/share/man/man1/dxdfir.1   # optional: man page
```
In-repo runs need no install — set `PYTHONPATH=python` (the roles do this via
`dfir_<source>_python_path`). Without installing the man page, read it directly with
`man ./python/man/dxdfir.1`.

## Test
```bash
cd python && PYTHONPATH=. python -m pytest        # 81 unit tests (pure logic; no docker)
```
