# dxdfir_memory

Process **memory images** into per-plugin JSON Lines. The role is structure only — it asserts inputs,
runs a preflight (docker reachable, memory dir present, the hardened
[`get-sybers/anamnesis`](https://github.com/Get-Sybers/Anamnesis) image guarded),
then **`docker run`s that image directly** — no processor module, no vendored
submodule. One `<plugin>.jsonl` per plugin per image.

## How it works
[anamnesis](https://github.com/Get-Sybers/Anamnesis) (MemProcFS) is fused into
the **self-orchestrating `get-sybers/anamnesis` image** (cloned + built at the
`sources.yml` pin). It discovers the images, runs the CAR plugin set over each
**in-process** (native MemProcFS, confined by the image — no nested docker),
is idempotent per plugin, and emits the JSON summary Ansible gates on. The role
just builds the confined `docker run` (cap-drop ALL, no-new-privileges, read-only
rootfs + `/tmp` tmpfs, no network unless `--symbols-online`, `--group-add` for the
read-only evidence mount) and passes config as `ANAMNESIS_*` env vars; the image writes
the raw `<dest>/plugins/<plugin>.jsonl` to the mounted `/out`.

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dxdfir_memory_memory_dir` | `<repo>/data_store/raw/memory` | Memory-image tree to process (recursed). |
| `dxdfir_memory_out_dir` | `<repo>/data_store/processed/memory` | Output base (override to redirect). |
| `dxdfir_memory_symbols_dir` | `<repo>/data_store/dependencies/memprocfs-symbols` | PDB/symbol cache (mounted at `/symbols`). |
| `dxdfir_memory_image` | `get-sybers/anamnesis:latest` | The hardened, env-driven anamnesis (MemProcFS) image the lane docker-runs (built by `playbooks/dxdfir-build-images.yml`). |
| `dxdfir_memory_symbols_online` | `false` | Allow container network access for PDB symbol fetch — the one legitimate network need; pre-seed the symbols dir instead. |
| `dxdfir_memory_python_path` | `<repo>/python` | PYTHONPATH for the image supply-chain guard (`get_sybers_dxdfir.images`); in-repo runs. |
| `dxdfir_memory_force` | `false` | Rerun plugins that already have valid output. |

## Symbols (network)
Windows plugins resolve the kernel against PDB symbols anamnesis fetches from
the symbol servers on first use — that needs **outbound network**. On an isolated
host, pre-seed `dxdfir_memory_symbols_dir`, or the Windows plugins error with
"symbol table requirement was not fulfilled". `banners.Banners` needs no symbols.

## Idempotence
A plugin whose `.jsonl` output exists and whose first line parses as JSON is
skipped — the skip lives in the Python processor, never in a task `when:`.
Per-plugin failures (e.g. symbols unavailable) are **normal** and non-fatal: the
verify gate is "some plugin produced output, or there were no images", not
`failed == 0`.

## Example
```bash
ansible-playbook playbooks/dxdfir-process-memory.yml
```

## Testing
Python unit tests cover the pure logic (image discovery, name folding, JSONL
validity, no-images path, the CAR plugin set, and a conformance check that shells
`anamnesis --list-plugins`). The **Molecule** scenario needs a memory image
(large/binary — not shipped) and, for the Windows plugins, symbols:
```bash
molecule test -- -e molecule_sample_memory=/path/dump.raw
```

## Validated
The lane mechanics — image discovery, the confined `docker run`, per-plugin
idempotence and the JSON summary gate — were proven end-to-end against a real
dump (Magnet 2020 CTF `memdump-001.mem`, 5 GB) on the previous engine. The
native MemProcFS engine keeps the same output contract, but its own on-target
validation over the standard corpora is still pending (tracked in Anamnesis
`docs/design/native-engine.md` §8) — wanted before the tool is tagged/promoted.
