# dxdfir_memory

Process **memory images** into per-plugin JSON Lines. The role is structure only — it asserts inputs,
runs a preflight (docker reachable, memory dir present, the hardened
[`get-sybers/anamnesis`](https://github.com/Get-Sybers/Anamnesis) image guarded),
then **`docker run`s that image directly** — no processor module, no vendored
submodule. One `<plugin>.jsonl` per plugin per image.

## How it works
[anamnesis](https://github.com/Get-Sybers/Anamnesis) (MemProcFS) is fused into
the **self-orchestrating `get-sybers/anamnesis` image** (cloned + built at the
Dockerfile's `ANAMNESIS_REF` pin). It discovers the images, runs the CAR plugin set over each
**in-process** (native MemProcFS, confined by the image — no nested docker),
is idempotent per plugin, and emits the JSON summary Ansible gates on. The role
just builds the confined `docker run` (cap-drop ALL, no-new-privileges, read-only
rootfs + `/tmp` tmpfs, `--network none` always, `--group-add` for the
read-only evidence mount) and passes config as `ANAMNESIS_*` env vars; the image writes
the raw `<dest>/plugins/<plugin>.jsonl` to the mounted `/out`.

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dxdfir_memory_memory_dir` | `<repo>/data_store/raw/memory` | Memory-image tree to process (recursed); mounted read-only at `/input` inside the container. |
| `dxdfir_memory_out_dir` | `<repo>/data_store/processed/memory` | Output base (override to redirect). |
| `dxdfir_memory_symbols_dir` | `<repo>/data_store/dependencies/memprocfs-symbols` | Persistent MemProcFS symbol cache (symsrv layout); mounted read-write at `/opt/anamnesis/lib/Symbols`. |
| `dxdfir_memory_image` | `get-sybers/anamnesis:latest` | The hardened, env-driven anamnesis (MemProcFS) image the lane docker-runs (built by `playbooks/dxdfir-build-images.yml`). |
| `dxdfir_memory_python_path` | `<repo>/python` | PYTHONPATH for the image supply-chain guard (`get_sybers_dxdfir.images`); in-repo runs. |
| `dxdfir_memory_force` | `false` | Rerun plugins that already have valid output. |

## Symbols (the persistent cache mount)
The PDB symbols the Windows fields need (`command_line`, `sid`, `user`, …)
live in `dxdfir_memory_symbols_dir`, bind-mounted **read-write** at
`/opt/anamnesis/lib/Symbols` — the one directory MemProcFS uses as its local
symbol cache when it is writable. The cache persists on the host and
accumulates across runs; it uses the symsrv layout
(`<name>/<GUID+age>/<name>`), so PDBs obtained by any external means can be
dropped straight in. The lane stays always offline — the engine never
downloads a PDB, and there is no network toggle. A dump whose Windows build
the cache does not cover still yields the whole kernel-derived surface, with
the PDB-derived fields empty.

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
(large/binary — not shipped); for populated Windows fields the mounted symbol
cache must cover that image's Windows build:
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
