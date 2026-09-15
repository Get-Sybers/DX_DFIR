# dxdfir_volatility

Process **memory images** with **Volatility 3** into per-plugin JSON Lines for the
Elastic-native or SOF-ELK pipeline. The role is structure only — it asserts inputs,
runs a preflight (docker reachable, memory dir present, the hardened
[`get-sybers/piiat-mem`](https://github.com/Get-Sybers/PIIAT-Mem) image guarded),
then **`docker run`s that image directly** — no processor module, no vendored
submodule. One `<plugin>.jsonl` per plugin per image.

## How it works
[PIIAT-Mem](https://github.com/Get-Sybers/PIIAT-Mem) (Volatility 3) is fused into
the **self-orchestrating `get-sybers/piiat-mem` image** (cloned + built at the
`sources.yml` pin). It discovers the images, runs the CAR plugin set over each with
Volatility **in-process** (`--native`, confined by the image — no nested docker),
is idempotent per plugin, and emits the JSON summary Ansible gates on. The role
just builds the confined `docker run` (cap-drop ALL, no-new-privileges, read-only
rootfs + `/tmp` tmpfs, no network unless `--symbols-online`, `--group-add` for the
read-only evidence mount) and passes config as `PIIAT_*` env vars; the image writes
the raw `<dest>/plugins/<plugin>.jsonl` to the mounted `/out`.

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dxdfir_volatility_pipeline` | `elastic` | `elastic` or `sofelk` — selects the output destination (the **playbook** decides this). |
| `dxdfir_volatility_memory_dir` | `<repo>/data_store/raw/memory` | Memory-image tree to process (recursed). |
| `dxdfir_volatility_elastic_out_dir` | `<repo>/data_store/processed/volatility` | Elastic-path output. |
| `dxdfir_volatility_sofelk_out_dir` | `<repo>/data_store/processed/sofelk/volatility` | SOF-ELK-path output. |
| `dxdfir_volatility_symbols_dir` | `<repo>/data_store/dependencies/volatility3-symbols` | Volatility 3 kernel-symbol cache (mounted at `/symbols`). |
| `dxdfir_volatility_image` | `get-sybers/piiat-mem:latest` | The hardened, env-driven PIIAT-Mem (Volatility 3) image the lane docker-runs (built by `playbooks/dxdfir-build-images.yml`). |
| `dxdfir_volatility_symbols_online` | `false` | Allow container network access for ISF symbol fetch — the one legitimate network need; pre-seed the symbols dir instead. |
| `dxdfir_volatility_python_path` | `<repo>/python` | PYTHONPATH for the image supply-chain guard (`get_sybers_dxdfir.images`); in-repo runs. |
| `dxdfir_volatility_force` | `false` | Rerun plugins that already have valid output. |

## Symbols (network)
Windows plugins resolve the kernel against ISF symbol tables Volatility fetches from
the symbol servers on first use — that needs **outbound network**. On an isolated
host, pre-seed `dxdfir_volatility_symbols_dir`, or the Windows plugins error with
"symbol table requirement was not fulfilled". `banners.Banners` needs no symbols.

## Idempotence
A plugin whose `.jsonl` output exists and whose first line parses as JSON is
skipped — the skip lives in the Python processor, never in a task `when:`.
Per-plugin failures (e.g. symbols unavailable) are **normal** and non-fatal: the
verify gate is "some plugin produced output, or there were no images", not
`failed == 0`.

## Example
```bash
ansible-playbook playbooks/dxdfir-process-volatility.yml -e dxdfir_volatility_pipeline=elastic
```

## Testing
Python unit tests cover the pure logic (image discovery, name folding, JSONL
validity, no-images path, the CAR plugin set, and a conformance check that shells
`piiat-mem --list-plugins`). The **Molecule** scenario needs a memory image
(large/binary — not shipped) and, for the Windows plugins, symbols:
```bash
molecule test -- -e molecule_sample_memory=/path/dump.raw
```

## Validated (real run, built image)
On 2026-08-29 the lane was run end-to-end through a built `get-sybers/piiat-mem:latest`
image against a real dump (Magnet 2020 CTF `memdump-001.mem`, 5 GB, 64-bit Windows).
All 15 CAR plugins loaded and ran through the container; the run exited 0. The
pool-scan plugins produced valid JSON Lines — **`windows.piiat.processes`** (65
processes, with full path / parent path / loaded DLLs), `windows.netscan` (69),
`windows.thrdscan` (988), plus `banners.Banners` and `windows.info`. The
active-list plugins (`pslist`, `pstree`, `dlllist`, …) and `windows.piiat.registry`
returned 0 rows **on that dump** — an image property, not a defect: the built-in
`windows.registry.hivelist` also finds 0 resident hives there, and the psscan-based
`windows.piiat.processes` is precisely what recovers the process list when the
active list does not resolve. A dump with resident hives is still wanted to show
`windows.piiat.registry` emitting rows before the tool is tagged/promoted.
