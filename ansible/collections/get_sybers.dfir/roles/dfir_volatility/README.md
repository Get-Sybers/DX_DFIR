# dfir_volatility

Process **memory images** with **Volatility 3** into per-plugin JSON Lines for the
ADX or SOF-ELK pipeline. The role is structure only — it asserts inputs, runs a
preflight (docker, memory dir, the `jsonl_dfir` renderer, the custom plugins dir),
then invokes the `get_sybers_dfir.volatility` Python processor as a **single
action** (one container run per plugin per image happens inside Python). One
`<plugin>.jsonl` per image, via the custom `jsonl_dfir` renderer.

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dfir_volatility_pipeline` | `adx` | `adx` or `sofelk` — selects the output destination (the **playbook** decides this). |
| `dfir_volatility_memory_dir` | `<repo>/data_store/raw/memory` | Memory-image tree to process (recursed). |
| `dfir_volatility_adx_out_dir` | `<repo>/data_store/processed/volatility` | ADX-path output. |
| `dfir_volatility_sofelk_out_dir` | `<repo>/data_store/processed/sofelk/volatility` | SOF-ELK-path output. |
| `dfir_volatility_symbols_dir` | `<repo>/data_store/dependencies/volatility3-symbols` | Volatility 3 kernel-symbol cache (passed as `--symbols-dir`). |
| `dfir_volatility_renderer` | `<repo>/dev-scripts/volatility/jsonl_dfir_renderer.py` | Custom JSONL renderer. |
| `dfir_volatility_plugins_dir` | `<repo>/dev-scripts/volatility/plugins` | Custom plugins (`dfir_processes`, `dfir_registry`). |
| `dfir_volatility_image` | `sk4la/volatility3:latest` | Volatility 3 container image. |
| `dfir_volatility_python_path` | `<repo>/python` | PYTHONPATH to `get_sybers_dfir` (in-repo runs). |
| `dfir_volatility_force` | `false` | Rerun plugins that already have valid output. |

## Symbols (network)
Windows plugins resolve the kernel against ISF symbol tables Volatility fetches from
the symbol servers on first use — that needs **outbound network**. On an isolated
host, pre-seed `dfir_volatility_symbols_dir`, or the Windows plugins error with
"symbol table requirement was not fulfilled". `banners.Banners` needs no symbols.

## Idempotence
A plugin whose `.jsonl` output exists and whose first line parses as JSON is
skipped — the skip lives in the Python processor, never in a task `when:`.
Per-plugin failures (e.g. symbols unavailable) are **normal** and non-fatal: the
verify gate is "some plugin produced output, or there were no images", not
`failed == 0`.

## Example
```bash
ansible-playbook playbooks/dfir-process-volatility.yml -e dfir_volatility_pipeline=adx
```

## Testing
Python unit tests cover the pure logic (image discovery, name folding, JSONL
validity, no-images path, the CAR plugin set). The **Molecule** scenario needs a
memory image (large/binary — not shipped) and, for the Windows plugins, symbols:
```bash
molecule test -- -e molecule_sample_memory=/path/dump.raw
```
