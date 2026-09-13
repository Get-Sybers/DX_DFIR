# dxdfir_evtx

Parse **Windows Event Logs (`.evtx`)** with **EvtxECmd** into normalised JSON for
the Elastic-native or SOF-ELK pipeline. The role is structure only — it asserts inputs, runs a
preflight (docker, input dir, **the EvtxECmd image or operator-supplied release**),
then invokes the `get_sybers_dxdfir.evtx` Python processor as a **single action** (one
container run per log happens inside Python). One `<base>_EvtxECmd_Output.json` per
log (+ an `.xml` sidecar, not ingested), grouped by the source sub-dir (host).

## Supplying EvtxECmd — two modes
Selected by `dxdfir_evtx_use_bundled_image` (default **bundled**):

- **Bundled (default).** The `get-sybers/evtxecmd` image (built from
  [`third_party/GoDFIR-toolz/evtxecmd`](https://github.com/Get-Sybers/GoDFIR-toolz/tree/main/evtxecmd)) bakes `EvtxECmd.dll` **and `Maps/`** onto a
  .NET runtime. Build it once and forget it — no files to place by hand:
  ```bash
  docker build -t get-sybers/evtxecmd:latest -f third_party/GoDFIR-toolz/evtxecmd/Dockerfile third_party/GoDFIR-toolz
  ```
- **Operator-supplied.** Set `dxdfir_evtx_use_bundled_image=false` and drop the .NET
  EvtxECmd release (incl. `Maps/`) under `dxdfir_evtx_evtxecmd_dir`. Download it from
  <https://github.com/EricZimmerman/evtx/releases>. It is mounted read-only into a
  stock .NET runtime image (`dxdfir_evtx_dotnet_image`, which **must be .NET 9.x** —
  EvtxECmd's current build targets net9.0). Without `Maps/`, `MapDescription` /
  `signature` comes out empty.

Both modes produce byte-identical output; the bundled image is just the release run
without a mount. EvtxECmd is **not vendored** either way — the Dockerfile *fetches*
the MIT-licensed release at build time; the repo ships the recipe, not the binary.

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dxdfir_evtx_pipeline` | `elastic` | `elastic` or `sofelk` — selects the output destination (the **playbook** decides this). |
| `dxdfir_evtx_evtx_dir` | `<repo>/data_store/raw/logs/winevt` | `.evtx` tree to parse (recursed). |
| `dxdfir_evtx_elastic_out_dir` | `<repo>/data_store/processed/windows_logs` | Elastic-path output. |
| `dxdfir_evtx_sofelk_out_dir` | `<repo>/data_store/processed/sofelk/windows_logs` | SOF-ELK-path output. |
| `dxdfir_evtx_use_bundled_image` | `true` | Use the bundled `get-sybers/evtxecmd` image; `false` = mount an operator release. |
| `dxdfir_evtx_bundled_image` | `get-sybers/evtxecmd:latest` | Bundled image tag (built from `third_party/GoDFIR-toolz/evtxecmd`). |
| `dxdfir_evtx_evtxecmd_dir` | `<repo>/data_store/dependencies/evtxecmd` | Operator-supplied EvtxECmd release (must hold `EvtxECmd.dll`; include `Maps/`). |
| `dxdfir_evtx_dotnet_image` | `mcr.microsoft.com/dotnet/runtime:9.0` | Operator mode: the .NET **9.x** runtime image the release mounts into. |
| `dxdfir_evtx_image` | (computed) | The image actually run; override to pin a digest. |
| `dxdfir_evtx_python_path` | `<repo>/python` | PYTHONPATH to `get_sybers_dxdfir` (in-repo runs). |
| `dxdfir_evtx_force` | `false` | Reparse logs that already have output. |

## Idempotence
A log whose `.json` output already exists (non-empty) is skipped — the skip lives in
the Python processor, never in a task `when:`. EvtxECmd exits 0 on an empty/corrupt
log; a zero-record output is removed and counted `failed`, not treated as done.

## Example
```bash
ansible-playbook playbooks/dxdfir-process-evtx.yml -e dxdfir_evtx_pipeline=elastic
```

## Testing
Python unit tests cover the pure logic (DLL location, host grouping, output naming,
discovery, missing-DLL handling). The **Molecule** scenario needs operator inputs
(a sample `.evtx` and an EvtxECmd release — neither is redistributable), supplied
as extra-vars:
```bash
molecule test -- -e molecule_sample_evtx=/path/Security.evtx \
                 -e molecule_evtxecmd_dir=/path/to/evtxecmd
```
