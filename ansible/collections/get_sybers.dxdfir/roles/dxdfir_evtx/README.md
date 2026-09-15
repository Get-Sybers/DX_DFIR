# dxdfir_evtx

Parse **Windows Event Logs (`.evtx`)** with **goevtx** (the static-Go EvtxECmd
substitute) into normalised JSON. The
role is structure only — it asserts inputs, runs a preflight (docker, input dir,
**the goevtx image is present**), then invokes the `get_sybers_dxdfir.evtx` Python
processor as a **single action** (one container run per log happens inside Python).
One `<base>_EvtxECmd_Output.json` per log (+ an `.xml` sidecar, not ingested),
grouped by the source sub-dir (host).

## The parser: goevtx (no .NET)
`.evtx` are parsed by **`get-sybers/goevtx`** — a static Go binary on Velociraptor's
go-evtx, built `FROM scratch` from
[`docker/GoDFIR-toolz/goevtx`](https://github.com/Get-Sybers/GoDFIR-toolz/tree/main/goevtx)
by the `dxdfir_images` role. No .NET runtime, no `EvtxECmd.dll` to supply. It emits
the same `*_EvtxECmd_Output.json` shape the CAR lane content-routes on (EventId,
Provider, Channel, Computer, EventRecordId, TimeCreated, Payload with the raw
EventData). It does **not** reproduce EvtxECmd's Maps layer (`MapDescription` /
`PayloadData1-6`) — byakugan reads the raw EventData, not those derived columns.

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dxdfir_evtx_evtx_dir` | `<repo>/data_store/raw/logs/winevt` | `.evtx` tree to parse (recursed). |
| `dxdfir_evtx_out_dir` | `<repo>/data_store/processed/windows_logs` | Output base (override to redirect). |
| `dxdfir_evtx_image` | `get-sybers/goevtx:latest` | The goevtx image the processor runs; override to pin a digest. |
| `dxdfir_evtx_python_path` | `<repo>/python` | PYTHONPATH to `get_sybers_dxdfir` (in-repo runs). |
| `dxdfir_evtx_force` | `false` | Reparse logs that already have output. |

## Idempotence
A log whose `.json` output already exists (non-empty) is skipped — the skip lives in
the Python processor, never in a task `when:`. EvtxECmd exits 0 on an empty/corrupt
log; a zero-record output is removed and counted `failed`, not treated as done.

## Example
```bash
ansible-playbook playbooks/dxdfir-process-evtx.yml
```

## Testing
Python unit tests cover the pure logic (argv construction, host grouping, output
naming, discovery, the records/empty/failed classification). The **Molecule**
scenario needs a sample `.evtx` (binary; not redistributable), supplied as an
extra-var (goevtx is the bundled image — no EvtxECmd release needed):
```bash
molecule test -- -e molecule_sample_evtx=/path/Security.evtx
```
