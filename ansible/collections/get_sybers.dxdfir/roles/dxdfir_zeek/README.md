# dxdfir_zeek

Process PCAPs into **Zeek JSON logs**. The role is
structure only — it asserts inputs, runs a preflight, then invokes the
`get_sybers_dxdfir.zeek` Python processor as a **single action** (one container run
per capture happens inside Python). One folder of `*.json` per capture.

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dxdfir_zeek_pcap_dir` | `<repo>/data_store/raw/pcaps` | Capture tree to process (recursed). |
| `dxdfir_zeek_out_dir` | `<repo>/data_store/processed/zeek` | Output base (override to redirect). |
| `dxdfir_zeek_image` | `get-sybers/zeek:latest` | The hardened in-repo Zeek image (`playbooks/dxdfir-build-images.yml`). |
| `dxdfir_zeek_python_path` | `<repo>/python` | PYTHONPATH to `get_sybers_dxdfir` (in-repo runs). |
| `dxdfir_zeek_force` | `false` | Reprocess captures that already have output. |

## Idempotence
A capture whose output folder already holds `*.json` is skipped — the skip lives in
the Python processor, never in a task `when:`. A first run that processes new
captures is `changed=true`; a second immediate run is `changed=false`.

## Example
```bash
ansible-playbook playbooks/dxdfir-process-zeek.yml
```

## Testing
`molecule test` — converges against a fixture capture, converges again asserting
zero changes (idempotence), and verifies a `conn.json` was produced. Needs Docker
and the `get-sybers/zeek` image (built by `dxdfir_images`).
