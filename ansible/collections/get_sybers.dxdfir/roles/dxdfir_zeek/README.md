# dxdfir_zeek

Process PCAPs into **Zeek JSON logs**. The role is structure only — it asserts
its inputs and declares one run of the `get-sybers/zeek` image, driven purely by
the tool's contract (`docker/GoDFIR-toolz/zeek/contract.yml`): the shared
`dxdfir_lane` skeleton builds the confined `docker run` from it (`-e ZEEK_*`,
`-v` for `/input` and `/output`), and the image's `zeek-run` entrypoint discovers
every capture under `/input` and parses each into its own folder of `*.json`
(ISO-8601 timestamps) plus a `zeek.jsonl` index. No host-side processor.

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dxdfir_zeek_pcap_dir` | `<repo>/data_store/raw/pcaps` | Capture tree to process (recursed). |
| `dxdfir_zeek_out_dir` | `<repo>/data_store/processed/zeek` | Output base, one folder per capture (override to redirect). |
| `dxdfir_zeek_contract` | `<repo>/docker/GoDFIR-toolz/zeek/contract.yml` | The contract the run is built from. |
| `dxdfir_zeek_image` | `""` (the contract's `get-sybers/zeek:latest`) | Image ref override, e.g. a digest pin. |
| `dxdfir_zeek_scripts` | `""` | Extra zeek argv after `-C -r <capture>` (`ZEEK_SCRIPTS`). |
| `dxdfir_zeek_force` | `false` | Reprocess captures that already have output (`ZEEK_FORCE`). |

## Idempotence
A capture whose output folder already holds valid output is skipped by the tool
itself, never by a task `when:`. A first run that processes new captures is
`changed=true` (the summary line's `processed > 0`); a second immediate run is
`changed=false`.

## Example
```bash
ansible-playbook playbooks/dxdfir-process-zeek.yml
```

## Testing
`molecule test` — converges against a fixture capture, converges again asserting
zero changes (idempotence), and verifies a `conn.json` was produced. Needs Docker
and the `get-sybers/zeek` image (built by `dxdfir_images`).
