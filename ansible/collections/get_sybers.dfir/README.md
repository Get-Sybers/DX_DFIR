# get_sybers.dfir

The DX_DFIR forensic processing pipeline as an Ansible Galaxy collection. The heavy
logic lives in the `get_sybers_dfir` Python package (`python/`); each Ansible **task
is one action** that invokes it, and the **playbook** holds every decision — which
roles run and the `--pipeline adx|sofelk` selection.

Conforms to the Get-Sybers Ansible standards (naming/structuring + one-action-per-task
+ robustness) — see `Get-Sybers/Ludus-Ansible` `docs/standards/ansible/`.

## Roles
One role per evidence source; each invokes its `get_sybers_dfir.<source>` processor
as a single action. All six process roles exist (`dfir_zeek` was the exemplar the
pattern was proven on); the matching `process-*.sh` scripts all remain and are
retired per source only as each role's full path is proven — none retired yet
(epic #46).

| Role | Source | Processor |
|---|---|---|
| `dfir_zeek` | PCAPs → Zeek JSON | `get_sybers_dfir.zeek` |
| `dfir_velociraptor` | Velociraptor collector ZIPs → per-artefact JSON | `get_sybers_dfir.velociraptor` |
| `dfir_volatility` | Memory images → Volatility 3 per-plugin JSONL | `get_sybers_dfir.volatility` |
| `dfir_evtx` | Windows Event Logs (`.evtx`) → EvtxECmd JSON | `get_sybers_dfir.evtx` |
| `dfir_plaso` | Disk images / VM exports → Plaso JSONL | `get_sybers_dfir.plaso` |
| `dfir_signatures` | YARA / Suricata / Hayabusa detections | `get_sybers_dfir.signatures` |

Deploy + load roles: **`dfir_deploy_adx`** (emulator + schema), **`dfir_ingest_adx`**
(processed → ADX, idempotent via an in-DB ledger), **`dfir_ingest_sofelk`** (deliver
into SOF-ELK's watch dir), **`dfir_deploy_sofelk`** (builds the from-source SOF-ELK
stack — `docker/sof-elk/`). `dxdfir deploy` / `dxdfir ingest` drive the ADX pair.

## Usage
The **`dxdfir` CLI** (Python package `get_sybers_dfir`) is the front-end — it drives
these roles for you:
```bash
dxdfir process zeek --pipeline adx      # = the dfir_zeek role, preflight → process → verify
dxdfir process signatures               # all lanes
```
Or run a playbook directly; each source has one under `playbooks/`, which selects
the role and passes the pipeline:
```bash
ansible-playbook playbooks/dfir-process-zeek.yml -e dfir_zeek_pipeline=adx
ansible-playbook playbooks/dfir-process-velociraptor.yml -e dfir_velociraptor_pipeline=adx
ansible-playbook playbooks/dfir-process-volatility.yml -e dfir_volatility_pipeline=adx
ansible-playbook playbooks/dfir-process-evtx.yml -e dfir_evtx_pipeline=adx
ansible-playbook playbooks/dfir-process-plaso.yml -e dfir_plaso_pipeline=adx
ansible-playbook playbooks/dfir-process-signatures.yml -e dfir_signatures_pipeline=adx
```
