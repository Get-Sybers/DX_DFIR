# 🚀 Get Started

> These steps reflect the paths that actually work today. See
> [What Actually Works](/README.md#what-actually-works) before you start, and
> note that the Kusto emulator carries licensing terms you are accepting
> — [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).

### 🧭 Two ways to drive this

The **`dxdfir` CLI** is the pipeline's front-end (three-layer design — see
[How It Runs](/README.md#how-it-runs)). The numbered steps below use the underlying
`process-*.sh` scripts directly — the layer the
[capability states](/README.md#what-actually-works) were validated with. The CLI
runs the same flow:

```bash
pip install ./python     # provides dxdfir (also needs ansible-playbook on PATH)
dxdfir process plaso     # sources: plaso | zeek | evtx | volatility | velociraptor | signatures
dxdfir deploy            # stand up the ADX (Kusto) emulator + apply schema
dxdfir ingest            # load data_store/processed into it
dxdfir validate          # run the repo check harness
```

`dxdfir deploy`/`ingest` target the ADX emulator; the SOF-ELK path is
`dxdfir process <source> --pipeline sofelk`, then the collection's
`dfir-deploy-sofelk.yml` / `dfir-ingest-sofelk.yml` playbooks. `man dxdfir` for
the manual.

### ⚙️ **Step 1: Setup Environment**
- **Run setup-environment.sh:**
  ```bash
  DX_DFIR/scripts/setup-environment.sh
  ```
_Refer to [📁 Setup_Environment](/docs/scripts/Setup_Environment.md) for details on the script._

### 🗂️ **Step 2: Place Raw Data**
- **Disk Images (`.E01`):**
  ```bash
  DX_DFIR/data_store/raw/disk_images/
  ```

- **VMware VM Exports (one folder per VM):**
  ```bash
  DX_DFIR/data_store/raw/VM_files/
  ```

- **Network Captures (`.pcap`, `.pcapng`):**
  ```bash
  DX_DFIR/data_store/raw/pcaps/
  ```

- **Other Raw Data Sources:**
  ```bash
  DX_DFIR/data_store/raw/other_raw_data/
  ```

_Refer to [📁 Dir-Structure](/docs/Dir-Structure.md) for detailed directory structures._

### 💾 **Step 3: Process Forensic Images (E01 / VMware)**
```bash
DX_DFIR/scripts/process-log2timeline-Dynamic.sh
```
- Automates forensic analysis of all `.E01` disk images and VMware VM exports using Plaso.
- Output lands in `data_store/processed/log2timeline/jsonl/` (Plaso `json_line`,
  fanned out into one `host.L2t<Parser>` table per top-level parser on ingest),
  the `.plaso` databases in `plaso/`, and job logs in `logs/`.

### 🛜 **Step 4: Process PCAPs with Zeek**
```bash
DX_DFIR/scripts/process-zeek-ALL.sh
```
- Automates processing of all network capture files (`.pcap` and `.pcapng`) using Zeek.
- Output lands in `data_store/processed/zeek/<pcap-name>/`.

### 🪟 **Step 5: Parse Windows Event Logs (optional)**
```bash
DX_DFIR/scripts/process-evtx-EvtxECmd.sh
```
- Converts `.evtx` in `data_store/raw/other_raw_data/WinEvt/<host>/` using EvtxECmd.
- Requires operator-supplied EvtxECmd — see
  [the README](/data_store/dependencies/evtxecmd/README.md). MIT licensed, no
  commercial-use restriction.
- ⚠️ Not runtime-tested — see
  [the script docs](/docs/scripts/processing_data/process-evtx-EvtxECmd.md).

### 🧊 **Step 6: Deploy the Kusto emulator**
```bash
DX_DFIR/scripts/deploy-kusto.sh
```
- Starts the **Azure Data Explorer Kusto emulator** in Docker — the real Kusto
  engine, entirely local. No Azure, no account, no cloud.
- ⚠️ This sets `ACCEPT_EULA=Y`, **accepting Microsoft's Software License Terms
  on your behalf.** The emulator is provided *as-is*, without support or
  warranties, and Microsoft documents it as generally unsuitable for
  production workloads.
- ⚠️ **The emulator has NO authentication and speaks plaintext HTTP.** It is
  published on `127.0.0.1` only; binding anywhere else requires typing
  `expose`. It also runs on an isolated network with no usable egress, and the
  deploy verifies both directions after start.

**Ephemeral by default — and that is the recommended mode.** Microsoft advises
against persisting emulator data outside the container (version compatibility,
no extent merging). `data_store/processed/` is the source of truth here, so the
intended workflow is redeploy + re-ingest, which is cheap:

```bash
./scripts/deploy-kusto.sh                 # ephemeral database (default)
./scripts/deploy-kusto.sh --persist       # opt in to a host-dir database, with the caveats above
./scripts/deploy-kusto.sh --purge         # delete container + persisted data, then redeploy
./scripts/deploy-kusto.sh --purge-only    # delete and STOP — no redeploy
./scripts/deploy-kusto.sh --help          # all options
```

**Unattended deploys**

| Variable | Default | Purpose |
|:---|:---|:---|
| `KUSTO_MEMORY` | `4G` | Container memory limit (Microsoft recommends ≥4G) |
| `KUSTO_READY_TIMEOUT` | `900` | Seconds to wait for the engine (first pull is multi-GB) |
| `KUSTO_BIND_ADDR` | `127.0.0.1` | Host address to publish on — **think hard before widening** |
| `KUSTO_PORT` | `8080` | Host port |
| `KUSTO_PERSIST` | `0` | `1` mounts `data_store/kusto` at `/kustodata` |
| `KUSTO_ISOLATED` | `1` | `1` = masquerade-disabled bridge, no usable egress |
| `KUSTO_REPLACE` | `always` | `always` \| `ask` \| `never` |
| `KUSTO_CONTAINER` | `kusto-emulator` | Container name |
| `KUSTO_NETWORK` | `kusto-dfir-isolated` | Isolated network name |

### 🏗️ **Step 7: Apply the schema**
```bash
DX_DFIR/scripts/apply-kusto-schema.sh
```
- Creates the databases (`host`, `network`, `memory`, `misc`, `mitre`), typed
  tables, ingestion mappings, and the MITRE CAR functions from
  `kusto/schema/`. Idempotent — safe to re-run.
- Detects from the running container whether `/kustodata` is mounted and picks
  persist/volatile to match; `--persist` / `--volatile` override.

### 📥 **Step 8: Ingest processed evidence**
```bash
DX_DFIR/scripts/ingest-kusto.sh
```
- Loads `data_store/processed/` into the emulator: Plaso `json_line` fanned out
  into per-parser `host.L2t<Parser>` tables, EvtxECmd JSON → `host.EvtxEcmdJson`,
  Zeek `conn` → `network.ZeekConn` (every other Zeek log → the generic
  `network.Zeek`), Volatility JSONL → `memory.VolatilityJson`, and Velociraptor
  JSON → `host.VelociraptorJson` (each record wrapped with its `Artefact`/`SourceFile`).
- The Velociraptor **ingest** loader is wired; what's still partial is the
  **upstream** collection path — the Velociraptor offline collectors running the
  EZ Tools (the KAPE replacement) aren't built yet, so in practice there is
  usually no processed Velociraptor data to load.
- Ingestion is additive with no fishbucket: re-running duplicates rows. To
  start clean, redeploy (ephemeral default) and re-ingest.
- `--only l2t|zeek|evtx|volatility|velociraptor` limits to one source;
  `--dry-run` lists without contacting anything.

### 🔎 **Step 9: Query**

Connect any Kusto client to `http://127.0.0.1:8080` (for example
[Kusto.Explorer](https://learn.microsoft.com/en-us/kusto/tools/kusto-explorer)
on Windows), or drive it with `curl` — the deploy banner prints the endpoints.

Start in the `mitre` database:

```kusto
CarCoverage()          // which CAR objects have data right now
CarProcess() | take 50
CarFlow() | where dest_port == 445
```

---

For detailed script usage, refer to the [📜 Scripts Overview](/docs/scripts/Scripts-Overview.md).
The design, the schema layout, and what is deliberately not done yet:
[docs/Kusto-Port.md](/docs/Kusto-Port.md).
