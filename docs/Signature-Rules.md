# Adding Your Own Signature Rules (YARA, Suricata, Sigma)

The detection lane is the `get-sybers/signatures` image — YARA, Suricata, Hayabusa
and the gomount→goyara disk scan as four sub-tools of one hardened container —
run by the `dxdfir_signatures` role (`dxdfir process signatures`) from the image's
contract (`docker/GoDFIR-toolz/signatures/contract.yml`). The image **bakes its
rulesets**: the [DetectRaptor](https://github.com/mgreen27/DetectRaptor) YARA merge
(yara + scan), the ET Open Suricata merge, and Hayabusa's default Sigma set. An
operator ruleset replaces the baked one for a run: the role bind-mounts it
read-only into the container and names it to the sub-tool through its `*_RULES`
variable. There is **no registration step** and nothing is copied into the image.

Outputs land in `data_store/processed/detections/<sub-tool>/<item>/` as
self-describing JSONL. Lane basics are in
[Scripts-Overview](/docs/scripts/Scripts-Overview.md#signature-detection).

---

## YARA (the `yara` and `scan` sub-tools)

**What:** one rules file (or a compiled index) — `dxdfir_signatures_yara_rules`.
It is mounted at `/rules/yara.yar` and passed as `SIGNATURES_YARA_RULES` (the
`yara` sub-tool: loose files, memory images) and `SIGNATURES_SCAN_RULES` (the
`scan` sub-tool: disk images streamed through goyara). Several rule files are
merged into one first — yara compiles one file, and duplicate rule identifiers
across files are a compile error, so namespace your rule names.

```bash
# merge your rules into one file
cat mine/*.yar > data_store/dependencies/yara-rules/mine.yar

# run just the yara sub-tool over the loose files with it
ansible-playbook ansible/collections/get_sybers.dxdfir/playbooks/dxdfir-process-signatures.yml \
    -e '{"dxdfir_signatures_lanes":["yara"],"dxdfir_signatures_yara_sources":["files"]}' \
    -e dxdfir_signatures_yara_rules="$PWD/data_store/dependencies/yara-rules/mine.yar"
```

### DetectRaptor content

[DetectRaptor](https://github.com/mgreen27/DetectRaptor) (Matt Green / mgreen27)
is bulk Velociraptor detection content; the part this pipeline consumes is its
**YARA** sets — a curated webshell ruleset plus per-OS file and process sets,
YARA-Forge-derived with per-rule provenance metadata. The image bakes a merge of
them. To refresh that set on the host (and mount it in place of the baked one),
the provisioning module fetches a **commit-pinned, sha256-verified** set of assets
and merges them into `yara-rules/detectraptor/detectraptor.yar` (~10,700 rules):

```bash
python3 -m get_sybers_dxdfir.signatures.detectraptor \
    --rules-dir data_store/dependencies/yara-rules
```

The merge is required: upstream publishes each set for a separate Velociraptor
artifact and freely repeats rule identifiers across files — duplicates are dropped
first-wins, and rules needing module features the image's yara lacks (`telfhash`)
are skipped. Per-rule `meta` blocks (author, `source_url`, `license_url`) are kept
byte-for-byte.

- **Idempotent** — an existing `detectraptor.yar` is left alone; delete it or
  pass `--force` to refresh.
- **Do not combine with YARA-Forge packages** (e.g. a downloaded YARA-Forge
  release) in one merged file — DetectRaptor's sets are largely YARA-Forge
  extracts, and duplicate identifiers fail the compile.
- **Advancing the pin:** bump `_PIN` in
  `python/get_sybers_dxdfir/signatures/detectraptor.py`, run
  `python3 -m get_sybers_dxdfir.signatures.detectraptor --print-hashes`, paste the
  digests into `ASSETS`.
- **Not consumed:** DetectRaptor's VQL artifacts and CSV lookups (they need a
  Velociraptor server); it ships no Sigma or Suricata rules. Licensing and
  attribution: [THIRD_PARTY_NOTICES.md](/.github/THIRD_PARTY_NOTICES.md).

**Verify:** each hit is one JSON object naming your rule:

```bash
jq -r '.rule' data_store/processed/detections/yara/files/*/yara.jsonl | sort | uniq -c
```

The `files` source scans `data_store/raw/other_raw_data/` (every immediate child
is one target). Plant an EICAR-style test file there to prove a rule fires.

**Gotchas**

- **One broken rule aborts the scan** — the ruleset compiles as one unit, so a
  syntax error in any rule fails the whole target. Pre-check a new file with the
  image's debug pass-through:
  ```bash
  docker run --rm -v "$PWD/data_store/dependencies/yara-rules":/rules:ro \
      get-sybers/signatures:latest yara /rules/mine.yar /dev/null
  ```
- A target whose output already exists is skipped — pass
  `dxdfir_signatures_force=true` (or delete its folder) to re-scan.

---

## Suricata

**What:** a **single `suricata.rules` file** — `dxdfir_signatures_suricata_rules`.
It is mounted at `/rules/suricata.rules` and passed as `SIGNATURES_SURICATA_RULES`,
which the sub-tool loads with `suricata -S` — **exclusively**; the baked ET Open
merge is ignored for that run. Merge several rule sources into that one file:

```bash
mkdir -p data_store/dependencies/suricata-rules
cat et-open.rules my-local.rules > data_store/dependencies/suricata-rules/suricata.rules

ansible-playbook ansible/collections/get_sybers.dxdfir/playbooks/dxdfir-process-signatures.yml \
    -e '{"dxdfir_signatures_lanes":["suricata"]}' \
    -e dxdfir_signatures_suricata_rules="$PWD/data_store/dependencies/suricata-rules/suricata.rules"
```

To refresh ET Open on the host, the provisioning module downloads the ruleset
tarball and writes the one `suricata.rules`
(`python3 -m get_sybers_dxdfir.signatures.suricata_rules --rules-dir data_store/dependencies/suricata-rules`);
append your own rules to it.

**Verify:** check the per-capture EVE output for alerts from your signatures:

```bash
jq -r 'select(.event_type=="alert") | .alert.signature' \
    data_store/processed/detections/suricata/*/eve.json | sort | uniq -c
```

**Gotchas**

- A rules file with syntax errors shows up as a failed capture in the run
  summary. Test first with the image's debug pass-through:
  ```bash
  docker run --rm -v "$PWD/data_store/dependencies/suricata-rules":/rules:ro \
      get-sybers/signatures:latest suricata -T -S /rules/suricata.rules
  ```
- Every rule needs a **unique `sid`** (use ≥ 1000000 for local rules) —
  duplicates are rejected at load.
- A capture whose output already exists is skipped — pass
  `dxdfir_signatures_force=true` after changing rules.

### Tuning

`HOME_NET` is Suricata's primary tuning variable: ET/Sigma-style rules key their
direction off `$HOME_NET` / `$EXTERNAL_NET`, so a `HOME_NET` matching the
capture's real internal range is what makes directional rules fire. Tuning is
passed to the sub-tool as `--set` entries through `SIGNATURES_SURICATA_SET`
(`dxdfir_signatures_suricata_set`), comma- or space-separated `key=value`,
and applies to every capture of the run:

```bash
-e dxdfir_signatures_suricata_set='vars.address-groups.HOME_NET=[10.0.0.0/8,192.168.0.0/16],vars.port-groups.HTTP_PORTS=[80,8080]'
```

`EXTERNAL_NET` defaults to `!$HOME_NET` in the image's suricata.yaml; set it
explicitly the same way when it should differ.

---

## Hayabusa (Sigma over Windows Event Logs)

The `hayabusa` sub-tool scans every `.evtx` tree — the loose logs under
`data_store/raw/logs/winevt/` and the evtx lane's disk-image export under
`processed/windows_logs/_extracted_evtx/` — with the image's default Sigma set.
An operator rules directory (`dxdfir_signatures_hayabusa_rules`) is mounted at
`/rules/hayabusa` and passed as `SIGNATURES_HAYABUSA_RULES`; the output profile
is `verbose` (the MITRE columns) unless `dxdfir_signatures_hayabusa_profile` says
otherwise. Detections land in `detections/hayabusa/<item>/timeline.jsonl`.
