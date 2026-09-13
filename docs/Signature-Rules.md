# Adding Your Own Signature Rules (YARA & Suricata)

The signature lanes (`python/get_sybers_dxdfir/signatures/`, run as
`python -m get_sybers_dxdfir.signatures` or via the `dxdfir_signatures` role) load
operator-supplied rules from `data_store/dependencies/`. There is **no
registration step** — drop the files in the right directory and run the lane;
discovery is recursive.

Outputs land in `data_store/processed/signatures/<lane>/` as self-describing
JSONL. Lane basics are in
[Scripts-Overview](/docs/scripts/Scripts-Overview.md#signature-detection-get_sybers_dxdfirsignatures).

---

## YARA

**Where:** anywhere under `data_store/dependencies/yara-rules/` — nested
subdirectories are fine, the lane walks the whole tree.

**What loads:** every `*.yar` / `*.yara` file (extension is case-insensitive).
Files whose basename starts with `_` are skipped — prefix a file with `_` to
disable it without deleting it.

**How they're loaded:** the lane generates an index file of
`include "/rules/<relative-path>"` lines — one per discovered rule file — and
compiles that single index. Your rules directory is bind-mounted **read-only**
at `/rules` inside the hardened `get-sybers/yara` container, so nested layouts survive
intact; the index itself goes to a temp file outside the tree, so the rules
directory may be read-only.

For the **memory** source (Volatility `vadyarascan`) all rule files are
concatenated into one file — so **rule names must be unique across every
file** or compilation fails.

```bash
# drop rules (any nesting)
mkdir -p data_store/dependencies/yara-rules/mine
cp my_malware.yar data_store/dependencies/yara-rules/mine/

# run just the YARA lane (--yara-sources files,disk,memory narrows the sources)
python3 -m get_sybers_dxdfir.signatures --only yara \
    --output-dir data_store/processed/signatures --repo-root .
```

`--fetch` provisions the pinned
[DetectRaptor](https://github.com/mgreen27/DetectRaptor) ruleset **only when the
directory has no rules yet** — your own rules suppress it. See below.

### DetectRaptor content

[DetectRaptor](https://github.com/mgreen27/DetectRaptor) (Matt Green / mgreen27)
is bulk Velociraptor detection content. The part this pipeline can consume is its
**YARA** sets — a curated webshell ruleset plus per-OS file and process sets,
YARA-Forge-derived with per-rule provenance metadata. Enable either way:

```bash
# implicitly — the Python YARA lane's --fetch (also dxdfir_signatures_fetch=true)
python3 -m get_sybers_dxdfir.signatures --only yara --fetch \
    --output-dir data_store/processed/signatures --repo-root .

# explicitly — the provisioning module itself
python3 -m get_sybers_dxdfir.signatures.detectraptor \
    --rules-dir data_store/dependencies/yara-rules
```

Both download a **commit-pinned, sha256-verified** set of assets and merge them
into `yara-rules/detectraptor/detectraptor.yar` (~10,700 rules). The merge is
required: upstream publishes each set for a separate Velociraptor artifact and
freely repeats rule identifiers across files, but this lane compiles one index —
so duplicates are dropped first-wins, and rules needing module features the
`get-sybers/yara` build lacks (`telfhash`) are skipped. Per-rule `meta` blocks
(author, `source_url`, `license_url`) are kept byte-for-byte.

- **Idempotent** — an existing `detectraptor.yar` is left alone; delete it or
  `--force` (module CLI) to refresh. The lane's `--fetch` also stands down when
  the tree already has *any* rules — your own rules always win.
- **Do not combine with YARA-Forge packages** (e.g. a downloaded YARA-Forge
  release) in one rules dir — DetectRaptor's sets are largely YARA-Forge
  extracts, and duplicate identifiers fail the whole single-index compile.
- **Advancing the pin:** bump `_PIN` in
  `python/get_sybers_dxdfir/signatures/detectraptor.py`, run
  `python3 -m get_sybers_dxdfir.signatures.detectraptor --print-hashes`, paste the
  digests into `ASSETS`.
- **Not consumed:** DetectRaptor's VQL artifacts and CSV lookups (they need a
  Velociraptor server); it ships no Sigma or Suricata rules. Licensing and
  attribution: [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).

**Verify:** the lane reports the rule-file count (confirm yours is counted), then
check the output — each match is one JSON object naming your rule:

```bash
jq -r '.rule' data_store/processed/signatures/yara/matches.jsonl | sort | uniq -c
```

The **files** source scans `data_store/raw/other_raw_data/`. Plant an
EICAR-style test file there to prove a rule fires.

**Gotchas**

- **One broken rule aborts everything.** All rules compile through a single
  index, so a syntax error in any file kills the whole scan (container stderr is
  discarded — you just get 0 matches). Pre-check a new rule:
  ```bash
  docker run --rm -v "$PWD/data_store/dependencies/yara-rules":/rules:ro \
      get-sybers/yara:latest -e '{"dxdfir_run_argv": ["yara", "/rules/mine/my_malware.yar", "/dev/null"]}'
  ```
- Duplicate rule identifiers across files are a compile error (memory source) —
  namespace your rule names.
- The Python lane skips a source whose output already exists — pass `--force`
  (or delete `matches.jsonl`) to re-scan.

---

## Suricata

**Where:** a **single file named exactly `suricata.rules`**, anywhere under
`data_store/dependencies/suricata-rules/`. The lane walks the whole tree and
takes the *first* one it finds — keep it shallow.

**How it's loaded:** the rules directory is mounted read-only at `/rules` and the
file is passed with `suricata -S`, which loads it **exclusively** — the container
image's bundled rules are ignored. If no `suricata.rules` exists, the lane falls
back to the `get-sybers/suricata` package defaults and says so.

Multiple rule sources therefore have to be merged into that one file:

```bash
mkdir -p data_store/dependencies/suricata-rules
cat et-open.rules my-local.rules > data_store/dependencies/suricata-rules/suricata.rules

python3 -m get_sybers_dxdfir.signatures --only suricata \
    --output-dir data_store/processed/signatures --repo-root .
```

To provision ET Open while online, run `suricata-update` (or download the ET Open
tarball) into the directory yourself, then append your own rules to the one
`suricata.rules` file.

**Verify:** the lane reports the ruleset it chose (if it says it's using the
image's bundled rules, your file wasn't found). Then check the per-PCAP EVE
output for alerts from your signatures:

```bash
jq -r 'select(.event_type=="alert") | .alert.signature' \
    data_store/processed/signatures/suricata/*.eve.jsonl | sort | uniq -c
```

**Gotchas**

- Suricata's stderr is discarded; a rules file with syntax errors shows up as no
  output or silent zero alerts. Test first:
  ```bash
  docker run --rm -v "$PWD/data_store/dependencies/suricata-rules":/rules:ro \
      get-sybers/suricata:latest -e '{"dxdfir_run_argv": ["suricata", "-T", "-S", "/rules/suricata.rules"]}'
  ```
- Every rule needs a **unique `sid`** (use ≥ 1000000 for local rules) —
  duplicates are rejected at load.
- Output is filtered to alert + context event types
  (`alert, anomaly, http, dns, tls, fileinfo, flow`); set `keep_all` for the full
  EVE stream.
- A PCAP with an existing non-empty `.eve.jsonl` is skipped — delete the output
  (or pass `--force`) after changing rules.

### Tuning (the consolidated variables and the per-PCAP template)

`HOME_NET` is Suricata's primary tuning variable: ET/Sigma-style rules key their
direction off `$HOME_NET` / `$EXTERNAL_NET`, so a `HOME_NET` matching the
capture's real internal range is what makes directional rules fire.

**The consolidated variable registry.** Every `vars.*` variable the stock
suricata.yaml defines lives in one registry (`suricata.SURICATA_VARS`) — its
kind (address/port group), stock default, and how the lane automates it. The
tuning template is generated from that registry, so the file itself carries the
full table. **Every var automates**, from the traffic each host sends and
receives on ports:

| Variable | Derived from |
|---|---|
| `home_net` / `external_net` | private supernets observed (RFC1918 + CGNAT + link-local; RFC1918 default when none appear) / its complement |
| `http/smtp/dns/sql/telnet/aim/dc_servers`, `dnp3/modbus/enip_server` | the flow's *receiving* side (dest IP) where the flow shows parser evidence (its app-layer protocol) or well-known-port evidence (25/465/587 SMTP, 53 DNS, 1433/1434/3306/5432/1521 SQL, 23 telnet, 5190 AIM, 88/464 Kerberos→DC, 20000/502/44818 SCADA), scoped home-side — except `aim_servers`, whose stock default is `$EXTERNAL_NET`, so external-side |
| `dnp3/modbus/enip_client` | the same evidence, taken from the flow's *initiating* side (src IP), home-scoped |
| `http_ports`, `ssh_ports`, `ftp_ports`, `modbus_ports`, `dnp3_ports` | ports the protocol was *actually spoken* on — flow `app_proto` included, so HTTP on 8080 is caught |
| `oracle/geneve/vxlan/teredo_ports` | no Suricata parser exists — the well-known ports that actually carried traffic (the observed subset) |
| `shellcode_ports` | `!$HTTP_PORTS` once `http_ports` is derived (`file_data_ports` follows by reference) |

A var with nothing observed keeps its stock default, and a derivation that
would enumerate half the capture (>16 ports, >32 IPs) is dropped in favour of
the default. Port-based evidence is a heuristic — any traffic to the service's
well-known port counts — so review the recorded sections where precision
matters; that is exactly what the editable file is for.

**The tuning template.** Per-capture tuning lives in an operator-editable INI
file, by default `data_store/dependencies/suricata-tuning.conf`
(`dxdfir_signatures_suricata_tuning_file` / `--tuning-file`):

- The **first run writes the template** (comments only). While the file holds no
  real sections — or is not valid INI — the lane **auto-detects** the vars above
  (one default-vars pass first) and **records** them as a section per capture.
- **Edit the recorded sections** and re-run with `--force` to apply your values.
  Any consolidated var is a valid key; an unknown key marks the file invalid
  (a typo would otherwise be silently ignored):

  ```ini
  [case1_capture.pcap]              ; the capture's summary key (path folded)
  home_net = [192.168.0.0/16]
  http_ports = [80,8080]
  dns_servers = [192.168.0.10]
  sets =                            ; anything beyond the vars, one per line
      stream.reassembly.depth=3mb

  [global]                          ; applies to captures without a section
  home_net = [10.0.0.0/8]
  ```

- An **invalid file** (broken INI, an unknown key, whitespace inside an address
  group) falls back to auto-detect; the broken file is kept beside the fresh
  one as `*.invalid`, never lost.
- Tuning is **reset for every capture** — a value derived from or configured
  for one pcap never carries into the next. Each capture's decision (values and
  source: `cli`/`file`/`auto`) is echoed in the run summary under `tuning`.

CLI overrides still exist and beat the file for every capture:

```bash
# set it explicitly (EXTERNAL_NET defaults to its complement)
--home-net '[10.0.0.0/8,192.168.0.0/16]'   [--external-net '[1.2.3.0/24]']

# any other Suricata variable, repeatable (appended to file entries too)
--suricata-set vars.port-groups.HTTP_PORTS=8080
```

(`--auto-home-net` is accepted for compatibility; auto-detection is now the
default whenever neither `--home-net` nor a tuning-file entry covers a capture.)

## Hayabusa (Sigma over Windows Event Logs)

Hayabusa runs inside the **evtx pipeline** (`python -m get_sybers_dxdfir.evtx
--hayabusa`), scanning the same `.evtx` the lane collected — loose logs or those
extracted from a disk image via `--image-src`. Sigma rules live under
`data_store/dependencies/hayabusa/rules/` (or `--hayabusa-rules`); detections are
written to `<out-dir>/hayabusa/timeline.jsonl`. See
[Scripts-Overview](/docs/scripts/Scripts-Overview.md#signature-detection-get_sybers_dxdfirsignatures).
