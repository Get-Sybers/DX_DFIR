# Third-Party Notices

This project redistributes third-party code and drives third-party tools. This
file records what comes from where, under what licence, and which obligations
are outstanding.

Two categories matter, and they matter differently:

- **Vendored** — code copied into this repository and redistributed with it.
  These licences bind the project and constrain what licence it can carry.
- **Invoked** — tools this project runs but does not ship. These impose no
  licence obligation on this repository, but they do constrain *you*, the
  operator, at run time.

---

## Vendored components

Code that ships inside this repository.

| Component | Path | Upstream | Licence |
|---|---|---|---|
| MITRE CAR data model | `car_data_model.json` | [mitre-attack/car](https://github.com/mitre-attack/car) | Apache-2.0 |

### MITRE CAR

`car_data_model.json` is the MITRE CAR object/field/action model. Apache-2.0,
attribution required — hence `NOTICE`. It is the reference copy of the model
the pipeline's CAR output follows (`docs/CAR-Pipeline.md` verifies it against
`car.mitre.org`); the CAR engine itself reconstructs its model from the `car`
repo it vendors as a submodule.

### DFIR test samples — catalogued, not redistributed

**This repository ships no sample data at all.** `dev-scripts/samples-manifest.tsv`
catalogues 860 files (2.8 TB) held by [Digital Corpora](https://digitalcorpora.org/),
recording their public URLs, sizes and hashes so `dev-scripts/fetch-samples.sh`
can retrieve them. Nothing is copied into this repository, so **no
redistribution obligation attaches to this project** for any of it.

That is a genuine change in kind, not bookkeeping. An earlier revision did
commit twelve of these files, two of them GPL-licensed, which meant carrying
their licence texts and passing them on. Fetching instead of vendoring retires
that obligation entirely.

The terms still bind whoever downloads them, and they are not uniform:

| Source | Licence / terms |
|---|---|
| NPS corpora (`drives-nps-*`, `scenarios-2011-nps-*`) | Public domain / unrestricted research use |
| DFTT images — `8-jpeg-search`, `12-carve-ext2` (Brian Carrier, Nick Mikus) | **GPL.** Redistributing them means carrying the GPL text and their READMEs; simply downloading them does not |
| The Sleuth Kit test data | IBM-PL / CPL / GPL, mixed per file |
| Magnet CTF sets (`scenarios-magnet`) | Published by Magnet Forensics for **training and competition**. Not public domain — check their terms before commercial use or onward redistribution |
| DFRWS challenge data (`dfrws-challenge-2021`) | Released for the DFRWS forensic challenge; research and education |
| Scenario corpora (LoneWolf, Narcos, Owl, Tuck, NGDC, Linux threat-analysis) | Produced for forensic education; generally free for research and teaching, several with citation requests recorded in their Digital Corpora READMEs |

None of these are case evidence. `data_store/` remains deny-by-default and
holds nothing, and `samples/` is now written the same way.

### DetectRaptor YARA content — fetched, not redistributed

**This repository ships none of it.** The YARA lane's `--fetch`
(`get_sybers_dxdfir/signatures/detectraptor.py`) downloads the YARA rulesets from
[mgreen27/DetectRaptor](https://github.com/mgreen27/DetectRaptor) — commit-pinned,
sha256-verified — and merges them into
`data_store/dependencies/yara-rules/detectraptor/detectraptor.yar`, which is
deny-by-default gitignored. Only the manifest (URLs + hashes) lives in this
repository, so no redistribution obligation attaches — the same position as the
sample corpora above.

Terms still bind the operator who fetches, and they are layered:

- **DetectRaptor itself declares no repository-level licence.** Treat the
  aggregation as all-rights-reserved beyond the fetching-for-use its README
  invites; do not redistribute the merged file.
- **Each rule carries its own provenance** — upstream is a YARA-Forge-style
  aggregation and every rule's `meta` block records `author`, `source_url` and
  `license_url` (Neo23x0 signature-base, Mandiant, Arkbird_SOLG, …). The merge
  keeps those blocks byte-for-byte; the per-rule licences (mostly DRL/CC/Apache)
  govern the rules.
- DetectRaptor's **VQL artifacts and CSV lookups are not fetched** — they need a
  Velociraptor server this pipeline does not run.

### Emerging Threats Open (Suricata rules) — fetched, not redistributed

**This repository ships none of it.** The Suricata lane's `--fetch`
(`get_sybers_dxdfir/signatures/suricata_rules.py`) downloads the
[ET Open](https://rules.emergingthreats.net/open/) ruleset — the version-pinned
tarball published per Suricata engine release — and concatenates its `*.rules`
into `data_store/dependencies/suricata-rules/suricata.rules`, which is
deny-by-default gitignored. Only the source URL lives in this repository, so no
redistribution obligation attaches — the same position as DetectRaptor above.

- ET Open is a **rolling feed** (rebuilt daily), so the pin is the engine-version
  URL, not a content hash; the fetch is HTTPS + structural validation, the trust
  model the official `suricata-update` uses.
- The ruleset carries **Proofpoint's ET Open licence** (BSD-style, non-commercial
  attribution terms); those terms bind the operator who fetches, not this repo.

---

---

## Build-time dependencies — the Go front-end

The `dxdfir` front-end (`go/`) is a Go program; these modules are pinned in
`go/go.mod` + `go/go.sum` and compiled into the built binary (so they are
redistributed if the binary is shipped). All are permissive. `go/go.sum` is the
integrity lock; `go mod vendor` (run by `scripts/package-offline.sh`) captures
them under `go/vendor/` for reproducible, air-gapped builds.

| Module | Version | Licence |
|---|---|---|
| [github.com/gizak/termui/v3](https://github.com/gizak/termui) | v3.1.0 | MIT |
| [github.com/spf13/cobra](https://github.com/spf13/cobra) | v1.10.1 | Apache-2.0 |
| [github.com/spf13/pflag](https://github.com/spf13/pflag) | v1.0.10 | BSD-3-Clause |
| [github.com/mattn/go-runewidth](https://github.com/mattn/go-runewidth) | v0.0.2 | MIT |
| [github.com/mitchellh/go-wordwrap](https://github.com/mitchellh/go-wordwrap) | 2015-03-14 | MIT |
| [github.com/nsf/termbox-go](https://github.com/nsf/termbox-go) | 2019-01-21 | MIT |
| [github.com/inconshreveable/mousetrap](https://github.com/inconshreveable/mousetrap) | v1.1.0 | Apache-2.0 |
| [github.com/apenella/go-ansible/v2](https://github.com/apenella/go-ansible) | v2.4.1 | MIT |
| [github.com/apenella/go-common-utils](https://github.com/apenella/go-common-utils) (`data`, `error`) | 2022-09-13 | MIT |
| [github.com/pkg/errors](https://github.com/pkg/errors) | v0.9.1 | BSD-2-Clause |
| [github.com/stretchr/testify](https://github.com/stretchr/testify) | v1.11.1 | MIT |
| [github.com/stretchr/objx](https://github.com/stretchr/objx) | v0.5.3 | MIT |
| [github.com/davecgh/go-spew](https://github.com/davecgh/go-spew) | v1.1.1 | ISC |
| [github.com/pmezard/go-difflib](https://github.com/pmezard/go-difflib) | v1.0.0 | BSD-3-Clause |
| [golang.org/x/sync](https://pkg.go.dev/golang.org/x/sync) | v0.17.0 | BSD-3-Clause |
| [gopkg.in/yaml.v2](https://gopkg.in/yaml.v2) | v2.4.0 | Apache-2.0 |
| [gopkg.in/yaml.v3](https://gopkg.in/yaml.v3) | v3.0.1 | MIT + Apache-2.0 (dual, per its LICENSE) |

go-ansible builds every `ansible-playbook` argv (typed options); it does not
execute ansible — the in-repo run engine does. Its `pkg/execute` imports
`stretchr/testify/mock` in non-test code, which is why the testify chain
(testify, objx, go-spew, go-difflib, yaml.v3) is genuinely **linked into the
shipped binary** rather than test-only — verified with `go mod why` /
`go list -deps`, not assumed from `go.mod`. yaml.v2 arrives via
go-common-utils. mousetrap is linked on Windows builds only.

The Go toolchain itself (BSD-3-Clause) is installed by
`scripts/setup-environment.sh` when absent; it is not redistributed.

## Runtime dependencies — the Python package

The `get_sybers_dxdfir` package's direct dependencies, declared in
`python/pyproject.toml` and installed beside it (never vendored — this closes a
tracing gap: the Python dependencies were not recorded here before). Exact
tested versions, transitive closure included, are pinned in
`python/constraints.txt`; the offline bundle (`scripts/package-offline.sh`)
carries them as unmodified wheels.

| Package | Licence |
|---|---|
| [ansible-core](https://github.com/ansible/ansible) | GPL-3.0-or-later |
| [requests](https://github.com/psf/requests) | Apache-2.0 |
| [docker](https://github.com/docker/docker-py) (Docker SDK for Python) | Apache-2.0 |
| [PyYAML](https://github.com/yaml/pyyaml) | MIT |

ansible-core's GPL does not reach this project's MIT code: nothing here imports
ansible — the package ships beside it and the front-end invokes
`ansible-playbook` as a subprocess. Where the offline bundle redistributes the
wheels, they are unmodified and their source is available upstream.

## Formerly vendored components

Removed from the working tree, but **still in git history** — their
attributions continue to apply to anyone working from an older commit. All of
these left with the Splunk stack when the SIEM moved to the Kusto emulator
(itself since retired in favour of the Elastic-native stack; nothing of it was
vendored, so no attribution debt remains).

### splunk-ansible (Apache-2.0)

One modified file (`ansible/playbooks/remove_first_login.yml`) shipped until
the Splunk retirement. Before that, earlier releases vendored 97 further files
under `ansible/tasks/` and `ansible/default_playbooks/`; an audit established
that *nothing in the repository ever executed them* — only
`ansible/playbooks/` was bind-mounted into the container, and the
`splunk/splunk` image ships its own copy of splunk-ansible internally. They
were removed in v0.2.0-beta; the provenance audit (61 byte-identical to
upstream `develop`, 18 modified, none original) is recorded in that release's
history.

### Splunk Security Content (ESCU) lookups (Apache-2.0)

The `DETECT` and `BASELINE` Splunk apps shipped **77 lookup files, roughly
3 MB**, from [splunk/security_content](https://github.com/splunk/security_content),
authored by the Splunk Threat Research Team and contributors. Filenames
carried a local taxonomy prefix (`bad_`, `com_`, `sus_`); contents and their
upstream identifiers were unmodified, and the YAML sidecars retained upstream
provenance. Some aggregate other projects' data upstream (HijackLibs,
LOLDrivers, LOLBAS). Removed with the Splunk apps.

### Third-party Splunk apps — never vendored after v0.2.0-beta

`Splunk_TA_zeek` (Corelight Add-on for Zeek, by Aplura, LLC) and
`sankey_diagram_app` (Splunk Inc., EOL) were vendored until `v0.2.0-beta`.
Both declared `"license": {"name": null, ...}` in their `app.manifest` — no
licence grant permitting redistribution — so they were removed and supplied by
the operator instead, until the Splunk path itself was retired. They remain in
git history before `v0.2.0-beta`; the position above applies to anyone working
from those commits.

---

## Invoked tools

Run by this project, not shipped with it. **These bind the operator, not this
repository.**

| Tool | How it is used | Licence | Operator obligation |
|---|---|---|---|
| [Plaso / log2timeline](https://github.com/log2timeline/plaso) | `log2timeline/plaso:latest` container | Apache-2.0 | None |
| [Zeek](https://zeek.org/) | `zeek/zeek:latest` container | BSD-3-Clause | None |
| [Elastic Stack](https://www.elastic.co/) (Elasticsearch, Kibana, Elastic Agent / Fleet Server, Filebeat) | `docker.elastic.co/*` images at a pinned `ELASTIC_VERSION` — **the analysis backend** (`docker/elastic/`) | [Elastic License 2.0](https://www.elastic.co/licensing/elastic-license) (default distribution; only the free Basic-tier features are enabled) | See below |
| [EvtxECmd](https://github.com/EricZimmerman/evtx) | `get_sybers_dxdfir.evtx` runs `EvtxECmd.dll` in a .NET container — either the bundled `dxdfir/evtxecmd` image (`docker/evtxecmd`, fetches the release at build time) or an operator-supplied release | **MIT** | None — no commercial-use restriction |
| [Velociraptor](https://github.com/Velocidex/velociraptor) | Formerly: JSON output normalised by `dev-scripts/` (the lane was removed in 0.6.0) | AGPL-3.0 | None — output ingestion does not trigger AGPL |

No tool binaries are vendored in this repository — every tool above is either
pulled as a container image, fetched at image-build time from its upstream release
(e.g. `docker/evtxecmd`), or supplied by the operator.

**Formerly invoked: KAPE** (Kroll Artifact Parser and Extractor). The KAPE
PowerShell automation was removed in favour of the planned **Velociraptor
offline collectors running the EZ Tools** — the same Zimmerman parsers under
MIT-style licences, without KAPE Solo's non-commercial restriction, which was
the sharpest licensing constraint this project carried. Nothing of KAPE was
ever vendored, so no attribution debt remains; the scripts are in git
history.

### Elastic Stack — the analysis backend

The Elastic-native stack (`docker/elastic/`) pulls the official
`docker.elastic.co` images at a pinned `ELASTIC_VERSION`; nothing of it is
vendored, so this is a constraint on you rather than on this code. The
default distribution ships under the
[Elastic License 2.0](https://www.elastic.co/licensing/elastic-license); this
project enables only the free Basic-tier features
(`xpack.license.self_generated.type: basic`). ELv2 permits self-hosted use in
your own casework; it restricts providing the software to third parties as a
hosted or managed service and circumventing licence keys — read it if either
is on the table for an engagement. The ES|QL / EQL detection rules, the
CAR→ECS projection and the index templates under `python/get_sybers_dxdfir/`
are this project's own work under MIT.

**Formerly invoked: the Azure Data Explorer Kusto emulator** (proprietary,
Microsoft Software License Terms, `ACCEPT_EULA=Y`) was the analysis backend
until the Elastic-native path superseded it. It was never vendored — the image
was pulled at deploy time — so no attribution debt remains; the KQL schema and
its deploy/ingest code are in git history.

---

## Why Apache-2.0

The project licence was chosen to follow the vendored code rather than
preference:

1. The vendored code is Apache-2.0: `car_data_model.json` from MITRE today,
   and previously the ESCU lookups and splunk-ansible playbooks (retired, but
   still redistributed via git history). Matching that licence removes any
   compatibility question over anything the repository has ever shipped.
2. Apache-2.0's §4 obligations (retain licence, retain `NOTICE`, state
   modifications) are met naturally by shipping `LICENSE`, `NOTICE`, and this
   file, rather than bolted on.
3. Copyleft would be a poor fit. Nothing vendored is copyleft. Velociraptor is
   AGPL-3.0 but is *not* vendored — this project only processes its JSON
   output, which does not trigger AGPL obligations.
4. A more permissive licence such as MIT would be legally workable but would
   sit awkwardly over Apache-2.0 vendored code, and would not carry the
   `NOTICE` obligation the vendored code actually requires.

---

## Outstanding items

Known gaps. Listed because a release that hides them is worse than one that
does not.

- **Formerly vendored files were not individually marked as modified.**
  Apache-2.0 §4(b) requires modified files to carry prominent notices. The
  modified `remove_first_login.yml` and the renamed ESCU lookups were recorded
  in `NOTICE` but never marked in-file; they are now history-only, and this
  note is the record.
