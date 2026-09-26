## Find Your Way Around

The pipeline is a three-layer design: the **`dxdfir` front-end** (the Go binary,
`go/` — the verbs) drives the **`get_sybers.dxdfir` Ansible collection**
(orchestration), which runs the **hardened GoDFIR-toolz tool containers** (the
per-item processing — every lane is a confined `docker run` built from the
tool's contract; no host python).

```
  $DX_DFIR
    └── go/                                           # the dxdfir front-end (Go/termui) — verbs + dashboards; shells out, re-implements nothing
    │   └── man/                                      # dxdfir.1 man page
    │
    └── ansible/collections/get_sybers.dxdfir/         # the Ansible collection — orchestration
    │   └── roles/                                    # one role per source + dxdfir_images / dxdfir_byakugan / dxdfir_exchange / dxdfir_stack / dxdfir_cleanup
    │   └── playbooks/                                # dxdfir-process-* / dxdfir-build-images / dxdfir-verify-images / dxdfir-build-car / dxdfir-verify-car / dxdfir-car-timeline / dxdfir-exchange-* / dxdfir-stack-* / dxdfir-cleanup
    │
    └── scripts/                                      # Host provisioning: setup, image save/load, the offline bundle (bash)
    │
    └── docker/                                       # Container builds — the hardened get-sybers/* tool images, the GoDFIR-toolz submodule (every tool-image build context), Byakugan's Elastic-native stack (elastic/)
    │
    └── dev-scripts/                                  # Experimental/one-off helpers, unsupported (e.g. the Plaso output module)
    │
    └── .github/                                      # CI workflows + the check harness (tests/: run-checks.sh, smoke-test.sh, the Elastic risk gate) + CONTRIBUTING / SECURITY / THIRD_PARTY_NOTICES
    │
    └── docs/                                         # Documentation for project usage and setup
    │
    └── evidence-taxonomy/                            # Single source of truth for the raw/ evidence lanes — one YAML per lane (subdir + magic signatures + extension claims); read by the dxdfir sort classifier and the Ansible roles' input-dir defaults
    │
    └── data_store/                                   # Data storage for raw and processed forensic data
        │
        └── raw/                                      # Unprocessed forensic data — the canonical evidence lanes (defined in evidence-taxonomy/)
        │   └── pcaps/                                # Packet captures (pcap/pcapng)
        │   └── logs/winevt/<host>/                   # Windows event logs (.evtx), one folder per host
        │   └── logs/linux/<host>/                    # Linux logs / staged root trees, one folder per host
        │   └── logs/macOS/<host>/                    # macOS logs (staged; no lane reads them yet)
        │   └── disk_images/                          # Forensic disk images (E01, QCOW, AFF, raw)
        │   └── VM_files/                             # VM disk exports (one folder per VM)
        │   └── memory/                               # Memory captures (raw dumps, crash/minidumps)
        │   └── filesystem/documents/                 # Documents and loose filesystem artefacts
        │   └── mobile/                               # Mobile-device extractions (one folder per set)
        │   └── other_raw_data/                       # Catch-all; other_raw_data/sql holds SQLite/SQL databases
        │   └── sort/                                 # Dropzone for staged evidence awaiting `dxdfir sort`
        │   └── collections/                          # Registered collections, each sorted into the lanes above
        │
        └── dependencies/                             # Operator-supplied rulesets/tools (Hayabusa, rulesets, MemProcFS symbols)
        │
        └── processed/                                # processed/<tool>/[<collection>/]<host>/… — what `dxdfir build-car` normalises to CAR
            └── zeek/[<collection>/]<capture>/        # Zeek JSON (conn.json + every other log) + zeek.jsonl
            │
            └── windowlicker/[<collection>/]          # the Windows parsers (gowindowlicker lane)
            │   └── <subtool>/<host>/<item>/          # goevtx/, gore/, gomft/, goprefetch/, goese/, … one <subtool>.jsonl per item
            │
            └── daemonhunter/[<collection>/]          # the Linux daemon parsers (godaemonhunter lane)
            │   └── knowledge/<host>/                 # Layer 1: gohost / gousers / gonetwork
            │   └── <subtool>/<host>/<item>/          # Layer 2: gojournal/, goauditd/, gosyslog/, gounit/, gocron/, …
            │
            └── anamnesis/[<collection>/]<image>/     # anamnesis (MemProcFS) JSONL per plugin + car.db
            │
            └── log2timeline/[<collection>/]<host>/   # <host>.plaso (also re-usable by Timesketch) + timeline.jsonl, side by side
            │
            └── detections/
            │   └── yara/ suricata/ hayabusa/         # [<collection>/]<host>/ — detection JSONL (YARA + the disk scan / Suricata EVE / Hayabusa Sigma)
            │   └── byakugan/                         # reserved for the engine's own detections
            │
            └── _extracted/[<collection>/]<image>/    # the shared disk-image artefact export (staging: never a source, never shipped)
            │
            └── byakugan/
            │   └── <source>/                         # the materialised CAR: car_<object>.jsonl (+ car_relationships.jsonl)
            │
            └── byakugan-load/  exchange/             # `load-car` state; the STIX/CTI exchange's bundles
```

The CAR engine lives **outside** this tree entirely: the Byakugan engine is
cloned + built into the hardened `get-sybers/byakugan` image
(`docker/GoDFIR-toolz/byakugan/Dockerfile`) at the pin in the repo-root `sources.yml`, by
`dxdfir build-docker`. The CAR lane only shells that image — nothing is checked
out on the host.

The Splunk-era tree (`splunk/` with its eight apps, and a since-removed
in-container provisioning `ansible/` — **unrelated to today's
`get_sybers.dxdfir` collection** under `ansible/collections/`) was retired when
the SIEM moved to the Kusto emulator (itself since retired in favour of the
Elastic-native stack), and the KAPE automation (`processed/kape/`, the two
PowerShell scripts) was removed in favour of the hardened GoDFIR-toolz containers.
All of it survives in git history and on the frozen
[`deprecated`](https://github.com/Get-Sybers/DX_DFIR/tree/deprecated) branch.
