## Find Your Way Around

The pipeline is a three-layer design: the **`dx` front-end** (the Go binary,
`go/`, the verbs) drives the **`get_sybers.dxdfir` Ansible collection**
(orchestration), which runs the **hardened GoDFIR-toolz tool containers** (the
per-item processing: every lane is a confined `docker run` built from the
tool's contract; no host python).

```
  $DX_DFIR
    └── go/                                           # the dx front-end (Go): verbs; shells out, re-implements nothing
    │
    └── ansible/collections/get_sybers.dxdfir/         # the Ansible collection: orchestration
    │   └── roles/                                    # one role per source + dxdfir_images / godfir_byakugan / dxdfir_exchange / dxdfir_stack / dxdfir_cleanup
    │   └── playbooks/                                # dxdfir-process-* / dxdfir-build-images / dxdfir-verify-images / dxdfir-build-car / dxdfir-verify-car / dxdfir-car-timeline / dxdfir-exchange-* / dxdfir-stack-* / dxdfir-cleanup
    │
    └── scripts/                                      # Host provisioning: setup, image save/load, the offline bundle (bash); dev/ holds unsupported one-off helpers (fetch-samples, set-version, cold-start)
    │
    └── docker/                                       # Container builds: the hardened get-sybers/* tool images, the GoDFIR-toolz submodule (every tool-image build context), Byakugan's Elastic-native stack (elastic/)
    │
    └── .github/                                      # CI workflows + the check harness (tests/: run-checks.sh, smoke-test.sh, the Elastic risk gate) + CONTRIBUTING / SECURITY / THIRD_PARTY_NOTICES
    │
    └── docs/                                         # Documentation for project usage and setup
    │
    └── evidence-taxonomy/                            # Single source of truth for the raw/ evidence lanes: one YAML per lane (subdir + magic signatures + extension claims); read by the dx sort classifier and the Ansible roles' input-dir defaults
    │
    └── data_store/                                   # Data storage for raw and processed forensic data
        │
        └── raw/                                      # Unprocessed forensic data: the canonical evidence lanes (defined in evidence-taxonomy/)
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
        │   └── sort/                                 # Dropzone for staged evidence awaiting `dx sort`
        │   └── collections/                          # Registered collections, each sorted into the lanes above
        │
        └── dependencies/                             # Operator-supplied rulesets/tools (Hayabusa, rulesets, MemProcFS symbols)
        │
        └── processed/                                # processed/<tool>/[<collection>/]<host>/…: what `dx byakugan build` normalises to CAR
            └── zeek/[<collection>/]<capture>/        # Zeek JSON (conn.json + every other log) + zeek.jsonl
            │
            └── windowlicker/[<collection>/]          # the Windows parsers (gowindowlicker lane)
            │   └── <subtool>/<host>/<item>/          # goevtx/, gore/, gomft/, goprefetch/, goese/, … one <subtool>.jsonl per item
            │
            └── daemonhunter/[<collection>/]          # the Linux daemon parsers (godaemonhunter lane)
            │   └── knowledge/<host>/<item>/          # Layer 1: gohost / gousers / gonetwork (a Mac: gomachost / gomacusers)
            │   └── <subtool>/<host>/<item>/          # Layer 2: gojournal/, goauditd/, gosyslog/, gounit/, gocron/, golaunchd/, …
            │
            └── anamnesis/[<collection>/]<image>/     # anamnesis (MemProcFS) JSONL per plugin + car.db
            │
            └── log2timeline/[<collection>/]<host>/   # <host>.plaso (also re-usable by Timesketch) + timeline.jsonl, side by side
            │
            └── detections/
            │   └── yara/ suricata/ hayabusa/         # [<collection>/]<host>/: detection JSONL (YARA + the disk scan / Suricata EVE / Hayabusa Sigma)
            │   └── byakugan/                         # reserved for the engine's own detections
            │
            ├── _extracted/[<collection>/]<image>/    # the disk-image artefact export, a utility (staging: never a source, never shipped)
            └── _scratch/<lane>/[<collection>/]<host>/ # the host lanes' per-image /work while they run ON an image (emptied after each)
            │
            └── byakugan/
            │   └── <source>/                         # the materialised CAR: car_<object>.jsonl (+ car_relationships.jsonl)
            │
            └── byakugan-load/  exchange/             # `byakugan load` state; the STIX/CTI exchange's bundles
```

The CAR engine lives **outside** this tree entirely: the Byakugan engine is
cloned + built into the hardened `get-sybers/byakugan` image
(`docker/GoDFIR-toolz/byakugan/Dockerfile`) at the pin in the repo-root `sources.yml`, by
`dx build images`. The CAR lane only shells that image; nothing is checked
out on the host.
