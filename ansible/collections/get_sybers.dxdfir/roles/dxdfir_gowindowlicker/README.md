# dxdfir_gowindowlicker

The Windows artefact lane — `get-sybers/gowindowlicker`'s parsers over every
**host**, one confined run per (parser, host), from the one image's
`contract.yml`. Delegates every run to [`dxdfir_lane`](../dxdfir_lane/README.md).
It succeeds the `evtx` and `godfir-toolz` lanes: goevtx is one of its parsers.

## Hosts

A host is either

- a folder directly under `data_store/raw/logs/winevt/` — `logs/winevt/<host>/*.evtx`,
  loose event logs; only `goevtx` runs over it. A log dropped at the tree
  root belongs to no host and is reported, not parsed;
- a disk image under `raw/disk_images/` or `raw/VM_files/`, first exported
  once by [`dxdfir_export`](../dxdfir_export/README.md) into the shared stage
  `processed/_extracted/[<collection>/]<image>/export/` (registry hives with
  their transaction logs, Amcache, jump lists and `.lnk`, Recycle Bin `$I`,
  the Windows Timeline and SRUM databases, Prefetch, `$MFT`, the event logs).
  Every parser in `dxdfir_gowindowlicker_subtools` runs over it. The image's
  item folder is the host name.

## Runs and output

Each run is one batch-mode sub-tool of the image (`gowindowlicker <subtool>`,
its own `<SUBTOOL>_*` env block), `/input` the host's tree, `/output` its own
folder:

```
data_store/processed/windowlicker/[<collection>/]<subtool>/<host>/<item>/<subtool>.jsonl
                                                 goevtx/<host>/<log>.evtx/goevtx.jsonl
                                                 gore/<host>/Windows_System32_config_SYSTEM/gore.jsonl
                                                 goese/<host>/<item>/<table>.jsonl + goese.jsonl
```

`<item>` is the artefact's path relative to the host, separators folded to
`_`. Most parsers find nothing on most hosts (exit 1) — that is normal; the
gate is "some parser produced output, or no artefacts". Idempotent per
item: a parser skips an item with valid output unless
`dxdfir_gowindowlicker_force`.

With `dxdfir_gowindowlicker_collection` set (the CLI passes it for
`dxdfir process <collection> gowindowlicker`), the output and the stage land
one level below their leaves.

Variables: `meta/argument_specs.yml`. Playbook:
`playbooks/dxdfir-process-gowindowlicker.yml`.

## Testing (molecule)

A `.evtx` is binary, so no fixture ships in-repo; point the scenario at one:

```bash
molecule test -- -e molecule_sample_evtx=/path/Security.evtx
```
