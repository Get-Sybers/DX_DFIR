# dxdfir_godaemonhunter

The Linux daemon lane — `get-sybers/godaemonhunter`'s layered matrix over
every **host**, one confined run per (parser, host), from the one image's
`contract.yml`. Delegates every run to [`dxdfir_lane`](../dxdfir_lane/README.md).

## Hosts

A host is either

- a folder directly under `data_store/raw/logs/linux/` — `logs/linux/<host>/`,
  a staged root filesystem or a pile of its logs (the parsers content-detect
  either); a file dropped at the tree root belongs to no host and is
  reported, not parsed;
- a disk image under `raw/disk_images/` or `raw/VM_files/`, first exported
  once by [`dxdfir_export`](../dxdfir_export/README.md) into the shared stage
  `processed/_extracted/[<collection>/]<image>/export/` (the artefact set
  carries the Linux core: `/etc`, `/var/log`, journals, units, cron, shell
  histories, trash). The image's item folder is the host name.

## Runs and output

Per host, **Layer 1** (`gohost`, `gousers`, `gonetwork`) builds the knowledge
store, then **Layer 2** (`gojournal`, `goauditd`, `gowtmp`, `gosyslog`,
`gounit`, `gocron`, `goshell`, `gotrash`, `goctl`) runs with that store
mounted read-only at `/knowledge` — every record enriched with the host's
identity, accounts and network as the tool documents. Each run is one
batch-mode sub-tool of the image (`godaemonhunter <subtool>`, its own
`<SUBTOOL>_*` env block), `/input` the host's tree, `/output` its own folder:

```
data_store/processed/daemonhunter/[<collection>/]
   knowledge/<host>/<item>/{gohost,gousers,gonetwork}.jsonl   Layer 1
   <subtool>/<host>/<item>/<subtool>.jsonl                    Layer 2
```

`<item>` is the artefact's path relative to the host, separators folded to
`_`. A Windows-only export makes the whole matrix exit 1 by design (nothing
to parse); the gate is "some parser produced output, or no artefacts".
Idempotent per item: a parser skips an item with valid output unless
`dxdfir_godaemonhunter_force`.

With `dxdfir_godaemonhunter_collection` set (the CLI passes it for
`dxdfir process <collection> godaemonhunter`), the output and the stage land
one level below their leaves.

Variables: `meta/argument_specs.yml`. Playbook:
`playbooks/dxdfir-process-godaemonhunter.yml`.

## Testing (molecule)

A Linux root tree is not shipped in-repo; point the scenario at one:

```bash
molecule test -- -e molecule_sample_linux=/path/to/root-tree
```
