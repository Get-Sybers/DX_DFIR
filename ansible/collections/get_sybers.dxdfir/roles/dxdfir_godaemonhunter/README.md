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
- a disk image under `raw/disk_images/` or `raw/VM_files/` — E01/Ex01,
  raw/dd/img, VMDK (monolithic, split, streamOptimized, snapshot chains),
  VHDX, VHD, QCOW2, VDI — which the parsers run **on**: one layered hunt run
  per image (`GODAEMONHUNTER_IMAGE`), the image's baked-in
  [gomount](../../../../../docker/GoDFIR-toolz/gomount) pulling the
  `linux-core` surface (`/etc`, `/var/log`, journals, units, cron, shell
  histories, trash — docs/linux §5.4) out of the root volume (LVM2 peeled)
  into a disk-backed `/work` scratch (`dxdfir_godaemonhunter_work_dir`) while
  the layers run — nothing is exported, nothing is mounted. The image's item
  name (its path relative to the tree, separators folded to `_`) is the host
  name; a VMDK's `-flat`/`-sNNN` extents and an EWF set's `.E02…` segments
  belong to their item.

## Runs and output

Per host, **Layer 1** (`gohost`, `gousers`, `gonetwork`, and the Mac's
`gomachost`, `gomacusers`) builds the knowledge store, then **Layer 2**
(`gojournal`, `goauditd`, `gowtmp`, `gosyslog`, `gounit`, `gocron`,
`goshell`, `gotrash`, `goctl`, `golaunchd`) runs with that store mounted
read-only at `/knowledge` — every record enriched with the host's identity,
accounts and network as the tool documents. A Mac is the same matrix: its
disk image (APFS or HFS+) resolves to the Data volume, the System volume is
pulled in a second pass for the OS version and Apple's launchd jobs, and a
staged Mac root tree under the loose lane is parsed by the same lists. The
lists are the contract's own `layer1`/`layer2` keys, read from the pinned
GoDFIR-toolz — a new parser in the image needs no change here — and a
parser that finds nothing on a host exits 1 by design. Each run is one
batch-mode sub-tool of the image (`godaemonhunter <subtool>`, its own
`<SUBTOOL>_*` env block), `/input` the host's tree, `/output` its own folder:

```
data_store/processed/daemonhunter/[<collection>/]
   knowledge/<host>/<item>/{gohost,gousers,gonetwork,gomachost,gomacusers}.jsonl   Layer 1
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
