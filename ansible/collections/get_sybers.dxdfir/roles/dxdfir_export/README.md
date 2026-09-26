# dxdfir_export

The shared disk-image artefact export. Not a lane — the step three lanes
share: the plaso image's `image_export` sub-tool pulls **one** artefact set
(`files/image-export-filter.yaml`: the Windows artefacts with their
transaction logs, the Windows event logs, the Linux core — `/etc`, `/var/log`,
journals, units, cron, shell histories, trash) out of every disk image under
the caller's trees into the one canonical stage:

```
data_store/processed/_extracted/[<collection>/]<image>/export/…   the artefact tree
                                              <image>/image_export.jsonl  the done marker
```

`dxdfir_gowindowlicker`, `dxdfir_godaemonhunter` and `dxdfir_signatures`
(its hayabusa run) each include this role first; whichever runs first
exports, the others find every image done and skip — the export happens
once per image, and `--force` re-pulls it. A tree with no disk image
declares no run at all, so a host that only stages loose logs never needs
the plaso image.

On exit `dxdfir_export_hosts` is the `<host>` level the parsing lanes fan
out over: one `{name, export}` per exported image, `name` the image's item
folder (the image path relative to its tree, separators folded to `_`).

The stage is `_`-prefixed on purpose: it holds raw artefacts, never
processed output — the CAR engine never walks it and Filebeat never ships
it.

Variables: `meta/argument_specs.yml`.
