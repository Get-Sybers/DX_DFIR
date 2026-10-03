# dxdfir_export

The disk-image artefact export, kept as a utility. Not a lane, and no lane
includes it any more — every lane that reads a disk image runs its tool ON
the image (the images' `<TOOL>_IMAGE`, the same gomount baked into each) —
it is here for an operator who wants the artefact set on disk to look at or
to hand to another tool: [gomount](https://github.com/Get-Sybers/GoDFIR-toolz/-/tree/main/gomount)'s
`materialise` verb pulls the artefact sets in `dxdfir_export_sets`
(`windows-core`: the registry hives with their transaction logs, Amcache,
NTUSER/UsrClass, SRUM, SUM, the Timeline database, the event logs, Prefetch,
`$MFT`, Recent/jump lists, the Recycle Bin index; `linux-core`: `/etc`,
`/var/log`, journals, units, cron, shell histories, trash — docs/linux §5.4)
out of every disk image under the caller's trees into the one canonical stage:

```
data_store/processed/_extracted/[<collection>/]<image>/export/…                 the artefact tree
                                              <image>/export/materialise.jsonl  the origin manifest = the done marker
```

gomount decodes the image itself — E01/Ex01, raw/dd/img, VMDK (sparse,
streamOptimized, descriptor + flat/split extents, snapshot chains), VHDX, VHD,
QCOW2, VDI — and reads the OS volume's filesystem (NTFS, ext2/3/4, XFS, vfat;
LVM2 peeled) in-process: no mount, no FUSE, no privilege. A VMDK's `-flat` /
`-sNNN` extents and an EWF set's `.E02…` segments belong to their item and are
never items themselves. The tree is bound read-only at `/evidence` (so a
multi-file image finds its parts) and the item's `export/` read-write at
`/output`.

**No lane uses this stage**: `godfir_gowindowlicker`, `godfir_godaemonhunter`
and `godfir_signatures` (hayabusa and the scan) all run *on* the image and
export nothing. Include the role from a playbook of your own to materialise a
tree; a run finds every image already done and skips — the export happens
once per image, and `dxdfir_export_force` re-pulls it. A tree with no disk
image declares no run at all.

On exit `dxdfir_export_hosts` is the `<host>` level a consumer can fan out
over: one `{name, export}` per exported image, `name` the image's item folder
(the image path relative to its tree, separators folded to `_` — the same
name the lanes give the image).

The stage is `_`-prefixed on purpose: it holds raw artefacts, never
processed output — the CAR engine never walks it and Filebeat never ships
it.

Variables: `meta/argument_specs.yml`.
