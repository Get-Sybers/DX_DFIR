# Step 07 — Wiring the detection lanes into the collection

> Part of the CAR cross-source linkage & detection research arc — see [README](README.md) for the full map.

**Status:** merged (PR #159, PR #161, PR #162)

## The gap

On a *sorted* collection, `dxdfir process all` produced **no suricata and no
yara detections** — the output dirs came back empty. Only hayabusa produced
alerts. For a detection pipeline that is a silent, wrong result: the operator
sees "hayabusa found things" and reasonably assumes the other engines found
nothing, when in fact they never looked at the right evidence and had no rules.

## What we found

**Root cause #1 — the `signatures` lane was absent from `collection.LANES`.**
`LANES` is the registry mapping each lane to the sorted-collection subdirs it
reads and its Ansible input var. With no entry, `process all` neither ran the
detection lane nor scoped its inputs. So the engines fell back to their raw
defaults:

- suricata → the empty `data_store/raw/pcaps`,
- yara → the empty `raw/disk_images` / `raw/memory`,

while the collection's actual sorted captures and images sat under
`raw/collections/<name>/…` and were never read. Hayabusa "worked" only by
accident: its loose-EVTX scan already walks `raw/` recursively, and its rules
ship inside the image — so it alone had both inputs and rules.

**Root cause #2 — no rulesets.** Even once the lane was wired, suricata and
yara had nothing to match against: the hardened images ship **no rules**.

## The fix

All fixes landed in DX_DFIR:

- **PR #159** — added `Lane("signatures", ("pcaps",), …)`, placed **last** in
  `LANES` so detection runs after the evidence lanes have populated the
  collection. Added a `--pcap-dir` CLI flag and the corresponding role var.
- **PR #161** — suricata **ET Open** ruleset provisioning on `--fetch`,
  mirroring the yara lane's DetectRaptor fetch. ET Open is a rolling daily
  feed, so the pin is the **engine-version URL** rather than a content hash —
  this is the `suricata-update` trust model, not a reproducible-artefact pin.
- **PR #162** — extended the signatures collection mapping to **all** detection
  inputs: `("pcaps", "disk_images", "memory")`, driving yara disk/memory scans
  and hayabusa image-EVTX extraction. Added `--disk-dir` / `--memory-dir` CLI
  flags, and made `--yara-sources` **merge** rather than clobber the scoped
  dirs.

The final lane definition — `Lane("signatures", ("pcaps", "disk_images",
"memory"), …)` as the last entry in `LANES` — is the wiring these three PRs
converged on.

## What it enables

`dxdfir process all <collection> --fetch` now runs **suricata + yara +
hayabusa** against the collection's *own* sorted evidence, with real rulesets
(**ET Open** for suricata, **DetectRaptor** for yara). Detection is no longer
silently scoped to empty raw defaults, and no engine is quietly ruleless.

This is the prerequisite for correlating detections across sources — the
next step, [Step 08](08-detection-correlation.md).

## Follow-ups

- Confirm ET Open / DetectRaptor fetch behaviour in the air-gapped /
  no-`--fetch` path, and document what a run without rulesets should report.
- Fold the unnormalised-values ruleset ([Step 05](05-yara-unnormalised.md))
  into the yara lane so coverage checks ride the same wiring.
