"""Signature/detection processors — YARA, Suricata, Hayabusa.

Port of the retired ``process-signatures.sh`` (+ its ``signatures/{yara,suricata,
hayabusa}.sh`` lanes and ``lib/disk-image.sh``). Runs the three signature engines
over the evidence and lands their native events as ingest-ready JSON Lines under
``<output_dir>/<lane>/``:

    yara       loose files + disk images (mounted read-only, needs /dev/fuse) +
               memory (Volatility windows.vadyarascan)
    suricata   captures (magic-first discovery, same as the zeek processor)
               -> Suricata EVE alerts (+context event types)
    hayabusa   Windows Event Logs -> Sigma detection timeline: loose .evtx AND
               disk images (staged image_export extraction, shared with the
               evtx processor — no fuse needed, extracted once, reused)

Each lane is a standalone runner (run one, or all via :func:`process`) — no lane
requires a processor to have run first, and a lane never re-does raw processing a
prior processor/detection run already staged. Container-first (YARA, Suricata) or
native binary (Hayabusa). Only the YARA disk source still needs ``/dev/fuse``
(mount-only by policy — it never extracts files out of images); when the host
can't mount it says so and moves on.

The heavy lifting (docker, mounting, the native binary) lives in the lane runners;
the parsing logic (yara text output, EVE filtering, detection tagging) is factored
into pure functions for unit testing.
"""
from __future__ import annotations

import os

LANES = ("yara", "suricata", "hayabusa")


def clean_name(path: str, base_dir: str) -> str:
    """Unique, path-preserving output name: fold subdir separators + spaces so two
    corpora that share a basename keep distinct output."""
    rel = os.path.relpath(path, base_dir)
    return rel.replace("/", "_").replace(" ", "_")


def list_images(root: str) -> list[str]:
    """Every disk image under root, sorted. Delegates to the shared
    ``imageexport`` discovery so the detection lanes see exactly the image
    formats the processors do (E01/Ex01/raw/img/dd/VMDK/001/AFF4/VHD/VHDX/QCOW2)."""
    from .. import imageexport
    return imageexport.discover_images(root)


def process(output_dir: str, lanes=LANES, *, repo_root: str, fetch: bool = False,
            force: bool = False, config: dict | None = None) -> dict:
    """Run the requested lanes; return a combined summary.

    ``config`` carries per-lane overrides (paths, images); missing keys fall back to
    the repo defaults each lane computes from ``repo_root``.
    """
    from . import hayabusa, suricata, yara

    config = config or {}
    runners = {"yara": yara.run, "suricata": suricata.run, "hayabusa": hayabusa.run}
    results, processed, skipped, failed = {}, 0, 0, 0
    for lane in lanes:
        res = runners[lane](
            output_dir=os.path.join(output_dir, lane),
            repo_root=repo_root, fetch=fetch, force=force,
            **config.get(lane, {}),
        )
        results[lane] = res
        processed += res.get("produced", 0)
        skipped += res.get("skipped", 0)
        failed += res.get("failed", 0)
    return {
        "tool": "signatures",
        "output_dir": output_dir,
        "lanes": list(lanes),
        "processed": processed,
        "skipped": skipped,
        "failed": failed,
        "results": results,
    }
