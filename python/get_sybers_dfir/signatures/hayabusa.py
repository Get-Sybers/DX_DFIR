"""Hayabusa lane — Sigma-based Windows event-log detection -> native JSONL.

Scans loose ``*.evtx`` under the raw tree. Disk-image EVTX (mount read-only and scan
winevt\\Logs in place, or a targeted image_export of only the event logs) is NOT YET
PORTED here — an image with no reachable EVTX records a note only; the working
implementation is in scripts/signatures/hayabusa.sh. (Hayabusa's ``-J`` JSON input
yields 0 detections on Plaso/evtx_dump JSON vs 792 natively, #1324, so real .evtx is
required.)

Native Rust binary (no official image); operator-supplied. ``--fetch`` is accepted
for parity with the bash script but not yet implemented here.
"""
from __future__ import annotations

import glob
import json
import os
import subprocess
import tempfile

from . import have_fuse, list_images


def tag_detections(text: str) -> list[dict]:
    """Tag each Hayabusa JSONL detection with tool="hayabusa". Pure."""
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        ev["tool"] = "hayabusa"
        out.append(ev)
    return out


def find_binary(hb_dir: str) -> str | None:
    """The hayabusa executable under hb_dir (not a .zip, executable), or None."""
    for cand in sorted(glob.glob(os.path.join(hb_dir, "**", "hayabusa*"), recursive=True)):
        if cand.endswith(".zip"):
            continue
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def _dir_has_evtx(d: str) -> bool:
    for _cur, _dirs, files in os.walk(d):
        if any(n.lower().endswith(".evtx") for n in files):
            return True
    return False


def _run_hayabusa(hb_bin, scan_dir, rules_dir) -> str:
    """Run hayabusa over scan_dir; return its JSONL detections (empty if none)."""
    if not _dir_has_evtx(scan_dir):
        return ""
    # Hayabusa won't overwrite an existing --output file. Use a fresh temp DIR and a
    # path inside it that does not exist yet — unique without the deprecated,
    # TOCTOU-prone tempfile.mktemp(); the dir (and file) are cleaned up on exit.
    with tempfile.TemporaryDirectory() as tmpd:
        tmp_out = os.path.join(tmpd, "timeline.jsonl")
        argv = [
            hb_bin, "json-timeline", "--directory", scan_dir, "--output", tmp_out,
            "--JSONL-output", "--no-wizard", "--UTC", "--quiet",
        ]
        if rules_dir:
            argv += ["--rules", rules_dir]
        subprocess.run(argv, capture_output=True, check=False)
        if os.path.isfile(tmp_out) and os.path.getsize(tmp_out) > 0:
            with open(tmp_out, encoding="utf-8", errors="replace") as fh:
                return fh.read()
        return ""


def run(*, output_dir, repo_root, fetch=False, force=False,
        loose_dir=None, disk_dir=None, hb_dir=None, hb_bin=None, rules_dir=None,
        scan_disk=True, **_ignored) -> dict:
    ds = os.path.join(repo_root, "data_store")
    loose_dir = loose_dir or os.path.join(ds, "raw")
    disk_dir = disk_dir or os.path.join(ds, "raw", "disk_images")
    hb_dir = hb_dir or os.path.join(ds, "dependencies", "hayabusa")
    os.makedirs(output_dir, exist_ok=True)

    res = {"lane": "hayabusa", "produced": 0, "skipped": 0, "failed": 0, "note": None}
    out = os.path.join(output_dir, "timeline.jsonl")
    if not force and os.path.exists(out) and os.path.getsize(out) > 0:
        res["skipped"] += 1
        return res

    hb_bin = hb_bin or find_binary(hb_dir)
    if not hb_bin or not os.access(hb_bin, os.X_OK):
        res["note"] = f"no hayabusa binary in {hb_dir} — supply one or --fetch"
        return res
    rules_dir = rules_dir or os.path.join(os.path.dirname(hb_bin), "rules")

    raw = ""
    # 1) loose EVTX
    if _dir_has_evtx(loose_dir):
        raw += _run_hayabusa(hb_bin, loose_dir, rules_dir)

    # 2) disk images: mount read-only and scan in place (needs /dev/fuse)
    if scan_disk and os.path.isdir(disk_dir):
        images = list_images(disk_dir)
        if images and not have_fuse():
            res["note"] = "disk: /dev/fuse unavailable — mount-enable the host to scan images"

    if not raw.strip():
        res["note"] = res["note"] or "no detections (no EVTX reachable)"
        return res
    detections = tag_detections(raw)
    with open(out, "w") as w:
        for ev in detections:
            w.write(json.dumps(ev) + "\n")
    res["produced"] += len(detections)
    return res
