"""SOF-ELK delivery — hand the sofelk-pipeline output to SOF-ELK's watch dir.

SOF-ELK ingests by watching filesystem directories (its Logstash pipelines), so
"ingest" here is *delivery*: copy the ``processed/sofelk/<tool>/`` output into the
SOF-ELK ingest location (a local path, a mount, or a path on the SOF-ELK host). The
processors already produced the files; this mirrors them into the target, preserving
the ``<tool>/…`` layout so SOF-ELK's per-type pipelines pick them up.

Idempotent: re-delivering a file would make Logstash re-read and duplicate it, so a
JSON ledger in the target (``.dxdfir-delivered.json``) records the sha1 of every file
delivered; a file already recorded is skipped unless ``force`` is set.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys

_LEDGER = ".dxdfir-delivered.json"


def _sha1(path: str) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def discover(src_dir: str) -> list[str]:
    # os.walk does not descend symlinked directories (followlinks=False). Skip
    # symlinked FILES too: a processed-tree entry is never legitimately a symlink,
    # so following one would sha1/copy the target's content (an arbitrary host
    # file) into the Logstash-ingested watch dir. Belt-and-braces with a realpath
    # containment check against src_dir.
    root = os.path.realpath(src_dir)
    out = []
    for cur, _dirs, files in os.walk(src_dir):
        for name in files:
            full = os.path.join(cur, name)
            if os.path.islink(full):
                continue
            real = os.path.realpath(full)
            if real != root and not real.startswith(root + os.sep):
                continue
            out.append(full)
    return sorted(out)


def _load_ledger(target_dir: str) -> set[str]:
    path = os.path.join(target_dir, _LEDGER)
    try:
        with open(path, encoding="utf-8") as fh:
            return set(json.load(fh))
    except (OSError, json.JSONDecodeError, ValueError):
        return set()


def _save_ledger(target_dir: str, hashes: set[str]) -> None:
    with open(os.path.join(target_dir, _LEDGER), "w", encoding="utf-8") as fh:
        json.dump(sorted(hashes), fh)


def deliver(src_dir: str, target_dir: str, force: bool = False) -> dict:
    """Mirror src_dir into target_dir; skip files already delivered (by sha1)."""
    src_dir = os.path.realpath(src_dir)
    target_dir = os.path.realpath(target_dir)
    summary = {
        "tool": "sofelk-deliver", "src_dir": src_dir, "target_dir": target_dir,
        "found": 0, "delivered": 0, "skipped": 0, "failed": 0,
    }
    if not os.path.isdir(src_dir):
        summary["error"] = f"no sofelk output dir at {src_dir}"
        return summary
    os.makedirs(target_dir, exist_ok=True)
    ledger = set() if force else _load_ledger(target_dir)
    files = discover(src_dir)
    summary["found"] = len(files)

    for f in files:
        digest = _sha1(f)
        if digest in ledger:
            summary["skipped"] += 1
            continue
        rel = os.path.relpath(f, src_dir)
        dest = os.path.join(target_dir, rel)
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy2(f, dest, follow_symlinks=False)  # discover already skips links
        except OSError as exc:
            summary["failed"] += 1
            summary.setdefault("errors", []).append({"file": rel, "error": str(exc)})
            continue
        ledger.add(digest)
        summary["delivered"] += 1

    _save_ledger(target_dir, ledger)
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="get_sybers_dxdfir.sofelk",
        description="deliver sofelk-processed output into SOF-ELK's watch dir",
    )
    ap.add_argument("--src-dir", required=True, help="processed/sofelk tree to deliver")
    ap.add_argument("--target-dir", required=True, help="SOF-ELK ingest/watch dir")
    ap.add_argument("--force", action="store_true", help="re-deliver files already in the ledger")
    args = ap.parse_args(argv)

    summary = deliver(args.src_dir, args.target_dir, force=args.force)
    json.dump(summary, sys.stdout)
    sys.stdout.write("\n")
    if summary.get("error"):
        sys.stderr.write(summary["error"] + "\n")
        return 2
    return 1 if summary["failed"] and not summary["delivered"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
