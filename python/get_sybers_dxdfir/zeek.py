"""Zeek processor — PCAPs → Zeek JSON logs.

Discover captures anywhere
under a pcap tree (magic bytes first, extension as fallback), run the ``zeek/zeek``
container per capture with ``LogAscii::use_json=T`` + ISO-8601 timestamps, and
rename each ``*.log`` (Zeek keeps the extension even for JSON) to ``*.json`` under
one output folder per capture.

Idempotent: a capture whose output folder already holds ``*.json`` is skipped.
Emits a machine-readable summary as JSON on stdout so the Ansible task can set an
honest ``changed_when`` (``processed > 0``) — no hand-rolled changed-ness.

Run standalone or via the ``dfir`` CLI:

    python -m get_sybers_dxdfir.zeek --pcap-dir RAW/pcaps --out-dir PROCESSED/zeek
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

from . import container

_PCAP_MAGIC = {"a1b2c3d4", "d4c3b2a1", "a1b23c4d", "4d3cb2a1", "0a0d0d0a"}
_PCAP_EXTS = (".pcap", ".pcapng", ".cap")


def is_pcap(path: str) -> bool:
    """True if the file looks like a capture — content first, extension fallback."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4).hex()
    except OSError:
        return False
    if head in _PCAP_MAGIC:
        return True
    return path.lower().endswith(_PCAP_EXTS)


def clean_name(rel: str) -> str:
    """Provenance name from a path relative to the pcap dir (dirs+ext folded in),
    so two captures sharing a basename in different folders keep distinct output."""
    rel = rel.replace("/", "_").replace(" ", "_")
    if "." in rel:
        stem, ext = rel.rsplit(".", 1)
        rel = f"{stem}_{ext}"
    return rel


def discover(pcap_dir: str) -> list[str]:
    """Every capture under pcap_dir, sorted, absolute."""
    found = []
    for root, _dirs, files in os.walk(pcap_dir):
        for name in files:
            p = os.path.join(root, name)
            if is_pcap(p):
                found.append(p)
    return sorted(found)


def _already_done(output_dir: str) -> bool:
    if not os.path.isdir(output_dir):
        return False
    try:
        return any(n.endswith(".json") for n in os.listdir(output_dir))
    except OSError:
        return False


def zeek_argv(pcap_dir: str, rel: str, temp_dir: str, image: str) -> list[str]:
    """The ``docker run`` argv for one zeek pass on the minimal hardened
    get-sybers/zeek image (zeek is the ENTRYPOINT; no caps, no network, read-only
    rootfs); zeek writes its logs to the mounted /logs working dir. Pure."""
    return container.run(
        image,
        ["-C", "-r", f"/pcap/{rel}",
         "LogAscii::use_json=T",
         "LogAscii::json_timestamps=JSON::TS_ISO8601"],
        mounts=[f"{pcap_dir}:/pcap:ro", f"{temp_dir}:/logs"],
        workdir="/logs",
    )


def _run_zeek(pcap_dir: str, rel: str, temp_dir: str, image: str) -> None:
    """Run zeek in a container over one capture, writing JSON logs into temp_dir."""
    # ansible-playbook narrates on stdout; capture it so OUR stdout stays the
    # machine-readable summary. Failures still raise with the output attached.
    subprocess.run(zeek_argv(pcap_dir, rel, temp_dir, image),
                   capture_output=True, check=True)


def _collect(temp_dir: str, output_dir: str) -> list[str]:
    """Move each temp *.log into output_dir as *.json; return the json filenames."""
    os.makedirs(output_dir, exist_ok=True)
    outputs = []
    for name in sorted(os.listdir(temp_dir)):
        if not name.endswith(".log"):
            continue
        src = os.path.join(temp_dir, name)
        # Only relocate a regular file the tool actually wrote. A symlink in the
        # container's output mount is never a legitimate zeek log — moving it would
        # carry a link to an arbitrary host file into the processed/CAR tree, which
        # every later reader would then follow. Skip it.
        if os.path.islink(src) or not os.path.isfile(src):
            continue
        dest = os.path.join(output_dir, name[: -len(".log")] + ".json")
        shutil.move(src, dest)
        outputs.append(os.path.basename(dest))
    return outputs


def process(pcap_dir: str, out_dir: str, image: str = "get-sybers/zeek:latest", force: bool = False) -> dict:
    """Process every capture under pcap_dir into out_dir/<capture>/. Idempotent."""
    pcap_dir = os.path.realpath(pcap_dir)
    out_dir = os.path.realpath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    captures = discover(pcap_dir)

    processed, skipped, failed, results = 0, 0, 0, []
    for pcap in captures:
        rel = os.path.relpath(pcap, pcap_dir)
        output_dir = os.path.join(out_dir, clean_name(rel))
        if not force and _already_done(output_dir):
            skipped += 1
            continue
        temp_dir = tempfile.mkdtemp()
        # the hardened image runs as uid 2000 and writes its logs here
        os.chmod(temp_dir, 0o777)
        try:
            _run_zeek(pcap_dir, rel, temp_dir, image)
            outputs = _collect(temp_dir, output_dir)
            processed += 1
            results.append({"capture": rel, "logs": outputs})
        except subprocess.CalledProcessError:
            failed += 1
            results.append({"capture": rel, "error": "zeek run failed"})
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    return {
        "tool": "zeek",
        "pcap_dir": pcap_dir,
        "out_dir": out_dir,
        "captures": len(captures),
        "processed": processed,
        "skipped": skipped,
        "failed": failed,
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="get_sybers_dxdfir.zeek", description="PCAPs -> Zeek JSON logs")
    ap.add_argument("--pcap-dir", required=True, help="directory tree of captures to process")
    ap.add_argument("--out-dir", required=True, help="output dir; one folder per capture is created")
    ap.add_argument("--image", default="get-sybers/zeek:latest",
                    help="zeek container image (default: the hardened get-sybers/zeek:latest — "
                         "build with the dxdfir-build-images playbook)")
    ap.add_argument("--force", action="store_true", help="reprocess captures that already have output")
    args = ap.parse_args(argv)

    summary = process(args.pcap_dir, args.out_dir, image=args.image, force=args.force)
    json.dump(summary, sys.stdout)
    sys.stdout.write("\n")
    # Fail only when the run produced nothing AND nothing was already done: inputs
    # that can never produce output (e.g. a plugin unsupported by this
    # image) are retried on every run, and must not flip an otherwise-complete,
    # idempotent re-run (processed=0, everything else skipped) into a failure.
    return 1 if summary["failed"] and not summary["processed"] and not summary["skipped"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
