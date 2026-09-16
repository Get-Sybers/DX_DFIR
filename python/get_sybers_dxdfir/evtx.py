"""EVTX lane (goevtx) — Windows Event Logs (.evtx) -> normalised JSON.

The analysis backend cannot read binary ``.evtx``, so **goevtx** (the static-Go
.evtx parser, ``get-sybers/goevtx``, on Velociraptor's go-evtx) converts
each log to ``<base>_EvtxECmd_Output.json`` (one JSON object per line ->
host.EvtxEcmdJson) plus a best-effort ``.xml`` sidecar (manual review, not
ingested). The output name stays ``*_EvtxECmd_Output.json`` — the CAR lane
content-routes on it. goevtx is a FROM-scratch Go binary: no .NET runtime, no
DLL to supply.

Output is grouped by the sub-directory the ``.evtx`` came from, so per-host
collections stay separated; logs sitting directly under the input root go to
``unspecified_host``.

Idempotent: a log whose ``.json`` output already has records is skipped. goevtx
exits 0 on an empty log (0 events) and non-zero when it cannot parse, so an empty
output is counted apart (not failed) and a real parse failure is surfaced. Emits
a machine-readable JSON summary on stdout so the Ansible task can set an honest
``changed_when`` (``processed > 0``).

Inputs may be loose ``.evtx`` (``--evtx-dir``) or a disk image / directory of images
(``--image-src``): WindowsEventLogs are pulled out of the image with log2timeline's
``image_export.py`` (see ``imageexport``) into a stage dir, then parsed like any other
log — so the lane consumes E01/raw/VMDK evidence without a hand-extraction step.

Run standalone or via the ``dxdfir`` CLI:

    python -m get_sybers_dxdfir.evtx --evtx-dir RAW/logs/winevt --out-dir PROCESSED/windows_logs
    python -m get_sybers_dxdfir.evtx --image-src RAW/disk_images/Host.E01 \
        --out-dir PROCESSED/windows_logs
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

from . import container, imageexport
from .signatures import hayabusa as _hb

# The Go substitute: get-sybers/goevtx — a static go-evtx binary (FROM scratch,
# ENTRYPOINT /goevtx) that parses .evtx to the ``*_EvtxECmd_Output.json`` shape the CAR lane
# content-routes on. No .NET runtime, no DLL to supply, no operator release.
_IMAGE = "get-sybers/goevtx:latest"


def discover(evtx_dir: str) -> list[str]:
    """Every .evtx under evtx_dir (recursed), sorted, absolute."""
    found = []
    for root, _dirs, files in os.walk(evtx_dir):
        for name in files:
            if name.lower().endswith(".evtx"):
                found.append(os.path.join(root, name))
    return sorted(found)


def host_group(evtx_file: str, evtx_dir: str) -> str:
    """Output sub-dir for a log: its parent dir relative to evtx_dir, or
    'unspecified_host' when it sits directly under the input root."""
    rel_dir = os.path.dirname(os.path.relpath(evtx_file, evtx_dir))
    return rel_dir if rel_dir not in ("", ".") else "unspecified_host"


def out_names(evtx_file: str) -> tuple[str, str]:
    """(_EvtxECmd_Output.json, _EvtxECmd_Output.xml) names for a log."""
    base = os.path.basename(evtx_file)
    if base.lower().endswith(".evtx"):
        base = base[: -len(".evtx")]
    return f"{base}_EvtxECmd_Output.json", f"{base}_EvtxECmd_Output.xml"


def goevtx_argv(evtx_file, dest_dir, json_out, xml_out, image):
    """The `docker run` argv for one goevtx run over one log — the flags only
    (goevtx is the ENTRYPOINT of the FROM-scratch get-sybers/goevtx image; no
    dotnet, no DLL). JSON + the best-effort XML sidecar both land in dest_dir,
    under every confinement flag. Pure (no I/O), unit-testable."""
    return container.run(
        image,
        ["-f", f"/input/{os.path.basename(evtx_file)}",
         "--json", "/output", "--jsonf", json_out,
         "--xml", "/output", "--xmlf", xml_out],
        mounts=[f"{os.path.dirname(evtx_file)}:/input:ro", f"{dest_dir}:/output"],
        workdir="/tmp",
    )


def _run_goevtx(evtx_file, dest_dir, json_out, xml_out, image):
    """One goevtx container run over one log (JSON + XML into dest_dir). goevtx
    exits 0 when the log parsed — even with zero events — and 2 when it could not
    be parsed, so a CalledProcessError is a genuine failure while exit 0 with no
    records written is a legitimately empty log. Output is captured so nothing
    reaches OUR stdout (which carries only the JSON summary)."""
    return subprocess.run(
        goevtx_argv(evtx_file, dest_dir, json_out, xml_out, image),
        capture_output=True,
        check=True,
    )


def _has_records(path: str) -> bool:
    """True if the output JSON holds at least one record.

    goevtx writes an empty file for a 0-event log; the emptiness test looks past a
    UTF-8 BOM / whitespace at the content, not the byte size, so an empty log is
    never miscounted as ``processed`` or left as an ill-formed input for the CAR
    lane downstream.
    """
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            for line in fh:
                if line.strip():
                    return True
    except OSError:
        return False
    return False


def process(evtx_dir, out_dir, image=None, force=False) -> dict:
    """Parse every .evtx under evtx_dir into out_dir/<host>/ with goevtx. Idempotent.

    goevtx (get-sybers/goevtx) is a static Go binary on go-evtx — no .NET runtime,
    no DLL to supply. ``image`` overrides the default get-sybers/goevtx.
    """
    evtx_dir = os.path.realpath(evtx_dir)
    out_dir = os.path.realpath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    if image is None:
        image = _IMAGE
    files = discover(evtx_dir)

    summary = {
        "tool": "evtx",
        "evtx_dir": evtx_dir,
        "out_dir": out_dir,
        "image": image,
        "files": len(files),
        "processed": 0,
        "skipped": 0,
        # Empty logs are normal (a Windows channel with no events), NOT failures —
        # counted apart so the role's failed==0 assert doesn't trip on them.
        "empty": 0,
        "failed": 0,
        "results": [],
    }
    for evtx in files:
        host = host_group(evtx, evtx_dir)
        dest_dir = os.path.join(out_dir, host)
        json_out, xml_out = out_names(evtx)
        rel = os.path.relpath(evtx, evtx_dir)
        json_path = os.path.join(dest_dir, json_out)
        # Skip only a real prior output — one with records. An empty leftover from
        # an empty log is not "done"; re-checking it is cheap.
        if not force and _has_records(json_path):
            summary["skipped"] += 1
            continue
        os.makedirs(dest_dir, exist_ok=True)
        try:
            os.chmod(dest_dir, 0o777)  # the hardened image writes as uid 2000
        except OSError:
            pass
        try:
            _run_goevtx(evtx, dest_dir, json_out, xml_out, image)
        except subprocess.CalledProcessError as exc:
            for p in (json_path, os.path.join(dest_dir, xml_out)):
                if os.path.exists(p):
                    os.remove(p)
            tail = (exc.stderr or b"").decode("utf-8", "replace").strip().splitlines()
            why = tail[-1].strip() if tail else "goevtx failed"
            summary["failed"] += 1
            summary["results"].append({"log": rel, "error": f"goevtx failed: {why}"})
            continue
        # goevtx exited 0: the log parsed. Records -> processed; none -> a
        # legitimately empty log. There is no output-error-masquerading-as-empty
        # case: goevtx returns non-zero if it cannot open/parse/write.
        if _has_records(json_path):
            summary["processed"] += 1
            summary["results"].append({"log": rel, "output": os.path.join(host, json_out)})
        else:
            for p in (json_path, os.path.join(dest_dir, xml_out)):
                if os.path.exists(p):
                    os.remove(p)
            summary["empty"] += 1
            summary["results"].append({"log": rel, "empty": True})
    return summary




def extract_images(image_src, stage_dir, *, plaso_image=imageexport.PLASO_IMAGE,
                   vss=False, force=False) -> dict:
    """Pull WindowsEventLogs (``.evtx``) out of every disk image at ``image_src`` into
    ``stage_dir/<image_stem>/``, so ``process()`` can then run over ``stage_dir`` as if
    the logs had been supplied loose. Per-image subdirs keep hosts separated.

    Thin wrapper over :func:`imageexport.extract_staged` — the SAME staged
    extraction the Hayabusa detection lane reuses, so an image staged by either
    is never extracted twice. Idempotent: an image whose stage subdir already
    holds ``.evtx`` is skipped unless ``force`` (re-extraction is the slow part).
    """
    return imageexport.extract_staged(
        image_src, stage_dir, artifact_filters=("WindowsEventLogs",),
        exts=(".evtx",), plaso_image=plaso_image, vss=vss, force=force,
    )


def run_hayabusa(sources, out_dir, *, hb_dir=None, hb_bin=None, rules_dir=None,
                 force=False) -> dict:
    """Run Hayabusa (Sigma detection) over the .evtx the evtx lane collected — the
    loose dirs and/or the image-extracted stage in ``sources`` — writing a tool-tagged
    detection timeline to ``<out_dir>/hayabusa/timeline.jsonl``.

    Reuses ``signatures.hayabusa`` (one Hayabusa implementation), and because it scans
    the SAME dirs the evtx lane populated, disk-image EVTX now reaches Hayabusa through
    the lane's ``imageexport`` extraction — the case the standalone signature lane could
    only cover by mounting (``/dev/fuse``).

    Hayabusa here is enrichment: a missing binary or zero detections is a note, never a
    failure — the evtx run's success is goevtx's.
    """
    out = os.path.join(out_dir, "hayabusa")
    timeline = os.path.join(out, "timeline.jsonl")
    summary = {"tool": "hayabusa", "produced": 0, "scanned": 0, "skipped": 0,
               "note": None, "output": None}
    if not force and os.path.exists(timeline) and os.path.getsize(timeline) > 0:
        summary["skipped"] = 1
        summary["output"] = timeline
        return summary
    # Hayabusa (binary + config + default rules) is baked into the signatures
    # image; rules_dir, when given, overrides the baked rule set.
    raw = ""
    for src in sources:
        if os.path.isdir(src):
            hits = _hb.scan_directory(src, rules_dir)
            if hits.strip():
                summary["scanned"] += 1
                raw += hits
    if not raw.strip():
        summary["note"] = "no detections (no EVTX reachable, or nothing matched)"
        return summary
    os.makedirs(out, exist_ok=True)
    detections = _hb.tag_detections(raw)
    with open(timeline, "w") as w:
        for ev in detections:
            w.write(json.dumps(ev) + "\n")
    summary["produced"] = len(detections)
    summary["output"] = timeline
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="get_sybers_dxdfir.evtx",
        description="Windows Event Logs (.evtx) -> goevtx normalised JSON",
    )
    ap.add_argument("--evtx-dir", help="directory tree of loose .evtx logs (recursed). "
                    "Optional if --image-src is given.")
    ap.add_argument("--image-src", help="disk image (E01/raw/VMDK) or a directory of them; "
                    "WindowsEventLogs (.evtx) are extracted with log2timeline/plaso "
                    "image_export.py, then processed. Combine with or use instead of --evtx-dir.")
    ap.add_argument("--stage-dir", help="where --image-src extractions land "
                    "(default: <out-dir>/_extracted_evtx). Per-image subdirs; reused across runs.")
    ap.add_argument("--plaso-image", default=imageexport.PLASO_IMAGE,
                    help="container image providing image_export.py (default: %(default)s)")
    ap.add_argument("--vss", action="store_true",
                    help="also extract from Volume Shadow Copies during --image-src extraction")
    ap.add_argument("--out-dir", required=True, help="output dir; grouped by source sub-dir (host)")
    ap.add_argument(
        "--image", dest="image", default=None,
        help="container image (default: get-sybers/goevtx, the static-Go .evtx parser).",
    )
    ap.add_argument("--force", action="store_true", help="reparse logs that already have output")
    ap.add_argument("--hayabusa", action="store_true",
                    help="also run Hayabusa (Sigma detection) over the same .evtx and write "
                         "<out-dir>/hayabusa/timeline.jsonl. Enrichment: a missing binary or "
                         "zero detections is a note, not a failure.")
    ap.add_argument("--hayabusa-dir", default="",
                    help="dir holding the hayabusa binary (+ rules/). Default when --hayabusa "
                         "is set: data_store/dependencies/hayabusa under the CWD.")
    ap.add_argument("--hayabusa-rules", default="",
                    help="Sigma rules dir for Hayabusa (default: rules/ beside the binary).")
    args = ap.parse_args(argv)

    if not args.evtx_dir and not args.image_src:
        ap.error("provide --evtx-dir, --image-src, or both")

    out_dir = os.path.realpath(args.out_dir)

    # Disk-image inputs first: extract WindowsEventLogs into the stage dir, then treat
    # that stage dir as an evtx source alongside any loose --evtx-dir.
    extract_summary = None
    sources = []
    if args.evtx_dir:
        sources.append(os.path.realpath(args.evtx_dir))
    if args.image_src:
        stage_dir = os.path.realpath(args.stage_dir) if args.stage_dir \
            else os.path.join(out_dir, "_extracted_evtx")
        extract_summary = extract_images(
            args.image_src, stage_dir, plaso_image=args.plaso_image,
            vss=args.vss, force=args.force,
        )
        sources.append(stage_dir)

    # Process each source; merge the per-source summaries into one honest total.
    summary = {"tool": "evtx", "out_dir": out_dir, "sources": [],
               "files": 0, "processed": 0, "skipped": 0, "empty": 0, "failed": 0}
    if extract_summary is not None:
        summary["extract"] = extract_summary
    for src in sources:
        s = process(src, out_dir, image=args.image, force=args.force)
        summary["sources"].append(s)
        if s.get("error"):
            summary["error"] = s["error"]
        for k in ("files", "processed", "skipped", "empty", "failed"):
            summary[k] += s.get(k, 0)

    # Hayabusa (Sigma detection) over the SAME .evtx set — part of evtx processing,
    # not a separate lane. Enrichment only: never changes the exit code.
    if args.hayabusa:
        hb_dir = os.path.realpath(args.hayabusa_dir) if args.hayabusa_dir \
            else os.path.join(os.getcwd(), "data_store", "dependencies", "hayabusa")
        summary["hayabusa"] = run_hayabusa(
            sources, out_dir, hb_dir=hb_dir,
            rules_dir=(os.path.realpath(args.hayabusa_rules) if args.hayabusa_rules else None),
            force=args.force,
        )

    json.dump(summary, sys.stdout)
    sys.stdout.write("\n")
    if summary.get("error"):
        sys.stderr.write(summary["error"] + "\n")
        return 2
    # Fail only when the run produced nothing AND nothing was already done: inputs
    # that can never produce output (e.g. a Volatility plugin unsupported by this
    # image) are retried on every run, and must not flip an otherwise-complete,
    # idempotent re-run (processed=0, everything else skipped) into a failure.
    return 1 if summary["failed"] and not summary["processed"] and not summary["skipped"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
