"""EvtxECmd processor — Windows Event Logs (.evtx) -> normalised JSON.

The analysis backend
cannot read binary ``.evtx``, so EvtxECmd (Eric Zimmerman, .NET, run via the dotnet
container) converts each log to ``<base>_EvtxECmd_Output.json`` (normalised records,
one JSON object per line -> host.EvtxEcmdJson) plus a best-effort ``.xml`` sidecar
(kept for manual review, not ingested).

Output is grouped by the sub-directory the ``.evtx`` came from, so per-host
collections stay separated; logs sitting directly under the input root go to
``unspecified_host``.

EvtxECmd is not vendored (we don't redistribute other people's builds) — the DLL is
operator-supplied under evtxecmd_dir; the processor locates it (root or nested).

Idempotent: a log whose ``.json`` output already exists (non-empty) is skipped.
EvtxECmd exits 0 on an empty/corrupt log, so a zero-record output is removed and
counted as failed (not treated as done). Emits a machine-readable summary as JSON on
stdout so the Ansible task can set an honest ``changed_when`` (``processed > 0``).

Inputs may be loose ``.evtx`` (``--evtx-dir``) or a disk image / directory of images
(``--image-src``): WindowsEventLogs are pulled out of the image with log2timeline's
``image_export.py`` (see ``imageexport``) into a stage dir, then parsed like any other
log — so the lane consumes E01/raw/VMDK evidence without a hand-extraction step.

Run standalone or via the ``dxdfir`` CLI:

    # loose logs, bundled EvtxECmd image
    python -m get_sybers_dxdfir.evtx --evtx-dir RAW/logs/winevt --out-dir PROCESSED/windows_logs

    # straight from a disk image
    python -m get_sybers_dxdfir.evtx --image-src RAW/disk_images/Host.E01 \
        --out-dir PROCESSED/windows_logs
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

from . import container, imageexport
from .signatures import hayabusa as _hb

# Operator-supplied mode: a stock .NET runtime image mounts the operator's release.
# EvtxECmd's current .NET build targets net9.0, so the runtime must be 9.x — the old
# sdk:8.0 default silently fails against today's release.
_DOTNET_IMAGE = "mcr.microsoft.com/dotnet/runtime:9.0"
# Bundled mode: DX_DFIR's own image (third_party/GoDFIR-toolz/evtxecmd) with the DLL + Maps/ baked in.
_BUNDLED_IMAGE = "get-sybers/evtxecmd:latest"
# Where the bundled image keeps EvtxECmd.dll (its WORKDIR, alongside Maps/).
BUNDLED_DLL = "/opt/evtxecmd/EvtxECmd.dll"


def discover(evtx_dir: str) -> list[str]:
    """Every .evtx under evtx_dir (recursed), sorted, absolute."""
    found = []
    for root, _dirs, files in os.walk(evtx_dir):
        for name in files:
            if name.lower().endswith(".evtx"):
                found.append(os.path.join(root, name))
    return sorted(found)


def locate_dll(evtxecmd_dir: str) -> str | None:
    """Path to EvtxECmd.dll RELATIVE to evtxecmd_dir, or None if absent.

    Releases sometimes nest the DLL under an ``EvtxECmd/`` folder, so search a few
    levels deep as the shell did (maxdepth 3), preferring the root.
    """
    root = os.path.join(evtxecmd_dir, "EvtxECmd.dll")
    if os.path.isfile(root):
        return "EvtxECmd.dll"
    for cur, _dirs, files in os.walk(evtxecmd_dir):
        # Depth relative to evtxecmd_dir, via os.sep splitting (portable — not a
        # literal "/" count, which breaks on Windows paths / redundant separators).
        rel = os.path.relpath(cur, evtxecmd_dir)
        depth = 0 if rel == "." else len(rel.split(os.sep))
        if depth > 3:
            continue
        if "EvtxECmd.dll" in files:
            return os.path.relpath(os.path.join(cur, "EvtxECmd.dll"), evtxecmd_dir)
    return None


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


def evtxecmd_argv(evtx_file, dest_dir, json_out, xml_out, image, *,
                  evtxecmd_dir=None, dll_rel=None, bundled_dll=BUNDLED_DLL):
    """The `docker run` argv for one EvtxECmd container run. Two modes:

    - bundled image (``evtxecmd_dir`` falsy): the minimal get-sybers/evtxecmd image
      whose ENTRYPOINT is ``dotnet /opt/evtxecmd/EvtxECmd.dll`` (DLL + Maps/
      baked in), so only the flags are passed.
    - operator-supplied (``evtxecmd_dir`` given): mount the release read-only at
      ``/evtxecmd`` into a stock .NET runtime and run ``dotnet /evtxecmd/<dll_rel>``
      — both with every confinement flag (no caps, no-new-privileges, no
      network, read-only rootfs).

    Pure (no I/O) so the argv is unit-testable without docker.
    """
    args = [
        "-f", f"/input/{os.path.basename(evtx_file)}",
        "--json", "/output", "--jsonf", json_out,
        "--xml", "/output", "--xmlf", xml_out,
    ]
    mounts = [f"{os.path.dirname(evtx_file)}:/input:ro", f"{dest_dir}:/output"]
    if evtxecmd_dir:
        # operator-supplied release mounted into a stock .NET runtime (no
        # ENTRYPOINT), so the full `dotnet <dll> ...` argv is passed; still with
        # every confinement flag.
        return container.run(
            image, ["dotnet", f"/evtxecmd/{dll_rel}", *args],
            mounts=[*mounts, f"{os.path.realpath(evtxecmd_dir)}:/evtxecmd:ro"],
            workdir="/tmp",
        )
    # bundled minimal image: `dotnet <bundled_dll>` is the ENTRYPOINT, so only
    # the flags are passed.
    return container.run(image, args, mounts=mounts, workdir="/tmp")


def _run_evtxecmd(evtx_file, dest_dir, json_out, xml_out, image, *,
                  evtxecmd_dir=None, dll_rel=None):
    """One EvtxECmd container run over one log, JSON + XML into dest_dir.

    Returns the CompletedProcess so the caller can tell a genuinely empty log
    (EvtxECmd opened it and printed a record tally) from an input it could not
    read at all (missing, or permission-denied under the hardened uid) — EvtxECmd
    exits 0 on both, but only prints a tally when it actually opened the log.
    """
    return subprocess.run(
        evtxecmd_argv(evtx_file, dest_dir, json_out, xml_out, image,
                      evtxecmd_dir=evtxecmd_dir, dll_rel=dll_rel),
        # EvtxECmd is chatty (version banner + per-record "time went backwards"
        # warnings). Capture it so nothing reaches OUR stdout, which carries only
        # the machine-readable JSON summary the role parses. On failure the output
        # is still attached to the CalledProcessError for the caller to surface.
        capture_output=True,
        check=True,
    )


def _nonempty(path: str) -> bool:
    try:
        return os.path.getsize(path) > 0
    except OSError:
        return False


def _has_records(path: str) -> bool:
    """True if the EvtxECmd JSON holds at least one record.

    EvtxECmd exits 0 on a log with no events and still writes a file — just a UTF-8
    BOM (3 bytes) and nothing else. That is NOT a real output: it has size > 0 but
    zero records, and if left on disk it (a) miscounts as ``processed`` and (b) is
    an ill-formed input for whatever reads the output tree next (the CAR lane, a
    shipper). So the emptiness test must look past the BOM/whitespace, not at the
    byte size.
    """
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            for line in fh:
                if line.strip():
                    return True
    except OSError:
        return False
    return False


def process(evtx_dir, out_dir, evtxecmd_dir=None, image=None, force=False) -> dict:
    """Parse every .evtx under evtx_dir into out_dir/<host>/. Idempotent.

    Two ways to supply EvtxECmd, chosen by ``evtxecmd_dir``:

    - given -> operator-supplied release: locate EvtxECmd.dll under it and mount it
      into a stock .NET runtime ``image`` (defaults to ``_DOTNET_IMAGE``).
    - falsy -> the bundled get-sybers/evtxecmd image (DLL + Maps/ baked in); no release dir
      is needed and none is looked for. ``image`` defaults to ``_BUNDLED_IMAGE``.

    Pass ``image`` to override either default.
    """
    evtx_dir = os.path.realpath(evtx_dir)
    out_dir = os.path.realpath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    bundled = not evtxecmd_dir
    # Default the image to match the mode, so a bare process(dir, out) is coherent
    # (bundled mode -> bundled image, not the stock runtime that has no baked DLL).
    if image is None:
        image = _BUNDLED_IMAGE if bundled else _DOTNET_IMAGE
    dll_rel = None if bundled else locate_dll(evtxecmd_dir)
    if not bundled and dll_rel is not None:
        # The container runs with every capability dropped (no DAC override),
        # so the mounted release must be world-readable. It's a tool build, not
        # evidence — normalise it best-effort.
        for cur, dirs, fnames in os.walk(evtxecmd_dir):
            for name in dirs + fnames:
                try:
                    path = os.path.join(cur, name)
                    os.chmod(path, os.stat(path).st_mode | 0o055)
                except OSError:
                    pass
        try:
            os.chmod(evtxecmd_dir, os.stat(evtxecmd_dir).st_mode | 0o055)
        except OSError:
            pass
    files = discover(evtx_dir)

    summary = {
        "tool": "evtx",
        "evtx_dir": evtx_dir,
        "out_dir": out_dir,
        "image": image,
        "bundled": bundled,
        "evtxecmd_dll": BUNDLED_DLL if bundled else dll_rel,
        "files": len(files),
        "processed": 0,
        "skipped": 0,
        # Empty logs are normal (a Windows channel with no events), NOT failures —
        # counted apart so the role's failed==0 assert doesn't trip on them.
        "empty": 0,
        "failed": 0,
        "results": [],
    }
    if not bundled and dll_rel is None:
        summary["error"] = "EvtxECmd.dll not found under evtxecmd_dir"
        return summary

    for evtx in files:
        host = host_group(evtx, evtx_dir)
        dest_dir = os.path.join(out_dir, host)
        json_out, xml_out = out_names(evtx)
        rel = os.path.relpath(evtx, evtx_dir)
        json_path = os.path.join(dest_dir, json_out)
        # Skip only a real prior output — one with records. A BOM-only leftover from
        # an empty log is not "done"; re-checking it is cheap.
        if not force and _has_records(json_path):
            summary["skipped"] += 1
            continue
        os.makedirs(dest_dir, exist_ok=True)
        try:
            # the hardened image writes as uid 2000
            os.chmod(dest_dir, 0o777)
        except OSError:
            pass
        try:
            proc = _run_evtxecmd(evtx, dest_dir, json_out, xml_out, image,
                                 evtxecmd_dir=evtxecmd_dir, dll_rel=dll_rel)
        except subprocess.CalledProcessError:
            for p in (json_path, os.path.join(dest_dir, xml_out)):
                if os.path.exists(p):
                    os.remove(p)
            summary["failed"] += 1
            summary["results"].append({"log": rel, "error": "EvtxECmd failed"})
            continue
        if _has_records(json_path):
            summary["processed"] += 1
            summary["results"].append({"log": rel, "output": os.path.join(host, json_out)})
            continue
        # No records written. EvtxECmd exits 0 in three shapes here, and only one is
        # benign, so we read its own "Total event log records found: <n>" tally:
        #   n == 0 -> genuinely EMPTY: it opened the log and there was nothing. Benign.
        #   n  > 0 -> it found records but wrote NONE to disk (an output/write error,
        #             e.g. an unwritable dest) — a failure masquerading as empty.
        #   no tally at all -> it never opened the log (missing file, or the
        #             permission-denied it prints as "... does not exist! Exiting").
        #             A failure; surface EvtxECmd's own reason.
        # Matching on the tally (not merely the "records found" substring) keeps a
        # non-zero-but-unwritten count from being hidden as a silent "empty".
        for p in (json_path, os.path.join(dest_dir, xml_out)):
            if os.path.exists(p):
                os.remove(p)
        out = (proc.stdout or b"") + (proc.stderr or b"")
        text = out.decode("utf-8", "replace")
        m = re.search(r"records found:\s*([\d,]+)", text, re.IGNORECASE)
        tally = int(m.group(1).replace(",", "")) if m else None
        if tally == 0:
            summary["empty"] += 1
            summary["results"].append({"log": rel, "empty": True})
        elif tally is not None:
            summary["failed"] += 1
            summary["results"].append(
                {"log": rel,
                 "error": f"EvtxECmd reported {m.group(1)} records but wrote none"})
        else:
            tail = text.strip().splitlines()
            why = tail[-1].strip() if tail else "no output and no record tally"
            summary["failed"] += 1
            summary["results"].append(
                {"log": rel, "error": f"EvtxECmd did not read the log: {why}"})
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
    failure — the evtx run's success is EvtxECmd's.
    """
    out = os.path.join(out_dir, "hayabusa")
    timeline = os.path.join(out, "timeline.jsonl")
    summary = {"tool": "hayabusa", "produced": 0, "scanned": 0, "skipped": 0,
               "note": None, "output": None}
    if not force and os.path.exists(timeline) and os.path.getsize(timeline) > 0:
        summary["skipped"] = 1
        summary["output"] = timeline
        return summary
    hb_bin = hb_bin or (_hb.find_binary(hb_dir) if hb_dir else None)
    if not hb_bin or not os.access(hb_bin, os.X_OK):
        summary["note"] = f"no hayabusa binary under {hb_dir!r} — supply --hayabusa-dir"
        return summary
    rules_dir = rules_dir or os.path.join(os.path.dirname(hb_bin), "rules")
    raw = ""
    for src in sources:
        if os.path.isdir(src):
            hits = _hb.scan_directory(hb_bin, src, rules_dir)
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
        description="Windows Event Logs (.evtx) -> EvtxECmd normalised JSON",
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
        "--evtxecmd-dir", default="",
        help="operator-supplied EvtxECmd release dir (holds EvtxECmd.dll). Omit to "
             "use the bundled image (third_party/GoDFIR-toolz/evtxecmd), which bakes the DLL + Maps/.",
    )
    ap.add_argument(
        "--image", "--dotnet-image", dest="image", default=None,
        help="container image: the bundled get-sybers/evtxecmd (default when --evtxecmd-dir "
             "is omitted) or a stock .NET runtime that mounts the operator release.",
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
        s = process(src, out_dir, args.evtxecmd_dir or None,
                    image=args.image, force=args.force)
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
