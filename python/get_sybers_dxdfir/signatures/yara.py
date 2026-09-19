"""YARA lane — scan a ruleset against evidence.

Sources (default all three):
  files   loose files                                              -> matches.jsonl
  disk    disk images MOUNTED read-only, scanned in place          -> disk.jsonl
          (ewfmount for E01 -> raw, then ntfs-3g on the first NTFS partition —
          both FUSE, so ``/dev/fuse`` must exist on the host; nothing is ever
          extracted out of an image — a host that can't mount records a note)
  memory  memory image files, scanned directly with YARA           -> memory.jsonl
          (no Volatility — coarser than per-VAD scanning: matches carry the image
          file + offset, not PID/process. An anamnesis/MemProcFS-native per-process
          scan is a planned follow-up.)

YARA has no JSON output and the container's recursive scan hangs, so file/disk scans
loop per-file inside ONE container (per-file scans print strings) and the stable text
form is parsed here. Each match is a self-describing JSON object:

    {"tool":"yara","source":"<file|disk|memory>","rule":"<name>","target":"...",
     "strings":[{"id":"$s1","offset":21,"data":"MZ"}...], "pid":123,"process":"..."}

The scan invocations are built by pure, unit-testable helpers (``_scan_dir`` for
loose files, staged disk trees and raw memory images; ``imageexport.extract`` for
userspace disk extraction), so the logic is exercised without FUSE, docker or
evidence.

Rules are operator-supplied under data_store/dependencies/yara-rules. ``--fetch``
provisions the DetectRaptor ruleset (pinned + sha256-verified, merged into
detectraptor/detectraptor.yar) when it is absent — see detectraptor.py.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile

from .. import container, imageexport

_SIGNATURES_IMAGE = "get-sybers/signatures:latest"  # yara + suricata + hayabusa, one image
# The DetectRaptor ruleset baked into the signatures image (the Dockerfile
# guarantees it with a build-time `test -s`). Used for the file + disk + memory
# scans when no operator rules are staged on the host — an in-image absolute path,
# never mounted.
_BAKED_YARA_RULES = "/opt/dxdfir/yara-rules/detectraptor/detectraptor.yar"
_STRING_RE = re.compile(r"^0x([0-9a-fA-F]+):(\$[^:]*):\s?(.*)$")


def parse_yara_text(text: str, source: str, strip: str, base: str) -> list[dict]:
    """Parse yara's text output (rule+path, then 0xoffset:$id: data lines) into
    match dicts. Pure — mirrors the shell's parse_yara heredoc."""
    matches: list[dict] = []
    cur: dict | None = None
    for line in text.splitlines():
        line = line.rstrip("\n")
        if not line:
            continue
        m = _STRING_RE.match(line)
        if m and cur is not None:
            cur["strings"].append(
                {"id": m.group(2), "offset": int(m.group(1), 16), "data": m.group(3)}
            )
            continue
        if cur is not None:
            matches.append(cur)
            cur = None
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        rule, path = parts
        if strip and path.startswith(strip):
            rel = path[len(strip):].lstrip("/")
        else:
            rel = path
        cur = {
            "tool": "yara", "source": source, "rule": rule, "target": rel,
            "match": os.path.join(base, rel) if base else rel, "strings": [],
        }
    if cur is not None:
        matches.append(cur)
    return matches


# --- disk source: userspace artefact extraction (no host mount) ---
#
# The disk YARA scan used to mount each image on the HOST via ewfmount + ntfs-3g
# (both FUSE) and scan it in place — native image parsers running unconfined on
# the analyst host (a container-safety audit's largest escape surface). It now
# extracts every allocated file out of each image in USERSPACE via the hardened
# get-sybers/plaso image_export (imageexport.extract, no --artifact_filters), into
# a temp staging dir, then scans the staged files inside the signatures container.
# Nothing is mounted on the host; no /dev/fuse, no SYS_ADMIN.


def extract_disk_files(image: str, stage_dir: str) -> list[str]:
    """Extract every allocated file from one disk image into ``stage_dir`` (via the
    plaso container) and return the files written. Raises on extraction failure."""
    return imageexport.extract(image, stage_dir, artifact_filters=None)


def _rule_files(rules_dir: str) -> list[str]:
    found = []
    for cur, _dirs, files in os.walk(rules_dir):
        for name in files:
            low = name.lower()
            if (low.endswith(".yar") or low.endswith(".yara")) and not name.startswith("_"):
                found.append(os.path.join(cur, name))
    return sorted(found)


def build_index(rules: list[str], rules_dir: str) -> str:
    """The include index yara loads: each rule referenced by its /rules mount path.

    Pure — the includes are absolute (/rules/<rel>), so the index file can live
    anywhere (we mount it read-only at /index.yar) and never has to be written into
    the operator's rules tree (which may be read-only or externally managed)."""
    return "".join(
        f'include "/rules/{os.path.relpath(rf, rules_dir)}"\n' for rf in rules
    )


def _scan_dir(scan_dir, rules_dir, index_path, source, base, image, *, mount_rules=True) -> list[dict]:
    """Scan every file under scan_dir in ONE container (per-file loop over a list
    file — a fixed sh -c script reads names from the mounted list, no interpolation).
    The index is bind-mounted at /index.yar; its includes resolve against /rules."""
    files = [os.path.join(r, n) for r, _d, fs in os.walk(scan_dir) for n in fs]
    if not files:
        return []
    listf = tempfile.NamedTemporaryFile("w", delete=False)
    try:
        for f in files:
            listf.write(f"/scan/{os.path.relpath(f, scan_dir)}\n")
        listf.close()
        # NamedTemporaryFile is 0600; the container reads it as uid 2000
        os.chmod(listf.name, 0o644)
        # The signatures image has no ENTRYPOINT; run its baked, allow-listed
        # per-file scan loop (/opt/dxdfir/scan-list.sh) explicitly. It reads the
        # mounted list + index and prints matches to stdout (captured here) — no
        # shell command is injected from here.
        # Mount the host rules at /rules only when the index references them; the
        # baked-rules index uses an in-image absolute path, so nothing is mounted.
        mounts = [f"{os.path.realpath(scan_dir)}:/scan:ro",
                  f"{os.path.realpath(index_path)}:/index.yar:ro",
                  f"{listf.name}:/list.txt:ro"]
        if mount_rules:
            mounts.append(f"{os.path.realpath(rules_dir)}:/rules:ro")
        proc = subprocess.run(
            container.run(image, ["/opt/dxdfir/scan-list.sh"], mounts=mounts),
            capture_output=True, text=True, check=False,
        )
        # A non-zero exit with no output is a SCAN failure, never "no matches" —
        # zero hits must always mean the scan actually ran.
        if proc.returncode != 0 and not proc.stdout.strip():
            raise RuntimeError(
                f"yara scan container failed (rc={proc.returncode}): "
                f"{(proc.stderr or '').strip()[:300]}")
        return parse_yara_text(proc.stdout, source, "/scan/", base)
    finally:
        os.unlink(listf.name)


def _note(res: dict, note: str) -> None:
    res["note"] = f"{res['note']}; {note}" if res["note"] else note


def run(*, output_dir, repo_root, fetch=False, force=False,
        sources=("files", "disk", "memory"),
        rules_dir=None, files_target=None, disk_dir=None, memory_dir=None,
        image=_SIGNATURES_IMAGE, **_ignored) -> dict:
    """Run the selected YARA sources. Returns {lane, produced, skipped, failed}.

    (Legacy symbols_dir/vol_image kwargs are accepted and ignored — the memory
    source no longer runs Volatility.)"""
    ds = os.path.join(repo_root, "data_store")
    rules_dir = rules_dir or os.path.join(ds, "dependencies", "yara-rules")
    files_target = files_target or os.path.join(ds, "raw", "other_raw_data")
    disk_dir = disk_dir or os.path.join(ds, "raw", "disk_images")
    memory_dir = memory_dir or os.path.join(ds, "raw", "memory")
    os.makedirs(output_dir, exist_ok=True)

    res = {"lane": "yara", "sources": list(sources), "produced": 0, "skipped": 0,
           "failed": 0, "note": None}

    if fetch and not _rule_files(rules_dir):
        # Provision the DetectRaptor ruleset — like the shell lane's YARA-Forge
        # starter, ONLY when the tree has no rules yet: operator rules suppress it,
        # and DetectRaptor's sets are YARA-Forge extracts, so dropping the merged
        # file next to a YARA-Forge set would fail the single-index compile on
        # duplicate identifiers. Offline/failed fetch is a note, not a failure.
        from . import detectraptor
        try:
            detectraptor.fetch(rules_dir)
        except Exception as exc:  # noqa: BLE001 — network/hash errors surface as a note
            res["note"] = f"detectraptor fetch failed: {exc}"

    rules = _rule_files(rules_dir)
    # Operator rules staged under rules_dir win; otherwise fall back to the
    # DetectRaptor ruleset BAKED into the signatures image (the file + disk scans
    # run there). `baked` drives the index contents and whether /rules is mounted.
    baked = not rules
    if baked:
        _note(res, "using the DetectRaptor ruleset baked into the signatures image "
                   f"(no operator rules staged under {rules_dir})")

    # Build the include index in a TEMP file (never write into the operator's rules
    # tree — it may be read-only/externally managed); it's bind-mounted at /index.yar.
    idxf = tempfile.NamedTemporaryFile("w", suffix=".yar", delete=False)
    idxf.write(f'include "{_BAKED_YARA_RULES}"\n' if baked else build_index(rules, rules_dir))
    idxf.close()
    # NamedTemporaryFile is 0600; the hardened container reads it as uid 2000
    os.chmod(idxf.name, 0o644)
    index_path = idxf.name
    os.chmod(index_path, 0o644)  # readable however the container's user maps

    if "files" in sources:
        out = os.path.join(output_dir, "matches.jsonl")
        if not force and os.path.exists(out):
            res["skipped"] += 1
        elif os.path.isdir(files_target):
            try:
                matches = _scan_dir(files_target, rules_dir, index_path, "file",
                                    os.path.basename(files_target), image,
                                    mount_rules=not baked)
            except RuntimeError as exc:
                res["failed"] += 1
                _note(res, f"files: {exc}")
            else:
                _write(out, matches)
                res["produced"] += len(matches)

    if "disk" in sources:
        out = os.path.join(output_dir, "disk.jsonl")
        if not force and os.path.exists(out):
            res["skipped"] += 1
        else:
            images = imageexport.discover_images(disk_dir) if os.path.isdir(disk_dir) else []
            matches: list[dict] = []
            for img in images:
                base = os.path.basename(img)
                # Extract every allocated file in userspace (plaso container), then
                # scan the staged tree in the signatures container. Nothing mounts
                # on the host. The stage is torn down per image to bound disk use.
                with tempfile.TemporaryDirectory(prefix="dxdfir-yara-disk-") as stage:
                    try:
                        os.chmod(stage, 0o777)
                    except OSError:
                        pass
                    try:
                        extract_disk_files(img, stage)
                    except subprocess.CalledProcessError as exc:
                        res["failed"] += 1
                        _note(res, f"disk {base}: extraction failed "
                                   f"({(exc.stderr or b'')[:200]!r})")
                        continue
                    try:
                        matches += _scan_dir(stage, rules_dir, index_path, "disk",
                                             base, image, mount_rules=not baked)
                    except RuntimeError as exc:
                        res["failed"] += 1
                        _note(res, f"disk {base}: {exc}")
            _write(out, matches)
            res["produced"] += len(matches)

    if "memory" in sources:
        out = os.path.join(output_dir, "memory.jsonl")
        if not force and os.path.exists(out):
            res["skipped"] += 1
        elif os.path.isdir(memory_dir):
            # anamnesis replaced Volatility, so there is no windows.vadyarascan.
            # Scan the raw memory image files directly with YARA — the same container
            # path as the loose-files source (works with the baked ruleset too).
            # Coarser than per-VAD scanning: matches carry the image file + offset,
            # not PID/process. An anamnesis/MemProcFS-native per-process YARA scan is
            # a planned follow-up.
            try:
                matches = _scan_dir(memory_dir, rules_dir, index_path, "memory",
                                    os.path.basename(memory_dir), image,
                                    mount_rules=not baked)
            except RuntimeError as exc:
                res["failed"] += 1
                _note(res, f"memory: {exc}")
            else:
                _write(out, matches)
                res["produced"] += len(matches)

    try:
        os.unlink(index_path)
    except OSError:
        pass
    return res


def _write(path: str, records: list[dict]) -> None:
    with open(path, "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
