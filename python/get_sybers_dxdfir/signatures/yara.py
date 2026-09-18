"""YARA lane — scan a ruleset against evidence.

Sources (default all three):
  files   loose files                                              -> matches.jsonl
  disk    disk images MOUNTED read-only, scanned in place          -> disk.jsonl
          (ewfmount for E01 -> raw, then ntfs-3g on the first NTFS partition —
          both FUSE, so ``/dev/fuse`` must exist on the host; nothing is ever
          extracted out of an image — a host that can't mount records a note)
  memory  process memory, THROUGH Volatility 3                     -> memory.jsonl
          (``windows.vadyarascan`` with the ``jsonl_dfir`` renderer — matches
          carry PID/process context)

YARA has no JSON output and the container's recursive scan hangs, so file/disk scans
loop per-file inside ONE container (per-file scans print strings) and the stable text
form is parsed here. Each match is a self-describing JSON object:

    {"tool":"yara","source":"<file|disk|memory>","rule":"<name>","target":"...",
     "strings":[{"id":"$s1","offset":21,"data":"MZ"}...], "pid":123,"process":"..."}

The mount/scan invocations are built by pure helpers (``ewfmount_argv``,
``mmls_argv``/``parse_mmls_offset``, ``ntfs3g_argv``, ``vadyarascan_argv``) so the
logic is unit-testable without FUSE, docker or evidence; ``mount_image`` /
``unmount_image`` orchestrate them. For the memory source all rule files are
concatenated into one file for Volatility's ``--yara-file`` (naive concat — rule
names must be unique across files).

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
_VOL_IMAGE = "get-sybers/piiat-mem:latest"
# The DetectRaptor ruleset baked into the signatures image (the Dockerfile
# guarantees it with a build-time `test -s`). Used for the file + disk scans when
# no operator rules are staged on the host — an in-image absolute path, never
# mounted. The memory scan runs on the piiat-mem image, which does not carry it.
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


def parse_vadyarascan(lines: str, mem: str) -> list[dict]:
    """vadyarascan JSONL -> yara-match dicts (Rule, PID, Process/Value/Offset)."""
    out: list[dict] = []
    for line in lines.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        rule = r.get("Rule") or r.get("rule")
        if not rule:
            continue
        out.append({
            "tool": "yara", "source": "memory", "rule": rule,
            "pid": r.get("PID"), "process": r.get("Process"),
            "offset": r.get("Offset"), "value": r.get("Value"),
            "target": mem, "match": mem,
        })
    return out


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


# --- memory source: Volatility 3 windows.vadyarascan -------------------------

# vadyarascan runs on the hardened get-sybers/piiat-mem image (Volatility 3 fused
# in). That image's ENTRYPOINT is the batch orchestrator, so we OVERRIDE it to run
# the BAKED vol_wrapper (/opt/piiat-mem/docker/vol_wrapper.py) with the BAKED
# jsonl_dfir renderer (/opt/piiat-mem/jsonl_dfir_renderer.py) — both ship inside
# the image, so nothing is mounted but the evidence, the symbols and the rules.


def vadyarascan_argv(mem: str, symbols_dir: str, rules_file: str,
                     vol_image: str = _VOL_IMAGE,
                     symbols_online: bool = False) -> list[str]:
    """The ``docker run`` argv for one vadyarascan pass over one memory image on
    the hardened get-sybers/piiat-mem image: the batch ENTRYPOINT is overridden to
    python3 running the baked vol_wrapper + renderer (no caps, read-only rootfs, no
    network unless ``symbols_online``). The scan's JSONL goes to stdout. Pure."""
    return container.run(
        vol_image,
        ["/opt/piiat-mem/docker/vol_wrapper.py",
         "/opt/piiat-mem/jsonl_dfir_renderer.py",
         "-q", "-s", "/symbols", "-r", "jsonl_dfir",
         "-f", f"/mem/{os.path.basename(mem)}",
         "windows.vadyarascan.VadYaraScan", "--yara-file", "/rules/combined.yar"],
        mounts=[f"{os.path.dirname(mem)}:/mem:ro",
                f"{os.path.realpath(symbols_dir)}:/symbols",
                f"{os.path.realpath(rules_file)}:/rules/combined.yar:ro"],
        network=symbols_online,
        entrypoint="python3",
    )


def combine_rules(rule_paths: list[str]) -> str:
    """All rule files concatenated for Volatility's single ``--yara-file`` (naive
    concat, so rule names must be unique across files — same contract as the
    retired shell lane)."""
    parts = []
    for path in rule_paths:
        with open(path, encoding="utf-8", errors="replace") as fh:
            parts.append(fh.read())
    return "\n".join(parts)


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
        symbols_dir=None,
        image=_SIGNATURES_IMAGE, vol_image=_VOL_IMAGE, **_ignored) -> dict:
    """Run the selected YARA sources. Returns {lane, produced, skipped, failed}."""
    ds = os.path.join(repo_root, "data_store")
    rules_dir = rules_dir or os.path.join(ds, "dependencies", "yara-rules")
    files_target = files_target or os.path.join(ds, "raw", "other_raw_data")
    disk_dir = disk_dir or os.path.join(ds, "raw", "disk_images")
    memory_dir = memory_dir or os.path.join(ds, "raw", "memory")
    symbols_dir = symbols_dir or os.path.join(ds, "dependencies", "volatility3-symbols")
    # The jsonl_dfir renderer + vol_wrapper are BAKED into the get-sybers/piiat-mem
    # image (at /opt/piiat-mem/); the memory scan overrides the batch entrypoint to
    # run them there, so nothing renderer-related is mounted (see vadyarascan_argv).
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
        elif baked:
            # The baked rules live in the signatures image; the memory scan runs on
            # the piiat-mem image, which cannot reach them. It needs operator YARA
            # rules staged on the host (and Vol3 symbols) — skip, don't run ruleless.
            res["skipped"] += 1
            _note(res, f"memory: skipped — stage operator YARA rules under {rules_dir} "
                       "(the baked rules are in the signatures image, not piiat-mem)")
        else:
            # Reuse the volatility processor's image discovery (its extension set
            # covers the shell lane's list plus the corpus-specific *dramimage).
            from ..volatility import discover as _discover_memory
            mems = _discover_memory(memory_dir) if os.path.isdir(memory_dir) else []
            os.makedirs(symbols_dir, exist_ok=True)
            try:
                os.chmod(symbols_dir, 0o777)  # the container writes its ISF cache here
            except OSError:
                pass
            combined = tempfile.NamedTemporaryFile("w", suffix=".yar", delete=False)
            combined.write(combine_rules(rules))
            combined.close()
            # NamedTemporaryFile is 0600; the Volatility container runs as a
            # non-root user and must be able to read the mounted rules file.
            os.chmod(combined.name, 0o644)
            matches = []
            failed_mems = []
            try:
                for mem in mems:
                    proc = subprocess.run(
                        vadyarascan_argv(mem, symbols_dir,
                                         combined.name, vol_image),
                        capture_output=True, text=True, check=False,
                    )
                    if proc.returncode != 0:
                        res["failed"] += 1
                        failed_mems.append(os.path.basename(mem))
                        continue
                    matches += parse_vadyarascan(
                        proc.stdout, os.path.relpath(mem, memory_dir))
            finally:
                os.unlink(combined.name)
            _write(out, matches)
            res["produced"] += len(matches)
            if failed_mems:
                _note(res, "memory: vadyarascan failed on: " + ", ".join(failed_mems))

    try:
        os.unlink(index_path)
    except OSError:
        pass
    return res


def _write(path: str, records: list[dict]) -> None:
    with open(path, "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
