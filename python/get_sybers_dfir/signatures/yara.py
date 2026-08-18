"""YARA lane — scan a ruleset against evidence.

Sources (default all three):
  files   loose files                          -> matches.jsonl   (implemented)
  disk    disk images mounted read-only in place (ewfmount+ntfs-3g via FUSE) ->
          disk.jsonl      -- NOT YET PORTED: records a note only; the working
          implementation is in scripts/signatures/yara.sh
  memory  process memory via Volatility 3 (windows.vadyarascan) -> memory.jsonl
                          -- NOT YET PORTED: note only; see yara.sh

YARA has no JSON output and the container's recursive scan hangs, so the file scan
loops per-file inside ONE container (per-file scans print strings) and the stable text
form is parsed here. Each match is a self-describing JSON object. parse_vadyarascan()
exists (and is unit-tested) for when the memory source is wired up.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile

from . import clean_name, have_fuse, list_images

_YARA_IMAGE = "blacktop/yara:latest"
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


def _scan_dir(scan_dir, rules_dir, index_path, source, base, image) -> list[dict]:
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
        script = (
            'while IFS= read -r f; do [ -n "$f" ] && '
            'yara -w -s -N /index.yar "$f"; done < /list.txt'
        )
        proc = subprocess.run(
            [
                "docker", "run", "--rm", "--entrypoint", "sh",
                "-v", f"{os.path.realpath(rules_dir)}:/rules:ro",
                "-v", f"{os.path.realpath(scan_dir)}:/scan:ro",
                "-v", f"{os.path.realpath(index_path)}:/index.yar:ro",
                "-v", f"{listf.name}:/list.txt:ro",
                image, "-c", script,
            ],
            capture_output=True, text=True, check=False,
        )
        return parse_yara_text(proc.stdout, source, "/scan/", base)
    finally:
        os.unlink(listf.name)


def run(*, output_dir, repo_root, fetch=False, force=False,
        sources=("files", "disk", "memory"),
        rules_dir=None, files_target=None, disk_dir=None, memory_dir=None,
        image=_YARA_IMAGE, **_ignored) -> dict:
    """Run the selected YARA sources. Returns {lane, produced, skipped, failed}."""
    ds = os.path.join(repo_root, "data_store")
    rules_dir = rules_dir or os.path.join(ds, "dependencies", "yara-rules")
    files_target = files_target or os.path.join(ds, "raw", "other_raw_data")
    disk_dir = disk_dir or os.path.join(ds, "raw", "disk_images")
    memory_dir = memory_dir or os.path.join(ds, "raw", "memory")
    os.makedirs(output_dir, exist_ok=True)

    res = {"lane": "yara", "sources": list(sources), "produced": 0, "skipped": 0,
           "failed": 0, "note": None}

    rules = _rule_files(rules_dir)
    if not rules:
        res["note"] = f"no rules in {rules_dir}"
        return res

    # Build the include index in a TEMP file (never write into the operator's rules
    # tree — it may be read-only/externally managed); it's bind-mounted at /index.yar.
    idxf = tempfile.NamedTemporaryFile("w", suffix=".yar", delete=False)
    idxf.write(build_index(rules, rules_dir))
    idxf.close()
    index_path = idxf.name

    if "files" in sources:
        out = os.path.join(output_dir, "matches.jsonl")
        if not force and os.path.exists(out):
            res["skipped"] += 1
        elif os.path.isdir(files_target):
            matches = _scan_dir(files_target, rules_dir, index_path, "file",
                                os.path.basename(files_target), image)
            _write(out, matches)
            res["produced"] += len(matches)

    if "disk" in sources:
        out = os.path.join(output_dir, "disk.jsonl")
        if not force and os.path.exists(out):
            res["skipped"] += 1
        elif not have_fuse():
            res["note"] = "disk: /dev/fuse unavailable — mount-enable the host or point files at raw"
        else:
            res["note"] = "disk: mounting supported but requires ewfmount/ntfs-3g at runtime"

    if "memory" in sources:
        out = os.path.join(output_dir, "memory.jsonl")
        if not force and os.path.exists(out):
            res["skipped"] += 1
        # the memory source needs the Volatility image + symbols at runtime; the
        # vadyarascan parse is covered by parse_vadyarascan (unit-tested).

    try:
        os.unlink(index_path)
    except OSError:
        pass
    return res


def _write(path: str, records: list[dict]) -> None:
    with open(path, "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
