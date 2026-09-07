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
import shutil
import subprocess
import tempfile

from .. import container
from . import clean_name, have_fuse, list_images

_YARA_IMAGE = "dxdfir/yara:latest"
_VOL_IMAGE = "dxdfir/volatility:latest"
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


# --- disk source: read-only image mounting (ewfmount + ntfs-3g, both FUSE) ---

def ewfmount_argv(image: str, mount_dir: str) -> list[str]:
    """Expose an E01/Ex01 as a raw device file (``<mount_dir>/ewf1``). Pure."""
    return ["ewfmount", image, mount_dir]


def mmls_argv(raw: str) -> list[str]:
    """TSK partition listing (allocated only) for the NTFS-offset probe. Pure."""
    return ["mmls", "-a", raw]


def parse_mmls_offset(text: str) -> int:
    """Byte offset of the first NTFS/"basic data"/0x07 partition in ``mmls -a``
    output (start sector * 512), or 0 for a partitionless volume. Pure — mirrors
    the awk in the retired disk-image.sh."""
    for line in text.splitlines():
        low = line.lower()
        if "ntfs" not in low and "basic data" not in low and "0x07" not in low:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            return int(parts[2], 10) * 512
        except ValueError:
            continue
    return 0


def ntfs3g_argv(raw: str, mount_dir: str, offset: int) -> list[str]:
    """Mount the NTFS filesystem at byte ``offset`` of ``raw`` read-only, with
    Windows-style ADS naming. Pure."""
    return ["ntfs-3g", "-o", f"ro,offset={offset},streams_interface=windows",
            raw, mount_dir]


def mount_image(image: str, mount_dir: str) -> list[tuple[str, str]] | None:
    """Mount a disk image read-only at ``mount_dir``. E01/Ex01 go through ewfmount
    (into a temp dir) first; the first NTFS partition (mmls) is then ntfs-3g-mounted
    — Windows images, which is what most Windows YARA targets need.

    Returns the unmount state for :func:`unmount_image` on success, None on failure
    (with everything already unwound)."""
    image = os.path.realpath(image)
    os.makedirs(mount_dir, exist_ok=True)
    state: list[tuple[str, str]] = []
    raw = image
    if image.lower().endswith((".e01", ".ex01")):
        ewfdir = tempfile.mkdtemp()
        proc = subprocess.run(ewfmount_argv(image, ewfdir),
                              capture_output=True, check=False)
        if proc.returncode != 0:
            shutil.rmtree(ewfdir, ignore_errors=True)
            return None
        state.append(("ewf", ewfdir))
        raw = os.path.join(ewfdir, "ewf1")
    probe = subprocess.run(mmls_argv(raw), capture_output=True, text=True, check=False)
    offset = parse_mmls_offset(probe.stdout)
    proc = subprocess.run(ntfs3g_argv(raw, mount_dir, offset),
                          capture_output=True, check=False)
    if proc.returncode == 0:
        state.append(("ntfs", mount_dir))
        return state
    unmount_image(state, mount_dir)
    return None


def unmount_image(state: list[tuple[str, str]], mount_dir: str) -> None:
    """Unwind :func:`mount_image` — newest mount first, ewf temp dirs removed."""
    for kind, path in reversed(state):
        if subprocess.run(["fusermount", "-u", path],
                          capture_output=True, check=False).returncode != 0:
            subprocess.run(["umount", path], capture_output=True, check=False)
        if kind == "ewf":
            shutil.rmtree(path, ignore_errors=True)
    try:
        os.rmdir(mount_dir)
    except OSError:
        pass


# --- memory source: Volatility 3 windows.vadyarascan -------------------------

# vadyarascan runs on the hardened dxdfir/volatility image through its BAKED
# wrapper (/opt/dfir/vol_wrapper.py — the only python entry the image
# allow-lists), which imports the mounted jsonl_dfir renderer then hands the
# CLI the remaining argv verbatim.


def vadyarascan_argv(mem: str, symbols_dir: str, renderer: str, rules_file: str,
                     vol_image: str = _VOL_IMAGE,
                     symbols_online: bool = False) -> list[str]:
    """The ``docker run`` argv for one vadyarascan pass over one memory image on
    the minimal hardened dxdfir/volatility image (the baked wrapper is the
    ENTRYPOINT; no caps, read-only rootfs, no network unless ``symbols_online``).
    The scan's JSONL goes to stdout. Pure (no I/O beyond path normalisation)."""
    return container.run(
        vol_image,
        ["/opt/jsonl_dfir_renderer.py",
         "-q", "-s", "/symbols", "-r", "jsonl_dfir",
         "-f", f"/mem/{os.path.basename(mem)}",
         "windows.vadyarascan.VadYaraScan", "--yara-file", "/rules/combined.yar"],
        mounts=[f"{os.path.dirname(mem)}:/mem:ro",
                f"{os.path.realpath(symbols_dir)}:/symbols",
                f"{os.path.realpath(renderer)}:/opt/jsonl_dfir_renderer.py:ro",
                f"{os.path.realpath(rules_file)}:/rules/combined.yar:ro"],
        network=symbols_online,
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
        # NamedTemporaryFile is 0600; the container reads it as uid 2000
        os.chmod(listf.name, 0o644)
        # The minimal dxdfir/yara image's ENTRYPOINT is the baked per-file scan
        # loop (/opt/dxdfir/scan-list.sh); it reads the mounted list + index and
        # prints matches to stdout (captured here) — no shell command is
        # injected from here.
        proc = subprocess.run(
            container.run(
                image, [],
                mounts=[f"{os.path.realpath(rules_dir)}:/rules:ro",
                        f"{os.path.realpath(scan_dir)}:/scan:ro",
                        f"{os.path.realpath(index_path)}:/index.yar:ro",
                        f"{listf.name}:/list.txt:ro"]),
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
        disk_subpath=None, mount_base="/mnt/dxdfir-sig",
        symbols_dir=None, renderer=None,
        image=_YARA_IMAGE, vol_image=_VOL_IMAGE, **_ignored) -> dict:
    """Run the selected YARA sources. Returns {lane, produced, skipped, failed}."""
    ds = os.path.join(repo_root, "data_store")
    rules_dir = rules_dir or os.path.join(ds, "dependencies", "yara-rules")
    files_target = files_target or os.path.join(ds, "raw", "other_raw_data")
    disk_dir = disk_dir or os.path.join(ds, "raw", "disk_images")
    memory_dir = memory_dir or os.path.join(ds, "raw", "memory")
    symbols_dir = symbols_dir or os.path.join(ds, "dependencies", "volatility3-symbols")
    # The jsonl_dfir renderer is owned by the vendored PIIAT-Mem tool (the same
    # renderer the volatility PROCESSOR drives through `python -m piiat_mem`); the
    # memory scan bind-mounts it into the hardened dxdfir/volatility image, whose
    # baked wrapper (/opt/dfir/vol_wrapper.py) loads it. It lives in the submodule,
    # not in a dev-scripts/ tree.
    renderer = renderer or os.path.join(
        repo_root, "third_party", "piiat-mem", "jsonl_dfir_renderer.py")
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
    if not rules:
        res["note"] = f"no rules in {rules_dir}"
        return res

    # Build the include index in a TEMP file (never write into the operator's rules
    # tree — it may be read-only/externally managed); it's bind-mounted at /index.yar.
    idxf = tempfile.NamedTemporaryFile("w", suffix=".yar", delete=False)
    idxf.write(build_index(rules, rules_dir))
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
                                    os.path.basename(files_target), image)
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
        elif not have_fuse():
            # This lane never extracts files out of images — either the host
            # allows FUSE (lxc.cgroup2.devices.allow: c 10:229 rwm + a /dev/fuse
            # mount entry) or the disk source stands down. No output file is
            # written, so the source runs for real once mounting is enabled.
            _note(res, "disk: /dev/fuse unavailable — cannot mount images here; "
                       "mount-enable the host (nothing is extracted from images)")
        else:
            images = list_images(disk_dir) if os.path.isdir(disk_dir) else []
            matches: list[dict] = []
            unmountable = []
            for i, img in enumerate(images):
                mnt = os.path.join(mount_base, f"y{i}")
                state = mount_image(img, mnt)
                if state is None:
                    unmountable.append(os.path.basename(img))
                    continue
                try:
                    scanroot = mnt
                    if disk_subpath and os.path.isdir(os.path.join(mnt, disk_subpath)):
                        scanroot = os.path.join(mnt, disk_subpath)
                    try:
                        matches += _scan_dir(scanroot, rules_dir, index_path, "disk",
                                             os.path.basename(img), image)
                    except RuntimeError as exc:
                        res["failed"] += 1
                        _note(res, f"disk {os.path.basename(img)}: {exc}")
                finally:
                    unmount_image(state, mnt)
            _write(out, matches)
            res["produced"] += len(matches)
            if unmountable:
                _note(res, "disk: not mountable Windows volumes (skipped): "
                           + ", ".join(unmountable))

    if "memory" in sources:
        out = os.path.join(output_dir, "memory.jsonl")
        if not force and os.path.exists(out):
            res["skipped"] += 1
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
                        vadyarascan_argv(mem, symbols_dir, renderer,
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
