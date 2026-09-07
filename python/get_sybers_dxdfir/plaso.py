"""Plaso processor — disk images / VM exports -> enriched Plaso JSON Lines.

For each forensic
image (and each VMware VM export) it runs the Plaso two-step in the
``log2timeline/plaso`` container:

  1. ``log2timeline.py`` parses the image into a durable ``.plaso`` storage db (kept
     so an analyst can re-run psort later without re-parsing the image).
  2. ``psort.py -o l2t_json_dxdfir`` renders the db to json_line with the repo's
     custom output module (dev-scripts/plaso/l2t_json_dxdfir.py), which adds
     image_hostname / username / disk_id / volume_id to EVERY event.
  3. the output is named by the resolved image_hostname (the box's own name), not
     the image filename.

Discovery is content-first: each file is identified by MAGIC BYTES (EWF/EWF2, VMDK,
VHD/VHDX, QCOW2), with the extension used only as a fallback (raw/dd/img/aff carry
no signature). Raw VMDK extents and EWF continuation segments are never processed on
their own. VM exports pick the right ``.vmdk`` descriptor (latest snapshot, else the
single base).

Idempotent: an image whose ``.plaso`` db AND recorded json_line output both exist is
skipped (a ``.host`` marker records the resolved output name, so a prior failed
psort is NOT mistaken for done). Emits a machine-readable summary as JSON on stdout
for an honest ``changed_when`` (``processed > 0``).

    python -m get_sybers_dxdfir.plaso --input-dir RAW/disk_images --vm-dir RAW/VM_files \
        --out-dir PROCESSED/log2timeline --module dev-scripts/plaso/l2t_json_dxdfir.py
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

from . import container

_IMAGE = "dxdfir/plaso:latest"

# psort runs through the image's BAKED wrapper (/opt/dxdfir/psort_wrapper.py —
# the only python entry the hardened plaso image allow-lists): it imports the
# mounted custom output module so psort discovers it, then hands psort the
# remaining argv verbatim.
_PSORT_WRAPPER_PATH = "/opt/dxdfir/psort_wrapper.py"

_DESCRIPTOR_HEADER = b"# Disk DescriptorFile"


def _ensure_writable(path: str) -> None:
    """Create a dir and make it container-writable. The plaso container runs as a
    non-root UID and writes the .plaso db and json_line INTO the mounted output, so
    the dir must be world-writable (the retired shell did `chmod -R 777` for the same
    Docker UID-mismatch reason — see docs/scripts/Scripts-Overview.md)."""
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, 0o777)
    except OSError:
        pass


# ---- content-first format detection ----------------------------------------
def _first8_hex(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(8).hex()
    except OSError:
        return ""


def detect_format(path: str) -> str:
    """Identify a file by content -> ewf1|ewf-cont|ewf2|vmdk|vhd|vhdx|qcow2|"".

    Reads only a few header bytes (and a VHD's 512-byte footer) — cheap on multi-GB
    images. RAW/dd/img and AFF carry no reliable signature (handled by ext_format).
    """
    if not os.path.isfile(path):
        return ""
    h = _first8_hex(path)
    if h == "455646090d0aff00":            # "EVF\x09\x0d\x0a\xff\x00" — EWF
        # segment number: uint16 LE at offset 9; only segment 1 heads the set.
        try:
            with open(path, "rb") as fh:
                fh.seek(9)
                seg = fh.read(2)
            segno = seg[0] + (seg[1] << 8) if len(seg) == 2 else 0
        except OSError:
            segno = 0
        return "ewf1" if segno == 1 else "ewf-cont"
    if h == "455646320d0a8100":            # "EVF2\x0d\x0a\x81\x00"
        return "ewf2"
    if h.startswith("4b444d56"):           # "KDMV" monolithic sparse VMDK
        return "vmdk"
    if h.startswith("514649fb"):           # "QFI\xfb"
        return "qcow2"
    if h == "7668647866696c65":            # "vhdxfile"
        return "vhdx"
    if h == "636f6e6563746978":            # "conectix" (dynamic VHD header)
        return "vhd"
    # VMDK text descriptor (points at -flat/-sNNN extents in the same dir).
    try:
        with open(path, "rb") as fh:
            if fh.read(64).startswith(b"# Disk DescriptorFile"):
                return "vmdk"
    except OSError:
        pass
    # A fixed-format VHD carries "conectix" only in its 512-byte footer.
    try:
        size = os.path.getsize(path)
        if size >= 512:
            with open(path, "rb") as fh:
                fh.seek(size - 512)
                if fh.read(8).hex() == "636f6e6563746978":
                    return "vhd"
    except OSError:
        pass
    return ""


def ext_format(name: str) -> str:
    """Format implied by the extension (fallback path).

    -> ewf1|ewf-cont|vmdk|vmdk-extent|vhd|vhdx|aff|raw|"". 'vmdk-extent' flags a raw
    VMDK extent and 'ewf-cont' an EWF continuation — neither processed on its own.
    """
    n = os.path.basename(name).lower()
    if re.search(r"-flat\.vmdk$|-delta\.vmdk$|-s[0-9]+\.vmdk$", n):
        return "vmdk-extent"
    if n.endswith(".e01"):
        return "ewf1"
    if re.search(r"\.e[0-9][0-9]$", n):
        return "ewf-cont"
    if n.endswith(".vmdk"):
        return "vmdk"
    if n.endswith(".vhd"):
        return "vhd"
    if n.endswith(".vhdx"):
        return "vhdx"
    if n.endswith(".aff"):
        return "aff"
    if n.endswith((".raw", ".img", ".dd")):
        return "raw"
    return ""


def get_clean_filename(rel: str) -> str:
    """Collision-free output base name from a path RELATIVE to the input dir:
    fold subdir separators + spaces, and keep the format in the name
    ("name.ext" -> "name_ext") so same-stem images in different formats don't collide."""
    rel = rel.replace("/", "_").replace(" ", "_")
    if "." in rel:
        stem, ext = rel.rsplit(".", 1)
        rel = f"{stem}_{ext}"
    return rel


def is_vmdk_descriptor(path: str) -> bool:
    """A real VMDK descriptor is a small text file whose first line is
    '# Disk DescriptorFile'. The -flat/-delta/-sNNN raw extents are binary."""
    try:
        with open(path, "rb") as fh:
            return fh.read(64).startswith(_DESCRIPTOR_HEADER)
    except OSError:
        return False


def get_vm_descriptor(vm_dir: str) -> tuple[str | None, str]:
    """Pick the .vmdk descriptor for a VM folder.

    Returns (path, status): status is 'ok' (path set), 'ambiguous' (multiple base
    descriptors, no snapshot), or 'none' (no usable descriptor). The latest snapshot
    descriptor wins (it chains back to the base); else the single base descriptor.
    """
    snapshot, base = [], []
    try:
        names = sorted(os.listdir(vm_dir))
    except OSError:
        return None, "none"
    for name in names:
        if not name.lower().endswith(".vmdk"):
            continue
        f = os.path.join(vm_dir, name)
        if not os.path.isfile(f):
            continue
        low = name.lower()
        if low.endswith("-flat.vmdk") or low.endswith("-delta.vmdk") or re.search(r"-s[0-9]+\.vmdk$", low):
            continue
        if not is_vmdk_descriptor(f):
            continue
        if re.search(r"-[0-9]{6}\.vmdk$", low):
            snapshot.append(f)
        else:
            base.append(f)
    if snapshot:
        return sorted(snapshot)[-1], "ok"
    if len(base) == 1:
        return base[0], "ok"
    if len(base) > 1:
        return None, "ambiguous"
    return None, "none"


# ---- discovery -------------------------------------------------------------
def discover_images(input_dir: str, recursive: bool = True) -> list[dict]:
    """Every processable image under input_dir (content-first), each as
    {path, rel, format, by}. Skips vmdk-extents and ewf-continuation segments.

    ``recursive=False`` restricts discovery to files sitting DIRECTLY in
    input_dir (no descent into subdirs) — used to pick up a loose single-file
    image dropped straight into VM_files/ without confusing it with the
    per-VM export folders that :func:`discover_vms` owns."""
    picks: list[dict] = []
    for root, dirs, files in os.walk(input_dir):
        for name in sorted(files):
            path = os.path.join(root, name)
            rel = os.path.relpath(path, input_dir)
            efmt = ext_format(path)
            if efmt == "vmdk-extent":
                continue
            cfmt = detect_format(path)
            if cfmt:
                fmt, by = cfmt, "content"
            else:
                fmt, by = efmt, "extension"
            if fmt in ("", "vmdk-extent", "ewf-cont"):
                continue
            picks.append({"path": path, "rel": rel, "format": fmt, "by": by})
        if not recursive:
            dirs[:] = []   # top level only — never descend into VM-export folders
    # stable order, de-dup by path
    seen, out = set(), []
    for p in sorted(picks, key=lambda d: d["rel"]):
        if p["path"] in seen:
            continue
        seen.add(p["path"])
        out.append(p)
    return out


def discover_vms(vm_dir: str) -> list[str]:
    """Immediate sub-folders of vm_dir (one VM export each), sorted."""
    if not os.path.isdir(vm_dir):
        return []
    return sorted(
        os.path.join(vm_dir, d) for d in os.listdir(vm_dir)
        if os.path.isdir(os.path.join(vm_dir, d))
    )


def discover_loose(loose_dir: str) -> list[str]:
    """Immediate sub-folders of loose_dir (one per-host artefact tree each),
    sorted. A loose source is a DIRECTORY of collected files (Linux /var/log
    trees, mobile filesystem dumps, triage output) — log2timeline parses a
    directory source natively (utmp/wtmp, syslog/auth/cron text, filestat, ...),
    which is how the non-image OS families reach the timeline."""
    if not os.path.isdir(loose_dir):
        return []
    return sorted(
        os.path.join(loose_dir, d) for d in os.listdir(loose_dir)
        if os.path.isdir(os.path.join(loose_dir, d))
    )


# ---- the Plaso two-step ----------------------------------------------------
def _sanitize_host(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]", "_", value or "")
    return value.strip("_")


def _resolved_host(raw_path: str) -> str:
    """image_hostname the module put on the events (constant across the file)."""
    try:
        with open(raw_path, encoding="utf-8", errors="replace") as fh:
            first = fh.readline()
        return _sanitize_host((json.loads(first).get("image_hostname") or "").strip())
    except (OSError, json.JSONDecodeError, AttributeError):
        return ""


def _marker(out_dir: str, name: str) -> str:
    return os.path.join(out_dir, "plaso", f"{name}.host")


def _already_done(out_dir: str, name: str) -> bool:
    """Done iff the .plaso db, the .host marker, and the recorded json_line all exist
    (so a prior FAILED psort — db present, no marker — is not mistaken for done)."""
    plaso_db = os.path.join(out_dir, "plaso", f"{name}.plaso")
    marker = _marker(out_dir, name)
    if not (os.path.isfile(plaso_db) and os.path.getsize(plaso_db) > 0 and os.path.isfile(marker)):
        return False
    try:
        with open(marker, encoding="utf-8") as fh:
            jsonl = fh.read().strip()
    except OSError:
        return False
    return bool(jsonl) and os.path.isfile(os.path.join(out_dir, "jsonl", jsonl))


def run_plaso(mount_dir, src_rel, name, out_dir, module_path, image=_IMAGE) -> dict:
    """Parse one source into a .plaso db, render it to <host>.jsonl. Returns a result
    dict {source, output, host, ok, error?}."""
    plaso_dir = os.path.join(out_dir, "plaso")
    jsonl_dir = os.path.join(out_dir, "jsonl")
    logs_dir = os.path.join(out_dir, "logs")
    _ensure_writable(out_dir)
    for d in (plaso_dir, jsonl_dir, logs_dir):
        _ensure_writable(d)
    plaso_db = os.path.join(plaso_dir, f"{name}.plaso")
    raw = os.path.join(jsonl_dir, f".{name}.raw")
    log = os.path.join(logs_dir, f"{name}.log")

    with open(log, "w") as logfh:
        # 1) parse image -> .plaso (minimal hardened image:
        #    tool argv passed directly, no caps, no network, read-only rootfs)
        subprocess.run(
            container.run(
                image,
                ["log2timeline.py", "--status_view", "none", "--partitions", "all",
                 "--vss-stores", "all",
                 "--storage-file", f"/output/plaso/{name}.plaso", f"/data/{src_rel}"],
                mounts=[f"{os.path.realpath(mount_dir)}:/data:ro",
                        f"{os.path.realpath(out_dir)}:/output"],
                workdir="/tmp",
            ),
            stdout=logfh, stderr=subprocess.STDOUT, check=False,
        )
    if not (os.path.isfile(plaso_db) and os.path.getsize(plaso_db) > 0):
        return {"source": src_rel, "ok": False, "error": "log2timeline produced no .plaso"}

    with open(log, "a") as logfh:
        # 2) render .plaso -> json_line via the custom output module, through the
        #    image's baked psort wrapper (the only python entry it allow-lists)
        subprocess.run(
            container.run(
                image,
                ["python3", _PSORT_WRAPPER_PATH, "/opt/l2t_json_dxdfir.py",
                 "--status_view", "none", "-o", "l2t_json_dxdfir",
                 "--output_fallback_hostname",
                 "-w", f"/output/jsonl/.{name}.raw", f"/output/plaso/{name}.plaso"],
                mounts=[f"{os.path.realpath(out_dir)}:/output",
                        f"{os.path.realpath(module_path)}:/opt/l2t_json_dxdfir.py:ro"],
                workdir="/tmp",
            ),
            stdout=logfh, stderr=subprocess.STDOUT, check=False,
        )
    if not (os.path.isfile(raw) and os.path.getsize(raw) > 0):
        if os.path.exists(raw):
            os.remove(raw)
        return {"source": src_rel, "ok": False, "error": "psort produced no json_line (0 events?)"}

    # name by the resolved image_hostname; keep distinct output on collision.
    host = _resolved_host(raw) or name
    final = os.path.join(jsonl_dir, f"{host}.jsonl")
    if os.path.exists(final):
        final = os.path.join(jsonl_dir, f"{host}_{name}.jsonl")
    os.replace(raw, final)
    with open(_marker(out_dir, name), "w") as fh:
        fh.write(os.path.basename(final))
    return {"source": src_rel, "ok": True, "host": host, "output": os.path.basename(final)}


def process(input_dir, vm_dir, out_dir, module_path, image=_IMAGE, force=False,
            loose_dir="") -> dict:
    """Process every image under input_dir, every VM export under vm_dir, and
    every per-host loose-artefact tree under loose_dir."""
    input_dir = os.path.realpath(input_dir)
    vm_dir = os.path.realpath(vm_dir) if vm_dir else ""
    loose_dir = os.path.realpath(loose_dir) if loose_dir else ""
    out_dir = os.path.realpath(out_dir)
    _ensure_writable(out_dir)
    for sub in ("plaso", "jsonl", "logs"):
        _ensure_writable(os.path.join(out_dir, sub))

    images = discover_images(input_dir) if os.path.isdir(input_dir) else []
    vms = discover_vms(vm_dir) if vm_dir else []
    # Loose single-file images dropped straight into vm_dir (a monolithic .vmdk /
    # .vhd / .vhdx, or an E01/dd left there) — NOT a per-VM export folder, so
    # discover_vms misses them. Collection sort routes every VMDK/VHD(X) to
    # VM_files/, so this is the common case for a single-file VM disk. Top level
    # only: never re-pick a VM-export folder's own descriptor/extents (those are
    # handled by discover_vms + get_vm_descriptor below). Each is processed like
    # any other image, mounting vm_dir instead of input_dir.
    vm_images = discover_images(vm_dir, recursive=False) if vm_dir and os.path.isdir(vm_dir) else []
    loose = discover_loose(loose_dir) if loose_dir else []

    processed = skipped = failed = warnings = 0
    results = []

    # (mount_dir, image) pairs: disk-image tree mounts input_dir; a loose image in
    # vm_dir mounts vm_dir. run_plaso hands log2timeline "/data/<rel>" either way.
    for mount_dir, img in ([(input_dir, i) for i in images]
                           + [(vm_dir, i) for i in vm_images]):
        name = get_clean_filename(img["rel"])
        if not force and _already_done(out_dir, name):
            skipped += 1
            continue
        res = run_plaso(mount_dir, img["rel"], name, out_dir, module_path, image)
        if res["ok"]:
            processed += 1
        else:
            failed += 1
        results.append(res)

    for vm in vms:
        vm_name = os.path.basename(vm)
        descriptor, status = get_vm_descriptor(vm)
        if status != "ok":
            # A missing/ambiguous descriptor is a config warning (the shell skips
            # with a message), NOT a processing failure — don't fail the run on it.
            warnings += 1
            results.append({"source": vm_name, "ok": False, "warning": f"vmdk descriptor {status}"})
            continue
        if not force and _already_done(out_dir, vm_name):
            skipped += 1
            continue
        res = run_plaso(vm, os.path.basename(descriptor), vm_name, out_dir, module_path, image)
        if res["ok"]:
            processed += 1
        else:
            failed += 1
        results.append(res)

    for tree in loose:
        # one per-host tree: mount its PARENT and hand log2timeline the subdir
        # as the source (a directory source — no image mounting involved).
        tree_name = get_clean_filename(os.path.basename(tree))
        if not force and _already_done(out_dir, tree_name):
            skipped += 1
            continue
        res = run_plaso(os.path.dirname(tree), os.path.basename(tree), tree_name,
                        out_dir, module_path, image)
        if res["ok"]:
            processed += 1
        else:
            failed += 1
        results.append(res)

    return {
        "tool": "plaso",
        "input_dir": input_dir,
        "vm_dir": vm_dir,
        "out_dir": out_dir,
        "images": len(images) + len(vm_images),
        "vms": len(vms),
        "processed": processed,
        "skipped": skipped,
        "failed": failed,
        "warnings": warnings,
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="get_sybers_dxdfir.plaso",
        description="disk images / VM exports / loose-artefact trees -> enriched Plaso JSON Lines",
    )
    ap.add_argument("--input-dir", required=True, help="disk-image tree (E01/raw/vmdk/vhd/...)")
    ap.add_argument("--vm-dir", default="", help="VMware VM exports (one folder per VM)")
    ap.add_argument("--loose-dir", default="",
                    help="loose-artefact trees (one folder per host: /var/log copies, "
                         "mobile filesystem dumps, triage output) — parsed as directory sources")
    ap.add_argument("--out-dir", required=True, help="output dir (jsonl/, plaso/, logs/ created within)")
    ap.add_argument("--module", required=True, help="path to the l2t_json_dxdfir.py output module")
    ap.add_argument("--image", default=_IMAGE,
                    help="plaso container image (default: the hardened dxdfir/plaso:latest — "
                         "build with the dxdfir-build-images playbook)")
    ap.add_argument("--force", action="store_true", help="reprocess images that already have output")
    args = ap.parse_args(argv)

    summary = process(
        args.input_dir, args.vm_dir, args.out_dir, args.module,
        image=args.image, force=args.force, loose_dir=args.loose_dir,
    )
    json.dump(summary, sys.stdout)
    sys.stdout.write("\n")
    # Fail only when the run produced nothing AND nothing was already done: inputs
    # that can never produce output (e.g. a Volatility plugin unsupported by this
    # image) are retried on every run, and must not flip an otherwise-complete,
    # idempotent re-run (processed=0, everything else skipped) into a failure.
    return 1 if summary["failed"] and not summary["processed"] and not summary["skipped"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
