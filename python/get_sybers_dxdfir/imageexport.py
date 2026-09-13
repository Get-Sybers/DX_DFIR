"""Targeted artefact extraction from disk images, via log2timeline/plaso.

The evtx lane needs real ``.evtx`` files, but evidence often arrives as a disk image
(E01/raw/VMDK), not loose logs. This module pulls ONLY a named artefact set out of an
image with Plaso's ``image_export.py`` (dfVFS, userspace, E01-capable) — the default
``WindowsEventLogs`` copies just ``winevt\\Logs\\*.evtx``, a triage-style collection,
never the whole filesystem.

It ports ``sig_extract_artifacts`` from the retired shell lane library
(``scripts/signatures/lib/disk-image.sh``, the Hayabusa lane's extractor) — same
container, same flags — so the evtx and signature lanes source disk-image EVTX the
one proven way. Reusing the pipeline's own hardened ``get-sybers/plaso`` image keeps the
.NET evtxecmd image free of a dfVFS/pytsk3 stack.

``image_export_argv`` is pure (no I/O) so the container invocation is unit-testable
without docker.
"""
from __future__ import annotations

import os
import subprocess

from . import container

# The pipeline's own hardened plaso image (built by the dxdfir-build-images playbook).
PLASO_IMAGE = "get-sybers/plaso:latest"

# Formats dfVFS can open. Supersets the retired disk-image.sh's sig_list_images()
# with the VHD/VHDX/QCOW2 formats the plaso processor also accepts, so every image
# the timeline lane can parse is also reachable for artefact extraction.
IMAGE_EXTS = (".e01", ".ex01", ".raw", ".img", ".dd", ".vmdk", ".001", ".aff4",
              ".vhd", ".vhdx", ".qcow2")


def discover_images(path: str) -> list[str]:
    """Disk images at ``path``: the file itself if it is one, else every image under
    it (recursed), sorted, absolute."""
    path = os.path.realpath(path)
    if os.path.isfile(path):
        return [path] if path.lower().endswith(IMAGE_EXTS) else []
    found = []
    for root, _dirs, files in os.walk(path):
        for name in files:
            if name.lower().endswith(IMAGE_EXTS):
                found.append(os.path.join(root, name))
    return sorted(found)


def image_export_argv(image, out_dir, *, artifact_filters=("WindowsEventLogs",),
                      plaso_image=PLASO_IMAGE, vss=False):
    """The ``docker run`` argv for one ``image_export.py`` extraction.

    The image's directory is mounted read-only at ``/data`` and the output dir at
    ``/out``; ``--artifact_filters`` scopes the copy to the named artefact set(s).
    ``--partitions all`` so a multi-partition Windows image is fully searched;
    ``--vss_stores none`` by default (skip shadow copies — set ``vss`` to include them).

    Runs on the minimal hardened get-sybers/plaso image (no caps, no network,
    read-only rootfs); image_export.py is the tool argv (plaso has no single
    ENTRYPOINT). Pure (no I/O).
    """
    return container.run(
        plaso_image,
        ["image_export.py", "-q", "--partitions", "all",
         "--vss_stores", "all" if vss else "none",
         "--artifact_filters", ",".join(artifact_filters),
         "-w", "/out",
         f"/data/{os.path.basename(image)}"],
        mounts=[f"{os.path.dirname(image)}:/data:ro", f"{out_dir}:/out"],
        workdir="/tmp",
    )


def extract(image, out_dir, *, artifact_filters=("WindowsEventLogs",),
            plaso_image=PLASO_IMAGE, vss=False) -> list[str]:
    """Extract the named artefacts from one image into ``out_dir``; return the files
    written (absolute paths). Creates ``out_dir``. Raises ``CalledProcessError`` if
    image_export fails; an image with none of the artefacts simply yields ``[]``.
    """
    image = os.path.realpath(image)
    out_dir = os.path.realpath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    # image_export runs as a non-root user inside the plaso container and creates
    # nested dirs (Windows/System32/winevt/Logs/...) under /out, so the mount point
    # must be writable by that uid. Mirrors sig_extract_artifacts's `chmod 777`.
    try:
        os.chmod(out_dir, 0o777)
    except OSError:
        pass
    subprocess.run(
        image_export_argv(image, out_dir, artifact_filters=artifact_filters,
                          plaso_image=plaso_image, vss=vss),
        # image_export is chatty on stderr (progress, per-file notes); capture it so
        # only the caller's own output (e.g. evtx's JSON summary) reaches stdout.
        capture_output=True,
        check=True,
    )
    written = []
    for root, _dirs, files in os.walk(out_dir):
        for name in files:
            written.append(os.path.join(root, name))
    return sorted(written)


def extract_staged(image_src, stage_dir, *, artifact_filters=("WindowsEventLogs",),
                   exts=(".evtx",), plaso_image=PLASO_IMAGE, vss=False,
                   force=False) -> dict:
    """Pull the named artefacts out of every disk image at ``image_src`` into
    ``stage_dir/<image_stem>/`` — one persistent, reusable stage per image.

    This is THE shared extraction step: the evtx processor and the Hayabusa
    detection lane both stage through here with the same default ``stage_dir``,
    so whichever runs first pays the extraction cost and every later run —
    processor or detection — reuses the staged files instead of re-processing
    the raw image.

    Idempotent: an image whose stage subdir already holds a file matching
    ``exts`` is skipped unless ``force`` (extraction is the slow part).
    Returns {image_src, stage_dir, images, extracted, reused, failed, results}.
    """
    stage_dir = os.path.realpath(stage_dir)
    images = discover_images(image_src)
    summary = {"image_src": os.path.realpath(image_src), "stage_dir": stage_dir,
               "images": len(images), "extracted": 0, "reused": 0, "failed": 0,
               "results": []}
    lowered = tuple(e.lower() for e in exts)
    for img in images:
        stem = os.path.splitext(os.path.basename(img))[0]
        dest = os.path.join(stage_dir, stem)
        have = [os.path.join(r, f) for r, _d, fs in os.walk(dest) for f in fs
                if f.lower().endswith(lowered)] if os.path.isdir(dest) else []
        if have and not force:
            summary["reused"] += 1
            summary["results"].append({"image": img, "files": len(have), "reused": True})
            continue
        try:
            written = extract(img, dest, artifact_filters=artifact_filters,
                              plaso_image=plaso_image, vss=vss)
        except subprocess.CalledProcessError:
            summary["failed"] += 1
            summary["results"].append({"image": img, "error": "image_export failed"})
            continue
        got = [f for f in written if f.lower().endswith(lowered)]
        summary["extracted"] += len(got)
        summary["results"].append({"image": img, "files": len(got)})
    return summary
