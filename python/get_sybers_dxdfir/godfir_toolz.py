"""GoDFIR-toolz processor — disk images -> per-host Windows-artefact parse.

The evtx/plaso lanes get their bytes straight off the image via Plaso's
``image_export.py`` (see ``imageexport``); this lane does the same for the
Windows artefact families the GoDFIR-toolz images parse, then runs a hardened
``get-sybers/<tool>`` container over what was pulled out. Every tool is a
Linux-native, static-Go ``FROM scratch`` binary (Get-Sybers/GoDFIR-toolz):
registry batch via ``gore``, jump lists via ``gojle``, ``.lnk`` via ``gole``,
Amcache via ``goamcache``, AppCompatCache via ``goappcompat``, ShellBags via
``gosbe``, Recycle Bin via ``gorb``, MFT via ``gomft``, plus the two artefact
families that had no Linux-viable parser at all before the Go ports: SRUM via
``goese`` (the ESE database needs no Windows engine here) and Prefetch via
``goprefetch``. The registry-family tools (gore/gosbe/goamcache/goappcompat)
replay each hive's .LOG1/.LOG2 dirty-hive transaction logs for full fidelity.
byakugan's ``esedump_srum`` / ``prefetch_dump`` maps normalise the
SRUM/Prefetch JSONL into CAR as their own MITRE data sources.

Extraction uses a plaso **YAML** collection filter (``plaso.engine.yaml_filter_file``),
NOT ``--artifact_filters`` (the WindowsEventLogs artifact set the evtx lane uses) —
verified against the built ``get-sybers/plaso`` image: ANY file passed to ``-f`` is parsed
as YAML unconditionally (``engine.BuildCollectionFilters`` always builds a
``YAMLFilterFile``), so the plain-text "one path per line" format the ``--help``
text describes is not actually reachable through this flag on this plaso version.
A filter document is ``description``/``type: include``/``path_separator: '/'``/
``paths:`` (REGEX per path segment, matched case-insensitively by dfVFS — the
path string itself needs no ``%SystemRoot%``-style expansion, which is an
``--artifact_filters``-only mechanism; a plain absolute path split on '/' already
resolves to the right dfVFS ``location_regex`` segments).

SRUM and Prefetch are extracted by the SAME filter and parsed by the Go
substitutes above. They are their own CAR data sources (byakugan
``esedump_srum`` / ``prefetch_dump``), distinct from — and coexisting with — the
main log2timeline lane's own SRUM/prefetch coverage; the Go tools keep higher
fidelity (goese's second-precision timestamps, decoded device paths/SIDs).

Output isolation follows the CAR pipeline's rule (docs/CAR-Pipeline.md §2 — "one
source, one database"): each image gets its OWN
``data_store/processed/godfir-toolz/<host>/``, holding the raw extraction
(``_extracted/``), the tool-container outputs (one sub-dir per tool), and a
combined run log. Idempotent at the HOST level: a host dir that already holds any
non-empty file is skipped whole unless ``--force`` — a partial prior run is
reprocessed entirely rather than guessed at file-by-file.

gowxt (Windows Timeline / ActivitiesCache.db) is wired as a pure argv builder
(``wxtcmd_argv``, unit-tested) but deliberately NOT invoked by ``process_image`` —
its SQLite interop needs a writable unpack path the tool's own working directory
provides, which the hardened read-only-rootfs base image does not; verifying that
against a real ActivitiesCache.db is deferred to issue #88. See its docstring.

    python -m get_sybers_dxdfir.godfir_toolz --image-src RAW/disk_images --out-dir PROCESSED/godfir-toolz
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

import yaml

from . import container, imageexport

PLASO_IMAGE = imageexport.PLASO_IMAGE
_RECMD_IMAGE = "get-sybers/gore:latest"
_JLECMD_IMAGE = "get-sybers/gojle:latest"
_LECMD_IMAGE = "get-sybers/gole:latest"
_AMCACHEPARSER_IMAGE = "get-sybers/goamcache:latest"
_APPCOMPATCACHEPARSER_IMAGE = "get-sybers/goappcompat:latest"
_SBECMD_IMAGE = "get-sybers/gosbe:latest"
_RBCMD_IMAGE = "get-sybers/gorb:latest"
_MFTECMD_IMAGE = "get-sybers/gomft:latest"
_WXTCMD_IMAGE = "get-sybers/gowxt:latest"  # TODO(#88): built but not invoked — see wxtcmd_argv()
# The Linux-native Go parsers for the Windows-bound artefact families
# (Get-Sybers/GoDFIR-toolz): goese parses SRUDB.dat (no Windows ESE engine
# needed); goprefetch parses .pf where no prior Linux parser
# refuses off-Windows. byakugan's esedump_srum / prefetch_dump maps normalise
# their JSONL into CAR (their own MITRE data sources).
_ESEDUMP_IMAGE = "get-sybers/goese:latest"
_PREFETCH_IMAGE = "get-sybers/goprefetch:latest"

# gore bakes its OWN curated forensic-key batch at /batch/default.reb (its --bn
# default) — a redistributable replacement for the non-redistributable Kroll batch
# (not redistributable), so the lane no longer supplies a batch path at all.


# ---- the artefact filter (plaso yaml_filter_file format, NOT --artifact_filters) --
# Each dict is one YAML document in the rendered filter file. path_separator '/' —
# dfVFS location matching is per-segment and separator-agnostic, so a plain
# forward-slash path needs no %variable expansion (that's an artifact_filters-only
# mechanism); "paths" entries are per-segment regex, matched case-insensitively.
ARTIFACT_GROUPS: list[dict] = [
    {
        "description": "Amcache (program-execution inventory hive + dirty-hive logs)",
        "type": "include",
        "path_separator": "/",
        "paths": [
            r"/Windows/AppCompat/Programs/Amcache\.hve",
            r"/Windows/AppCompat/Programs/Amcache\.hve\.LOG1",
            r"/Windows/AppCompat/Programs/Amcache\.hve\.LOG2",
        ],
    },
    {
        "description": "System-wide registry hives + dirty-hive transaction logs",
        "type": "include",
        "path_separator": "/",
        "paths": [
            r"/Windows/System32/config/SYSTEM",
            r"/Windows/System32/config/SYSTEM\.LOG1",
            r"/Windows/System32/config/SYSTEM\.LOG2",
            r"/Windows/System32/config/SOFTWARE",
            r"/Windows/System32/config/SOFTWARE\.LOG1",
            r"/Windows/System32/config/SOFTWARE\.LOG2",
            r"/Windows/System32/config/SAM",
            r"/Windows/System32/config/SAM\.LOG1",
            r"/Windows/System32/config/SAM\.LOG2",
            r"/Windows/System32/config/SECURITY",
            r"/Windows/System32/config/SECURITY\.LOG1",
            r"/Windows/System32/config/SECURITY\.LOG2",
        ],
    },
    {
        # Dirty-hive replay (gore/gosbe) needs the .LOG1/.LOG2 transaction logs
        # sitting ALONGSIDE the hive — never extract one without the other.
        "description": "Per-user registry hives (NTUSER.DAT / UsrClass.dat) + logs",
        "type": "include",
        "path_separator": "/",
        "paths": [
            r"/Users/.*/NTUSER\.DAT",
            r"/Users/.*/NTUSER\.DAT\.LOG1",
            r"/Users/.*/NTUSER\.DAT\.LOG2",
            r"/Users/.*/AppData/Local/Microsoft/Windows/UsrClass\.dat",
            r"/Users/.*/AppData/Local/Microsoft/Windows/UsrClass\.dat\.LOG1",
            r"/Users/.*/AppData/Local/Microsoft/Windows/UsrClass\.dat\.LOG2",
        ],
    },
    {
        "description": "Jump lists and .lnk shortcuts (Explorer \"Recent\")",
        "type": "include",
        "path_separator": "/",
        "paths": [
            r"/Users/.*/AppData/Roaming/Microsoft/Windows/Recent/.*\.lnk",
            r"/Users/.*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/.*",
            r"/Users/.*/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/.*",
        ],
    },
    {
        "description": "Recycle Bin $I metadata records",
        "type": "include",
        "path_separator": "/",
        "paths": [
            r"/\$Recycle\.Bin/.*/\$I.*",
        ],
    },
    {
        "description": "Windows Timeline activity database (gowxt input; see #88)",
        "type": "include",
        "path_separator": "/",
        "paths": [
            r"/Users/.*/AppData/Local/ConnectedDevicesPlatform/.*/ActivitiesCache\.db",
        ],
    },
    {
        "description": "System Resource Usage Monitor (SRUM) database",
        "type": "include",
        "path_separator": "/",
        "paths": [
            r"/Windows/System32/sru/SRUDB\.dat",
        ],
    },
    {
        "description": "Windows Prefetch (.pf) — goprefetch input",
        "type": "include",
        "path_separator": "/",
        "paths": [
            r"/Windows/Prefetch/.*\.pf",
        ],
    },
    {
        "description": "Master File Table, when resident (gomft input)",
        "type": "include",
        "path_separator": "/",
        "paths": [
            r"/\$MFT",
        ],
    },
]


def build_filter_yaml(groups: list[dict] = ARTIFACT_GROUPS) -> str:
    """Render ``groups`` as the multi-document YAML ``image_export.py -f`` expects.
    Pure (no I/O) — the caller writes the result to a file for the container to mount."""
    return yaml.safe_dump_all(groups, sort_keys=False)


# ---- extraction (image -> stage dir), via a YAML filter file, not --artifact_filters --
def image_export_argv(image, out_dir, filter_file, *, plaso_image=PLASO_IMAGE,
                      vss=False) -> list[str]:
    """The ``docker run`` argv for one ``image_export.py`` extraction using a
    filter FILE (``-f``) instead of ``--artifact_filters`` — the godfir-toolz artefact
    set has no named forensic-artifact-definitions entry, so it's declared as our
    own YAML filter (``build_filter_yaml``) and mounted in read-only. Pure (no I/O).
    """
    return container.run(
        plaso_image,
        ["image_export.py", "-q", "--partitions", "all",
         "--vss_stores", "all" if vss else "none",
         "-f", "/filter.yaml",
         "-w", "/out",
         f"/data/{os.path.basename(image)}"],
        mounts=[f"{os.path.dirname(image)}:/data:ro", f"{out_dir}:/out",
                f"{filter_file}:/filter.yaml:ro"],
        workdir="/tmp",
    )


def extract_artifacts(image, stage_dir, *, plaso_image=PLASO_IMAGE, vss=False) -> list[str]:
    """Extract the godfir-toolz artefact set from one image into ``stage_dir``
    (the filter YAML is written alongside as ``_filter.yaml`` for debugging, and
    excluded from the returned file list). Returns files written (absolute
    paths). Raises ``CalledProcessError`` if image_export fails."""
    image = os.path.realpath(image)
    stage_dir = os.path.realpath(stage_dir)
    os.makedirs(stage_dir, exist_ok=True)
    try:
        # image_export runs as a non-root uid inside the plaso container.
        os.chmod(stage_dir, 0o777)
    except OSError:
        pass
    filter_path = os.path.join(stage_dir, "_filter.yaml")
    with open(filter_path, "w") as fh:
        fh.write(build_filter_yaml())
    subprocess.run(
        image_export_argv(image, stage_dir, filter_path, plaso_image=plaso_image, vss=vss),
        capture_output=True, check=True,
    )
    written = []
    for root, _dirs, files in os.walk(stage_dir):
        for name in files:
            if os.path.join(root, name) == filter_path:
                continue
            written.append(os.path.join(root, name))
    return sorted(written)


# ---- discovery / naming -----------------------------------------------------
def discover_images(path: str) -> list[str]:
    """Disk images to process — the SAME extension-based discovery the evtx and
    plaso lanes' extraction step uses (``imageexport.discover_images``)."""
    return imageexport.discover_images(path)


def host_name(image_path: str) -> str:
    """Per-host output-dir label for an image: its filename stem (extension
    dropped), spaces folded — one image, one host, one directory."""
    stem = os.path.splitext(os.path.basename(image_path))[0]
    return stem.replace(" ", "_")


def find_file(root: str, name: str) -> str | None:
    """First file under ``root`` (any depth) whose basename matches ``name``
    case-insensitively; sorted for a deterministic pick among duplicates
    (e.g. the same hive staged under more than one path). None if absent."""
    target = name.lower()
    matches = [os.path.join(cur, f) for cur, _dirs, files in os.walk(root)
               for f in files if f.lower() == target]
    return sorted(matches)[0] if matches else None


def find_file_ext(root: str, ext: str) -> str | None:
    """First file under ``root`` (any depth) whose extension matches ``ext``
    (with the leading dot, case-insensitively) — the presence probe for a whole
    class of files (e.g. any ``.pf``). None if absent."""
    target = ext.lower()
    matches = [os.path.join(cur, f) for cur, _dirs, files in os.walk(root)
               for f in files if os.path.splitext(f)[1].lower() == target]
    return sorted(matches)[0] if matches else None


# ---- per-tool container argv builders (pure — no I/O, no docker) ------------
def recmd_argv(hives_dir, out_dir) -> list[str]:
    """gore's ``-d`` recurses the whole directory looking for hives (content-detected
    by the ``regf`` header), so pointing it at the FULL extraction root processes
    every system + per-user hive in one batch pass against its baked
    ``/batch/default.reb`` — no per-hive invocation and no ``--bn`` needed.

    Dirty-hive replay keeps full registry fidelity: gore replays each hive's
    sibling .LOG1/.LOG2 (regparser.RecoverHive) by default (no ``--nl``), writing
    the recovered copy under ``--work-dir`` — a writable tmpfs, since the rootfs
    is read-only — and falling back to the committed hive when logs are absent."""
    return container.run(
        _RECMD_IMAGE,
        ["-d", "/in", "--json", "/out", "--jsonf", "recmd_batch.json",
         "--work-dir", "/work"],
        mounts=[f"{hives_dir}:/in:ro", f"{out_dir}:/out"],
        tmpfs=("/work:rw,nosuid,nodev,size=256m,uid=2000,gid=2000",),
    )


def srum_esedump_argv(srudb_dir, out_dir) -> list[str]:
    """SRUM: no Windows ESE engine exists off-Windows,
    so the Linux-native ``goese`` (get-sybers/goese, Go on go-ese) parses
    ``SRUDB.dat`` instead — one JSONL file per SRUM provider table
    (NetworkDataUsage.jsonl, ApplicationResourceUsage.jsonl, …). byakugan's
    ``esedump_srum`` map routes the Network/Application usage tables to CAR
    (flow/message + process/create); the rest stay raw."""
    return container.run(
        _ESEDUMP_IMAGE,
        ["-f", "/in/SRUDB.dat", "--json", "/out"],
        mounts=[f"{srudb_dir}:/in:ro", f"{out_dir}:/out"],
    )


def prefetch_argv(scan_dir, out_dir) -> list[str]:
    """Prefetch: no prior parser ran off-Windows, so the
    Linux-native ``goprefetch`` (get-sybers/goprefetch, Go on go-prefetch)
    parses ``.pf`` instead. ``-d`` walks ``scan_dir`` recursively for every
    ``.pf`` (the extraction root holds only the filtered artefact set), writing
    one ``PrefetchDump_Output.jsonl``. byakugan's ``prefetch_dump`` map routes it
    to process/create."""
    return container.run(
        _PREFETCH_IMAGE,
        ["-d", "/in", "--json", "/out"],
        mounts=[f"{scan_dir}:/in:ro", f"{out_dir}:/out"],
    )


def jlecmd_argv(recent_dir, out_dir) -> list[str]:
    """gojle's ``-d`` recurses; pointing it at the whole extraction root is safe
    (that tree holds only the filtered artefact set, never the rest of the
    filesystem) and needs no per-user Recent-folder lookup. It reads the
    AutomaticDestinations jump lists (an OLE compound file) and their DestList
    stream, emitting the record shape byakugan's ``jlecmd_dest`` map consumes."""
    return container.run(
        _JLECMD_IMAGE,
        ["-d", "/in", "--json", "/out", "--jsonf", "jlecmd.json"],
        mounts=[f"{recent_dir}:/in:ro", f"{out_dir}:/out"],
    )


def lecmd_argv(recent_dir, out_dir) -> list[str]:
    """gole's ``-d`` recurses the same way gojle's does, content-detecting ``.lnk``
    by the ``0x4C`` Shell Link header (so Plaso's ``$`` -> ``_`` rename doesn't
    hide them). It emits gole's lnk-record shape as JSONL."""
    return container.run(
        _LECMD_IMAGE,
        ["-d", "/in", "--json", "/out"],
        mounts=[f"{recent_dir}:/in:ro", f"{out_dir}:/out"],
    )


def amcacheparser_argv(amcache_dir, out_dir) -> list[str]:
    """``amcache_dir`` holds ``Amcache.hve`` (+ its .LOG1/.LOG2, read from the same
    dir) — located by ``find_file(stage_dir, "Amcache.hve")``. goamcache replays
    the dirty-hive transaction logs (.LOG1/.LOG2) via regparser.RecoverHive, writing the recovered copy
    under ``--work-dir`` — a writable tmpfs, since the rootfs is read-only."""
    return container.run(
        _AMCACHEPARSER_IMAGE,
        ["-f", "/in/Amcache.hve", "--csv", "/out", "--csvf", "amcache.csv", "-i",
         "--work-dir", "/work"],
        mounts=[f"{amcache_dir}:/in:ro", f"{out_dir}:/out"],
        tmpfs=("/work:rw,nosuid,nodev,size=256m,uid=2000,gid=2000",),
    )


def appcompatcacheparser_argv(system_dir, out_dir) -> list[str]:
    """``system_dir`` holds a file literally named ``SYSTEM`` (+ its .LOG1/.LOG2
    alongside) — located by ``find_file(stage_dir, "SYSTEM")``. goappcompat
    replays the dirty-hive transaction logs (.LOG1/.LOG2) via regparser.RecoverHive, writing the
    recovered copy under ``--work-dir`` — a writable tmpfs (read-only rootfs)."""
    return container.run(
        _APPCOMPATCACHEPARSER_IMAGE,
        ["-f", "/in/SYSTEM", "--csv", "/out", "--csvf", "appcompatcache.csv",
         "--work-dir", "/work"],
        mounts=[f"{system_dir}:/in:ro", f"{out_dir}:/out"],
        tmpfs=("/work:rw,nosuid,nodev,size=256m,uid=2000,gid=2000",),
    )


def sbecmd_argv(user_dir, out_dir) -> list[str]:
    """gosbe's ``-d`` looks for hives (``regf`` header) under the given directory;
    pointed at the whole extraction root it picks up every user's
    NTUSER.DAT/UsrClass.dat. Like gore, it replays each hive's sibling .LOG1/.LOG2
    (regparser.RecoverHive) by default, writing the recovered copy under
    ``--work-dir`` (a writable tmpfs — the rootfs is read-only), matching .NET
    full dirty-hive fidelity and falling back to the committed hive when
    logs are absent."""
    return container.run(
        _SBECMD_IMAGE,
        ["-d", "/in", "--json", "/out", "--jsonf", "sbecmd.json",
         "--work-dir", "/work"],
        mounts=[f"{user_dir}:/in:ro", f"{out_dir}:/out"],
        tmpfs=("/work:rw,nosuid,nodev,size=256m,uid=2000,gid=2000",),
    )


def rbcmd_argv(recyclebin_dir, out_dir) -> list[str]:
    """gorb's ``-d`` recurses looking for $I records; the whole extraction root
    is safe to hand it (only $Recycle.Bin/*/$I* was ever extracted there)."""
    return container.run(
        _RBCMD_IMAGE,
        ["-d", "/in", "--csv", "/out", "--csvf", "rbcmd.csv"],
        mounts=[f"{recyclebin_dir}:/in:ro", f"{out_dir}:/out"],
    )


def mftecmd_argv(scan_dir, out_dir) -> list[str]:
    """gomft's ``-d`` finds the $MFT by its ``FILE`` record signature anywhere
    under ``scan_dir`` — so it picks up Plaso's renamed ``_MFT`` (image_export
    maps ``$`` -> ``_``), which a literal ``$MFT`` name lookup misses. Point it at
    the whole extraction root (only the filtered artefact set lives there); a
    host with no $MFT just yields nothing."""
    return container.run(
        _MFTECMD_IMAGE,
        ["-d", "/in", "--json", "/out", "--jsonf", "mftecmd.json"],
        mounts=[f"{scan_dir}:/in:ro", f"{out_dir}:/out"],
    )


def wxtcmd_argv(activitiescache_dir, out_dir) -> list[str]:
    """TODO(#88): NOT invoked by ``process_image`` yet. gowxt's SQLite interop
    (it copies ActivitiesCache.db before opening it) needs a WRITABLE working
    area — the hardened rootfs is read-only, so gowxt takes a ``--work-dir``
    (a writable tmpfs, uid/gid 2000 to match the container's non-root user), the
    same replay/unpack pattern goamcache/goappcompat/gore/gosbe use. That solves
    the read-only-rootfs blocker; the step stays deferred only until a real
    ActivitiesCache.db run confirms the end-to-end shape (issue #88 — none of the
    lab images carried a Timeline DB to validate against). Kept as a pure,
    unit-tested argv builder so it is ready to wire in the moment one does.
    """
    return container.run(
        _WXTCMD_IMAGE,
        ["-f", "/in/ActivitiesCache.db", "--csv", "/out", "--work-dir", "/work"],
        mounts=[f"{activitiescache_dir}:/in:ro", f"{out_dir}:/out"],
        tmpfs=("/work:rw,nosuid,nodev,size=256m,uid=2000,gid=2000",),
    )


# ---- running + idempotence ---------------------------------------------------
def _nonempty(path: str) -> bool:
    try:
        return os.path.getsize(path) > 0
    except OSError:
        return False


def _has_output(dir_path: str) -> bool:
    """True if dir_path (any depth) holds at least one non-empty file."""
    if not os.path.isdir(dir_path):
        return False
    for cur, _dirs, files in os.walk(dir_path):
        for f in files:
            if _nonempty(os.path.join(cur, f)):
                return True
    return False


def _run(argv: list[str], log_path: str) -> bool:
    """One tool container invocation, appended to log_path (never our own
    stdout — that carries only the JSON summary). True on a clean exit."""
    with open(log_path, "a") as logfh:
        result = subprocess.run(argv, stdout=logfh, stderr=subprocess.STDOUT, check=False)
    return result.returncode == 0


def _run_step(argv: list[str], out_dir: str, log_path: str) -> dict:
    """Run one tool container into out_dir; report {ran, ok}. "ok" needs both
    a clean exit AND actual output — a tool that exits 0 having found nothing
    (e.g. no hives matched a filter) is not silently counted as done."""
    os.makedirs(out_dir, exist_ok=True)
    try:
        os.chmod(out_dir, 0o777)
    except OSError:
        pass
    ok = _run(argv, log_path)
    return {"ran": True, "ok": ok and _has_output(out_dir)}


def process_image(image, host_out_dir, *, plaso_image=PLASO_IMAGE, force=False,
                  vss=False) -> dict:
    """Extract + run every godfir-toolz step for one disk image into ``host_out_dir``
    (== ``processed/godfir-toolz/<host>/`` — one host, one directory, per the CAR
    isolation rule in docs/CAR-Pipeline.md §2). Idempotent at the HOST level: a
    host dir that already holds any non-empty file is skipped whole unless
    ``force`` (a partial prior run is reprocessed entirely, not resumed
    file-by-file — simpler and safer than guessing which step half-completed).
    """
    host_out_dir = os.path.realpath(host_out_dir)
    result: dict = {"image": image, "host_dir": host_out_dir, "steps": {}, "skipped": False}
    if not force and _has_output(host_out_dir):
        result["skipped"] = True
        return result

    os.makedirs(host_out_dir, exist_ok=True)
    try:
        os.chmod(host_out_dir, 0o777)
    except OSError:
        pass
    log_path = os.path.join(host_out_dir, "godfir-toolz.log")

    stage_dir = os.path.join(host_out_dir, "_extracted")
    try:
        extracted = extract_artifacts(image, stage_dir, plaso_image=plaso_image, vss=vss)
    except subprocess.CalledProcessError:
        result["error"] = "image_export failed"
        return result
    result["extracted_files"] = len(extracted)

    # Directory-recursive tools: point each at the whole extraction root (it
    # holds only the filtered artefact set, so scanning it whole is both
    # correct and cheap — no per-user directory lookup needed).
    recmd_out = os.path.join(host_out_dir, "recmd")
    result["steps"]["recmd"] = _run_step(recmd_argv(stage_dir, recmd_out), recmd_out, log_path)

    jlecmd_out = os.path.join(host_out_dir, "jlecmd")
    result["steps"]["jlecmd"] = _run_step(jlecmd_argv(stage_dir, jlecmd_out), jlecmd_out, log_path)

    lecmd_out = os.path.join(host_out_dir, "lecmd")
    result["steps"]["lecmd"] = _run_step(lecmd_argv(stage_dir, lecmd_out), lecmd_out, log_path)

    sbecmd_out = os.path.join(host_out_dir, "sbecmd")
    result["steps"]["sbecmd"] = _run_step(sbecmd_argv(stage_dir, sbecmd_out), sbecmd_out, log_path)

    rbcmd_out = os.path.join(host_out_dir, "rbcmd")
    result["steps"]["rbcmd"] = _run_step(rbcmd_argv(stage_dir, rbcmd_out), rbcmd_out, log_path)

    # SRUM (goese) — only when SRUDB.dat was actually extracted.
    srudb = find_file(stage_dir, "SRUDB.dat")
    if srudb:
        srum_out = os.path.join(host_out_dir, "srum")
        result["steps"]["srum"] = _run_step(
            srum_esedump_argv(os.path.dirname(srudb), srum_out), srum_out, log_path)
    else:
        result["steps"]["srum"] = {"ran": False, "reason": "no SRUDB.dat extracted"}

    # Prefetch (goprefetch) — only when at least one .pf was extracted.
    pf = find_file_ext(stage_dir, ".pf")
    if pf:
        prefetch_out = os.path.join(host_out_dir, "prefetch")
        result["steps"]["prefetch"] = _run_step(
            prefetch_argv(stage_dir, prefetch_out), prefetch_out, log_path)
    else:
        result["steps"]["prefetch"] = {"ran": False, "reason": "no .pf extracted"}

    # Single-file tools — only when their specific file was actually extracted.
    amcache_hive = find_file(stage_dir, "Amcache.hve")
    if amcache_hive:
        amcache_out = os.path.join(host_out_dir, "amcache")
        result["steps"]["amcache"] = _run_step(
            amcacheparser_argv(os.path.dirname(amcache_hive), amcache_out), amcache_out, log_path)
    else:
        result["steps"]["amcache"] = {"ran": False, "reason": "no Amcache.hve extracted"}

    system_hive = find_file(stage_dir, "SYSTEM")
    if system_hive:
        appcompat_out = os.path.join(host_out_dir, "appcompatcache")
        result["steps"]["appcompatcache"] = _run_step(
            appcompatcacheparser_argv(os.path.dirname(system_hive), appcompat_out),
            appcompat_out, log_path)
    else:
        result["steps"]["appcompatcache"] = {"ran": False, "reason": "no SYSTEM hive extracted"}

    # MFT: gomft -d content-detects the $MFT by header (Plaso renames $MFT ->
    # _MFT, which a name lookup would miss), so run it over the extraction root
    # like the other directory-recursive tools — it yields nothing when absent.
    mftecmd_out = os.path.join(host_out_dir, "mftecmd")
    result["steps"]["mftecmd"] = _run_step(
        mftecmd_argv(stage_dir, mftecmd_out), mftecmd_out, log_path)

    # gowxt — TODO(#88): its --work-dir/tmpfs solves the read-only-rootfs
    # blocker (see wxtcmd_argv()), but the step stays deferred until a real
    # ActivitiesCache.db confirms the end-to-end shape (no lab image carried one).
    result["steps"]["wxtcmd"] = {"ran": False, "reason": "deferred to #88 (needs a real ActivitiesCache.db to validate)"}

    return result


def process_source(image_src, out_dir, *, plaso_image=PLASO_IMAGE, force=False, vss=False) -> dict:
    """Process every disk image under ONE source (``image_src``: a file or a
    directory of them) into ``out_dir/<host>/``."""
    out_dir = os.path.realpath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    images = discover_images(image_src)

    summary = {
        "source": os.path.realpath(image_src),
        "out_dir": out_dir,
        "images": len(images),
        "processed": 0,
        "skipped": 0,
        # An image with none of the godfir-toolz artefact set (e.g. a non-Windows
        # image) is normal, not a failure — counted apart like evtx's "empty".
        "empty": 0,
        "failed": 0,
        "results": [],
    }
    for img in images:
        host = host_name(img)
        host_dir = os.path.join(out_dir, host)
        res = process_image(img, host_dir, plaso_image=plaso_image, force=force, vss=vss)
        res["host"] = host
        if res.get("skipped"):
            summary["skipped"] += 1
        elif res.get("error"):
            summary["failed"] += 1
        else:
            any_ok = any(s.get("ok") for s in res["steps"].values())
            if any_ok:
                summary["processed"] += 1
            elif res.get("extracted_files", 0) == 0:
                summary["empty"] += 1
            else:
                summary["failed"] += 1
        summary["results"].append(res)
    return summary


def process(input_dir, out_dir, *, vm_dir="", plaso_image=PLASO_IMAGE, force=False,
           vss=False) -> dict:
    """Process disk images under ``input_dir`` and (if given) ``vm_dir`` into
    ``out_dir/<host>/`` — the same two-source shape as ``plaso.process``.
    ``vm_dir`` is optional and tolerated when absent/empty (a VM-export folder
    holds a plain ``.vmdk``, which ``discover_images`` finds like any other
    image; it does not get plaso.py's descriptor-vs-extent disambiguation, so
    keep VM exports to a single base/snapshot descriptor per folder for now).
    """
    sources = [os.path.realpath(input_dir)]
    if vm_dir and os.path.isdir(vm_dir):
        sources.append(os.path.realpath(vm_dir))

    summary = {"tool": "godfir-toolz", "out_dir": os.path.realpath(out_dir), "sources": [],
              "images": 0, "processed": 0, "skipped": 0, "empty": 0, "failed": 0}
    for src in sources:
        s = process_source(src, out_dir, plaso_image=plaso_image, force=force, vss=vss)
        summary["sources"].append(s)
        for k in ("images", "processed", "skipped", "empty", "failed"):
            summary[k] += s.get(k, 0)
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="get_sybers_dxdfir.godfir_toolz",
        description="disk images -> godfir-toolz Windows-artefact parse (registry, "
                    "Amcache, AppCompatCache, jump lists/lnk, ShellBags, Recycle Bin, "
                    "MFT, SRUM), one output dir per host",
    )
    ap.add_argument("--input-dir", required=True,
                    help="disk image (E01/raw/VMDK/...) or a directory of them")
    ap.add_argument("--vm-dir", default="",
                    help="VMware VM export folders (one per VM); optional")
    ap.add_argument("--out-dir", required=True,
                    help="output dir; one sub-dir per host (image stem)")
    ap.add_argument("--plaso-image", default=PLASO_IMAGE,
                    help="container image providing image_export.py/log2timeline.py/psort.py "
                         "(default: %(default)s)")
    ap.add_argument("--vss", action="store_true",
                    help="also extract from Volume Shadow Copies")
    ap.add_argument("--force", action="store_true",
                    help="reprocess hosts that already have output")
    args = ap.parse_args(argv)

    summary = process(args.input_dir, args.out_dir, vm_dir=args.vm_dir,
                      plaso_image=args.plaso_image, force=args.force, vss=args.vss)
    json.dump(summary, sys.stdout)
    sys.stdout.write("\n")
    # Fail only when the run produced nothing AND nothing was already done — see
    # the same rationale in evtx.py/plaso.py: a source that can
    # never produce output for a given image must not flip an otherwise-complete,
    # idempotent re-run into a failure.
    return 1 if summary["failed"] and not summary["processed"] and not summary["skipped"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
