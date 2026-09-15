"""Drive the standalone **Byakugan** engine — now entirely inside the hardened
``get-sybers/byakugan`` container. Byakugan is a standalone public project; the
engine is cloned + built INTO the image at the commit pinned by ``byakugan.ref``
(docker/byakugan/Dockerfile), so the DX_DFIR checkout no longer provisions or
holds an engine checkout at all — the ONLY thing this repo has is how it INVOKES
the image, which is this module.

The image's ENTRYPOINT is one binary dispatched on its first argument to the
engine's three operations (docker/byakugan/byakugan-entry.py):

    build     the pipeline (``--in``/``--out`` single-source, or ``--batch``) —
              one processed evidence SOURCE -> its own MITRE CAR database (one
              SQLite table per CAR object) + per-object ``car_<object>.jsonl``,
              the materialised CAR every sink reads (epic #86).
    timeline  the unified, time-ordered CAR timeline from a source's stores.
    car-vocab the canonical car_action vocabulary per object, as JSON — the
              verify-car gate (carcheck) reads it here instead of importing the
              engine on the analyst host, so the object model stays in the engine.

This module maps the HOST paths in the engine's own flags to container mounts —
processed evidence read-only, the car/ output read-write — exactly like the
other processing lanes (see plaso.py). Every flag is otherwise the engine's own
(see the Byakugan README); this lane only supplies the confinement.

    python -m get_sybers_dxdfir.mitrecar --batch data_store/processed
    python -m get_sybers_dxdfir.mitrecar --in <file-or-dir> --out <dir> [--host H]
    python -m get_sybers_dxdfir.mitrecar timeline <car_dir> [--out F] [--host H]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

from get_sybers_dxdfir import container, images

_IMAGE = "get-sybers/byakugan:latest"

# The ONE provisioning hint, shared by every dead-end message (carcheck imports
# it): the engine now lives in a built image, not a host checkout.
PROVISION_HINT = (
    "build the CAR engine image with: dxdfir build-docker — it clones Byakugan at "
    "the byakugan.ref pin and builds get-sybers/byakugan:latest.")

# Engine flags that TAKE a following value (so the argv walker consumes it).
_BUILD_VALUE_FLAGS = {"--in", "--out", "--batch", "--artefacts", "--host"}
_TIMELINE_VALUE_FLAGS = {"--out", "--host", "--after", "--before"}


def _writable(path: str) -> None:
    """Create an output dir and make it container-writable — the engine runs as
    the image's non-root uid and writes the CAR stores INTO the mounted output,
    so the dir must be world-writable (the Docker uid-mismatch reason, as in the
    other lanes; see plaso._ensure_writable)."""
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, 0o777)
    except OSError:
        pass


def _split(argv: list[str], value_flags: set[str]) -> tuple[dict, list[str], list[str]]:
    """Split a flat engine argv into ({value-flag: value}, [bare flags],
    [positionals]) so the path-bearing flags can be remapped and everything else
    passed through verbatim."""
    opts: dict[str, str] = {}
    bare: list[str] = []
    pos: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in value_flags:
            opts[tok] = argv[i + 1] if i + 1 < len(argv) else ""
            i += 2
            continue
        if tok.startswith("-"):
            bare.append(tok)
        else:
            pos.append(tok)
        i += 1
    return opts, bare, pos


def _run(argv: list[str], mounts: list[str]) -> subprocess.CompletedProcess:
    """One confined engine invocation. stdout is the engine's JSON summary
    (returned, not swallowed). Raises RuntimeError (via images.require) if the
    engine image is absent or not hardened."""
    images.require(_IMAGE)
    return subprocess.run(
        container.run(_IMAGE, argv, mounts=mounts, workdir="/tmp"),
        capture_output=True, text=True, check=False)


def run(tool_argv: list[str]) -> subprocess.CompletedProcess:
    """Materialise CAR (the engine build). Maps the host paths in the build flags
    to container mounts: processed evidence read-only, the car/ output read-write."""
    opts, bare, _pos = _split(tool_argv, _BUILD_VALUE_FLAGS)

    if "--batch" in opts:
        src = os.path.realpath(opts["--batch"])
        out = os.path.realpath(opts.get("--out") or os.path.join(src, "car"))
        _writable(out)
        # processed tree read-only (inputs are DX_DFIR's own prior outputs); only
        # the car/ tree is writable, so a compromised engine cannot rewrite the
        # other lanes' outputs.
        argv = ["--batch", "/work", "--out", "/out", *bare]
        return _run(argv, [f"{src}:/work:ro", f"{out}:/out"])

    if "--in" in opts and opts.get("--out"):
        src = os.path.realpath(opts["--in"])
        out = os.path.realpath(opts["--out"])
        _writable(out)
        mounts = [f"{out}:/out"]
        if os.path.isdir(src):
            mounts.append(f"{src}:/in:ro")
            in_arg = "/in"
        else:
            mounts.append(f"{os.path.dirname(src)}:/in:ro")
            in_arg = f"/in/{os.path.basename(src)}"
        argv = ["--in", in_arg, "--out", "/out"]
        if "--host" in opts:
            argv += ["--host", opts["--host"]]
        if "--artefacts" in opts:
            argv += ["--artefacts", opts["--artefacts"]]
        argv += bare
        return _run(argv, mounts)

    # no runnable in/out (e.g. --help, or --in without --out): pass through
    # unmapped so the engine emits its own usage error (it checks args first).
    return _run(list(tool_argv) or ["--help"], [])


def run_timeline(tool_argv: list[str]) -> subprocess.CompletedProcess:
    """Build the unified CAR timeline (the engine's timeline op) from a source's
    car.db + superset.db. Maps the car_dir (and an optional --out) to mounts."""
    opts, bare, pos = _split(tool_argv, _TIMELINE_VALUE_FLAGS)
    if not pos:
        return _run(["timeline", *tool_argv], [])  # engine errors: car_dir required

    car_dir = os.path.realpath(pos[0])
    argv = ["timeline"]
    if opts.get("--out"):
        out = os.path.realpath(opts["--out"])
        out_dir = os.path.dirname(out)
        _writable(out_dir)
        mounts = [f"{car_dir}:/work:ro", f"{out_dir}:/out"]
        argv += ["/work", "--out", f"/out/{os.path.basename(out)}"]
    else:
        # default output is <car_dir>/timeline.jsonl, so car_dir must be writable.
        _writable(car_dir)
        mounts = [f"{car_dir}:/work"]
        argv += ["/work"]
    for flag in ("--host", "--after", "--before"):
        if flag in opts:
            argv += [flag, opts[flag]]
    argv += bare  # --objects-only / --edges-only
    return _run(argv, mounts)


def car_vocab() -> dict[str, set[str]] | None:
    """The canonical car_action vocabulary per CAR object, ``{object: {actions}}``,
    read from the engine container (``byakugan car-vocab``) — RECONSTRUCTED inside
    the engine from the forked car repo it owns, exactly as the engine builds it.
    The verify-car gate reads it here rather than importing the engine, so the
    object model stays entirely in the container. Returns None when the image is
    unavailable or the dump fails (verify-car degrades gracefully)."""
    try:
        images.require(_IMAGE)
    except RuntimeError:
        return None
    proc = subprocess.run(
        container.run(_IMAGE, ["car-vocab"], workdir="/tmp"),
        capture_output=True, text=True, check=False)
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    return {obj: set(actions or []) for obj, actions in data.items()}


def main(argv: list[str] | None = None) -> int:
    """A transparent pass-through to the engine, confined in its image: every flag
    is the engine's own (see the Byakugan README) — this lane only supplies the
    container mounts.

    The one reserved word is the leading ``timeline`` subcommand, which routes to
    the engine's timeline op so a non-Python front-end can build the unified CAR
    timeline as ``python -m get_sybers_dxdfir.mitrecar timeline <car_dir> …``;
    every other invocation flows to the Byakugan build unchanged.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if args and args[0] == "timeline":
            proc = run_timeline(args[1:])
        else:
            proc = run(args)
    except RuntimeError as exc:            # image absent / not hardened
        sys.stderr.write(f"{exc}\n{PROVISION_HINT}\n")
        return 2
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
