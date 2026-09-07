"""``dxdfir`` — the DX_DFIR pipeline front-end (Typer).

The three layers of epic #46 meet here: this CLI holds the user-facing verbs, the
``get_sybers.dxdfir`` Ansible collection holds the orchestration (one role per source,
one action per task), and the ``get_sybers_dxdfir`` package holds the heavy per-item
processing the roles invoke.

    dxdfir process zeek --pipeline elastic   # drive the dxdfir_zeek role
    dxdfir build-car                         # normalise every processed source into CAR
    dxdfir verify-car                        # the CAR correctness gate over the materialised CAR
    dxdfir build-docker                      # build (and hardening-verify) every dxdfir/* tool image
    dxdfir validate                          # run the check harness
    dxdfir stix export                       # detections -> STIX 2.1 sightings (+ OpenCTI push)

``process`` drives the collection with ``ansible-playbook`` (preflight → process →
verify); the role's single action calls ``python -m get_sybers_dxdfir.<source>`` for
the tight loop. The analysis backend is the Elastic-native stack
(``docker/elastic``, deployed with compose; the Elastic detection rules live as
data under ``get_sybers_dxdfir/detect/rules``); ``validate`` runs the repo's check
harness (``tests/run-checks.sh``).
"""
from __future__ import annotations

import enum
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import typer

from . import __version__
from . import collection as _collection
from .stix.cli import app as stix_app

app = typer.Typer(
    help="DX_DFIR forensic pipeline front-end (process / build-car / verify-car / validate).",
    no_args_is_help=True,
    add_completion=False,
    # Accept -h as well as --help at every level: the group and, by context
    # inheritance, each subcommand — so `dxdfir -h`, `dxdfir process -h`, etc. all work.
    context_settings={"help_option_names": ["-h", "--help"]},
)
# The STIX / OpenCTI exchange verbs live in their own sub-app (get_sybers_dxdfir.stix.cli).
app.add_typer(stix_app, name="stix")

_COLLECTION = "ansible/collections/get_sybers.dxdfir"


class Source(str, enum.Enum):
    zeek = "zeek"
    evtx = "evtx"
    volatility = "volatility"
    plaso = "plaso"
    zimmerman = "zimmerman"
    signatures = "signatures"
    all = "all"  # every evidence lane (see `dxdfir process all [<collection>]`)


class Pipeline(str, enum.Enum):
    # elastic: the processed tree the CAR lane builds from (the Elastic-native
    # path); sofelk: the retiring SOF-ELK delivery tree (processed/sofelk/).
    elastic = "elastic"
    sofelk = "sofelk"


# --------------------------------------------------------------------------- helpers
def _repo_root(explicit: Path | None) -> Path:
    """Locate the DX_DFIR repo: --repo-root, then $DFIR_REPO_ROOT, then walk up from
    cwd, then the installed package's in-repo location. Must hold the collection."""
    candidates: list[Path] = []
    if explicit:
        candidates.append(explicit)
    if os.environ.get("DFIR_REPO_ROOT"):
        candidates.append(Path(os.environ["DFIR_REPO_ROOT"]))
    cur = Path.cwd()
    candidates.extend([cur, *cur.parents])
    # get_sybers_dxdfir/cli.py -> get_sybers_dxdfir -> python -> <repo>
    candidates.append(Path(__file__).resolve().parents[2])
    for c in candidates:
        if (c / _COLLECTION).is_dir():
            return c.resolve()
    typer.secho(
        "Could not locate the DX_DFIR repo (no ansible/collections/get_sybers.dxdfir "
        "found). Pass --repo-root or set $DFIR_REPO_ROOT.",
        fg=typer.colors.RED, err=True,
    )
    raise typer.Exit(2)


def _run(cmd: list[str], *, cwd: Path | None = None, env: dict | None = None) -> None:
    """Echo and run a command; exit non-zero on failure (fail loud)."""
    typer.secho("→ " + " ".join(cmd), fg=typer.colors.BRIGHT_BLACK)
    full_env = {**os.environ, **(env or {})}
    rc = subprocess.call(cmd, cwd=str(cwd) if cwd else None, env=full_env)
    if rc != 0:
        typer.secho(f"command failed (exit {rc}): {cmd[0]}", fg=typer.colors.RED, err=True)
        raise typer.Exit(rc)


def _need(tool: str) -> None:
    if shutil.which(tool) is None:
        typer.secho(f"required tool not on PATH: {tool}", fg=typer.colors.RED, err=True)
        raise typer.Exit(127)


def _ansible_playbook() -> str:
    """Path to ansible-playbook. Prefer the one installed alongside this CLI (same
    environment as sys.executable — ansible-core is a declared dependency of
    get_sybers_dxdfir), so `dxdfir` works however it was installed (venv, pipx, system)
    without ansible-playbook needing to be on PATH; fall back to PATH otherwise."""
    cand = os.path.join(os.path.dirname(sys.executable), "ansible-playbook")
    if os.path.isfile(cand) and os.access(cand, os.X_OK):
        return cand
    found = shutil.which("ansible-playbook")
    if found:
        return found
    typer.secho(
        "ansible-playbook not found. Install the CLI with its dependencies "
        "(`pip install ./python` or `scripts/setup-environment.sh`) — ansible-core "
        "ships with it.", fg=typer.colors.RED, err=True)
    raise typer.Exit(127)


# --------------------------------------------------------------------------- commands
def _valid_or_exit(name: str) -> None:
    """Reject an invalid collection name (traversal / absolute / . ..) with a clean
    CLI error before it is ever joined into a filesystem path."""
    if not _collection.valid_name(name):
        typer.secho(f"invalid collection name {name!r} — use letters/digits then . _ -",
                    fg=typer.colors.RED, err=True)
        raise typer.Exit(2)


def _resolve_collection(repo: Path, name: str, *, no_register: bool = False) -> None:
    """Make a collection usable before it is sorted or processed. Registered -> ok.
    A hand-staged (unregistered) folder -> offer to register it (prompt when
    interactive, auto otherwise) so the run is recorded, unless --no-register.
    Absent -> error out."""
    _valid_or_exit(name)
    if _collection.is_registered(repo, name):
        return
    if name in _collection.unregistered(repo):
        if no_register:
            typer.secho(f"⚠️  '{name}' is unregistered — proceeding untracked (no log).",
                        fg=typer.colors.YELLOW)
            return
        do_register = True
        if sys.stdin.isatty():
            do_register = typer.confirm(
                f"Detected unregistered collection '{name}'. Register it to keep a "
                "processing record?", default=True)
        else:
            typer.secho(f"ℹ️  auto-registering detected collection '{name}' (non-interactive).",
                        fg=typer.colors.BRIGHT_BLACK)
        if do_register:
            _collection.register(repo, name, source="detected")
            typer.secho(f"✅ registered '{name}'.", fg=typer.colors.GREEN)
        else:
            typer.secho(f"⚠️  '{name}' left unregistered — this run won't be logged.",
                        fg=typer.colors.YELLOW)
        return
    typer.secho(f"no such collection '{name}'. Register it: "
                f"dxdfir collection register {name}", fg=typer.colors.RED, err=True)
    raise typer.Exit(2)


def _hash_and_report(repo: Path, name: str) -> None:
    """SHA-1 the collection's evidence, persist the manifest, print the rollup."""
    n = len(_collection.evidence_files(_collection.collection_dir(repo, name)))
    if n == 0:
        typer.echo("  (no evidence files to hash yet)")
        return
    typer.secho(f"🔒 hashing {n} evidence file(s) …", fg=typer.colors.BRIGHT_BLACK)
    rollups, count = _collection.write_manifest(repo, name)
    typer.secho(f"   SHA-1: {rollups['sha1']}  ({count} files → .collection.hashes)",
                fg=typer.colors.GREEN)


def _process_lane(ap: str, repo: Path, name: str, pipeline: Pipeline, force: bool,
                  extra_vars: list[str], scope_vars: list[str]) -> None:
    """Drive one lane's process role (preflight → process → verify). ``scope_vars``
    are extra ``KEY=VALUE`` input-dir overrides — how a collection narrows a lane."""
    playbook = repo / _COLLECTION / "playbooks" / f"dxdfir-process-{name}.yml"
    if not playbook.is_file():
        typer.secho(f"no playbook for source '{name}': {playbook}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    cmd = [
        ap, "-i", "localhost,", "-c", "local", str(playbook),
        "-e", f"dxdfir_{name}_pipeline={pipeline.value}",
        "-e", f"dxdfir_{name}_force={'true' if force else 'false'}",
    ]
    for kv in scope_vars:      # collection scope first, so an explicit --extra-var can still override
        cmd += ["-e", kv]
    for kv in extra_vars:
        cmd += ["-e", kv]
    # resolve the role without installing the collection
    env = {"ANSIBLE_ROLES_PATH": str(repo / _COLLECTION / "roles")}
    scoped = "  (collection-scoped)" if scope_vars else ""
    typer.secho(f"processing {name} → {pipeline.value}{scoped}", fg=typer.colors.GREEN)
    _run(cmd, cwd=repo, env=env)


@app.command()
def process(
    source: Source = typer.Argument(..., help="Evidence source to process, or 'all' for every lane."),
    collection: str = typer.Argument(
        None, help="Scope to a collection (data_store/raw/collections/<name>)."),
    pipeline: Pipeline = typer.Option(Pipeline.elastic, "--pipeline", "-p", help="Backend to target."),
    force: bool = typer.Option(False, "--force", help="Reprocess inputs that already have output."),
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
    extra_var: list[str] = typer.Option(
        None, "--extra-var", "-e", help="Extra Ansible var KEY=VALUE (repeatable)."
    ),
    no_register: bool = typer.Option(
        False, "--no-register", help="With a collection: process an unregistered one without registering/logging."),
) -> None:
    """Process one evidence source — or 'all' lanes — driving each role (preflight → process → verify).

    With a COLLECTION, each lane is scoped to that collection's subdir under
    data_store/raw/collections/<name>/. `dxdfir process all <collection>` runs
    every lane that has evidence staged in the collection.
    """
    _ap = _ansible_playbook()
    repo = _repo_root(repo_root)

    # No collection arg → fall back to the active one (dxdfir collection select).
    if not collection:
        collection = _collection.get_selected(repo)

    # A collection scopes each lane's input dir(s), and tells us which lanes have evidence.
    scope: dict[str, list[str]] = {}
    counts: dict[str, int] = {}
    if collection:
        _resolve_collection(repo, collection, no_register=no_register)
        for lane_name, var, d, n in _collection.lane_inputs(repo, collection):
            scope.setdefault(lane_name, []).append(f"{var}={d}")
            counts[lane_name] = counts.get(lane_name, 0) + n

    if source is Source.all:
        lanes = [lane.name for lane in _collection.LANES]     # evidence lanes + the detection lane (last)
        if collection:
            lanes = [ln for ln in lanes if counts.get(ln, 0) > 0]
            if not lanes:
                typer.secho(
                    f"collection '{collection}' has no evidence — drop files in "
                    f"data_store/raw/sort/ then: dxdfir collection sort {collection}",
                    fg=typer.colors.YELLOW)
                return
        typer.secho(f"process all → {', '.join(lanes)}"
                    + (f"  (collection '{collection}')" if collection else ""), bold=True)
    else:
        lanes = [source.value]

    for ln in lanes:
        _process_lane(_ap, repo, ln, pipeline, force, extra_var or [], scope.get(ln, []))
    if collection and _collection.is_registered(repo, collection):
        _collection.log_event(
            repo, collection, "processed", lanes=lanes, pipeline=pipeline.value,
            files={ln: counts.get(ln, 0) for ln in lanes},
            collection_sha1=_collection.manifest_rollup(repo, collection))


@app.command()
def validate(
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
) -> None:
    """Run the repository check harness (fronts tests/run-checks.sh)."""
    _need("bash")
    repo = _repo_root(repo_root)
    checks = repo / "tests" / "run-checks.sh"
    if not checks.is_file():
        typer.secho(f"check harness not found: {checks}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    _run(["bash", str(checks)], cwd=repo)


@app.command(name="verify-car")
def verify_car(
    car_dir: Path = typer.Option(
        None, "--car-dir", help="The materialised CAR tree (default: <repo>/data_store/processed/car)."),
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
) -> None:
    """CAR run-through: assert EXPECTED FIELD VALUES in the materialised CAR.

    The promotion gate for CAR correctness over the car_<object>.jsonl the engine
    wrote — each exercised object populated, values sane (IPs, ports, SIDs,
    car_action in the model's vocabulary), every row traceable to one artefact,
    relationship edges naming real endpoints. Run the pipeline first
    (process -> build-car).
    """
    from . import carcheck
    if car_dir is None:
        car_dir = _repo_root(repo_root) / "data_store" / "processed" / "car"
    raise typer.Exit(carcheck.main(["--car-dir", str(car_dir)]))


@app.command(name="build-car")
def build_car(
    processed_dir: str = typer.Argument(
        None, help="Processed tree to build from (default: <repo>/data_store/processed). Ignored with --in."),
    in_path: str = typer.Option(None, "--in", help="Single-source: one processed file/dir → one car.db."),
    out: str = typer.Option(None, "--out", help="Output dir (single-source: this source's car dir; batch: the car/ root)."),
    host: str = typer.Option(None, "--host", help="Single-source: fallback source_host where the map derives none."),
    artefacts: str = typer.Option(None, "--artefacts", help="Single-source: comma-separated artefact map keys (default: route by filename)."),
    rebuild: bool = typer.Option(False, "--rebuild", help="Rebuild CAR stores that already exist (e.g. after a map/coverage change)."),
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
) -> None:
    """Build the per-source CAR stores (car.db + superset.db) from processed evidence.

    Default (batch): discover every source under the processed tree and build each
    one's car.db + superset.db + car_<object>.jsonl. Single-source (--in): one
    file/dir → one car.db.

    A source whose car.db already exists is left as-is; pass --rebuild to re-derive
    it from the current maps — required after a coverage/map change, otherwise the
    existing (stale) stores keep skipping the newly-mapped events.
    """
    from . import mitrecar
    if in_path:
        argv = ["--in", in_path]
        for flag, val in (("--out", out), ("--host", host), ("--artefacts", artefacts)):
            if val:
                argv += [flag, val]
    else:
        batch = processed_dir or str(_repo_root(repo_root) / "data_store" / "processed")
        argv = ["--batch", batch]
        if out:
            argv += ["--out", out]
        if rebuild:                      # the engine's own flag for "rebuild existing"
            argv.append("--force")
    proc = mitrecar.run(argv)
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    raise typer.Exit(proc.returncode)


@app.command(name="car-timeline")
def car_timeline(
    car_dir: str = typer.Argument(..., help="A source's car directory, or a tree to aggregate."),
    out: str = typer.Option(None, "--out", help="Output path (default: <car_dir>/timeline.jsonl)."),
    host: str = typer.Option(None, help="Only events whose source_host matches."),
    after: str = typer.Option(None, help="Only events at/after this ISO timestamp."),
    before: str = typer.Option(None, help="Only events at/before this ISO timestamp."),
) -> None:
    """Build one property-rich, time-ordered CAR timeline from car.db + superset.db.

    Unions the object events (every populated CAR property + native) and the
    relationship edges (source→verb→target, confidence/method) from a source's
    stores into <car_dir>/timeline.jsonl. Point it at one source's car directory,
    or a tree to aggregate every source under it.
    """
    from . import mitrecar
    argv = [car_dir]
    for flag, val in (("--out", out), ("--host", host),
                      ("--after", after), ("--before", before)):
        if val:
            argv += [flag, val]
    proc = mitrecar.run_timeline(argv)
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    raise typer.Exit(proc.returncode)


@app.command(name="verify-images")
def verify_images() -> None:
    """Audit the hardened dxdfir/* tool-image inventory.

    Fails if any expected tool image is missing or un-hardened (no
    com.get-sybers.hardened label / not uid 2000), or if an UNEXPECTED dxdfir/*
    image is present — something added to the namespace that should not be. The
    processors also run the per-image form of this at start, so a substituted
    image never processes evidence.
    """
    from . import images
    result = images.audit()
    if result["ok"]:
        typer.secho(
            f"✅ image inventory clean — {len(result['checked'])} hardened tool "
            "images present, nothing unexpected.", fg=typer.colors.GREEN)
        return
    typer.secho("❌ image inventory violations:", fg=typer.colors.RED, err=True)
    for v in result["violations"]:
        typer.secho(f"   • {v}", fg=typer.colors.RED, err=True)
    raise typer.Exit(1)


@app.command(name="build-docker")
def build_docker(
    image: list[str] = typer.Option(
        None, "--image", "-i",
        help="Restrict the build set to this image (repeatable). Default: build every dxdfir/* tool image."),
    force: bool = typer.Option(
        False, "--force", help="Rebuild even when the image already exists (docker layer cache still applies)."),
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
    extra_var: list[str] = typer.Option(
        None, "--extra-var", "-e", help="Extra Ansible var KEY=VALUE (repeatable)."),
) -> None:
    """Build (and hardening-verify) the dxdfir/* tool images from the in-repo Dockerfiles.

    Fronts playbooks/dxdfir-build-images.yml (the dxdfir_images role): builds each
    image from its ansible-hardened Dockerfile under docker/, then asserts the
    hardening contract on the result (fixed non-root USER, com.get-sybers.hardened
    label, no apt-get/dpkg/sudo/pip/ansible; shell + python absent from the
    tool-only images). Run this once per host before first processing, and again
    after changing anything under docker/.
    """
    ap = _ansible_playbook()
    repo = _repo_root(repo_root)
    playbook = repo / _COLLECTION / "playbooks" / "dxdfir-build-images.yml"
    if not playbook.is_file():
        typer.secho(f"build-images playbook not found: {playbook}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    cmd = [ap, "-i", "localhost,", "-c", "local", str(playbook)]
    if force:
        cmd += ["-e", "dxdfir_images_force=true"]
    if image:
        # JSON so ansible parses it as a list, matching the playbook's own docs.
        cmd += ["-e", f"dxdfir_images_set={json.dumps(list(image))}"]
    for kv in extra_var or []:
        cmd += ["-e", kv]
    env = {"ANSIBLE_ROLES_PATH": str(repo / _COLLECTION / "roles")}
    scope = f"  ({', '.join(image)})" if image else ""
    typer.secho(f"building dxdfir/* tool images{scope}", fg=typer.colors.GREEN)
    _run(cmd, cwd=repo, env=env)


# Where each source reads its evidence from (relative to data_store/raw), and the
# file types that count as evidence there — mirrors the roles' input-dir defaults.
_EVIDENCE: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "zeek":         (("pcaps",),                 (".pcap", ".pcapng", ".cap")),
    "evtx":         (("logs/winevt",), (".evtx",)),
    "volatility":   (("memory",),                (".dmp", ".mem", ".lime", ".vmem", ".raw", ".dump", ".bin")),
    "plaso":        (("disk_images", "VM_files"), (".e01", ".ex01", ".dd", ".raw", ".img", ".vmdk",
                                                   ".vhd", ".vhdx", ".001", ".aff4", ".vmx", ".ova")),
    "zimmerman":    (("disk_images", "VM_files"), (".e01", ".ex01", ".dd", ".raw", ".img", ".vmdk",
                                                   ".vhd", ".vhdx", ".001", ".aff4", ".vmx", ".ova")),
}

# Top-level raw/ subdirs shown by `dxdfir list raw` (filesystem layout — no
# lane-mapping); a directory-oriented view of what the operator has on disk.
_RAW_SUBDIRS: tuple[str, ...] = (
    "pcaps", "memory", "disk_images", "VM_files", "logs", "filesystem",
    "mobile", "other_raw_data", "collections", "sort",
)

# Top-level processed/ subdirs shown by `dxdfir list processed` — mirrors the
# roles' output-dir defaults.
_PROCESSED_SUBDIRS: tuple[str, ...] = (
    "zeek", "windows_logs", "volatility", "plaso", "zimmerman",
    "linux_logs", "software_logs", "log2timeline", "csv", "json",
)


def _count_files(d: Path) -> int:
    return sum(1 for p in d.rglob("*") if p.is_file()) if d.is_dir() else 0


def _print_dir_view(root: Path, subs: tuple[str, ...], repo: Path) -> None:
    typer.secho(f"Evidence under {root.relative_to(repo)}/", bold=True)
    for sub in subs:
        d = root / sub
        count = _count_files(d)
        colour = typer.colors.GREEN if count else typer.colors.BRIGHT_BLACK
        note = "" if d.is_dir() else typer.style("  (missing)", fg=typer.colors.BRIGHT_BLACK)
        typer.echo(f"  {sub:<16} {typer.style(f'{count:>5}', fg=colour)} file(s){note}")


@app.command(name="list")
def list_sources(
    kind: str = typer.Argument(None, help="'raw' | 'processed' | 'lanes' (default: lane view over raw/)."),
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
) -> None:
    """List staged evidence.

    Views:
      • (default / 'lanes') — per-lane counts over data_store/raw/ (what
        `dxdfir process <source>` will read).
      • 'raw' — a directory view of data_store/raw/ top-level subdirs.
      • 'processed' — a directory view of data_store/processed/ top-level subdirs.
    """
    repo = _repo_root(repo_root)
    if kind == "raw":
        _print_dir_view(repo / "data_store" / "raw", _RAW_SUBDIRS, repo)
        return
    if kind == "processed":
        _print_dir_view(repo / "data_store" / "processed", _PROCESSED_SUBDIRS, repo)
        return
    if kind not in (None, "lanes"):
        typer.secho(f"unknown list view {kind!r} — use one of: lanes, raw, processed",
                    fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    raw = repo / "data_store" / "raw"
    typer.secho(f"Evidence under {raw.relative_to(repo)}/", bold=True)
    for src in Source:
        name = src.value
        if name in ("signatures", "all"):
            continue  # signatures spans the other lanes (reported below); 'all' is not a real lane
        subs, exts = _EVIDENCE[name]
        count = 0
        missing = []
        for sub in subs:
            d = raw / sub
            if d.is_dir():
                count += sum(1 for p in d.rglob("*") if p.is_file() and p.suffix.lower() in exts)
            else:
                missing.append(sub)
        colour = typer.colors.GREEN if count else typer.colors.BRIGHT_BLACK
        loc = ", ".join(subs) + "/"
        note = typer.style("  (not staged)", fg=typer.colors.BRIGHT_BLACK) if count == 0 else ""
        typer.echo(f"  {name:<13} {typer.style(f'{count:>5}', fg=colour)} file(s)  {loc}{note}")
    typer.echo(f"  {'signatures':<13} {'—':>5}          scans pcaps / files / disk images / evtx (the lanes above)")
    typer.echo("")
    typer.echo("Process one with:  dxdfir process <source>   (see  dxdfir process -h)")
    typer.echo("Other views:       dxdfir list raw   |   dxdfir list processed")


# --------------------------------------------------------------------- collections
collection_app = typer.Typer(
    help="Group raw evidence into collections and auto-sort the raw/sort dropzone.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
app.add_typer(collection_app, name="collection")


@collection_app.command("list")
def collection_list(
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
) -> None:
    """List collections (registered + dropzone candidates). The active one is starred."""
    repo = _repo_root(repo_root)
    registered = _collection.list_collections(repo)
    unreg = _collection.unregistered(repo)
    candidates = _collection.dropzone_candidates(repo)
    active = _collection.get_selected(repo)
    if not registered and not unreg and not candidates:
        typer.echo("No collections yet. Register one:  dxdfir collection register <name> [--from PATH]")
        return

    def _row(c: str, tag: str, tag_colour: str) -> None:
        counts: dict[str, int] = {}
        for lane_name, var, d, n in _collection.lane_inputs(repo, c):
            counts[lane_name] = counts.get(lane_name, 0) + n
        total = sum(counts.values())
        detail = ", ".join(f"{ln}:{counts[ln]}" for ln in counts if counts[ln]) or "empty"
        roll = _collection.manifest_rollup(repo, c)
        sha = f"  sha1:{roll[:12]}…" if roll else ""
        colour = typer.colors.GREEN if total else typer.colors.BRIGHT_BLACK
        tagged = f"  {typer.style(tag, fg=tag_colour)}" if tag else ""
        mark = typer.style("★", fg=typer.colors.YELLOW) if c == active else " "
        typer.echo(f" {mark} {c:<22} {typer.style(f'{total:>4}', fg=colour)} file(s)  [{detail}]{sha}{tagged}")

    for c in registered:
        _row(c, "", typer.colors.GREEN)
    for c in unreg:
        _row(c, "unregistered", typer.colors.YELLOW)
    for c in candidates:
        typer.echo(f"   {c:<22} {typer.style('  ?', fg=typer.colors.CYAN)}          "
                   f"{typer.style(f'dropzone candidate — dxdfir register {c}', fg=typer.colors.CYAN)}")
    hints = []
    if unreg:
        hints.append("register a detected one:  dxdfir register <name>")
    if candidates:
        hints.append("or promote a dropzone folder: dxdfir register <name>")
    if active is None and registered:
        hints.append("pick an active one:  dxdfir collection select <name>")
    for h in hints:
        typer.echo(f"\n  {h}")


@app.command("register")
def register(
    name: str = typer.Argument(..., help="Collection name — same string as the dropzone folder if you're promoting one."),
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
    do_hash: bool = typer.Option(True, "--hash/--no-hash",
                                 help="SHA-1 the evidence + write .collection.hashes."),
) -> None:
    """Register a collection (sugar for `dxdfir collection register`).

    If ``data_store/raw/sort/<NAME>/`` exists it is promoted (evidence auto-sorted
    into lane subdirs); otherwise an empty ``data_store/raw/collections/<NAME>/``
    is created. Either way, a SQLite registry row is added. For the external-dir
    symlink flavour, use ``dxdfir collection register <NAME> --from <PATH>``.
    """
    repo = _repo_root(repo_root)
    _valid_or_exit(name)
    dropzone = repo / "data_store" / "raw" / "sort" / name
    from_path = dropzone if dropzone.is_dir() else None
    try:
        _collection.register(repo, name, from_path=from_path, source="manual")
    except ValueError as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    origin = f" (promoted from data_store/raw/sort/{name}/)" if from_path else ""
    typer.secho(f"✅ registered '{name}'{origin}", fg=typer.colors.GREEN)
    if do_hash:
        _hash_and_report(repo, name)


@collection_app.command("register")
def collection_register(
    name: str = typer.Argument(
        None,
        help="Collection name (letters/digits then . _ -). "
             "Optional with --from: defaults to the basename of --from."),
    from_path: Path = typer.Option(
        None, "--from", "-f",
        help="Source: a dropzone subfolder (data_store/raw/sort/<name>) or an external directory to symlink."),
    do_hash: bool = typer.Option(True, "--hash/--no-hash",
                                 help="SHA-1 the evidence + write .collection.hashes."),
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
) -> None:
    """Register a collection (long form — `dxdfir register <name>` is the sugar).

    * no ``--from`` — ensure ``data_store/raw/collections/<name>/`` exists
      (creates lane subdirs on demand) and add the SQLite registry row.
    * ``--from data_store/raw/sort/<name>`` — promote the dropzone folder into
      ``collections/<name>/`` and register it (auto-classify loose files).
    * ``--from <external dir>`` — create a directory symlink
      ``collections/<name> → <external dir>`` and register the target.

    NAME is optional when ``--from`` is given: it defaults to the basename of the
    source directory (so ``register --from data_store/raw/sort/foo`` registers
    ``foo``).
    """
    repo = _repo_root(repo_root)
    if not name:
        if from_path is None:
            typer.secho("register: NAME is required (or pass --from PATH to infer it from the basename).",
                        fg=typer.colors.RED, err=True)
            raise typer.Exit(2)
        name = from_path.name
        typer.secho(f"ℹ️  no NAME given — using '{name}' (basename of --from).",
                    fg=typer.colors.BRIGHT_BLACK)
    _valid_or_exit(name)
    try:
        _collection.register(repo, name, from_path=from_path, source="manual")
    except ValueError as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    typer.secho(f"✅ registered '{name}'", fg=typer.colors.GREEN)
    if do_hash:
        _hash_and_report(repo, name)


@collection_app.command("unregister")
def collection_unregister(
    name: str = typer.Argument(..., help="A registered collection."),
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
) -> None:
    """Drop the SQLite row + marker (evidence and log are preserved)."""
    repo = _repo_root(repo_root)
    _valid_or_exit(name)
    try:
        removed = _collection.unregister(repo, name)
    except ValueError as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    if removed:
        typer.secho(f"✅ unregistered '{name}' — evidence + log are untouched.", fg=typer.colors.GREEN)
    else:
        typer.secho(f"ℹ️  '{name}' was not registered — nothing to do.", fg=typer.colors.YELLOW)


@collection_app.command("select")
def collection_select(
    name: str = typer.Argument(..., help="The collection to mark as active."),
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
) -> None:
    """Mark a collection as the active target for subsequent commands (`sort`, `process` …)."""
    repo = _repo_root(repo_root)
    _valid_or_exit(name)
    try:
        _collection.select_collection(repo, name)
    except ValueError as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    typer.secho(f"★ active collection is now '{name}'", fg=typer.colors.YELLOW)


@collection_app.command("unselect")
def collection_unselect(
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
) -> None:
    """Clear the active collection."""
    repo = _repo_root(repo_root)
    prev = _collection.unselect_collection(repo)
    if prev is None:
        typer.echo("no active collection was set.")
    else:
        typer.secho(f"✅ cleared active collection (was '{prev}')", fg=typer.colors.GREEN)


@collection_app.command("sort")
def collection_sort(
    name: str = typer.Argument(None, help="Target collection (defaults to the active one, or the only one, if unambiguous)."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would move; move nothing."),
    no_register: bool = typer.Option(False, "--no-register", help="Sort an unregistered collection without registering it."),
    no_hash: bool = typer.Option(False, "--no-hash", help="Skip the hash manifest refresh after sorting."),
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
) -> None:
    """Sort the data_store/raw/sort dropzone into a collection's lane subdirs by file type.

    Classification delegates to the processors' magic-byte detectors, so CONTENT
    beats extension (a mislabelled `.raw` E01 lands in disk_images/); an ambiguous
    (`.raw` = memory OR disk) or unknown file is left in the dropzone, never guessed.
    A registered collection gets its hash manifest refreshed afterwards.
    """
    repo = _repo_root(repo_root)
    known = _collection.list_collections(repo) + _collection.unregistered(repo)
    if name is None:
        active = _collection.get_selected(repo)
        if active:
            name = active
        elif len(known) == 1:
            name = known[0]
        elif not known:
            typer.secho("No collections. Register one first:  dxdfir collection register <name> [--from PATH]",
                        fg=typer.colors.RED, err=True)
            raise typer.Exit(2)
        else:
            typer.secho(f"Several collections ({', '.join(known)}) — pick one with `dxdfir collection select <name>` "
                        "or pass it explicitly.", fg=typer.colors.RED, err=True)
            raise typer.Exit(2)
    if not dry_run:
        _resolve_collection(repo, name, no_register=no_register)
    try:
        res = _collection.sort_into(repo, name, dry_run=dry_run)
    except ValueError as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    verb = "would move" if dry_run else "moved"
    if res.moved:
        typer.secho(f"✅ {verb} {res.moved_count} file(s) into collection '{name}':", fg=typer.colors.GREEN)
        for sub in sorted(res.moved):
            typer.echo(f"   {sub}/  ← {', '.join(res.moved[sub])}")
    else:
        typer.echo(f"Nothing to sort into '{name}' (dropzone: data_store/raw/sort/).")
    if res.skipped:
        typer.secho(f"⚠️  left in the dropzone ({len(res.skipped)} — place by hand):", fg=typer.colors.YELLOW)
        for fn, why in res.skipped:
            typer.echo(f"   {fn}  ({why})")
        cands = _collection.dropzone_candidates(repo)
        if cands:
            typer.secho(
                f"\n💡 dropzone subfolder(s) look like collections: {', '.join(cands)}",
                fg=typer.colors.CYAN)
            typer.echo(f"   register one with:  dxdfir collection register <name> --from data_store/raw/sort/<name>")
    if not dry_run and res.moved and not no_hash and _collection.is_registered(repo, name):
        _hash_and_report(repo, name)


# ------------------------------------------------------------------ stack (compose)
class Stack(str, enum.Enum):
    elastic = "elastic"   # docker/elastic (Elastic-native, security ON — the default)
    sofelk = "sofelk"     # docker/sof-elk (retiring)


_STACK_DIRS: dict[str, tuple[str, ...]] = {
    "elastic": ("docker", "elastic"),
    "sofelk":  ("docker", "sof-elk"),
}


def _compose_dir(repo: Path, stack: Stack) -> Path:
    d = repo.joinpath(*_STACK_DIRS[stack.value])
    if not (d / "docker-compose.yml").is_file():
        typer.secho(f"no docker-compose.yml under {d}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    return d


def _compose(repo: Path, stack: Stack, *args: str) -> None:
    """Run `docker compose -f <stack>/docker-compose.yml <args>` with cwd = the
    compose dir (so relative volume mounts + .env resolve correctly)."""
    _need("docker")
    d = _compose_dir(repo, stack)
    _run(["docker", "compose", "-f", str(d / "docker-compose.yml"), *args], cwd=d)


stack_app = typer.Typer(
    help="Bring the analysis stack up/down (docker compose around docker/elastic or docker/sof-elk).",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
app.add_typer(stack_app, name="stack")


@stack_app.command("deploy")
def stack_deploy(
    stack: Stack = typer.Option(Stack.elastic, "--stack", "-s", help="Which stack to deploy."),
    build: bool = typer.Option(True, "--build/--no-build", help="Build images before starting."),
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
) -> None:
    """Build (if needed) and start the stack in the background (`docker compose up -d`)."""
    repo = _repo_root(repo_root)
    args = ["up", "-d", "--remove-orphans"]
    if build:
        args.insert(1, "--build")
    _compose(repo, stack, *args)
    typer.secho(f"✅ {stack.value} stack deployed.", fg=typer.colors.GREEN)


@stack_app.command("destroy")
def stack_destroy(
    stack: Stack = typer.Option(Stack.elastic, "--stack", "-s", help="Which stack to destroy."),
    volumes: bool = typer.Option(False, "--volumes/--keep-volumes",
                                 help="Also remove named volumes (WIPES stack data)."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not prompt."),
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
) -> None:
    """Stop and remove the stack's containers/networks (optionally its volumes)."""
    repo = _repo_root(repo_root)
    if volumes and not yes:
        typer.confirm(
            f"Remove '{stack.value}' containers AND named volumes? "
            "This DELETES ingested data.", abort=True)
    args = ["down", "--remove-orphans"]
    if volumes:
        args.append("--volumes")
    _compose(repo, stack, *args)
    typer.secho(f"✅ {stack.value} stack destroyed.", fg=typer.colors.GREEN)


@stack_app.command("start")
def stack_start(
    stack: Stack = typer.Option(Stack.elastic, "--stack", "-s", help="Which stack to start."),
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
) -> None:
    """Start EXISTING stopped containers (`docker compose start`)."""
    _compose(_repo_root(repo_root), stack, "start")
    typer.secho(f"✅ {stack.value} stack started.", fg=typer.colors.GREEN)


@stack_app.command("stop")
def stack_stop(
    stack: Stack = typer.Option(Stack.elastic, "--stack", "-s", help="Which stack to stop."),
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
) -> None:
    """Stop containers but keep them (`docker compose stop`)."""
    _compose(_repo_root(repo_root), stack, "stop")
    typer.secho(f"✅ {stack.value} stack stopped.", fg=typer.colors.GREEN)


@stack_app.command("status")
def stack_status(
    stack: Stack = typer.Option(Stack.elastic, "--stack", "-s", help="Which stack to inspect."),
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
) -> None:
    """Show container status (`docker compose ps`)."""
    _compose(_repo_root(repo_root), stack, "ps")


# ------------------------------------------------------------------------ cleanup
def _rm_tree_contents(root: Path, *, dry_run: bool) -> tuple[int, int]:
    """Remove every child of ``root`` (files + subdirs), preserving ``.gitkeep``
    at the top level. Returns (files_removed, dirs_removed)."""
    if not root.is_dir():
        return 0, 0
    files = dirs = 0
    for child in sorted(root.iterdir()):
        if child.name == ".gitkeep":
            continue
        if child.is_symlink() or child.is_file():
            files += 1
            if not dry_run:
                child.unlink()
        elif child.is_dir():
            dirs += 1
            if not dry_run:
                shutil.rmtree(child)
    return files, dirs


cleanup_app = typer.Typer(
    help="Wipe processed evidence, CAR stores, or dxdfir/* docker images.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
app.add_typer(cleanup_app, name="cleanup")


@cleanup_app.command("processed")
def cleanup_processed(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be removed."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not prompt."),
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
) -> None:
    """Wipe everything under data_store/processed/ (all lanes + CAR)."""
    repo = _repo_root(repo_root)
    target = repo / "data_store" / "processed"
    if not target.is_dir():
        typer.echo(f"Nothing to clean — {target.relative_to(repo)}/ does not exist.")
        return
    if not dry_run and not yes:
        typer.confirm(f"Wipe everything under {target.relative_to(repo)}/?", abort=True)
    files, dirs = _rm_tree_contents(target, dry_run=dry_run)
    verb = "would remove" if dry_run else "removed"
    typer.secho(f"✅ {verb} {files} file(s) + {dirs} dir(s) under {target.relative_to(repo)}/",
                fg=typer.colors.GREEN)


@cleanup_app.command("car")
def cleanup_car(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be removed."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not prompt."),
    repo_root: Path = typer.Option(None, "--repo-root", help="DX_DFIR repo (auto-detected otherwise)."),
) -> None:
    """Wipe the materialised CAR (data_store/processed/car/*: car.db + superset.db + car_<object>.jsonl)."""
    repo = _repo_root(repo_root)
    target = repo / "data_store" / "processed" / "car"
    if not target.is_dir():
        typer.echo(f"Nothing to clean — {target.relative_to(repo)}/ does not exist.")
        return
    if not dry_run and not yes:
        typer.confirm(f"Wipe the CAR tree under {target.relative_to(repo)}/?", abort=True)
    files, dirs = _rm_tree_contents(target, dry_run=dry_run)
    verb = "would remove" if dry_run else "removed"
    typer.secho(f"✅ {verb} {files} file(s) + {dirs} dir(s) under {target.relative_to(repo)}/",
                fg=typer.colors.GREEN)


@cleanup_app.command("docker")
def cleanup_docker(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be removed."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not prompt."),
    dangling: bool = typer.Option(False, "--dangling", help="Also `docker image prune -f` dangling layers."),
    all_dfir: bool = typer.Option(False, "--all-dxdfir",
                                  help="Remove EVERY dxdfir/* image (default: only the hardened tool set)."),
) -> None:
    """Remove built dxdfir/* tool images so the next `dxdfir-build-images.yml` rebuild is clean."""
    _need("docker")
    from . import images as _images
    if all_dfir:
        targets = _images._list_dxdfir_images()
    else:
        targets = list(_images.HARDENED_IMAGES)
    # Only touch images that actually exist on the host.
    proc = subprocess.run(
        ["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"],
        capture_output=True, text=True, check=False)
    present = set(proc.stdout.splitlines())
    to_remove = [t for t in targets if t in present]
    if not to_remove and not dangling:
        typer.echo("Nothing to clean — no matching dxdfir/* images on this host.")
        return
    if to_remove:
        typer.secho(f"{'would remove' if dry_run else 'removing'} {len(to_remove)} image(s):",
                    fg=typer.colors.YELLOW)
        for img in to_remove:
            typer.echo(f"   {img}")
        if not dry_run and not yes:
            typer.confirm("Proceed?", abort=True)
        if not dry_run:
            _run(["docker", "rmi", "-f", *to_remove])
    if dangling and not dry_run:
        _run(["docker", "image", "prune", "-f"])
    typer.secho("✅ docker cleanup complete.", fg=typer.colors.GREEN)


def _version_cb(value: bool) -> None:
    if value:
        typer.echo(f"dxdfir (get_sybers_dxdfir) {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_cb, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """DX_DFIR forensic processing pipeline — process evidence, build + verify CAR, validate."""


if __name__ == "__main__":
    app()
