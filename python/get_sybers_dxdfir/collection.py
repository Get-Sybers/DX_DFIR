"""Evidence collections and the ``data_store/raw`` auto-sorter for the dxdfir CLI.

A *collection* is a named case folder under
``data_store/raw/collections/<name>/`` holding the same per-lane subdirs the
processing roles read from (``pcaps/``, ``logs/winevt/``, ``memory/``,
``disk_images/``, ``VM_files/``). A registered collection carries a
``.collection`` marker and a ``.collection.log`` — an append-only record of what
was created, registered, sorted, hashed and processed, so a case keeps its history.

Two ways in:

* ``dxdfir collection create`` + drop into ``data_store/raw/sort/`` +
  ``dxdfir collection sort`` — the tool files each item into the right lane
  subdir. Classification is **not** reinvented: it delegates to the processors'
  own magic-byte detectors (:func:`zeek.is_pcap`, :func:`plaso.detect_format` /
  :func:`plaso.ext_format`, :func:`volatility.is_memory_image`), so **content
  beats extension** — an E01 mislabelled ``.raw`` files as a disk image by its
  header, not its name.
* Stage the lane subdirs by hand. Such a folder is an *unregistered* collection
  (no marker); the CLI detects it and offers to register it so the run is logged
  (see :func:`unregistered` / :func:`register`).

Forensic-safe: a header-less file two lanes both claim by extension (``.raw`` is
a memory image AND a raw disk image) or that none recognise is never guessed — it
stays in the dropzone and is reported, for the operator to place by hand.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class Lane:
    """One processing lane: the ``raw/`` subdirs it reads and the Ansible
    input-dir var(s) that point there (parallel to ``subdirs``) — the hook a
    collection uses to scope ``dxdfir process`` to itself. Detection is the
    processors' job (see :func:`classify`); this only says where a lane reads."""

    name: str
    subdirs: tuple[str, ...]
    input_vars: tuple[str, ...]


# Mirrors each dxdfir_<lane> role's input-dir defaults (defaults/main.yml).
LANES: tuple[Lane, ...] = (
    Lane("zeek", ("pcaps",), ("dxdfir_zeek_pcap_dir",)),
    Lane("evtx", ("logs/winevt",), ("dxdfir_evtx_evtx_dir",)),
    Lane("volatility", ("memory",), ("dxdfir_volatility_memory_dir",)),
    Lane("plaso", ("disk_images", "VM_files"),
         ("dxdfir_plaso_input_dir", "dxdfir_plaso_vm_dir")),
    Lane("zimmerman", ("disk_images", "VM_files"),
         ("dxdfir_zimmerman_input_dir", "dxdfir_zimmerman_vm_dir")),
    # The detection lane (yara/suricata/hayabusa). Listed LAST so `process all`
    # runs it after the evidence lanes (hayabusa reads the processed evtx stage).
    # Scoped by the pcaps subdir — the input suricata replays; without this the
    # suricata sub-lane fell back to the empty data_store/raw/pcaps and produced
    # nothing on a sorted collection (hayabusa/yara use their own processed/tool
    # inputs). A collection with pcaps therefore drives the detection lane too.
    Lane("signatures", ("pcaps",), ("dxdfir_signatures_pcap_dir",)),
)

# The lane subdirs a collection materialises (order = display order).
LANE_SUBDIRS: tuple[str, ...] = ("pcaps", "logs/winevt", "memory", "disk_images", "VM_files")

# How a plaso image format (from detect_format / ext_format) maps to a raw/ subdir.
_DISK_FORMATS = ("ewf1", "ewf2", "ewf-cont", "qcow2", "aff", "raw")
_VM_FORMATS = ("vmdk", "vmdk-extent", "vhd", "vhdx")

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_COLLECTIONS_REL = ("data_store", "raw", "collections")
_DROPZONE_REL = ("data_store", "raw", "sort")
_MARKER = ".collection"
_LOG = ".collection.log"
_MANIFEST = ".collection.hashes"
# Central SQLite registry lives at data_store/raw/collections/.registry.db.
_REGISTRY = ".registry.db"


# --------------------------------------------------------------- paths / naming
def collections_root(repo: Path) -> Path:
    return repo.joinpath(*_COLLECTIONS_REL)


def dropzone(repo: Path) -> Path:
    return repo.joinpath(*_DROPZONE_REL)


def collection_dir(repo: Path, name: str) -> Path:
    """The collection's directory. Validates ``name`` at this single choke point,
    so no caller can build a path outside collections/ (no traversal, no absolute
    or ``.``/``..`` segments). Raises ValueError on a bad name."""
    if not valid_name(name):
        raise ValueError(f"invalid collection name {name!r} — use letters/digits then . _ -")
    return collections_root(repo) / name


def valid_name(name: str) -> bool:
    return name not in (".", "..") and bool(_NAME_RE.match(name))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------- registry / log
# Two backing stores: the SQLite registry (queryable, cross-collection view)
# and the per-collection .collection marker + .collection.log JSONL (forensic-
# friendly, human-readable, survive without sqlite). The DB is authoritative for
# "is this name registered"; the files are shadows written alongside every write.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS collections (
    name          TEXT PRIMARY KEY,
    target_path   TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    source        TEXT NOT NULL,
    sha1          TEXT,
    files         INTEGER,
    selected      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT NOT NULL,
    ts       TEXT NOT NULL,
    event    TEXT NOT NULL,
    detail   TEXT,
    FOREIGN KEY(name) REFERENCES collections(name) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_events_name_ts ON events(name, ts);
-- Per-file identification: what each file was classified as at intake, and its
-- change-detection SHA-1 once hashed. Primary key = (collection, relative path).
CREATE TABLE IF NOT EXISTS files (
    collection_name TEXT NOT NULL,
    path            TEXT NOT NULL,
    lane            TEXT,
    detected_by     TEXT NOT NULL,
    sha1            TEXT,
    size            INTEGER,
    added_at        TEXT NOT NULL,
    PRIMARY KEY (collection_name, path),
    FOREIGN KEY(collection_name) REFERENCES collections(name) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_files_lane ON files(collection_name, lane);
"""

# Per-process cache: repos whose existing markers we've already migrated.
_MIGRATED: set[str] = set()


def _registry_path(repo: Path) -> Path:
    return collections_root(repo) / _REGISTRY


def _db(repo: Path) -> sqlite3.Connection:
    """Open (initialise + migrate on first access) the collections registry DB."""
    collections_root(repo).mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_registry_path(repo)))
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(_SCHEMA)
    # In-place schema evolution: drop the legacy sha256 column if a DB from an
    # earlier build of this session still carries it. Safe on SQLite ≥ 3.35.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(collections)").fetchall()}
    if "sha256" in cols:
        try:
            conn.execute("ALTER TABLE collections DROP COLUMN sha256")
        except sqlite3.OperationalError:
            pass  # older SQLite: leave the column, it's ignored by all reads
    if "selected" not in cols:
        try:
            conn.execute("ALTER TABLE collections ADD COLUMN selected INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass
    _migrate_markers(repo, conn)
    return conn


def _migrate_markers(repo: Path, conn: sqlite3.Connection) -> None:
    """One-shot: import pre-DB `.collection` markers (and their JSONL logs) into
    the DB, so upgrading to the SQLite registry keeps every existing case."""
    key = str(repo.resolve())
    if key in _MIGRATED:
        return
    _MIGRATED.add(key)
    root = collections_root(repo)
    if not root.is_dir():
        return
    for p in sorted(root.iterdir()):
        if not p.is_dir() or p.name.startswith("."):
            continue
        marker = p / _MARKER
        if not marker.is_file():
            continue
        cur = conn.execute("SELECT 1 FROM collections WHERE name = ?", (p.name,))
        if cur.fetchone():
            continue
        reg_at = _now()
        try:
            for line in marker.read_text(encoding="utf-8").splitlines():
                if line.startswith("registered_at:"):
                    reg_at = line.split(":", 1)[1].strip() or reg_at
                    break
        except OSError:
            pass
        conn.execute(
            "INSERT INTO collections(name, target_path, registered_at, source) "
            "VALUES(?, ?, ?, ?)",
            (p.name, str(p.resolve()), reg_at, "migrated"))
        log_p = p / _LOG
        if log_p.is_file():
            try:
                for line in log_p.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    ts = rec.pop("ts", _now())
                    ev = rec.pop("event", "?")
                    conn.execute(
                        "INSERT INTO events(name, ts, event, detail) VALUES(?, ?, ?, ?)",
                        (p.name, ts, ev, json.dumps(rec) if rec else None))
            except OSError:
                pass
    conn.commit()


def _upsert_collection(repo: Path, name: str, *, source: str,
                       target_path: Path | None = None) -> None:
    target = str(Path(target_path or collection_dir(repo, name)).resolve())
    with _db(repo) as conn:
        conn.execute(
            "INSERT INTO collections(name, target_path, registered_at, source) "
            "VALUES(?, ?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET target_path = excluded.target_path",
            (name, target, _now(), source))


def _delete_collection_row(repo: Path, name: str) -> bool:
    with _db(repo) as conn:
        cur = conn.execute("DELETE FROM collections WHERE name = ?", (name,))
        return cur.rowcount > 0


def _log_event_db(repo: Path, name: str, event: str, **detail) -> None:
    with _db(repo) as conn:
        conn.execute(
            "INSERT INTO events(name, ts, event, detail) VALUES(?, ?, ?, ?)",
            (name, _now(), event, json.dumps(detail) if detail else None))


def _log_event_file(root: Path, event: str, **detail) -> None:
    rec = {"ts": _now(), "event": event, **detail}
    try:
        with open(root / _LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=False) + "\n")
    except OSError:
        pass


def _update_hashes_db(repo: Path, name: str, sha1: str, files: int) -> None:
    with _db(repo) as conn:
        conn.execute(
            "UPDATE collections SET sha1 = ?, files = ? WHERE name = ?",
            (sha1, files, name))


def _lane_from_relpath(rel: str) -> str | None:
    """Infer the processing lane from a path relative to the collection root.
    Returns the LANE_SUBDIRS entry the path lives under, or None if it doesn't."""
    for sub in LANE_SUBDIRS:
        if rel == sub or rel.startswith(sub + "/"):
            return sub
    return None


def _record_file(repo: Path, coll_name: str, root: Path, path: Path,
                 detected_by: str) -> None:
    """Upsert one row into the files table. Called at classification time
    (sort/promote/link) with the freshly-decided ``detected_by``; ``sha1``
    is left NULL for the hash pass to fill in. No-op when the collection
    isn't in the registry (a `--no-register` flow with unregistered target)."""
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        return
    if not is_registered(repo, coll_name):
        return
    try:
        size = path.stat().st_size
    except OSError:
        size = None
    lane = _lane_from_relpath(rel)
    with _db(repo) as conn:
        conn.execute(
            "INSERT INTO files(collection_name, path, lane, detected_by, size, added_at) "
            "VALUES(?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(collection_name, path) DO UPDATE SET "
            "  lane = excluded.lane, detected_by = excluded.detected_by, "
            "  size = excluded.size",
            (coll_name, rel, lane, detected_by, size, _now()))


def _record_file_hash(repo: Path, coll_name: str, rel: str,
                      sha1: str, size: int | None) -> None:
    """Update (or insert) a files-table row with its freshly-computed SHA-1 and
    size. Preserves any existing ``detected_by``; defaults to ``manual`` for
    files first seen at hash time (e.g. hand-staged into a lane subdir).
    No-op for unregistered collections."""
    if not is_registered(repo, coll_name):
        return
    lane = _lane_from_relpath(rel)
    with _db(repo) as conn:
        conn.execute(
            "INSERT INTO files(collection_name, path, lane, detected_by, sha1, size, added_at) "
            "VALUES(?, ?, ?, 'manual', ?, ?, ?) "
            "ON CONFLICT(collection_name, path) DO UPDATE SET "
            "  lane = excluded.lane, sha1 = excluded.sha1, size = excluded.size",
            (coll_name, rel, lane, sha1, size, _now()))


def list_files(repo: Path, name: str, *, lane: str | None = None,
               detected_by: str | None = None) -> list[dict]:
    """Every files-table row for a collection, oldest-first. Filter by lane or
    by detection method for the CLI query view."""
    q = ("SELECT path, lane, detected_by, sha1, size, added_at "
         "FROM files WHERE collection_name = ?")
    args: list = [name]
    if lane is not None:
        q += " AND lane = ?"; args.append(lane)
    if detected_by is not None:
        q += " AND detected_by = ?"; args.append(detected_by)
    q += " ORDER BY added_at, path"
    with _db(repo) as conn:
        cur = conn.execute(q, args)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def registry_rows(repo: Path) -> list[dict]:
    """Every collections-table row as a dict."""
    with _db(repo) as conn:
        cur = conn.execute(
            "SELECT name, target_path, registered_at, source, sha1, files, selected "
            "FROM collections ORDER BY name")
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def select_collection(repo: Path, name: str) -> None:
    """Mark ``name`` as the active collection; clears the active flag on every
    other row so exactly one collection can be selected at a time. Raises
    ValueError if ``name`` isn't in the registry."""
    if not is_registered(repo, name):
        raise ValueError(f"cannot select {name!r} — not registered")
    with _db(repo) as conn:
        conn.execute("UPDATE collections SET selected = 0 WHERE selected = 1")
        conn.execute("UPDATE collections SET selected = 1 WHERE name = ?", (name,))
    _log_event_db(repo, name, "selected")
    _log_event_file(collection_dir(repo, name), "selected")


def unselect_collection(repo: Path) -> str | None:
    """Clear the active flag. Returns the previously-selected name (or None)."""
    prev = get_selected(repo)
    with _db(repo) as conn:
        conn.execute("UPDATE collections SET selected = 0 WHERE selected = 1")
    if prev is not None:
        _log_event_db(repo, prev, "unselected")
        try:
            _log_event_file(collection_dir(repo, prev), "unselected")
        except ValueError:
            pass
    return prev


def get_selected(repo: Path) -> str | None:
    """Name of the currently-selected collection, or None."""
    with _db(repo) as conn:
        cur = conn.execute("SELECT name FROM collections WHERE selected = 1 LIMIT 1")
        row = cur.fetchone()
        return row[0] if row else None


def is_registered(repo: Path, name: str) -> bool:
    """True when the collection is in the SQLite registry."""
    with _db(repo) as conn:
        cur = conn.execute("SELECT 1 FROM collections WHERE name = ?", (name,))
        return cur.fetchone() is not None


def list_collections(repo: Path) -> list[str]:
    """Registered collection names, from the SQLite registry (alpha-sorted)."""
    with _db(repo) as conn:
        cur = conn.execute("SELECT name FROM collections ORDER BY name")
        return [r[0] for r in cur.fetchall()]


def _has_evidence(d: Path) -> bool:
    return bool(evidence_files(d))


def unregistered(repo: Path) -> list[str]:
    """collections/ subdirs that hold evidence but are NOT in the registry — a
    case an operator staged by hand instead of via ``collection create``."""
    root = collections_root(repo)
    if not root.is_dir():
        return []
    known = set(list_collections(repo))
    return sorted(p.name for p in root.iterdir()
                  if (p.is_dir() or p.is_symlink())
                  and not p.name.startswith(".")
                  and p.name not in known
                  and valid_name(p.name) and _has_evidence(p))


def _write_marker(root: Path, name: str) -> None:
    try:
        (root / _MARKER).write_text(
            f"name: {name}\nregistered_at: {_now()}\n", encoding="utf-8")
    except OSError:
        pass  # symlinked-to read-only target: the DB is authoritative anyway


def log_event(repo: Path, name: str, event: str, **detail) -> None:
    """Append one event to the DB (queryable) AND the collection's JSONL log
    (forensic-friendly, human-readable)."""
    root = collection_dir(repo, name)
    root.mkdir(parents=True, exist_ok=True)
    _log_event_db(repo, name, event, **detail)
    _log_event_file(root, event, **detail)


def read_log(repo: Path, name: str) -> list[dict]:
    """The collection's log events, oldest first (``[]`` if none). Prefers the
    on-disk JSONL log; falls back to the DB events table."""
    p = collection_dir(repo, name) / _LOG
    if p.is_file():
        out: list[dict] = []
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if out:
            return out
    with _db(repo) as conn:
        cur = conn.execute(
            "SELECT ts, event, detail FROM events WHERE name = ? ORDER BY ts, id",
            (name,))
        rows: list[dict] = []
        for ts, ev, detail in cur.fetchall():
            rec = {"ts": ts, "event": ev}
            if detail:
                try:
                    rec.update(json.loads(detail))
                except json.JSONDecodeError:
                    pass
            rows.append(rec)
        return rows


# ---------------------------------------------------------- integrity (SHA-1)
def _hash_file(path: Path) -> str:
    """SHA-1 hex digest of a file (single read pass). SHA-1 is the tracking
    checksum: fast, compact, sufficient for change detection — not a forensic
    cryptographic integrity guarantee."""
    h1 = hashlib.sha1()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h1.update(chunk)
    return h1.hexdigest()


def _walk_files(root: Path):
    """Regular, non-symlink files under ``root`` WITHOUT following symlinked dirs —
    a symlink loop can't hang it and a symlink can't pull in files outside the
    collection (integrity + no traversal)."""
    for dirpath, _dirs, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        for fn in filenames:
            p = base / fn
            if p.is_symlink() or not p.is_file():
                continue
            yield p


def evidence_files(root: Path) -> list[Path]:
    """Every evidence file under a collection, excluding ONLY the collection's own
    control files (.collection, .collection.log, .collection.hashes). Dot-prefixed
    EVIDENCE (.bash_history, .ssh/…) is included — it is real forensic data.
    Symlinks are skipped and symlinked directories are not followed."""
    control = {root / _MARKER, root / _LOG, root / _MANIFEST}
    return sorted(p for p in _walk_files(root) if p not in control)


def hash_collection(repo: Path, name: str) -> tuple[list[tuple[str, str]], dict[str, str]]:
    """``([(relpath, sha1)], {"sha1": rollup})``.

    Every evidence file is SHA-1'd; the collection rollup is the SHA-1 of every
    file's hex digest sorted alphabetically and concatenated — order-independent,
    changes whenever any file's content changes. Used for change detection, not
    cryptographic integrity."""
    root = collection_dir(repo, name)
    if not root.is_dir():
        raise ValueError(f"no such collection {name!r} to hash")
    per_file: list[tuple[str, str]] = []
    for p in evidence_files(root):
        per_file.append((str(p.relative_to(root)), _hash_file(p)))
    per_file.sort(key=lambda t: t[0])                    # manifest ordered by path
    rollups = {
        "sha1": hashlib.sha1(
            "".join(sorted(t[1] for t in per_file)).encode("ascii")).hexdigest(),
    }
    return per_file, rollups


def write_manifest(repo: Path, name: str) -> tuple[dict[str, str], int]:
    """(Re)compute the collection's hash manifest, persist it to
    ``.collection.hashes``, update the per-file registry rows with fresh SHA-1s
    and sizes, and log a 'hashed' event (when registered). Returns
    ``({"sha1": rollup}, file_count)``. As slow as the evidence is large."""
    root = collection_dir(repo, name)
    root.mkdir(parents=True, exist_ok=True)
    per_file, rollups = hash_collection(repo, name)
    header = (f"# DX_DFIR collection manifest\n"
              f"# collection: {name}\n"
              f"# collection_sha1: {rollups['sha1']}\n"
              f"# files: {len(per_file)}\n"
              f"# generated: {_now()}\n"
              f"# columns: sha1  path\n")
    body = "".join(f"{s1}  {rel}\n" for rel, s1 in per_file)
    (root / _MANIFEST).write_text(header + body, encoding="utf-8")
    _update_hashes_db(repo, name, rollups["sha1"], len(per_file))
    for rel, s1 in per_file:
        try:
            size = (root / rel).stat().st_size
        except OSError:
            size = None
        _record_file_hash(repo, name, rel, s1, size)
    if is_registered(repo, name):
        log_event(repo, name, "hashed", collection_sha1=rollups["sha1"],
                  files=len(per_file))
    return rollups, len(per_file)


def manifest_rollup(repo: Path, name: str) -> str | None:
    """The stored collection SHA-1 rollup from the manifest header, or None if
    never hashed. Cheap — reads the header, does not re-hash."""
    p = collection_dir(repo, name) / _MANIFEST
    if not p.is_file():
        return None
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.startswith("# collection_sha1:"):
            return line.split(":", 1)[1].strip() or None
    return None


def _create(repo: Path, name: str) -> Path:
    """Internal: create a collection folder (lane subdirs) and register it.
    Idempotent. Raises ValueError on a bad name."""
    if not valid_name(name):
        raise ValueError(
            f"invalid collection name {name!r} — use letters/digits then . _ -")
    root = collection_dir(repo, name)
    dir_existed = root.is_dir()
    had_marker = (root / _MARKER).exists()
    for sub in LANE_SUBDIRS:
        (root / sub).mkdir(parents=True, exist_ok=True)
    if not had_marker:            # write the marker (and its registered_at) ONCE — idempotent
        _write_marker(root, name)
        source = "create" if not dir_existed else "register"
        _upsert_collection(repo, name, source=source)
        log_event(repo, name, "registered" if dir_existed else "created",
                  **({"source": "create"} if dir_existed else {}))
    dropzone(repo).mkdir(parents=True, exist_ok=True)
    return root


# Kept as a backward-compat alias for any Python caller still using ``create``.
create = _create


def register(repo: Path, name: str, *,
             from_path: Path | None = None,
             source: str = "detected") -> Path:
    """Register a collection. The unified entry point:

    * ``from_path=None`` — ensures ``collections/<name>/`` exists (creates its
      lane subdirs on demand) and registers it (equivalent to the old ``create``
      / plain ``register``).
    * ``from_path=data_store/raw/sort/<name>`` — promotes the dropzone folder
      into ``collections/<name>/`` and registers it.
    * ``from_path`` is anywhere else — creates a symlink
      ``collections/<name> → <from_path>`` and registers the target as the
      collection's canonical location.

    Idempotent when the collection is already registered. Raises ValueError on
    a bad name, missing/invalid ``from_path``, or a name collision that can't
    be reused."""
    if not valid_name(name):
        raise ValueError(
            f"invalid collection name {name!r} — use letters/digits then . _ -")
    root = collection_dir(repo, name)
    if from_path is not None:
        from_path = Path(from_path).expanduser().resolve()
        dz_target = (dropzone(repo) / name).resolve() if dropzone(repo).exists() else None
        if dz_target is not None and from_path == dz_target:
            return _promote(repo, name)
        if not from_path.is_dir():
            raise ValueError(f"--from path is not an existing directory: {from_path}")
        return _link_external(repo, name, from_path)
    if root.is_dir() or root.is_symlink():
        already_in_db = is_registered(repo, name)
        if not (root / _MARKER).exists():
            _write_marker(root, name)
        if not already_in_db:
            _upsert_collection(repo, name, source=source)
            log_event(repo, name, "registered", source=source)
        dropzone(repo).mkdir(parents=True, exist_ok=True)
        return root
    return _create(repo, name)


def unregister(repo: Path, name: str) -> bool:
    """Remove the SQLite row + ``.collection`` marker so ``name`` is no longer
    tracked; the evidence and log file are left in place. Returns True when
    the collection was actually registered. Raises ValueError on a missing folder."""
    root = collection_dir(repo, name)
    if not (root.is_dir() or root.is_symlink()):
        raise ValueError(f"no such collection {name!r}")
    was_in_db = is_registered(repo, name)
    marker = root / _MARKER
    had_marker = marker.is_file()
    if not was_in_db and not had_marker:
        return False
    _log_event_file(root, "unregistered")
    _delete_collection_row(repo, name)
    if had_marker:
        marker.unlink()
    return True


def _link_external(repo: Path, name: str, target_path: Path) -> Path:
    """Internal: register a collection whose evidence lives OUTSIDE the repo
    by creating a directory symlink at ``collections/<name>``."""
    target = Path(target_path).expanduser().resolve()
    if not target.is_dir():
        raise ValueError(f"target path {target_path} is not an existing directory")
    dest = collection_dir(repo, name)   # validates name
    if dest.exists() or dest.is_symlink():
        raise ValueError(
            f"collections/{name}/ already exists — remove or rename it first")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.symlink_to(target, target_is_directory=True)
    for sub in LANE_SUBDIRS:
        (target / sub).mkdir(parents=True, exist_ok=True)
    _write_marker(target, name)
    _upsert_collection(repo, name, source="link", target_path=target)
    log_event(repo, name, "registered", source="link", target=str(target))
    for p in evidence_files(target):
        _record_file(repo, name, target, p, "manual")
    dropzone(repo).mkdir(parents=True, exist_ok=True)
    return dest


# Backward-compat alias.
link_external = _link_external


def dropzone_candidates(repo: Path) -> list[str]:
    """Top-level dirs under ``data_store/raw/sort/`` that look like candidate
    collections (valid name, hold at least one file). These are what
    ``dxdfir collection promote <name>`` turns into a real collection."""
    dz = dropzone(repo)
    if not dz.is_dir():
        return []
    out: list[str] = []
    for p in sorted(dz.iterdir()):
        if not p.is_dir() or p.name.startswith(".") or not valid_name(p.name):
            continue
        # any regular file underneath (recursive) qualifies it as non-empty
        for _f in _walk_files(p):
            out.append(p.name)
            break
    return out


def _promote(repo: Path, name: str) -> Path:
    """Internal: move ``data_store/raw/sort/<name>/`` into ``collections/<name>/``,
    register it, and auto-classify any LOOSE files at the collection root into
    their lane subdirs (existing subdirs are left as-is)."""
    dest = collection_dir(repo, name)   # validates name
    src = dropzone(repo) / name
    if not src.is_dir():
        raise ValueError(f"no dropzone folder at data_store/raw/sort/{name}/")
    if dest.exists():
        raise ValueError(
            f"collections/{name}/ already exists — cannot promote over it")
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dest))
    for sub in LANE_SUBDIRS:
        (dest / sub).mkdir(parents=True, exist_ok=True)
    _write_marker(dest, name)
    _upsert_collection(repo, name, source="promote")
    log_event(repo, name, "registered", source="promote")
    # classify + relocate only the LOOSE files at the collection root; any
    # pre-existing lane subdirs (`pcaps/`, `memory/`, …) are trusted as-is.
    control = {dest / _MARKER, dest / _LOG, dest / _MANIFEST}
    for p in sorted(dest.iterdir()):
        if p.is_dir() or p in control or p.name.startswith("."):
            continue
        subdir, detected_by = classify(p)
        if subdir:
            target = dest / subdir / p.name
            if not target.exists():
                shutil.move(str(p), str(target))
                _record_file(repo, name, dest, target, detected_by)
    # every hand-staged file already in a lane subdir counts as classified too
    for p in evidence_files(dest):
        try:
            rel = str(p.relative_to(dest))
        except ValueError:
            continue
        with _db(repo) as conn:
            cur = conn.execute(
                "SELECT 1 FROM files WHERE collection_name = ? AND path = ?",
                (name, rel))
            if cur.fetchone():
                continue
        _record_file(repo, name, dest, p, "manual")
    return dest


# Backward-compat alias.
promote = _promote


# --------------------------------------------------------------- classification
def _content_subdir(path: Path) -> str | None:
    """The lane subdir from CONTENT (magic bytes) alone — the definitive signal,
    reusing the processors' own magic checks. None when nothing matches by magic."""
    from . import plaso, zeek  # lazy import: keep `dxdfir` startup light
    p = str(path)
    try:
        with open(p, "rb") as fh:
            head4 = fh.read(4).hex()
    except OSError:
        head4 = ""
    if head4 in zeek._PCAP_MAGIC:            # zeek's authoritative pcap magic set
        return "pcaps"
    cfmt = plaso.detect_format(p)            # plaso's image magic (EWF/VMDK/VHDX/QCOW2)
    if cfmt in _DISK_FORMATS:
        return "disk_images"
    if cfmt in _VM_FORMATS:
        return "VM_files"
    return None


def _ext_subdirs(path: Path) -> set[str]:
    """Lane subdirs claiming this file by NAME/extension — the fallback used only
    when no magic matched. Reuses the processors' own extension logic."""
    from . import plaso, volatility, zeek  # lazy import
    claims: set[str] = set()
    if zeek.is_pcap(str(path)):                 # .pcap/.pcapng/.cap (magic already missed)
        claims.add("pcaps")
    efmt = plaso.ext_format(str(path))
    if efmt in _DISK_FORMATS:
        claims.add("disk_images")
    elif efmt in _VM_FORMATS:
        claims.add("VM_files")
    if volatility.is_memory_image(path.name):   # memory-dump extensions
        claims.add("memory")
    if path.name.lower().endswith(".evtx"):     # Windows event log
        claims.add("logs/winevt")
    return claims


def classify(path: Path) -> tuple[str | None, str]:
    """Where a file sorts to, magic-first via the processors' detectors.

    Returns ``(subdir, detected_by)`` where ``detected_by`` names how we
    identified it:

    * ``"magic"``    — a single lane owned it by content (definitive).
    * ``"ext"``      — no magic matched; a single lane claims it by extension.
    * ``"ambiguous:a,b"``  — several lanes claim it by extension, no magic
      to break the tie (a header-less ``.raw`` is a memory OR disk image);
      ``subdir`` is ``None``.
    * ``"unknown"``  — nothing recognises it; ``subdir`` is ``None``.

    Content beats extension, so a mislabelled image is filed by its real type.
    """
    magic = _content_subdir(path)
    if magic:
        return magic, "magic"
    claims = _ext_subdirs(path)
    if not claims:
        return None, "unknown"
    if len(claims) > 1:
        return None, "ambiguous:" + ",".join(sorted(claims))
    return next(iter(claims)), "ext"


# --------------------------------------------------------------- sort / inspect
@dataclass
class SortResult:
    moved: dict[str, list[str]] = field(default_factory=dict)      # subdir -> filenames
    skipped: list[tuple[str, str]] = field(default_factory=list)   # (filename, reason)

    @property
    def moved_count(self) -> int:
        return sum(len(v) for v in self.moved.values())


def sort_into(repo: Path, name: str, *, dry_run: bool = False) -> SortResult:
    """Classify each file directly in the dropzone and move it into the named
    collection's matching lane subdir. Works on any existing collection dir
    (registered or not); logs the move only when the collection is registered.
    Ambiguous/unknown files stay and are reported; dirs/dotfiles are ignored."""
    root = collection_dir(repo, name)
    if not root.is_dir():
        raise ValueError(
            f"no such collection {name!r} — create it first: "
            f"dxdfir collection create --name {name}")
    dz = dropzone(repo)
    dz.mkdir(parents=True, exist_ok=True)
    res = SortResult()
    for p in sorted(dz.iterdir()):
        if p.name.startswith("."):
            continue
        if p.is_dir():
            # a subfolder in the dropzone is almost certainly a hand-staged case
            # of its own; surface it so the operator can register it or flatten it
            res.skipped.append((p.name + "/", "directory — register as its own collection or move its files up"))
            continue
        subdir, detected_by = classify(p)
        if subdir is None:
            res.skipped.append((p.name, detected_by))
            continue
        dest = root / subdir / p.name
        if dest.exists():
            res.skipped.append((p.name, f"already in {subdir}/"))
            continue
        if not dry_run:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(p), str(dest))
            _record_file(repo, name, root, dest, detected_by)
        res.moved.setdefault(subdir, []).append(p.name)
    if not dry_run and res.moved_count and is_registered(repo, name):
        log_event(repo, name, "sorted", moved=res.moved_count, skipped=len(res.skipped))
    return res


def lane_inputs(repo: Path, name: str) -> list[tuple[str, str, Path, int]]:
    """For ``process all``: one ``(lane, input_var, dir, file_count)`` per lane
    input, scoped to the collection."""
    root = collection_dir(repo, name)
    out: list[tuple[str, str, Path, int]] = []
    for lane in LANES:
        for var, sub in zip(lane.input_vars, lane.subdirs):
            d = root / sub
            n = sum(1 for _ in _walk_files(d)) if d.is_dir() else 0
            out.append((lane.name, var, d, n))
    return out
