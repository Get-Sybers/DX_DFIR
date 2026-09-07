"""Unit tests for get_sybers_dxdfir.collection — the raw/ auto-sorter.

Classification delegates to the processors' own magic-byte detectors, so these
tests assert the delegation: content (magic) beats extension, a header-less
``.raw`` is ambiguous, and create/sort file evidence into the right lane subdirs.
No docker/ansible — pure filesystem.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from get_sybers_dxdfir import collection

# EWF/E01 header "EVF\x09\x0d\x0a\xff\x00" + fields_start + segment 1 (uint16 LE).
_EWF_MAGIC = b"\x45\x56\x46\x09\x0d\x0a\xff\x00\x01\x01\x00"
_PCAP_MAGIC = b"\xa1\xb2\xc3\xd4"


def _write(p: Path, data: bytes = b"") -> Path:
    p.write_bytes(data)
    return p


def test_classify_magic_beats_extension(tmp_path):
    # An E01 mislabelled .raw must file as a disk image by its header, not its name.
    f = _write(tmp_path / "image.raw", _EWF_MAGIC + b"padding")
    assert collection.classify(f) == ("disk_images", "magic")


def test_classify_pcap_magic_over_odd_extension(tmp_path):
    f = _write(tmp_path / "capture.dat", _PCAP_MAGIC + b"rest")
    assert collection.classify(f) == ("pcaps", "magic")


def test_classify_headerless_raw_is_ambiguous(tmp_path):
    subdir, reason = collection.classify(_write(tmp_path / "dump.raw", b"no magic here"))
    assert subdir is None
    assert reason == "ambiguous:disk_images,memory"


def test_classify_memory_extension(tmp_path):
    assert collection.classify(_write(tmp_path / "ram.mem"))[0] == "memory"


def test_classify_evtx_extension(tmp_path):
    assert collection.classify(_write(tmp_path / "Security.evtx"))[0] == "logs/winevt"


def test_classify_unknown(tmp_path):
    assert collection.classify(_write(tmp_path / "notes.txt", b"hello")) == (None, "unknown")


def test_create_makes_lane_subdirs_and_marker(tmp_path):
    root = collection.create(tmp_path, "case-a")
    assert (root / ".collection").is_file()
    for sub in collection.LANE_SUBDIRS:
        assert (root / sub).is_dir()
    assert collection.list_collections(tmp_path) == ["case-a"]
    assert collection.dropzone(tmp_path).is_dir()


def test_create_rejects_bad_name(tmp_path):
    with pytest.raises(ValueError):
        collection.create(tmp_path, "../escape")


def test_sort_routes_and_leaves_ambiguous(tmp_path):
    collection.create(tmp_path, "case-a")
    dz = collection.dropzone(tmp_path)
    _write(dz / "image.raw", _EWF_MAGIC)     # -> disk_images (magic)
    _write(dz / "capture.dat", _PCAP_MAGIC)  # -> pcaps (magic)
    _write(dz / "ram.mem")                   # -> memory (ext)
    _write(dz / "Security.evtx")             # -> logs/winevt (ext)
    _write(dz / "dump.raw", b"no magic")     # -> ambiguous, stays
    _write(dz / "notes.txt", b"x")           # -> unknown, stays
    res = collection.sort_into(tmp_path, "case-a")
    root = collection.collection_dir(tmp_path, "case-a")
    assert (root / "disk_images" / "image.raw").is_file()
    assert (root / "pcaps" / "capture.dat").is_file()
    assert (root / "memory" / "ram.mem").is_file()
    assert (root / "logs" / "winevt" / "Security.evtx").is_file()
    assert res.moved_count == 4
    assert (dz / "dump.raw").is_file() and (dz / "notes.txt").is_file()
    skipped = {n: why for n, why in res.skipped}
    assert skipped["dump.raw"].startswith("ambiguous")
    assert skipped["notes.txt"] == "unknown"


def test_sort_is_idempotent_on_second_run(tmp_path):
    collection.create(tmp_path, "case-a")
    _write(collection.dropzone(tmp_path) / "capture.dat", _PCAP_MAGIC)
    assert collection.sort_into(tmp_path, "case-a").moved_count == 1
    # nothing left to move; a re-run moves nothing and does not error
    assert collection.sort_into(tmp_path, "case-a").moved_count == 0


def test_sort_unknown_collection_raises(tmp_path):
    with pytest.raises(ValueError):
        collection.sort_into(tmp_path, "nope")


# --- registration of hand-staged (unregistered) collections ------------------
def test_unregistered_detection(tmp_path):
    root = collection.collection_dir(tmp_path, "hand")
    (root / "pcaps").mkdir(parents=True)
    _write(root / "pcaps" / "c.pcap", _PCAP_MAGIC)
    assert collection.unregistered(tmp_path) == ["hand"]
    assert collection.list_collections(tmp_path) == []
    assert not collection.is_registered(tmp_path, "hand")


def test_register_marks_and_logs(tmp_path):
    root = collection.collection_dir(tmp_path, "hand")
    (root / "pcaps").mkdir(parents=True)
    _write(root / "pcaps" / "c.pcap", _PCAP_MAGIC)
    collection.register(tmp_path, "hand")
    assert collection.is_registered(tmp_path, "hand")
    assert collection.unregistered(tmp_path) == []
    assert "registered" in [e["event"] for e in collection.read_log(tmp_path, "hand")]


def test_register_missing_collection_creates_and_registers(tmp_path):
    # register is now the unified entry point (from_path=None): it ensures the
    # collection dir exists (lane subdirs on demand) and registers it, rather
    # than raising on a not-yet-existing collection.
    collection.register(tmp_path, "nope")
    assert collection.is_registered(tmp_path, "nope")


# --- integrity: per-file SHA-1 + collection rollup ---------------------------
def test_hash_collection_is_deterministic_and_content_addressed(tmp_path):
    collection.create(tmp_path, "case")
    root = collection.collection_dir(tmp_path, "case")
    _write(root / "pcaps" / "a.pcap", b"AAA")
    _write(root / "memory" / "b.mem", b"BBB")
    per_file, roll1 = collection.hash_collection(tmp_path, "case")
    rec = {rel: s1 for rel, s1 in per_file}
    assert rec["pcaps/a.pcap"] == hashlib.sha1(b"AAA").hexdigest()
    # rollup == sha1 of the sorted per-file digests, concatenated
    assert roll1["sha1"] == hashlib.sha1(
        "".join(sorted(s1 for _r, s1 in per_file)).encode()).hexdigest()
    assert collection.hash_collection(tmp_path, "case")[1] == roll1        # deterministic
    _write(root / "memory" / "b.mem", b"CHANGED")
    assert collection.hash_collection(tmp_path, "case")[1] != roll1        # content-addressed


def test_write_manifest_persists_and_logs(tmp_path):
    collection.create(tmp_path, "case")
    root = collection.collection_dir(tmp_path, "case")
    _write(root / "pcaps" / "a.pcap", b"AAA")
    rollups, count = collection.write_manifest(tmp_path, "case")
    assert count == 1 and collection.manifest_rollup(tmp_path, "case") == rollups["sha1"]
    manifest = (root / ".collection.hashes").read_text()
    assert "pcaps/a.pcap" in manifest
    assert hashlib.sha1(b"AAA").hexdigest() in manifest        # per-file SHA-1 recorded
    assert "hashed" in [e["event"] for e in collection.read_log(tmp_path, "case")]


def test_manifest_includes_dot_evidence_excludes_control(tmp_path):
    collection.create(tmp_path, "case")
    root = collection.collection_dir(tmp_path, "case")
    _write(root / "disk_images" / ".bash_history", b"whoami\n")   # dot-prefixed EVIDENCE
    _write(root / "pcaps" / "a.pcap", b"AAA")
    collection.write_manifest(tmp_path, "case")                   # writes .collection.hashes
    files = [rel for rel, _s1 in collection.hash_collection(tmp_path, "case")[0]]
    assert "disk_images/.bash_history" in files                   # real dot-evidence IS hashed
    assert "pcaps/a.pcap" in files
    assert not any(f.startswith(".collection") for f in files)    # control files are NOT


def test_create_is_idempotent_marker_stable(tmp_path):
    root = collection.create(tmp_path, "case")
    marker = (root / ".collection").read_text()
    collection.create(tmp_path, "case")                    # a second create must not rewrite it
    assert (root / ".collection").read_text() == marker    # registered_at preserved
    assert [e["event"] for e in collection.read_log(tmp_path, "case")].count("created") == 1


def test_unregistered_detects_dot_only_evidence(tmp_path):
    root = collection.collection_dir(tmp_path, "hand")
    (root / "disk_images").mkdir(parents=True)
    _write(root / "disk_images" / ".bash_history", b"cmd")   # only dot-prefixed evidence
    assert collection.unregistered(tmp_path) == ["hand"]     # detected (was missed before)


# --- security: name validation + symlink safety -----------------------------
@pytest.mark.parametrize("bad", ["../escape", "..", ".", "/abs", "a/b", "with space", ""])
def test_collection_dir_rejects_bad_names(tmp_path, bad):
    with pytest.raises(ValueError):
        collection.collection_dir(tmp_path, bad)


def test_sort_and_hash_reject_traversal(tmp_path):
    with pytest.raises(ValueError):
        collection.sort_into(tmp_path, "../escape")
    with pytest.raises(ValueError):
        collection.hash_collection(tmp_path, "../escape")


def test_hash_absent_collection_raises(tmp_path):
    with pytest.raises(ValueError):
        collection.hash_collection(tmp_path, "nope")


def test_symlinks_not_followed_in_evidence(tmp_path):
    collection.create(tmp_path, "case")
    root = collection.collection_dir(tmp_path, "case")
    _write(root / "pcaps" / "real.pcap", _PCAP_MAGIC)
    outside = _write(tmp_path / "outside.bin", b"secret")           # a file OUTSIDE the collection
    (root / "pcaps" / "link.pcap").symlink_to(outside)             # symlink to it
    outdir = tmp_path / "outdir"; outdir.mkdir(); _write(outdir / "loot.bin", b"x")
    (root / "memory" / "linkdir").symlink_to(outdir, target_is_directory=True)
    files = [rel for rel, _s1 in collection.hash_collection(tmp_path, "case")[0]]
    assert files == ["pcaps/real.pcap"]                            # symlink + symlinked dir skipped


def test_create_on_existing_folder_logs_registered(tmp_path):
    root = collection.collection_dir(tmp_path, "hand")
    (root / "pcaps").mkdir(parents=True)
    _write(root / "pcaps" / "c.pcap", _PCAP_MAGIC)                 # hand-staged, no marker
    collection.create(tmp_path, "hand")
    events = [e["event"] for e in collection.read_log(tmp_path, "hand")]
    assert "registered" in events and "created" not in events     # registration, not creation


# --- the signatures/detection lane is wired to the sorted collection pcaps ----

def test_signatures_lane_registered_for_pcaps():
    # regression: the signatures lane was ABSENT from LANES, so `process all`
    # never handed a sorted collection's pcaps/ to suricata (it fell back to the
    # empty data_store/raw/pcaps). It must map pcaps -> dxdfir_signatures_pcap_dir.
    sig = next((ln for ln in collection.LANES if ln.name == "signatures"), None)
    assert sig is not None, "signatures lane missing from LANES"
    assert sig.subdirs == ("pcaps",)
    assert sig.input_vars == ("dxdfir_signatures_pcap_dir",)
    # listed LAST so process all runs it after the evidence lanes
    assert collection.LANES[-1].name == "signatures"


def test_lane_inputs_scopes_signatures_pcaps(tmp_path):
    collection.create(tmp_path, "case-x")
    root = collection.collection_dir(tmp_path, "case-x")
    _write(root / "pcaps" / "c.pcap", _PCAP_MAGIC + b"rest")
    rows = collection.lane_inputs(tmp_path, "case-x")
    sig = [(lane, var, str(d), n) for (lane, var, d, n) in rows if lane == "signatures"]
    assert sig == [("signatures", "dxdfir_signatures_pcap_dir",
                    str(root / "pcaps"), 1)]
