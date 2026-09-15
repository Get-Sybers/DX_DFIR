"""Unit tests for the SOF-ELK delivery module (local copy + ledger idempotence)."""
import os

from get_sybers_dxdfir import sofelk


def _seed(src):
    os.makedirs(os.path.join(src, "zeek", "cap"))
    with open(os.path.join(src, "zeek", "cap", "conn.json"), "w") as fh:
        fh.write('{"id":1}\n')
    with open(os.path.join(src, "zeek", "cap", "dns.json"), "w") as fh:
        fh.write('{"q":"x"}\n')


def test_deliver_mirrors_and_is_idempotent(tmp_path):
    src = tmp_path / "sofelk"
    tgt = tmp_path / "watch"
    _seed(str(src))

    s1 = sofelk.deliver(str(src), str(tgt))
    assert s1["found"] == 2 and s1["delivered"] == 2 and s1["skipped"] == 0
    assert os.path.isfile(tgt / "zeek" / "cap" / "conn.json")      # layout preserved

    # second run: ledger skips everything (no re-delivery -> no Logstash dup)
    s2 = sofelk.deliver(str(src), str(tgt))
    assert s2["delivered"] == 0 and s2["skipped"] == 2

    # a NEW/changed file is delivered
    with open(src / "zeek" / "cap" / "http.json", "w") as fh:
        fh.write('{"h":1}\n')
    s3 = sofelk.deliver(str(src), str(tgt))
    assert s3["delivered"] == 1 and s3["skipped"] == 2

    # force re-delivers all
    s4 = sofelk.deliver(str(src), str(tgt), force=True)
    assert s4["delivered"] == 3


def test_deliver_missing_src(tmp_path):
    s = sofelk.deliver(str(tmp_path / "nope"), str(tmp_path / "t"))
    assert s.get("error") and s["delivered"] == 0


def test_discover_skips_symlinked_files(tmp_path):
    """sofelk.discover never yields a symlinked file — following one would sha1/copy
    a host file's content into the Logstash-ingested watch dir."""
    src = tmp_path / "processed"; src.mkdir()
    (src / "real.json").write_text("{}\n")
    secret = tmp_path / "secret"; secret.write_text("HOST SECRET\n")
    os.symlink(secret, src / "leak.json")
    found = sofelk.discover(str(src))
    assert [os.path.basename(f) for f in found] == ["real.json"]
