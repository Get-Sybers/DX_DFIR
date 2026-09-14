"""Unit tests for the pure logic of the evtx (goevtx) lane (no docker needed)."""
import json
import os
import subprocess

from get_sybers_dxdfir import evtx


def test_out_names():
    j, x = evtx.out_names("/x/Security.evtx")
    assert j == "Security_EvtxECmd_Output.json"   # output name unchanged — CAR routes on it
    assert x == "Security_EvtxECmd_Output.xml"
    # case-insensitive extension
    j2, _ = evtx.out_names("/x/System.EVTX")
    assert j2 == "System_EvtxECmd_Output.json"


def test_host_group_root_is_unspecified(tmp_path):
    (tmp_path / "Security.evtx").write_bytes(b"x")
    assert evtx.host_group(str(tmp_path / "Security.evtx"), str(tmp_path)) == "unspecified_host"


def test_host_group_uses_subdir(tmp_path):
    sub = tmp_path / "HOST01"
    sub.mkdir()
    (sub / "Security.evtx").write_bytes(b"x")
    assert evtx.host_group(str(sub / "Security.evtx"), str(tmp_path)) == "HOST01"


def test_discover_recurses_and_sorts(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "System.evtx").write_bytes(b"x")
    (tmp_path / "Security.EVTX").write_bytes(b"x")
    (tmp_path / "notes.txt").write_bytes(b"x")
    got = [os.path.relpath(p, tmp_path) for p in evtx.discover(str(tmp_path))]
    assert got == ["Security.EVTX", "a/System.evtx"]


# ---- container invocation (goevtx: flags only, ENTRYPOINT is the binary) -----
def test_goevtx_argv_passes_only_flags():
    """get-sybers/goevtx's ENTRYPOINT is the /goevtx binary, so the invocation
    passes ONLY the flags — no dotnet, no DLL, no release mount."""
    argv = evtx.goevtx_argv(
        "/raw/HOST01/Security.evtx", "/out/HOST01",
        "Security_EvtxECmd_Output.json", "Security_EvtxECmd_Output.xml",
        "get-sybers/goevtx:latest",
    )
    assert argv[:3] == ["docker", "run", "--rm"]
    for flag in ("--cap-drop", "--security-opt", "--read-only", "--network"):
        assert flag in argv
    assert "dotnet" not in argv
    assert not any(str(a).endswith(":/evtxecmd:ro") for a in argv)
    assert "/raw/HOST01:/input:ro" in argv and "/out/HOST01:/output" in argv
    tail = argv[argv.index("get-sybers/goevtx:latest") + 1:]
    assert tail == ["-f", "/input/Security.evtx", "--json", "/output",
                    "--jsonf", "Security_EvtxECmd_Output.json",
                    "--xml", "/output", "--xmlf", "Security_EvtxECmd_Output.xml"]


# ---- empty-vs-records detection (unchanged) ----------------------------------
def test_has_records_bom_only_is_empty(tmp_path):
    p = tmp_path / "HardwareEvents_EvtxECmd_Output.json"
    p.write_bytes(b"\xef\xbb\xbf")
    assert p.stat().st_size == 3          # non-empty by byte size...
    assert evtx._has_records(str(p)) is False   # ...but no records


def test_has_records_true_with_a_record(tmp_path):
    p = tmp_path / "Security_EvtxECmd_Output.json"
    p.write_bytes(b"\xef\xbb\xbf" + b'{"EventId":4624}\n')
    assert evtx._has_records(str(p)) is True


def test_has_records_whitespace_only_is_empty(tmp_path):
    p = tmp_path / "x.json"
    p.write_text("\n  \n")
    assert evtx._has_records(str(p)) is False


# ---- process(): goevtx exit 0 (records / empty) vs non-zero (failed) ---------
def test_process_records_are_processed(tmp_path, monkeypatch):
    evtx_dir = tmp_path / "in"
    evtx_dir.mkdir()
    (evtx_dir / "Security.evtx").write_bytes(b"x")
    calls = {}

    def fake_run(evtx_file, dest_dir, json_out, xml_out, image):
        calls["image"] = image
        with open(os.path.join(dest_dir, json_out), "w") as f:
            f.write('{"EventId":1}\n')
        return subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(evtx, "_run_goevtx", fake_run)
    s = evtx.process(str(evtx_dir), str(tmp_path / "out"))
    assert s["processed"] == 1 and s["empty"] == 0 and s["failed"] == 0
    assert calls["image"] == "get-sybers/goevtx:latest"   # defaults to the Go image


def test_process_counts_empty_log_apart_from_failed(tmp_path, monkeypatch):
    evtx_dir = tmp_path / "in"
    evtx_dir.mkdir()
    (evtx_dir / "Empty.evtx").write_bytes(b"x")

    def fake_run(evtx_file, dest_dir, json_out, xml_out, image):
        # goevtx on a 0-event log: exits 0, writes an empty output file
        open(os.path.join(dest_dir, json_out), "wb").close()
        return subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(evtx, "_run_goevtx", fake_run)
    s = evtx.process(str(evtx_dir), str(tmp_path / "out"), image="get-sybers/goevtx:latest")
    assert s["empty"] == 1 and s["failed"] == 0 and s["processed"] == 0
    # the empty artefact is dropped so it never reaches ingest
    assert not (tmp_path / "out" / "unspecified_host" / "Empty_EvtxECmd_Output.json").exists()


def test_process_counts_unparseable_log_as_failed(tmp_path, monkeypatch):
    evtx_dir = tmp_path / "in"
    evtx_dir.mkdir()
    (evtx_dir / "Corrupt.evtx").write_bytes(b"x")

    def fake_run(evtx_file, dest_dir, json_out, xml_out, image):
        # goevtx exits non-zero (2) when it cannot parse the log
        raise subprocess.CalledProcessError(
            2, [], output=b"", stderr=b"goevtx: FAILED /input/Corrupt.evtx: bad header")

    monkeypatch.setattr(evtx, "_run_goevtx", fake_run)
    s = evtx.process(str(evtx_dir), str(tmp_path / "out"))
    assert s["failed"] == 1 and s["empty"] == 0 and s["processed"] == 0
    assert "goevtx failed" in s["results"][0]["error"]


def test_process_skips_existing_output(tmp_path, monkeypatch):
    evtx_dir = tmp_path / "in"
    evtx_dir.mkdir()
    (evtx_dir / "Security.evtx").write_bytes(b"x")
    dest = tmp_path / "out" / "unspecified_host"
    dest.mkdir(parents=True)
    (dest / "Security_EvtxECmd_Output.json").write_text('{"EventId":1}\n')  # prior real output

    def boom(*a, **k):
        raise AssertionError("goevtx must not run when a real prior output exists")

    monkeypatch.setattr(evtx, "_run_goevtx", boom)
    s = evtx.process(str(evtx_dir), str(tmp_path / "out"))
    assert s["skipped"] == 1 and s["processed"] == 0


def test_extract_images_reuses_existing(tmp_path, monkeypatch):
    """An image whose stage subdir already holds .evtx is reused, not re-extracted."""
    img = tmp_path / "Host.E01"
    img.write_bytes(b"x")
    stage = tmp_path / "stage"
    dest = stage / "Host"
    dest.mkdir(parents=True)
    (dest / "System.evtx").write_bytes(b"x")

    def boom(*a, **k):
        raise AssertionError("extract() must not run when logs are already staged")

    monkeypatch.setattr(evtx.imageexport, "extract", boom)
    s = evtx.extract_images(str(img), str(stage))
    assert s["images"] == 1 and s["reused"] == 1 and s["extracted"] == 0


def test_extract_images_runs_and_counts(tmp_path, monkeypatch):
    img = tmp_path / "Host.raw"
    img.write_bytes(b"x")
    stage = tmp_path / "stage"

    def fake_extract(image, out_dir, **kw):
        os.makedirs(out_dir, exist_ok=True)
        p = os.path.join(out_dir, "Security.evtx")
        open(p, "wb").write(b"x")
        return [p, os.path.join(out_dir, "ignored.txt")]

    monkeypatch.setattr(evtx.imageexport, "extract", fake_extract)
    s = evtx.extract_images(str(img), str(stage))
    assert s["extracted"] == 1 and s["reused"] == 0 and s["failed"] == 0


def test_main_requires_a_source():
    import pytest
    with pytest.raises(SystemExit):
        evtx.main(["--out-dir", "/tmp/x"])
