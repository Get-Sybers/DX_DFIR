import json
"""Unit tests for the pure logic of the evtx processor (no docker/EvtxECmd needed)."""
import os
import subprocess

from get_sybers_dxdfir import evtx


def test_out_names():
    j, x = evtx.out_names("/x/Security.evtx")
    assert j == "Security_EvtxECmd_Output.json"
    assert x == "Security_EvtxECmd_Output.xml"
    # case-insensitive extension
    j2, _ = evtx.out_names("/x/System.EVTX")
    assert j2 == "System_EvtxECmd_Output.json"


def test_host_group_root_is_unspecified(tmp_path):
    root = tmp_path
    (root / "Security.evtx").write_bytes(b"x")
    assert evtx.host_group(str(root / "Security.evtx"), str(root)) == "unspecified_host"


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


def test_locate_dll_at_root(tmp_path):
    (tmp_path / "EvtxECmd.dll").write_bytes(b"MZ")
    assert evtx.locate_dll(str(tmp_path)) == "EvtxECmd.dll"


def test_locate_dll_nested(tmp_path):
    nested = tmp_path / "EvtxECmd"
    nested.mkdir()
    (nested / "EvtxECmd.dll").write_bytes(b"MZ")
    assert evtx.locate_dll(str(tmp_path)) == os.path.join("EvtxECmd", "EvtxECmd.dll")


def test_locate_dll_absent(tmp_path):
    assert evtx.locate_dll(str(tmp_path)) is None


def test_locate_dll_ignores_redundant_separators(tmp_path):
    # depth is computed via os.sep splitting, so a trailing/duplicated separator in
    # the search root must not throw off the maxdepth-3 bound.
    nested = tmp_path / "EvtxECmd"
    nested.mkdir()
    (nested / "EvtxECmd.dll").write_bytes(b"MZ")
    messy_root = str(tmp_path) + os.sep + os.sep  # e.g. ".../dir//"
    assert evtx.locate_dll(messy_root) == os.path.join("EvtxECmd", "EvtxECmd.dll")


def test_locate_dll_respects_maxdepth(tmp_path):
    deep = tmp_path / "a" / "b" / "c" / "d"     # depth 4 > 3
    deep.mkdir(parents=True)
    (deep / "EvtxECmd.dll").write_bytes(b"MZ")
    assert evtx.locate_dll(str(tmp_path)) is None


def test_process_reports_missing_dll(tmp_path):
    evtx_dir = tmp_path / "in"
    evtx_dir.mkdir()
    (evtx_dir / "Security.evtx").write_bytes(b"x")
    # operator-supplied mode with no DLL under the dir -> hard error
    s = evtx.process(str(evtx_dir), str(tmp_path / "out"), str(tmp_path / "noevtxecmd"))
    assert s["evtxecmd_dll"] is None and s.get("error")
    assert s["processed"] == 0


# ---- two-mode container invocation ----------------------------------------
def test_argv_operator_mode_mounts_release():
    argv = evtx.evtxecmd_argv(
        "/raw/HOST01/Security.evtx", "/out/HOST01",
        "Security_EvtxECmd_Output.json", "Security_EvtxECmd_Output.xml",
        "mcr.microsoft.com/dotnet/runtime:9.0",
        evtxecmd_dir="/deps/evtxecmd", dll_rel="EvtxECmd.dll",
    )
    # hardened docker run + the operator release mounted read-only; the stock
    # runtime has no ENTRYPOINT so the full dotnet argv is passed
    assert argv[:3] == ["docker", "run", "--rm"]
    for flag in ("--cap-drop", "--security-opt", "--read-only", "--network"):
        assert flag in argv
    assert "/deps/evtxecmd:/evtxecmd:ro" in argv
    assert "/raw/HOST01:/input:ro" in argv and "/out/HOST01:/output" in argv
    assert argv[argv.index("dotnet") + 1] == "/evtxecmd/EvtxECmd.dll"
    assert argv[argv.index("-f") + 1] == "/input/Security.evtx"


def test_argv_bundled_mode_passes_only_flags():
    """The minimal get-sybers/evtxecmd image's ENTRYPOINT is `dotnet <dll>`, so the
    bundled invocation passes ONLY the flags (no dotnet/dll, no release mount)."""
    argv = evtx.evtxecmd_argv(
        "/raw/HOST01/Security.evtx", "/out/HOST01",
        "Security_EvtxECmd_Output.json", "Security_EvtxECmd_Output.xml",
        "get-sybers/evtxecmd:latest",
    )
    assert argv[:3] == ["docker", "run", "--rm"]
    for flag in ("--cap-drop", "--security-opt", "--read-only", "--network"):
        assert flag in argv
    assert "dotnet" not in argv
    assert not any(str(a).endswith(":/evtxecmd:ro") for a in argv)
    assert "/raw/HOST01:/input:ro" in argv and "/out/HOST01:/output" in argv
    # the image name is followed by the tool flags
    tail = argv[argv.index("get-sybers/evtxecmd:latest") + 1:]
    assert tail[:2] == ["-f", "/input/Security.evtx"]
    assert "--jsonf" in tail


def test_argv_modes_drive_the_same_tool_invocation():
    """Operator mode runs `dotnet <dll> <flags>`; bundled mode's ENTRYPOINT is
    `dotnet <dll>` and passes the same `<flags>`. The flag tail matches."""
    common = ("/raw/x/S.evtx", "/out/x", "S.json", "S.xml")
    op = evtx.evtxecmd_argv(*common, "img", evtxecmd_dir="/d", dll_rel="EvtxECmd.dll")
    bd = evtx.evtxecmd_argv(*common, "img")
    op_flags = op[op.index("-f"):]
    bd_flags = bd[bd.index("-f"):]
    assert op_flags == bd_flags
    for a in (op, bd):
        for flag in ("--cap-drop", "--security-opt", "--read-only", "--network"):
            assert flag in a


def test_has_records_bom_only_is_empty(tmp_path):
    # EvtxECmd writes a BOM-only file for a log with no events — size 3, zero records.
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


def test_process_counts_empty_log_apart_from_failed(tmp_path, monkeypatch):
    evtx_dir = tmp_path / "in"
    evtx_dir.mkdir()
    (evtx_dir / "Empty.evtx").write_bytes(b"x")

    def fake_run(evtx_file, dest_dir, json_out, xml_out, image, **kw):
        # simulate EvtxECmd on an empty log: exits 0, writes a BOM-only file, and
        # reports it OPENED the log (a records-found tally of 0)
        with open(os.path.join(dest_dir, json_out), "wb") as f:
            f.write(b"\xef\xbb\xbf")
        return subprocess.CompletedProcess(
            [], 0, stdout=b"Total event log records found: 0", stderr=b"")

    monkeypatch.setattr(evtx, "_run_evtxecmd", fake_run)
    s = evtx.process(str(evtx_dir), str(tmp_path / "out"), image="get-sybers/evtxecmd:latest")
    assert s["empty"] == 1
    assert s["failed"] == 0            # an empty log is not a failure
    assert s["processed"] == 0
    # the BOM-only artefact is dropped so it never reaches ingest
    assert not (tmp_path / "out" / "unspecified_host" / "Empty_EvtxECmd_Output.json").exists()


def test_process_counts_unreadable_log_as_failed(tmp_path, monkeypatch):
    evtx_dir = tmp_path / "in"
    evtx_dir.mkdir()
    (evtx_dir / "Locked.evtx").write_bytes(b"x")

    def fake_run(evtx_file, dest_dir, json_out, xml_out, image, **kw):
        # EvtxECmd that could not READ the input: exits 0, writes no output, and
        # prints "does not exist" — it never reports a records-found tally.
        return subprocess.CompletedProcess(
            [], 0, stdout=b"/input/Locked.evtx does not exist! Exiting", stderr=b"")

    monkeypatch.setattr(evtx, "_run_evtxecmd", fake_run)
    s = evtx.process(str(evtx_dir), str(tmp_path / "out"), image="get-sybers/evtxecmd:latest")
    assert s["failed"] == 1        # a log EvtxECmd could not read is a failure...
    assert s["empty"] == 0         # ...not a benign empty
    assert s["processed"] == 0
    assert "did not read" in s["results"][0]["error"]


def test_process_nonzero_tally_but_no_output_is_failed(tmp_path, monkeypatch):
    evtx_dir = tmp_path / "in"
    evtx_dir.mkdir()
    (evtx_dir / "Security.evtx").write_bytes(b"x")

    def fake_run(evtx_file, dest_dir, json_out, xml_out, image, **kw):
        # EvtxECmd that OPENED the log and counted records but wrote none to disk
        # (an output/write error): exits 0, reports a non-zero tally, no JSON on disk.
        return subprocess.CompletedProcess(
            [], 0, stdout=b"Total event log records found: 1,234", stderr=b"")

    monkeypatch.setattr(evtx, "_run_evtxecmd", fake_run)
    s = evtx.process(str(evtx_dir), str(tmp_path / "out"), image="get-sybers/evtxecmd:latest")
    assert s["failed"] == 1        # records found but none written is a failure...
    assert s["empty"] == 0         # ...not a benign empty
    assert s["processed"] == 0
    assert "1,234 records but wrote none" in s["results"][0]["error"]


def test_process_bundled_mode_needs_no_dll(tmp_path, monkeypatch):
    evtx_dir = tmp_path / "in"
    evtx_dir.mkdir()
    (evtx_dir / "Security.evtx").write_bytes(b"x")

    calls = {}

    def fake_run(evtx_file, dest_dir, json_out, xml_out, image, **kw):
        calls["image"] = image
        calls["kw"] = kw
        # simulate EvtxECmd writing a non-empty json
        with open(os.path.join(dest_dir, json_out), "w") as f:
            f.write('{"EventId":1}\n')

    monkeypatch.setattr(evtx, "_run_evtxecmd", fake_run)
    s = evtx.process(str(evtx_dir), str(tmp_path / "out"), image="get-sybers/evtxecmd:latest")
    assert s["bundled"] is True
    assert s.get("error") is None
    assert s["evtxecmd_dll"] == evtx.BUNDLED_DLL
    assert s["processed"] == 1
    # bundled mode passes no release dir down to the runner
    assert calls["kw"].get("evtxecmd_dir") in (None, "")
    assert calls["image"] == "get-sybers/evtxecmd:latest"


def test_extract_images_reuses_existing(tmp_path, monkeypatch):
    """An image whose stage subdir already holds .evtx is reused, not re-extracted."""
    img = tmp_path / "Host.E01"
    img.write_bytes(b"x")
    stage = tmp_path / "stage"
    # pre-seed the stage subdir (image stem) with an already-extracted log
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


def test_main_requires_a_source(capsys):
    import pytest
    with pytest.raises(SystemExit):
        evtx.main(["--out-dir", "/tmp/x"])
