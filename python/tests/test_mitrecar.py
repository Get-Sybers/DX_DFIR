"""The mitrecar lane — DX_DFIR drives the external Byakugan engine entirely
inside the hardened get-sybers/byakugan container. This suite tests the DX_DFIR
seam: that host paths in the engine's own flags are mapped to the right
container mounts (processed evidence read-only, the car/ output read-write), that
the CAR correctness gate runs inside the container, and the CLI dispatch. The
engine's own correctness has its own 100-test suite in the engine repo."""
import json
import os
import subprocess
from unittest import mock

import pytest

from get_sybers_dxdfir import mitrecar

_IMAGE = mitrecar._IMAGE


def _capture(fn, *args):
    """Run a mapping fn with the supply-chain guard, docker exec and the
    writable-output chmod all stubbed; return (after-image argv, [mount specs])
    — i.e. exactly what the confined docker run would have executed."""
    calls = []

    def fake_run(argv, **_kw):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="{}", stderr="")

    with mock.patch("get_sybers_dxdfir.images.require"), \
            mock.patch("subprocess.run", side_effect=fake_run), \
            mock.patch("get_sybers_dxdfir.mitrecar._writable"):
        fn(*args)
    assert calls, "no docker invocation was captured"
    argv = calls[0]
    img = argv.index(_IMAGE)
    mounts = [argv[i + 1] for i, tok in enumerate(argv) if tok == "-v"]
    return argv[img + 1:], mounts


# ---- build: batch ----------------------------------------------------------
def test_batch_reads_processed_readonly_and_writes_car_readwrite(tmp_path):
    processed = tmp_path / "processed"
    processed.mkdir()
    after, mounts = _capture(mitrecar.run, ["--batch", str(processed), "--force"])
    assert after == ["--batch", "/work", "--out", "/out", "--force"]
    # inputs read-only; only the byakugan/ tree is writable (a compromised engine
    # cannot rewrite the other lanes' outputs).
    assert f"{os.path.realpath(str(processed))}:/work:ro" in mounts
    assert f"{os.path.realpath(str(processed / 'byakugan'))}:/out" in mounts


# ---- build: single source --------------------------------------------------
def test_single_source_dir_mounts_in_readonly_out_readwrite(tmp_path):
    src = tmp_path / "windows_logs" / "h1"
    src.mkdir(parents=True)
    out = tmp_path / "car" / "h1"
    after, mounts = _capture(mitrecar.run,
                             ["--in", str(src), "--out", str(out), "--host", "H1"])
    assert after == ["--in", "/in", "--out", "/out", "--host", "H1"]
    assert f"{os.path.realpath(str(src))}:/in:ro" in mounts
    assert f"{os.path.realpath(str(out))}:/out" in mounts


def test_single_source_file_mounts_its_parent(tmp_path):
    src = tmp_path / "in" / "l2t_text.jsonl"
    src.parent.mkdir(parents=True)
    src.write_text("{}\n")
    out = tmp_path / "car"
    after, mounts = _capture(mitrecar.run, ["--in", str(src), "--out", str(out)])
    assert after[:4] == ["--in", "/in/l2t_text.jsonl", "--out", "/out"]
    assert f"{os.path.realpath(str(src.parent))}:/in:ro" in mounts


# ---- timeline --------------------------------------------------------------
def test_timeline_default_output_makes_car_dir_writable(tmp_path):
    car = tmp_path / "car"
    car.mkdir()
    after, mounts = _capture(mitrecar.run_timeline, [str(car), "--host", "H1"])
    # default output is <car_dir>/timeline.jsonl, so /work must be writable (no :ro)
    assert after == ["timeline", "/work", "--host", "H1"]
    assert f"{os.path.realpath(str(car))}:/work" in mounts


def test_timeline_explicit_out_keeps_car_readonly(tmp_path):
    car = tmp_path / "car"
    car.mkdir()
    out = tmp_path / "t.jsonl"
    after, mounts = _capture(mitrecar.run_timeline,
                             [str(car), "--out", str(out), "--objects-only"])
    assert after == ["timeline", "/work", "--out", "/out/t.jsonl", "--objects-only"]
    assert f"{os.path.realpath(str(car))}:/work:ro" in mounts
    assert f"{os.path.realpath(str(tmp_path))}:/out" in mounts


# ---- verify (the CAR correctness gate, run inside the container) -----------
def test_verify_mounts_car_tree_readonly_and_runs_the_engine_gate(tmp_path):
    car = tmp_path / "byakugan"
    car.mkdir()
    seen = {}

    def fake_run(argv, **_kw):
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

    with mock.patch("get_sybers_dxdfir.images.require"), \
            mock.patch("subprocess.run", side_effect=fake_run):
        proc = mitrecar.run_verify(str(car))
    argv = seen["argv"]
    # the engine's own gate runs via the image's own /usr/bin/python3 (entrypoint
    # override) over the CAR tree mounted read-only at /work — the object model
    # stays in the engine; the stripped image has no bare `python`.
    assert "--entrypoint" in argv and argv[argv.index("--entrypoint") + 1] == "/usr/bin/python3"
    img = argv.index(_IMAGE)
    assert argv[img + 1:] == ["-m", "byakugan.verify", "/work"]
    mounts = [argv[i + 1] for i, tok in enumerate(argv) if tok == "-v"]
    assert f"{os.path.realpath(str(car))}:/work:ro" in mounts
    assert proc.returncode == 0


def test_verify_raises_when_image_absent():
    with mock.patch("get_sybers_dxdfir.images.require", side_effect=RuntimeError("absent")):
        with pytest.raises(RuntimeError):
            mitrecar.run_verify("/x")


# ---- CLI dispatch ----------------------------------------------------------
def test_main_reports_missing_image_with_the_provision_hint(capsys):
    with mock.patch("get_sybers_dxdfir.images.require",
                    side_effect=RuntimeError("refusing to run get-sybers/byakugan:latest")):
        rc = mitrecar.main(["--help"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "refusing to run" in err
    assert "build the CAR engine image" in err   # PROVISION_HINT


def test_main_timeline_word_routes_to_the_timeline_op(tmp_path):
    car = tmp_path / "car"
    car.mkdir()
    seen = {}

    def fake_run(argv, **_kw):
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout="{}", stderr="")

    with mock.patch("get_sybers_dxdfir.images.require"), \
            mock.patch("subprocess.run", side_effect=fake_run), \
            mock.patch("get_sybers_dxdfir.mitrecar._writable"):
        mitrecar.main(["timeline", str(car)])
    assert "timeline" in seen["argv"]


# ---- image-gated end-to-end (real container) -------------------------------
def _image_present() -> bool:
    return subprocess.run(["docker", "image", "inspect", _IMAGE],
                          capture_output=True).returncode == 0


@pytest.mark.skipif(not _image_present(),
                    reason="get-sybers/byakugan:latest not built (dxdfir build-docker)")
def test_end_to_end_one_source_in_the_container(tmp_path):
    # a minimal Security event -> the engine's own maps produce auth + session,
    # proving the whole containerised path (mount + baked BYAKUGAN_PARSE_BIN ->
    # materialised CAR on the host output mount) end to end.
    src = tmp_path / "Security_EvtxECmd_Output.json"
    src.write_text(json.dumps({
        "EventId": 4624, "Channel": "Security", "Computer": "HOSTA",
        "EventRecordId": 1, "TimeCreated": "2020-01-01T00:00:00Z",
        "Payload": json.dumps({"EventData": {"Data": [
            {"@Name": "TargetUserName", "#text": "alice"},
            {"@Name": "TargetLogonId", "#text": "0x111"}]}})}) + "\n")
    # present a readable evidence tree, as the host's data_store is (pytest's
    # tmp_path is 0700, so the container's uid 2000 could not otherwise traverse
    # the read-only input mount).
    os.chmod(tmp_path, 0o755)
    os.chmod(src, 0o644)
    out = tmp_path / "car"
    proc = mitrecar.run(["--in", str(src), "--out", str(out)])
    assert proc.returncode == 0, proc.stderr
    summary = json.loads(proc.stdout)
    assert summary["objects"] == {"authentication": 1, "user_session": 1}
    assert (out / "car.db").is_file()
    assert (out / "car_authentication.jsonl").is_file()
