"""Unit tests for the pure logic of the volatility processor (no docker needed)."""
import os
import sys

import pytest

from get_sybers_dxdfir import volatility as vol

# The conformance guard below shells the PIIAT-Mem CLI, so it needs the vendored
# submodule checked out — skip (don't fail the suite) when it isn't, mirroring
# the mitrecar lane's submodule gating.
_HAVE_PIIAT_MEM = os.path.isfile(
    os.path.join(vol._PIIAT_MEM_DIR, "piiat_mem", "__init__.py"))


def test_is_memory_image_extensions():
    assert vol.is_memory_image("dump.raw")
    assert vol.is_memory_image("box.MEM")
    assert vol.is_memory_image("charlie-2009-12-11.mddramimage")  # M57 corpus
    assert not vol.is_memory_image("notes.txt")
    assert not vol.is_memory_image("capture.pcap")


def test_clean_name_folds_dirs_and_spaces():
    assert vol.clean_name("lonewolf/mem dump.mem") == "lonewolf_mem_dump.mem"


def test_discover_recurses_and_sorts(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "x.raw").write_bytes(b"m")
    (tmp_path / "b.vmem").write_bytes(b"m")
    (tmp_path / "readme.txt").write_bytes(b"m")
    got = [os.path.relpath(p, tmp_path) for p in vol.discover(str(tmp_path))]
    assert got == ["a/x.raw", "b.vmem"]


def test_valid_jsonl(tmp_path):
    good = tmp_path / "good.jsonl"
    good.write_text('{"PID": 4}\n{"PID": 8}\n')
    assert vol._valid_jsonl(str(good)) is True

    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    assert vol._valid_jsonl(str(empty)) is False

    junk = tmp_path / "junk.jsonl"
    junk.write_text("not json at all\n")
    assert vol._valid_jsonl(str(junk)) is False


def test_process_no_images_is_clean(tmp_path):
    s = vol.process(str(tmp_path / "mem"), str(tmp_path / "out"), str(tmp_path / "sym"))
    assert s["images"] == 0 and s["processed"] == 0 and s["failed"] == 0
    assert s["plugins"] == len(vol.DEFAULT_PLUGINS)


def test_default_plugins_include_car_set():
    assert "windows.piiat.processes" in vol.DEFAULT_PLUGINS
    assert "windows.piiat.registry" in vol.DEFAULT_PLUGINS
    assert vol.DEFAULT_PLUGINS[0] == "banners.Banners"


@pytest.mark.skipif(not _HAVE_PIIAT_MEM,
                    reason="third_party/piiat-mem submodule not initialised")
def test_car_set_covers_the_tools_default_plugins():
    """Conformance guard (not runtime coupling): the CAR set is named by PIIAT-Mem's
    public plugin names, so a tool-side rename must not silently drift. Shell the
    tool's own `--list-plugins` and assert the CAR set still covers it."""
    import json
    import subprocess

    env = dict(os.environ)
    env["PYTHONPATH"] = vol._PIIAT_MEM_DIR + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    out = subprocess.run(
        [sys.executable, "-m", "piiat_mem", "--list-plugins"],
        capture_output=True, text=True, env=env, check=True)
    engine = set(json.loads(out.stdout))
    missing = engine - set(vol.DEFAULT_PLUGINS)
    assert not missing, f"CAR set no longer covers the tool's plugins: {missing}"


def test_vol_native_requires_acknowledgement(tmp_path, capsys):
    """--vol-native (unconfined host execution) is refused without --accept-unconfined."""
    mem = tmp_path / "mem"; mem.mkdir()
    argv = ["--memory-dir", str(mem), "--out-dir", str(tmp_path / "out"),
            "--symbols-dir", str(tmp_path / "sym"), "--vol-native", "python3"]
    rc = vol.main(argv)
    assert rc == 2
    assert "refusing --vol-native" in capsys.readouterr().err


def test_vol_native_accepted_warns_and_proceeds(tmp_path, capsys):
    """With --accept-unconfined it proceeds (no images.require); no images => clean run."""
    mem = tmp_path / "mem"; mem.mkdir()   # empty: process short-circuits, no host tool run
    argv = ["--memory-dir", str(mem), "--out-dir", str(tmp_path / "out"),
            "--symbols-dir", str(tmp_path / "sym"),
            "--vol-native", "python3", "--accept-unconfined"]
    rc = vol.main(argv)
    assert rc == 0
    assert "WARNING: --vol-native" in capsys.readouterr().err
