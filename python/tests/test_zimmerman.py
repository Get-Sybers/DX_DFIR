"""Unit tests for the pure logic of the zimmerman processor (no docker needed).

Every test here is offline: docker invocations are represented purely as argv
lists (never executed) or, in the process_image tests, monkeypatched out.
"""
import os
import subprocess

import yaml

from get_sybers_dxdfir import zimmerman as z


# ---- the YAML collection filter ---------------------------------------------
def test_build_filter_yaml_is_valid_multi_document_yaml():
    text = z.build_filter_yaml()
    docs = list(yaml.safe_load_all(text))
    assert len(docs) == len(z.ARTIFACT_GROUPS) > 0
    for doc in docs:
        assert set(doc.keys()) == {"description", "type", "path_separator", "paths"}
        assert doc["type"] == "include"
        assert doc["path_separator"] == "/"
        assert doc["paths"] and all(isinstance(p, str) for p in doc["paths"])


def _all_paths() -> list[str]:
    return [p for group in z.ARTIFACT_GROUPS for p in group["paths"]]


def test_filter_covers_amcache_and_its_transaction_logs():
    paths = _all_paths()
    assert any("Amcache" in p for p in paths)
    assert any("Amcache" in p and "LOG1" in p for p in paths)
    assert any("Amcache" in p and "LOG2" in p for p in paths)


def test_filter_covers_all_four_system_hives_and_logs():
    paths = _all_paths()
    for hive in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY"):
        assert any(p.endswith(f"config/{hive}") for p in paths), hive
        assert any(f"{hive}\\.LOG1" in p for p in paths), f"{hive} missing .LOG1"
        assert any(f"{hive}\\.LOG2" in p for p in paths), f"{hive} missing .LOG2"


def test_filter_covers_per_user_hives_and_logs():
    paths = _all_paths()
    assert any("NTUSER" in p and "LOG1" not in p and "LOG2" not in p for p in paths)
    assert any("NTUSER" in p and "LOG1" in p for p in paths)
    assert any("NTUSER" in p and "LOG2" in p for p in paths)
    assert any("UsrClass" in p for p in paths)
    assert any("UsrClass" in p and "LOG1" in p for p in paths)
    assert any("UsrClass" in p and "LOG2" in p for p in paths)


def test_filter_covers_jumplists_and_lnk():
    paths = _all_paths()
    assert any(r"\.lnk" in p for p in paths)
    assert any("AutomaticDestinations" in p for p in paths)
    assert any("CustomDestinations" in p for p in paths)


def test_filter_covers_recycle_bin_i_records():
    paths = _all_paths()
    assert any("Recycle" in p and r"\$I" in p for p in paths)


def test_filter_covers_activitiescache_and_srum_and_mft():
    paths = _all_paths()
    assert any("ActivitiesCache" in p for p in paths)
    assert any("SRUDB" in p for p in paths)
    assert any(p == r"/\$MFT" for p in paths)


def test_filter_covers_prefetch():
    """Prefetch IS extracted here now — prefetch_dump (the Linux-native PECmd
    substitute) parses the .pf; the filter must stage them."""
    paths = _all_paths()
    assert any("Prefetch" in p and ".pf" in p.lower() for p in paths)


# ---- extraction argv (image_export.py, YAML filter file — not --artifact_filters) --
def test_image_export_argv_uses_filter_file_not_artifact_filters(tmp_path):
    img = tmp_path / "Host.E01"
    img.write_bytes(b"x")
    argv = z.image_export_argv(str(img), str(tmp_path / "out"), str(tmp_path / "filter.yaml"))
    assert argv[:3] == ["docker", "run", "--rm"]
    for flag in ("--cap-drop", "--security-opt", "--read-only", "--network"):
        assert flag in argv
    assert "image_export.py" in argv
    assert "--artifact_filters" not in argv
    assert argv[argv.index("-f") + 1] == "/filter.yaml"
    assert f"{tmp_path / 'filter.yaml'}:/filter.yaml:ro" in argv
    assert f"{tmp_path}:/data:ro" in argv
    assert f"{tmp_path / 'out'}:/out" in argv
    assert argv[-1] == "/data/Host.E01"
    assert argv[argv.index("--vss_stores") + 1] == "none"


def test_image_export_argv_vss_all():
    argv = z.image_export_argv("/d/Host.raw", "/o", "/f/filter.yaml", vss=True)
    assert argv[argv.index("--vss_stores") + 1] == "all"


# ---- per-tool argv builders --------------------------------------------------
def test_recmd_argv():
    argv = z.recmd_argv("/stage", "/out/recmd")
    assert argv[:3] == ["docker", "run", "--rm"]
    assert "/stage:/in:ro" in argv and "/out/recmd:/out" in argv
    tail = argv[argv.index("get-sybers/recmd:latest") + 1:]
    assert tail == ["-d", "/in", "--bn", z._RECMD_BATCH_FILE,
                    "--json", "/out", "--jsonf", "recmd_batch.json", "--nl"]


def test_srum_esedump_argv():
    argv = z.srum_esedump_argv("/srum", "/out/srum")
    assert argv[:3] == ["docker", "run", "--rm"]
    assert "/srum:/in:ro" in argv and "/out/srum:/out" in argv
    tail = argv[argv.index("get-sybers/esedump:latest") + 1:]
    assert tail == ["-f", "/in/SRUDB.dat", "--json", "/out"]


def test_prefetch_argv():
    argv = z.prefetch_argv("/stage", "/out/prefetch")
    assert argv[:3] == ["docker", "run", "--rm"]
    assert "/stage:/in:ro" in argv and "/out/prefetch:/out" in argv
    tail = argv[argv.index("get-sybers/prefetch:latest") + 1:]
    assert tail == ["-d", "/in", "--json", "/out"]


def test_jlecmd_argv():
    argv = z.jlecmd_argv("/stage", "/out/jlecmd")
    tail = argv[argv.index("get-sybers/jlecmd:latest") + 1:]
    assert tail == ["-d", "/in", "--json", "/out", "--jsonf", "jlecmd.json"]


def test_lecmd_argv_has_no_q_flag():
    """The exact proven recipe: LECmd runs WITHOUT -q (unlike its siblings)."""
    argv = z.lecmd_argv("/stage", "/out/lecmd")
    tail = argv[argv.index("get-sybers/lecmd:latest") + 1:]
    assert tail == ["-d", "/in", "--json", "/out"]
    assert "-q" not in tail


def test_amcacheparser_argv():
    argv = z.amcacheparser_argv("/amcache", "/out/amcache")
    assert "/amcache:/in:ro" in argv
    tail = argv[argv.index("get-sybers/amcacheparser:latest") + 1:]
    assert tail == ["-f", "/in/Amcache.hve", "--csv", "/out", "--csvf", "amcache.csv", "-i"]


def test_appcompatcacheparser_argv():
    argv = z.appcompatcacheparser_argv("/sys", "/out/appcompat")
    tail = argv[argv.index("get-sybers/appcompatcacheparser:latest") + 1:]
    assert tail == ["-f", "/in/SYSTEM", "--csv", "/out", "--csvf", "appcompatcache.csv"]


def test_sbecmd_argv():
    argv = z.sbecmd_argv("/stage", "/out/sbecmd")
    tail = argv[argv.index("get-sybers/sbecmd:latest") + 1:]
    assert tail == ["-d", "/in", "--json", "/out", "--jsonf", "sbecmd.json"]


def test_rbcmd_argv():
    argv = z.rbcmd_argv("/stage", "/out/rbcmd")
    tail = argv[argv.index("get-sybers/rbcmd:latest") + 1:]
    assert tail == ["-d", "/in", "--csv", "/out", "--csvf", "rbcmd.csv"]


def test_mftecmd_argv():
    argv = z.mftecmd_argv("/mft", "/out/mftecmd")
    tail = argv[argv.index("get-sybers/mftecmd:latest") + 1:]
    assert tail == ["-f", "/in/$MFT", "--json", "/out", "--jsonf", "mftecmd.json"]


def test_wxtcmd_argv_adds_writable_opt_eztool_tmpfs():
    """Not invoked by process_image (see its docstring / #88), but the builder
    itself must produce the writable-unpack-path fix described in the recipe."""
    argv = z.wxtcmd_argv("/wxt", "/out/wxt")
    assert "--tmpfs" in argv
    assert "/opt/eztool:rw,nosuid,nodev,exec,size=256m,uid=2000,gid=2000" in argv
    tail = argv[argv.index("get-sybers/wxtcmd:latest") + 1:]
    assert tail == ["-f", "/in/ActivitiesCache.db", "--csv", "/out"]


def test_every_tool_argv_is_hardened():
    builders = [
        z.recmd_argv("/a", "/b"),
        z.srum_esedump_argv("/a", "/b"),
        z.prefetch_argv("/a", "/b"),
        z.jlecmd_argv("/a", "/b"),
        z.lecmd_argv("/a", "/b"),
        z.amcacheparser_argv("/a", "/b"),
        z.appcompatcacheparser_argv("/a", "/b"),
        z.sbecmd_argv("/a", "/b"),
        z.rbcmd_argv("/a", "/b"),
        z.mftecmd_argv("/a", "/b"),
        z.wxtcmd_argv("/a", "/b"),
    ]
    for argv in builders:
        assert argv[:3] == ["docker", "run", "--rm"]
        for flag in ("--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    "--read-only", "--network", "none"):
            assert flag in argv


# ---- discovery / naming ------------------------------------------------------
def test_discover_images_delegates_to_imageexport(tmp_path):
    (tmp_path / "Host.E01").write_bytes(b"x")
    (tmp_path / "notes.txt").write_bytes(b"x")
    assert z.discover_images(str(tmp_path)) == z.imageexport.discover_images(str(tmp_path))


def test_host_name_drops_extension_and_folds_spaces():
    assert z.host_name("/raw/disk_images/LoneWolf HostA.E01") == "LoneWolf_HostA"
    assert z.host_name("/x/Host.raw") == "Host"


def test_find_file_case_insensitive_and_deterministic(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "amcache.hve").write_bytes(b"x")
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "AMCACHE.HVE").write_bytes(b"x")
    found = z.find_file(str(tmp_path), "Amcache.hve")
    assert found == sorted([str(tmp_path / "a" / "amcache.hve"),
                            str(tmp_path / "b" / "AMCACHE.HVE")])[0]


def test_find_file_absent_is_none(tmp_path):
    assert z.find_file(str(tmp_path), "Amcache.hve") is None


# ---- process_image: idempotence + per-artefact gating (docker mocked out) ---
def test_process_image_skips_when_host_dir_has_output(tmp_path, monkeypatch):
    host_dir = tmp_path / "out" / "LoneWolf"
    host_dir.mkdir(parents=True)
    (host_dir / "recmd" ).mkdir()
    (host_dir / "recmd" / "recmd_batch.json").write_text('{"x": 1}')

    def boom(*a, **k):
        raise AssertionError("extract_artifacts must not run when the host dir already has output")

    monkeypatch.setattr(z, "extract_artifacts", boom)
    res = z.process_image("/img/LoneWolf.E01", str(host_dir))
    assert res["skipped"] is True


def test_process_image_force_reprocesses_even_with_existing_output(tmp_path, monkeypatch):
    host_dir = tmp_path / "out" / "LoneWolf"
    host_dir.mkdir(parents=True)
    (host_dir / "stale.txt").write_text("x")

    calls = {"extract": 0, "run": 0}

    def fake_extract(image, stage_dir, **kw):
        calls["extract"] += 1
        os.makedirs(stage_dir, exist_ok=True)
        return []

    def fake_run(argv, log_path):
        calls["run"] += 1
        return True

    monkeypatch.setattr(z, "extract_artifacts", fake_extract)
    monkeypatch.setattr(z, "_run", fake_run)
    res = z.process_image("/img/LoneWolf.E01", str(host_dir), force=True)
    assert res["skipped"] is False
    assert calls["extract"] == 1
    # every directory-recursive step (recmd/jlecmd/lecmd/sbecmd/rbcmd) ran
    assert calls["run"] == 5
    assert res["extracted_files"] == 0


def test_process_image_no_artefacts_extracted_is_empty_not_failed(tmp_path, monkeypatch):
    host_dir = tmp_path / "out" / "NonWindows"

    monkeypatch.setattr(z, "extract_artifacts",
                        lambda image, stage_dir, **kw: os.makedirs(stage_dir, exist_ok=True) or [])
    monkeypatch.setattr(z, "_run", lambda argv, log_path: True)   # exits clean, finds nothing
    res = z.process_image("/img/NonWindows.raw", str(host_dir))
    assert res["extracted_files"] == 0
    # nothing to find -> the single-file steps report ran=False with a reason
    assert res["steps"]["amcache"] == {"ran": False, "reason": "no Amcache.hve extracted"}
    assert res["steps"]["appcompatcache"] == {"ran": False, "reason": "no SYSTEM hive extracted"}
    assert res["steps"]["mftecmd"] == {"ran": False, "reason": "no $MFT extracted"}
    assert res["steps"]["srum"] == {"ran": False, "reason": "no SRUDB.dat extracted"}
    assert res["steps"]["prefetch"] == {"ran": False, "reason": "no .pf extracted"}


def test_process_image_gates_amcache_on_extracted_file_presence(tmp_path, monkeypatch):
    host_dir = tmp_path / "out" / "LoneWolf"
    seen_argvs = []

    def fake_extract(image, stage_dir, **kw):
        os.makedirs(os.path.join(stage_dir, "Windows", "AppCompat", "Programs"), exist_ok=True)
        p = os.path.join(stage_dir, "Windows", "AppCompat", "Programs", "Amcache.hve")
        open(p, "wb").write(b"hive")
        return [p]

    def fake_run(argv, log_path):
        seen_argvs.append(argv)
        # simulate the tool writing real output: find the "<host_dir>:/out" mount
        # and drop a file there, since a faked _run never invokes a real container.
        for mount in argv:
            if mount.endswith(":/out"):
                host_out = mount[: -len(":/out")]
                os.makedirs(host_out, exist_ok=True)
                with open(os.path.join(host_out, "result.json"), "w") as fh:
                    fh.write("{}")
        return True

    monkeypatch.setattr(z, "extract_artifacts", fake_extract)
    monkeypatch.setattr(z, "_run", fake_run)
    res = z.process_image("/img/LoneWolf.E01", str(host_dir))
    assert res["steps"]["amcache"]["ran"] is True
    assert res["steps"]["amcache"]["ok"] is True
    amcache_calls = [a for a in seen_argvs if "get-sybers/amcacheparser:latest" in a]
    assert len(amcache_calls) == 1
    assert amcache_calls[0][amcache_calls[0].index("-f") + 1] == "/in/Amcache.hve"


def test_process_image_wxtcmd_is_never_invoked(tmp_path, monkeypatch):
    """TODO(#88): wxtcmd_argv exists and is unit-tested, but process_image must
    not call it yet (no writable /opt/eztool wiring verified against a real
    ActivitiesCache.db)."""
    host_dir = tmp_path / "out" / "LoneWolf"
    monkeypatch.setattr(z, "extract_artifacts",
                        lambda image, stage_dir, **kw: os.makedirs(stage_dir, exist_ok=True) or [])

    def fail_if_wxtcmd(argv, log_path):
        assert "get-sybers/wxtcmd:latest" not in argv
        return True

    monkeypatch.setattr(z, "_run", fail_if_wxtcmd)
    res = z.process_image("/img/LoneWolf.E01", str(host_dir))
    assert res["steps"]["wxtcmd"]["ran"] is False


def test_process_image_extraction_failure_is_reported(tmp_path, monkeypatch):
    host_dir = tmp_path / "out" / "LoneWolf"

    def boom(image, stage_dir, **kw):
        raise subprocess.CalledProcessError(1, ["image_export.py"])

    monkeypatch.setattr(z, "extract_artifacts", boom)
    res = z.process_image("/img/LoneWolf.E01", str(host_dir))
    assert res["error"] == "image_export failed"
    assert res["steps"] == {}


# ---- process(): one host, one directory; source merging ----------------------
def test_process_one_host_one_dir_and_no_cross_host_mixing(tmp_path, monkeypatch):
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "HostA.E01").write_bytes(b"x")
    (tmp_path / "in" / "HostB.raw").write_bytes(b"x")
    out_dir = tmp_path / "out"

    seen_dirs = []

    def fake_process_image(image, host_out_dir, **kw):
        seen_dirs.append(os.path.realpath(host_out_dir))
        return {"image": image, "host_dir": host_out_dir, "steps": {"recmd": {"ran": True, "ok": True}},
               "skipped": False, "extracted_files": 1}

    monkeypatch.setattr(z, "process_image", fake_process_image)
    summary = z.process(str(tmp_path / "in"), str(out_dir))
    assert summary["images"] == 2
    assert summary["processed"] == 2
    # each image landed in its OWN dir, named by its own stem — no shared dir
    assert seen_dirs == sorted([str(out_dir / "HostA"), str(out_dir / "HostB")])
    assert len(set(seen_dirs)) == 2


def test_process_merges_input_dir_and_vm_dir(tmp_path, monkeypatch):
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    (in_dir / "HostA.E01").write_bytes(b"x")
    vm_dir = tmp_path / "vm" / "SomeVM"
    vm_dir.mkdir(parents=True)
    (vm_dir / "disk.vmdk").write_bytes(b"x")

    monkeypatch.setattr(z, "process_image", lambda image, host_out_dir, **kw: {
        "skipped": False, "extracted_files": 1, "steps": {"recmd": {"ran": True, "ok": True}},
    })
    summary = z.process(str(in_dir), str(tmp_path / "out"), vm_dir=str(tmp_path / "vm"))
    assert summary["images"] == 2
    assert len(summary["sources"]) == 2


def test_process_ignores_missing_vm_dir(tmp_path, monkeypatch):
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    monkeypatch.setattr(z, "process_image", lambda *a, **k: {})
    summary = z.process(str(in_dir), str(tmp_path / "out"), vm_dir=str(tmp_path / "does_not_exist"))
    assert len(summary["sources"]) == 1


# ---- CLI entry point ---------------------------------------------------------
def test_main_requires_input_dir():
    import pytest
    with pytest.raises(SystemExit):
        z.main(["--out-dir", "/tmp/x"])


def test_main_requires_out_dir():
    import pytest
    with pytest.raises(SystemExit):
        z.main(["--input-dir", "/tmp/x"])


def test_main_no_images_is_clean_exit(tmp_path, capsys):
    rc = z.main(["--input-dir", str(tmp_path / "empty"), "--out-dir", str(tmp_path / "out")])
    assert rc == 0
    out = capsys.readouterr().out
    assert '"images": 0' in out
