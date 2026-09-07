"""Unit tests for the signatures lanes' pure parsing logic (no engines needed)."""
import json
import os

from get_sybers_dxdfir import signatures
from get_sybers_dxdfir.signatures import hayabusa, suricata, yara


# ---- shared helpers --------------------------------------------------------
def test_clean_name_folds(tmp_path):
    p = tmp_path / "a" / "b.pcap"
    assert signatures.clean_name(str(p), str(tmp_path)) == "a_b.pcap"


def test_list_images(tmp_path):
    (tmp_path / "case.E01").write_bytes(b"x")
    (tmp_path / "m.raw").write_bytes(b"x")
    (tmp_path / "notes.txt").write_bytes(b"x")
    got = [os.path.basename(p) for p in signatures.list_images(str(tmp_path))]
    assert got == ["case.E01", "m.raw"]


# ---- yara text parsing -----------------------------------------------------
def test_parse_yara_text_rule_and_strings():
    raw = (
        "EICAR_Test /scan/samples/eicar.txt\n"
        "0x0:$s1: X5O!P%@AP\n"
        "0x10:$s2: EICAR-STANDARD\n"
        "AnotherRule /scan/samples/eicar.txt\n"
    )
    matches = yara.parse_yara_text(raw, "file", "/scan/", "other_raw_data")
    assert len(matches) == 2
    first = matches[0]
    assert first["rule"] == "EICAR_Test"
    assert first["source"] == "file"
    assert first["target"] == "samples/eicar.txt"
    assert first["match"] == os.path.join("other_raw_data", "samples/eicar.txt")
    assert first["strings"][0] == {"id": "$s1", "offset": 0, "data": "X5O!P%@AP"}
    assert first["strings"][1]["offset"] == 16
    assert matches[1]["rule"] == "AnotherRule" and matches[1]["strings"] == []


def test_build_index_uses_rules_mount_paths():
    idx = yara.build_index(["/r/a.yar", "/r/sub/b.yara"], "/r")
    assert idx == 'include "/rules/a.yar"\ninclude "/rules/sub/b.yara"\n'


def test_yara_run_never_writes_into_rules_dir(tmp_path):
    # a read-only rules tree must not be mutated (index goes to a temp file). Point
    # files_target at a non-existent dir so the container scan is never reached.
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r.yar").write_text("rule X { condition: true }\n")
    before = set(os.listdir(rules))
    res = yara.run(output_dir=str(tmp_path / "out"), repo_root=str(tmp_path),
                   sources=("files",), rules_dir=str(rules),
                   files_target=str(tmp_path / "does_not_exist"))
    assert set(os.listdir(rules)) == before   # no _dxdfir_index.yar left behind
    assert res["lane"] == "yara"


def test_parse_yara_text_ignores_malformed():
    assert yara.parse_yara_text("", "file", "/scan/", "b") == []
    assert yara.parse_yara_text("justoneword\n", "file", "/scan/", "b") == []


def test_parse_vadyarascan():
    lines = (
        '{"Rule": "Cobalt", "PID": 123, "Process": "evil.exe", "Offset": 4096, "Value": "MZ"}\n'
        '{"nope": 1}\n'
        'garbage\n'
    )
    got = yara.parse_vadyarascan(lines, "mem/dump.raw")
    assert len(got) == 1
    assert got[0] == {
        "tool": "yara", "source": "memory", "rule": "Cobalt", "pid": 123,
        "process": "evil.exe", "offset": 4096, "value": "MZ",
        "target": "mem/dump.raw", "match": "mem/dump.raw",
    }


# ---- yara disk source: mount argv construction (pure, no FUSE needed) ------
_MMLS = """DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
002:  000:000   0000000128   0031457279   0031457151   NTFS / exFAT (0x07)
003:  000:001   0031457280   0031459327   0000002048   Linux (0x83)
"""


def test_parse_mmls_offset_first_ntfs_partition():
    assert yara.parse_mmls_offset(_MMLS) == 128 * 512


def test_parse_mmls_offset_basic_data_and_none():
    text = "005:  000:002   0000206848   0104855551   0104648704   Basic data partition\n"
    assert yara.parse_mmls_offset(text) == 206848 * 512
    assert yara.parse_mmls_offset("") == 0                       # partitionless volume
    assert yara.parse_mmls_offset("no table\n") == 0


def test_mount_argvs():
    assert yara.ewfmount_argv("/d/case.E01", "/tmp/ewf") == \
        ["ewfmount", "/d/case.E01", "/tmp/ewf"]
    assert yara.mmls_argv("/tmp/ewf/ewf1") == ["mmls", "-a", "/tmp/ewf/ewf1"]
    argv = yara.ntfs3g_argv("/tmp/ewf/ewf1", "/mnt/y0", 65536)
    assert argv == ["ntfs-3g", "-o", "ro,offset=65536,streams_interface=windows",
                    "/tmp/ewf/ewf1", "/mnt/y0"]
    assert "ro," in argv[2]                                      # read-only, always


# ---- yara memory source: vadyarascan argv + rules concat --------------------
def test_vadyarascan_argv_mounts_and_wrapper_args(tmp_path):
    mem = tmp_path / "case" / "memdump.mem"
    mem.parent.mkdir()
    mem.write_bytes(b"x")
    sym = tmp_path / "symbols"; sym.mkdir()
    ren = tmp_path / "r.py"; ren.write_text("")
    rules = tmp_path / "combined.yar"; rules.write_text("rule X { condition: true }")
    argv = yara.vadyarascan_argv(str(mem), str(sym), str(ren), str(rules), "vol:img")
    for flag in ("--cap-drop", "--security-opt", "--read-only"):
        assert flag in argv
    assert "--network" in argv                                   # offline by default
    assert f"{mem.parent}:/mem:ro" in argv                       # image dir read-only
    assert f"{sym}:/symbols" in argv                             # symbols writable (ISF cache)
    assert f"{rules}:/rules/combined.yar:ro" in argv
    assert "vol:img" in argv
    # the baked wrapper is the ENTRYPOINT, so the argv after the image is the
    # renderer path + vol CLI args, ending in the plugin + --yara-file
    tail = argv[argv.index("vol:img") + 1:]
    assert tail[0] == "/opt/jsonl_dfir_renderer.py"
    assert "windows.vadyarascan.VadYaraScan" in tail
    assert tail[tail.index("--yara-file") + 1] == "/rules/combined.yar"
    # symbols_online lifts the network isolation for ISF fetch
    online = yara.vadyarascan_argv(str(mem), str(sym), str(ren), str(rules),
                                   "vol:img", symbols_online=True)
    assert "--network" not in online


def test_combine_rules_concatenates(tmp_path):
    a = tmp_path / "a.yar"; a.write_text("rule A { condition: true }")
    b = tmp_path / "b.yar"; b.write_text("rule B { condition: false }")
    got = yara.combine_rules([str(a), str(b)])
    assert "rule A" in got and "rule B" in got
    assert got.index("rule A") < got.index("rule B")


# ---- suricata EVE filtering ------------------------------------------------
def test_filter_eve_keeps_wanted_and_annotates():
    stream = (
        '{"event_type": "alert", "alert": {"signature": "ET X"}}\n'
        '{"event_type": "stats", "x": 1}\n'          # dropped
        '{"event_type": "dns", "dns": {}}\n'
        'not-json\n'
    )
    got = suricata.filter_eve(stream, "raw/pcaps/a.pcap")
    assert [e["event_type"] for e in got] == ["alert", "dns"]
    assert all(e["source_pcap"] == "raw/pcaps/a.pcap" and e["tool"] == "suricata" for e in got)


def test_filter_eve_keep_all():
    stream = '{"event_type": "stats"}\n{"event_type": "alert"}\n'
    assert len(suricata.filter_eve(stream, "p", keep_all=True)) == 2


# ---- hayabusa tagging ------------------------------------------------------
def test_tag_detections():
    raw = '{"RuleTitle": "Susp Logon", "Level": "high"}\ngarbage\n{"RuleTitle": "X"}\n'
    got = hayabusa.tag_detections(raw)
    assert len(got) == 2
    assert all(d["tool"] == "hayabusa" for d in got)
    assert got[0]["RuleTitle"] == "Susp Logon"


def test_find_binary(tmp_path):
    assert hayabusa.find_binary(str(tmp_path)) is None
    b = tmp_path / "hayabusa-3.4.0-lin"
    b.write_bytes(b"#!/bin/sh\n")
    os.chmod(b, 0o755)
    (tmp_path / "hayabusa.zip").write_bytes(b"zip")   # ignored
    assert hayabusa.find_binary(str(tmp_path)) == str(b)


# ---- orchestrator ----------------------------------------------------------
def test_process_no_rules_no_pcaps_is_clean(tmp_path):
    repo = tmp_path
    (repo / "data_store").mkdir()
    s = signatures.process(str(tmp_path / "out"), repo_root=str(repo))
    assert s["tool"] == "signatures"
    assert s["processed"] == 0 and s["failed"] == 0
    assert set(s["results"]) == {"yara", "suricata", "hayabusa"}


# ---- Suricata tuning (HOME_NET / --set), all pure ---------------------------
from get_sybers_dxdfir.signatures import suricata


def test_derive_home_net_picks_observed_private_supernets():
    hn = suricata.derive_home_net(["10.1.2.3", "192.168.1.5", "8.8.8.8"])
    assert hn == "[10.0.0.0/8,192.168.0.0/16]"          # only the seen privates, in order


def test_derive_home_net_falls_back_when_no_private():
    hn = suricata.derive_home_net(["8.8.8.8", "1.1.1.1", "garbage"])
    assert hn == "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"   # RFC1918 default


def test_var_sets_home_net_implies_external_complement():
    s = suricata.var_sets(home_net="[10.0.0.0/8]")
    assert "vars.address-groups.HOME_NET=[10.0.0.0/8]" in s
    assert "vars.address-groups.EXTERNAL_NET=![10.0.0.0/8]" in s


def test_var_sets_explicit_external_and_extra_passthrough():
    s = suricata.var_sets(home_net="[10.0.0.0/8]", external_net="[1.2.3.0/24]",
                          extra_sets=["vars.port-groups.HTTP_PORTS=8080"])
    assert "vars.address-groups.EXTERNAL_NET=[1.2.3.0/24]" in s
    assert "vars.port-groups.HTTP_PORTS=8080" in s


def test_var_sets_empty_when_nothing_given():
    assert suricata.var_sets() == []


def test_suricata_argv_carries_sets_and_rules(tmp_path):
    pcap = tmp_path / "c.pcap"; pcap.write_bytes(b"x")
    rules = tmp_path / "r"; rules.mkdir(); rf = rules / "suricata.rules"; rf.write_text("")
    argv = suricata.suricata_argv(str(pcap), "/out", str(rules), str(rf), "img",
                                  sets=["vars.address-groups.HOME_NET=[10.0.0.0/8]"])
    # minimal hardened docker run: confinement flags + suricata args (suricata
    # is the image ENTRYPOINT, so no "suricata" token in argv)
    for flag in ("--cap-drop", "--security-opt", "--read-only", "--network"):
        assert flag in argv
    tail = argv[argv.index("img") + 1:]
    assert "-r" in tail and "/pcaps/c.pcap" in tail
    assert tail[tail.index("-S") + 1] == "/rules/suricata.rules"
    assert tail[tail.index("--set") + 1] == "vars.address-groups.HOME_NET=[10.0.0.0/8]"


def test_collect_ips_from_eve_stream():
    eve = '\n'.join([
        '{"event_type":"flow","src_ip":"10.0.0.1","dest_ip":"8.8.8.8"}',
        '{"event_type":"alert","src_ip":"10.0.0.2","dest_ip":"10.0.0.1"}',
        'not json',
        '{"event_type":"stats"}',
    ])
    assert suricata.collect_ips(eve) == ["10.0.0.1", "10.0.0.2", "8.8.8.8"]


# ---- Hayabusa in the evtx pipeline (no-binary note path) --------------------
from get_sybers_dxdfir import evtx


def test_evtx_run_hayabusa_notes_missing_binary(tmp_path):
    empty = tmp_path / "hb"; empty.mkdir()
    out = tmp_path / "out"; out.mkdir()
    res = evtx.run_hayabusa([str(tmp_path)], str(out), hb_dir=str(empty))
    assert res["produced"] == 0 and res["output"] is None
    assert "no hayabusa binary" in res["note"]


# ---- unified image discovery (detections see what the processors see) ------
def test_list_images_covers_processor_formats(tmp_path):
    for name in ("a.E01", "b.ex01", "c.vhdx", "d.qcow2", "e.vhd", "f.vmdk"):
        (tmp_path / name).write_bytes(b"x")
    (tmp_path / "notes.txt").write_bytes(b"x")
    got = sorted(os.path.basename(p) for p in signatures.list_images(str(tmp_path)))
    assert got == ["a.E01", "b.ex01", "c.vhdx", "d.qcow2", "e.vhd", "f.vmdk"]


# ---- suricata capture discovery (magic-first, like the zeek processor) -----
def test_suricata_discover_by_magic_not_just_extension(tmp_path):
    # pcap magic under a non-capture extension: the zeek processor parses it,
    # so the suricata lane must replay it too.
    (tmp_path / "capture.dmp").write_bytes(bytes.fromhex("a1b2c3d4") + b"\x00" * 8)
    # extension fallback still applies to a capture without readable magic
    (tmp_path / "old.pcap").write_bytes(b"????")
    (tmp_path / "readme.txt").write_bytes(b"not a capture")
    got = sorted(os.path.basename(p) for p in suricata.discover(str(tmp_path)))
    assert got == ["capture.dmp", "old.pcap"]


# ---- hayabusa disk images via the shared stage -----------------------------
def test_hayabusa_default_stage_matches_evtx_processor():
    stage = hayabusa.default_stage_dir("/repo")
    assert stage == os.path.join(
        "/repo", "data_store", "processed", "windows_logs", "_extracted_evtx")


def _fake_hb_bin(repo):
    hb = repo / "data_store" / "dependencies" / "hayabusa"
    hb.mkdir(parents=True)
    exe = hb / "hayabusa-9.9.9-lin-x64-gnu"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    return hb


def test_hayabusa_run_stages_disk_images_without_fuse(tmp_path, monkeypatch):
    """A disk image is staged via image_export (no fuse) and the stage scanned."""
    repo = tmp_path
    disk = repo / "data_store" / "raw" / "disk_images"
    disk.mkdir(parents=True)
    (disk / "host.E01").write_bytes(b"x")
    _fake_hb_bin(repo)
    stage = repo / "stage"

    def fake_extract_staged(image_src, stage_dir, **kw):
        assert os.path.realpath(stage_dir) == os.path.realpath(str(stage))
        d = os.path.join(stage_dir, "host")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "Security.evtx"), "wb") as fh:
            fh.write(b"ElfFile")
        return {"images": 1, "extracted": 1, "reused": 0, "failed": 0, "results": []}

    scanned = []

    def fake_scan(hb_bin, scan_dir, rules_dir):
        scanned.append(scan_dir)
        return '{"RuleTitle": "T"}\n'

    monkeypatch.setattr(hayabusa.imageexport, "extract_staged", fake_extract_staged)
    monkeypatch.setattr(hayabusa, "scan_directory", fake_scan)
    res = hayabusa.run(
        output_dir=str(tmp_path / "out"), repo_root=str(repo),
        loose_dir=str(repo / "nowhere"), stage_dir=str(stage),
    )
    assert res["extract"] == {"images": 1, "extracted": 1, "reused": 0, "failed": 0}
    assert res["produced"] == 1
    assert scanned == [str(stage)]


def test_hayabusa_run_notes_extract_failures(tmp_path, monkeypatch):
    repo = tmp_path
    disk = repo / "data_store" / "raw" / "disk_images"
    disk.mkdir(parents=True)
    (disk / "host.E01").write_bytes(b"x")
    _fake_hb_bin(repo)

    monkeypatch.setattr(
        hayabusa.imageexport, "extract_staged",
        lambda *a, **kw: {"images": 1, "extracted": 0, "reused": 0, "failed": 1,
                          "results": []})
    res = hayabusa.run(output_dir=str(tmp_path / "out"), repo_root=str(repo),
                       loose_dir=str(repo / "nowhere"),
                       stage_dir=str(tmp_path / "stage"))
    assert "image_export failed on 1" in res["note"]
    assert res["produced"] == 0


# ---- suricata per-pcap tuning template -------------------------------------
def test_tuning_template_is_template_only():
    assert suricata.parse_tuning(suricata.template_text()) == {}


def test_parse_tuning_sections_and_multiline_sets():
    text = (
        "[global]\n"
        "home_net = [10.0.0.0/8]\n"
        "[case1_a.pcap]\n"
        "home_net = [192.168.0.0/16]\n"
        "external_net = ![192.168.0.0/16]\n"
        "sets =\n"
        "    vars.port-groups.HTTP_PORTS=8080\n"
        "    vars.port-groups.SSH_PORTS=2222\n"
    )
    got = suricata.parse_tuning(text)
    assert got["global"] == {"home_net": "[10.0.0.0/8]"}
    assert got["case1_a.pcap"]["external_net"] == "![192.168.0.0/16]"
    assert got["case1_a.pcap"]["extra_sets"] == [
        "vars.port-groups.HTTP_PORTS=8080", "vars.port-groups.SSH_PORTS=2222"]


def test_parse_tuning_invalid_returns_none():
    assert suricata.parse_tuning("not an ini\n[broken") is None
    # whitespace inside an address group is a typo, not a valid group
    assert suricata.parse_tuning("[a.pcap]\nhome_net = [10.0.0.0/8, 192.168.0.0/16]\n") is None


def test_render_tuning_round_trips():
    entries = {
        "b.pcap": {"home_net": "[10.0.0.0/8]",
                   "extra_sets": ["vars.port-groups.HTTP_PORTS=8080"]},
        "a.pcap": {"home_net": "[192.168.0.0/16]", "external_net": "!$HOME_NET"},
    }
    assert suricata.parse_tuning(suricata.render_tuning(entries)) == entries


def _pcap_repo(tmp_path):
    """A fake repo with two captures whose (faked) traffic differs."""
    repo = tmp_path
    pdir = repo / "data_store" / "raw" / "pcaps"
    pdir.mkdir(parents=True)
    magic = bytes.fromhex("a1b2c3d4") + b"\x00" * 8
    (pdir / "a.pcap").write_bytes(magic)
    (pdir / "b.pcap").write_bytes(magic)
    return repo, pdir


def _fake_pass(calls):
    """_suricata_pass stand-in: per-pcap EVE whose src_ip depends on the capture."""
    def fake(pcap, rules_dir, rules_file, image, sets):
        calls.append((os.path.basename(pcap), tuple(sets or [])))
        ip = "10.1.1.1" if os.path.basename(pcap) == "a.pcap" else "192.168.5.5"
        return f'{{"event_type": "alert", "src_ip": "{ip}", "dest_ip": "8.8.8.8"}}\n'
    return fake


def test_suricata_run_autodetects_and_records_per_pcap(tmp_path, monkeypatch):
    """Missing tuning file: template written, HOME_NET derived per capture from its
    OWN traffic (no leakage between pcaps), and the values recorded."""
    repo, _ = _pcap_repo(tmp_path)
    calls = []
    monkeypatch.setattr(suricata, "_suricata_pass", _fake_pass(calls))
    tfile = repo / "data_store" / "dependencies" / "suricata-tuning.conf"
    res = suricata.run(output_dir=str(tmp_path / "out"), repo_root=str(repo))
    assert res["tuning_file"]["status"] == "created"
    assert res["tuning"]["a.pcap"]["HOME_NET"] == "[10.0.0.0/8]"
    assert res["tuning"]["a.pcap"]["auto"] is True
    assert res["tuning"]["b.pcap"]["HOME_NET"] == "[192.168.0.0/16]"
    assert res["tuning"]["b.pcap"]["source"] == "auto"
    recorded = suricata.parse_tuning(tfile.read_text())
    assert recorded["a.pcap"]["home_net"] == "[10.0.0.0/8]"
    assert recorded["b.pcap"]["home_net"] == "[192.168.0.0/16]"
    assert recorded["a.pcap"]["external_net"] == "!$HOME_NET"
    # probe pass + real pass per capture, and the REAL pass of b.pcap must carry
    # b's own HOME_NET, not a's
    real_b = [s for name, s in calls if name == "b.pcap" and s][-1]
    assert "vars.address-groups.HOME_NET=[192.168.0.0/16]" in real_b


def test_suricata_run_uses_recorded_file_without_probing(tmp_path, monkeypatch):
    """Second run: the recorded file is authoritative — one pass per capture, no
    probe, values applied per pcap."""
    repo, _ = _pcap_repo(tmp_path)
    tfile = repo / "data_store" / "dependencies" / "suricata-tuning.conf"
    tfile.parent.mkdir(parents=True)
    tfile.write_text(suricata.render_tuning({
        "a.pcap": {"home_net": "[172.16.0.0/12]"},
        "b.pcap": {"home_net": "[192.168.0.0/16]"},
    }))
    calls = []
    monkeypatch.setattr(suricata, "_suricata_pass", _fake_pass(calls))
    res = suricata.run(output_dir=str(tmp_path / "out"), repo_root=str(repo))
    assert res["tuning_file"]["status"] == "ok"
    assert [c[0] for c in calls] == ["a.pcap", "b.pcap"]     # no probe passes
    assert res["tuning"]["a.pcap"]["source"] == "file"
    assert "vars.address-groups.HOME_NET=[172.16.0.0/12]" in calls[0][1]
    assert "vars.address-groups.HOME_NET=[192.168.0.0/16]" in calls[1][1]


def test_suricata_run_invalid_file_falls_back_and_preserves(tmp_path, monkeypatch):
    repo, _ = _pcap_repo(tmp_path)
    tfile = repo / "data_store" / "dependencies" / "suricata-tuning.conf"
    tfile.parent.mkdir(parents=True)
    tfile.write_text("[broken\nnot ini")
    monkeypatch.setattr(suricata, "_suricata_pass", _fake_pass([]))
    res = suricata.run(output_dir=str(tmp_path / "out"), repo_root=str(repo))
    assert res["tuning_file"]["status"] == "invalid"
    assert "not valid" in res["note"]
    assert (tfile.parent / "suricata-tuning.conf.invalid").read_text().startswith("[broken")
    assert suricata.parse_tuning(tfile.read_text())          # regenerated, valid


def test_suricata_run_explicit_home_net_beats_file(tmp_path, monkeypatch):
    repo, _ = _pcap_repo(tmp_path)
    tfile = repo / "data_store" / "dependencies" / "suricata-tuning.conf"
    tfile.parent.mkdir(parents=True)
    tfile.write_text(suricata.render_tuning({"a.pcap": {"home_net": "[172.16.0.0/12]"}}))
    calls = []
    monkeypatch.setattr(suricata, "_suricata_pass", _fake_pass(calls))
    res = suricata.run(output_dir=str(tmp_path / "out"), repo_root=str(repo),
                       home_net="[10.9.0.0/16]")
    assert all(v["source"] == "cli" for v in res["tuning"].values())
    assert all("vars.address-groups.HOME_NET=[10.9.0.0/16]" in s for _, s in calls)


# ---- consolidated Suricata variables ---------------------------------------
def test_suricata_vars_registry_is_complete_and_typed():
    # both kinds present, every entry typed, and EVERY var automatable — parser
    # evidence where Suricata has one, well-known-port traffic where it doesn't
    kinds = {m["kind"] for m in suricata.SURICATA_VARS.values()}
    assert kinds == {"address", "port"}
    assert all(m["default"] for m in suricata.SURICATA_VARS.values())
    assert all(m["auto"] for m in suricata.SURICATA_VARS.values())
    # every address var (beyond the two net groups) has an evidence spec
    addr_vars = {n for n, m in suricata.SURICATA_VARS.items()
                 if m["kind"] == "address"} - {"HOME_NET", "EXTERNAL_NET"}
    assert addr_vars == (set(suricata._SERVER_ADDR_VARS)
                         | set(suricata._CLIENT_ADDR_VARS))


def test_template_lists_every_consolidated_var():
    text = suricata.template_text()
    for name in suricata.SURICATA_VARS:
        assert name.lower() in text
    assert suricata.parse_tuning(text) == {}     # still template-only


def test_derive_vars_ports_servers_and_home():
    eve = "\n".join([
        # http on a non-standard port, served by a home host
        '{"event_type":"http","src_ip":"10.0.0.9","dest_ip":"10.0.0.5","dest_port":8080}',
        '{"event_type":"http","src_ip":"10.0.0.9","dest_ip":"10.0.0.5","dest_port":80}',
        # flow app_proto catches protocols without their own probe event
        '{"event_type":"flow","app_proto":"ssh","src_ip":"10.0.0.9","dest_ip":"8.8.4.4","dest_port":2222}',
        # dns answered by a home resolver
        '{"event_type":"dns","src_ip":"10.0.0.9","dest_ip":"10.0.0.1","dest_port":53}',
        # dns to an external resolver: port counted, server NOT (not home-side)
        '{"event_type":"dns","src_ip":"10.0.0.9","dest_ip":"8.8.8.8","dest_port":53}',
    ])
    got = suricata.derive_vars(eve)
    assert got["HOME_NET"] == "[10.0.0.0/8]"
    assert got["EXTERNAL_NET"] == "!$HOME_NET"
    assert got["HTTP_PORTS"] == "[80,8080]"
    assert got["SHELLCODE_PORTS"] == "!$HTTP_PORTS"
    assert got["SSH_PORTS"] == "2222"
    assert got["HTTP_SERVERS"] == "[10.0.0.5]"
    assert got["DNS_SERVERS"] == "[10.0.0.1]"
    assert "FTP_PORTS" not in got                # nothing observed -> default stands


def test_vars_to_sets_routes_by_registry_kind():
    sets = suricata.vars_to_sets({"HOME_NET": "[10.0.0.0/8]", "HTTP_PORTS": "[80,8080]"})
    assert sets == ["vars.address-groups.HOME_NET=[10.0.0.0/8]",
                    "vars.port-groups.HTTP_PORTS=[80,8080]"]


def test_parse_tuning_unknown_key_is_invalid():
    assert suricata.parse_tuning("[a.pcap]\nhome_nte = [10.0.0.0/8]\n") is None


def test_parse_tuning_accepts_any_consolidated_var():
    got = suricata.parse_tuning("[a.pcap]\nhttp_ports = [80,8080]\ndns_servers = [10.0.0.1]\n")
    assert got == {"a.pcap": {"http_ports": "[80,8080]", "dns_servers": "[10.0.0.1]"}}


def test_run_records_derived_ports_and_uses_them(tmp_path, monkeypatch):
    """The probe's derivations (not just HOME_NET) are applied to the real pass
    and recorded per pcap."""
    repo, _ = _pcap_repo(tmp_path)
    calls = []

    def fake(pcap, rules_dir, rules_file, image, sets):
        calls.append((os.path.basename(pcap), tuple(sets or [])))
        return ('{"event_type":"http","src_ip":"10.0.0.9","dest_ip":"10.0.0.5",'
                '"dest_port":8080}\n')

    monkeypatch.setattr(suricata, "_suricata_pass", fake)
    res = suricata.run(output_dir=str(tmp_path / "out"), repo_root=str(repo))
    real = [s for name, s in calls if name == "a.pcap"][-1]
    assert "vars.port-groups.HTTP_PORTS=8080" in real
    assert "vars.address-groups.HTTP_SERVERS=[10.0.0.5]" in real
    tfile = repo / "data_store" / "dependencies" / "suricata-tuning.conf"
    recorded = suricata.parse_tuning(tfile.read_text())
    assert recorded["a.pcap"]["http_ports"] == "8080"
    assert res["tuning"]["a.pcap"]["vars"]["HTTP_SERVERS"] == "[10.0.0.5]"


def test_derive_vars_port_evidence_for_parserless_services():
    """Services without a Suricata parser derive from the traffic hosts send and
    receive on the well-known ports."""
    eve = "\n".join([
        # a home host receiving on 3306: SQL server by port evidence
        '{"event_type":"flow","src_ip":"10.0.0.9","dest_ip":"10.0.0.7","dest_port":3306,"app_proto":"failed"}',
        # home host receiving kerberos: a DC
        '{"event_type":"flow","src_ip":"10.0.0.9","dest_ip":"10.0.0.2","dest_port":88,"app_proto":"krb5"}',
        # telnet to a home host
        '{"event_type":"flow","src_ip":"10.0.0.9","dest_ip":"10.0.0.3","dest_port":23}',
        # AIM: the EXTERNAL side receiving on 5190 is the server
        '{"event_type":"flow","src_ip":"10.0.0.9","dest_ip":"64.12.24.1","dest_port":5190}',
        # oracle + teredo well-known ports actually carrying traffic
        '{"event_type":"flow","src_ip":"10.0.0.9","dest_ip":"10.0.0.7","dest_port":1521}',
        '{"event_type":"flow","src_ip":"10.0.0.9","dest_ip":"8.8.8.8","dest_port":3544}',
    ])
    got = suricata.derive_vars(eve)
    assert got["SQL_SERVERS"] == "[10.0.0.7]"
    assert got["DC_SERVERS"] == "[10.0.0.2]"
    assert got["TELNET_SERVERS"] == "[10.0.0.3]"
    assert got["AIM_SERVERS"] == "[64.12.24.1]"
    assert got["ORACLE_PORTS"] == "1521"
    assert got["TEREDO_PORTS"] == "3544"
    assert "GENEVE_PORTS" not in got            # no traffic on 6081 -> default


def test_derive_vars_scada_client_server_split():
    """SCADA vars split by flow direction: receiver = *_SERVER, initiator = *_CLIENT."""
    eve = ('{"event_type":"flow","src_ip":"10.0.1.5","dest_ip":"10.0.1.9",'
           '"dest_port":502,"app_proto":"modbus"}\n')
    got = suricata.derive_vars(eve)
    assert got["MODBUS_SERVER"] == "[10.0.1.9]"
    assert got["MODBUS_CLIENT"] == "[10.0.1.5]"
    assert got["MODBUS_PORTS"] == "502"


def test_derive_vars_scope_excludes_wrong_side():
    """An EXTERNAL host receiving SQL-port traffic is not a home SQL server, and
    a home host receiving on 5190 is not an (external-scope) AIM server."""
    eve = "\n".join([
        '{"event_type":"flow","src_ip":"10.0.0.9","dest_ip":"8.8.8.8","dest_port":3306}',
        '{"event_type":"flow","src_ip":"10.0.0.9","dest_ip":"10.0.0.4","dest_port":5190}',
    ])
    got = suricata.derive_vars(eve)
    assert "SQL_SERVERS" not in got
    assert "AIM_SERVERS" not in got


# ---- tool-image inventory guard --------------------------------------------
def test_check_config_flags_root_and_missing_label():
    from get_sybers_dxdfir import images
    assert images.check_config(None) == ["image not present"]
    assert images.check_config({"User": "0:0", "Labels": {}})  # root + no label -> problems
    good = {"User": "2000:2000", "Labels": {"com.get-sybers.hardened": "true"}}
    assert images.check_config(good) == []
    assert any("uid" in p for p in images.check_config(
        {"User": "", "Labels": {"com.get-sybers.hardened": "true"}}))


def test_require_refuses_unknown_dxdfir_image(monkeypatch):
    from get_sybers_dxdfir import images
    # a non-dxdfir image is out of scope, never inspected
    monkeypatch.setattr(images, "_inspect", lambda i: (_ for _ in ()).throw(AssertionError("inspected")))
    images.require("mcr.microsoft.com/dotnet/runtime:9.0")
    # an unknown dxdfir/* repo is refused before inspection
    import pytest
    with pytest.raises(RuntimeError, match="not a known DX_DFIR tool image"):
        images.require("dxdfir/evil:latest")


def test_require_refuses_unhardened_known_image(monkeypatch):
    from get_sybers_dxdfir import images
    monkeypatch.setattr(images, "_inspect",
                        lambda i: {"User": "0:0", "Labels": {}})
    import pytest
    with pytest.raises(RuntimeError, match="not hardened"):
        images.require("dxdfir/zeek:latest")


def test_require_passes_hardened_known_image(monkeypatch):
    from get_sybers_dxdfir import images
    monkeypatch.setattr(images, "_inspect",
                        lambda i: {"User": "2000:2000",
                                   "Labels": {"com.get-sybers.hardened": "true"}})
    images.require("dxdfir/zeek:latest")   # no raise


def test_audit_flags_unexpected_and_missing(monkeypatch):
    from get_sybers_dxdfir import images
    hardened = {"User": "2000:2000", "Labels": {"com.get-sybers.hardened": "true"}}
    monkeypatch.setattr(images, "_inspect", lambda i: hardened)
    # host has all expected + a rogue dfir image + an allowed non-tool one
    monkeypatch.setattr(images, "_list_dxdfir_images",
                        lambda: list(images.HARDENED_IMAGES)
                        + ["dxdfir/rogue:latest", "dxdfir/sof-elk:test"])
    result = images.audit()
    assert not result["ok"]
    assert any("dxdfir/rogue" in v and "unexpected" in v for v in result["violations"])
    assert not any("sof-elk" in v for v in result["violations"])   # allow-listed


# ---- suricata reads the pcap dir it is given (the collection-scoping fix) ----
_PCAP_MAGIC = b"\xa1\xb2\xc3\xd4"


def test_suricata_run_honors_pcap_dir(tmp_path, monkeypatch):
    # a sorted collection points suricata at its own pcaps/ via pcap_dir; the
    # lane must discover captures THERE, not only the default data_store/raw/pcaps.
    pcaps = tmp_path / "collections" / "case" / "pcaps"
    pcaps.mkdir(parents=True)
    (pcaps / "c.pcap").write_bytes(_PCAP_MAGIC + b"rest")
    monkeypatch.setattr(suricata, "_suricata_pass", lambda *a, **k: "")  # no docker
    res = suricata.run(output_dir=str(tmp_path / "out"), repo_root=str(tmp_path),
                       pcap_dir=str(pcaps))
    assert res["note"] != f"no pcaps under {pcaps}"    # it FOUND the capture
    assert res["failed"] == 1 and res["produced"] == 0  # tried it (stub -> no eve)


def test_suricata_run_default_pcap_dir_is_raw_pcaps(tmp_path, monkeypatch):
    # with no pcap_dir, the default is still data_store/raw/pcaps (unchanged) —
    # the collection scoping is what supplies the real path.
    monkeypatch.setattr(suricata, "_suricata_pass", lambda *a, **k: "")
    res = suricata.run(output_dir=str(tmp_path / "out"), repo_root=str(tmp_path))
    assert res["note"] == f"no pcaps under {os.path.join(str(tmp_path), 'data_store', 'raw', 'pcaps')}"


def test_signatures_cli_plumbs_pcap_dir(tmp_path, monkeypatch):
    from get_sybers_dxdfir.signatures import __main__ as sig_main
    captured = {}
    monkeypatch.setattr(sig_main, "process",
                        lambda *a, **k: captured.update(k) or {"failed": 0, "processed": 1, "skipped": 0})
    sig_main.main(["--output-dir", str(tmp_path / "o"), "--repo-root", str(tmp_path),
                   "--only", "suricata", "--pcap-dir", "/some/pcaps"])
    assert captured["config"]["suricata"]["pcap_dir"] == "/some/pcaps"
