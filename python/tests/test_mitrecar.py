"""The mitrecar lane — DX_DFIR drives the external Byakugan engine via its
CLI (the engine is a standalone public checkout resolved by
mitrecar.engine_root; the engine's own 100-test suite lives there)."""
import json
import os

import pytest

from get_sybers_dxdfir import mitrecar

_ENGINE_ROOT = mitrecar.engine_root()
# the tool AND its nested model submodules (car + attack-datasources) must be
# present at the resolved engine root — the engine reconstructs its model live
_HAVE_TOOL = (os.path.isfile(os.path.join(_ENGINE_ROOT, "piiat_mitrecar", "pipeline.py"))
              and mitrecar._model_sources_present())


def test_engine_root_honours_byakugan_root(monkeypatch, tmp_path):
    # $BYAKUGAN_ROOT wins, and is read at call time (monkeypatchable)
    monkeypatch.setenv("BYAKUGAN_ROOT", str(tmp_path))
    assert mitrecar.engine_root() == str(tmp_path)


def test_engine_root_defaults_to_sibling_byakugan(monkeypatch):
    # without $BYAKUGAN_ROOT, the byakugan checkout next to the DX_DFIR repo
    monkeypatch.delenv("BYAKUGAN_ROOT", raising=False)
    assert mitrecar.engine_root() == os.path.join(
        os.path.dirname(mitrecar._REPO_ROOT), "byakugan")


@pytest.mark.skipif(not _HAVE_TOOL, reason="Byakugan engine checkout not provisioned")
def test_cli_end_to_end_one_source(tmp_path):
    # a minimal Security log -> the tool's own maps produce auth + session,
    # proving the external-engine CLI wiring end to end
    src = tmp_path / "Security_EvtxECmd_Output.json"
    src.write_text(json.dumps({
        "EventId": 4624, "Channel": "Security", "Computer": "HOSTA",
        "EventRecordId": 1, "TimeCreated": "2020-01-01T00:00:00Z",
        "Payload": json.dumps({"EventData": {"Data": [
            {"@Name": "TargetUserName", "#text": "alice"},
            {"@Name": "TargetLogonId", "#text": "0x111"}]}})}) + "\n")
    out = tmp_path / "car"
    proc = mitrecar.run(["--in", str(src), "--out", str(out)])
    assert proc.returncode == 0, proc.stderr
    summary = json.loads(proc.stdout)
    assert summary["objects"] == {"authentication": 1, "user_session": 1}
    assert (out / "car.db").is_file()
    assert (out / "car_authentication.jsonl").is_file()
