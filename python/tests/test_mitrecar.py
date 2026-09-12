"""The mitrecar lane — DX_DFIR drives the vendored byakugan engine (formerly
PIIAT-MitreCar) via its CLI (the submodule stays standalone; the engine's own
100-test suite lives there)."""
import json
import os

import pytest

from get_sybers_dxdfir import mitrecar

_SUBMODULE = mitrecar._PIIAT_MITRECAR_DIR
# the tool AND its nested model submodules (car + attack-datasources) must be
# present — the engine reconstructs its model live from them
_HAVE_TOOL = (os.path.isfile(os.path.join(_SUBMODULE, "piiat_mitrecar", "pipeline.py"))
              and mitrecar._model_sources_present())


def test_lane_points_at_the_vendored_submodule():
    assert _SUBMODULE.endswith(os.path.join("third_party", "piiat-mitrecar"))


@pytest.mark.skipif(not _HAVE_TOOL, reason="submodule not initialised")
def test_cli_end_to_end_one_source(tmp_path):
    # a minimal Security log -> the tool's own maps produce auth + session,
    # proving the vendored CLI wiring end to end
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
