"""verify-car is a thin front over the engine's own gate: carcheck.main runs
byakugan.verify inside the hardened get-sybers/byakugan image (via
mitrecar.run_verify) and relays its report and exit code. The CAR-correctness
checks themselves live in the engine (byakugan.verify) and are tested there."""
import subprocess
from unittest import mock

from get_sybers_dxdfir import carcheck


def test_main_relays_the_engine_gate_verdict_and_report(capsys):
    with mock.patch("get_sybers_dxdfir.mitrecar.run_verify",
                    return_value=subprocess.CompletedProcess([], 1, stdout="REPORT", stderr="warn")):
        rc = carcheck.main(["--car-dir", "/some/tree"])
    assert rc == 1                                    # the engine gate's verdict, verbatim
    out = capsys.readouterr()
    assert "REPORT" in out.out and "warn" in out.err


def test_main_passes_the_car_dir_to_the_engine_gate():
    seen = {}

    def fake_verify(car_dir):
        seen["car_dir"] = car_dir
        return subprocess.CompletedProcess([], 0, stdout="", stderr="")

    with mock.patch("get_sybers_dxdfir.mitrecar.run_verify", side_effect=fake_verify):
        assert carcheck.main(["--car-dir", "/x/y"]) == 0
    assert seen["car_dir"] == "/x/y"


def test_main_reports_missing_image_with_the_provision_hint(capsys):
    with mock.patch("get_sybers_dxdfir.mitrecar.run_verify",
                    side_effect=RuntimeError("refusing to run get-sybers/byakugan:latest")):
        rc = carcheck.main(["--car-dir", "/x"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "refusing to run" in err
    assert "build the CAR engine image" in err        # mitrecar.PROVISION_HINT


def test_default_car_dir_is_the_processed_byakugan_tree():
    assert carcheck.DEFAULT_CAR_DIR.replace("\\", "/").endswith("data_store/processed/byakugan")
