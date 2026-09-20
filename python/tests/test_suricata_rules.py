"""ET Open ruleset provisioning (get_sybers_dxdfir.signatures.suricata_rules) —
pure logic, the download mocked out. The ruleset lands on the host for the
dxdfir_signatures role to mount as the operator suricata.rules."""
import io
import tarfile

import pytest

from get_sybers_dxdfir.signatures import suricata_rules


def _tar_gz(files: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_extract_rules_concatenates_only_rules_members():
    blob = _tar_gz({
        "rules/emerging-malware.rules": b"alert tcp any any -> any any (msg:\"m\"; sid:1;)\n",
        "rules/emerging-dns.rules": b"alert dns any any -> any any (msg:\"d\"; sid:2;)\n",
        "classification.config": b"config: not a rule\n",   # excluded
    })
    text, n = suricata_rules.extract_rules(blob)
    assert n == 2
    assert "sid:1;" in text and "sid:2;" in text
    assert "not a rule" not in text


def test_extract_rules_rejects_an_archive_with_no_rules():
    with pytest.raises(ValueError):
        suricata_rules.extract_rules(_tar_gz({"classification.config": b"x"}))


def test_fetch_writes_ruleset_and_is_idempotent(tmp_path, monkeypatch):
    blob = _tar_gz({"rules/a.rules": b"alert ip any any -> any any (msg:\"a\"; sid:9;)\n"})
    monkeypatch.setattr(suricata_rules, "_download", lambda url: blob)
    res = suricata_rules.fetch(str(tmp_path))
    out = tmp_path / "suricata.rules"
    assert out.is_file() and "sid:9;" in out.read_text() and res["rule_files"] == 1
    # exists -> skipped; force -> refreshed
    assert suricata_rules.fetch(str(tmp_path))["skipped"] is True
    assert suricata_rules.fetch(str(tmp_path), force=True)["skipped"] is False
