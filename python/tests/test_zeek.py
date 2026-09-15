"""Unit tests for the pure logic of the zeek processor (no docker needed)."""
import struct

from get_sybers_dxdfir import zeek


def test_clean_name_folds_dirs_and_extension():
    assert zeek.clean_name("a/b/packets.pcap") == "a_b_packets_pcap"
    assert zeek.clean_name("cap with space.pcapng") == "cap_with_space_pcapng"


def test_is_pcap_by_magic_bytes(tmp_path):
    p = tmp_path / "nomatch.bin"
    p.write_bytes(struct.pack("<I", 0xA1B2C3D4))  # classic pcap LE magic
    assert zeek.is_pcap(str(p)) is True


def test_is_pcap_by_extension(tmp_path):
    p = tmp_path / "weird.pcap"
    p.write_bytes(b"not-a-magic")
    assert zeek.is_pcap(str(p)) is True


def test_is_pcap_rejects_plain_file(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_bytes(b"hello world")
    assert zeek.is_pcap(str(p)) is False


def test_collect_skips_symlinked_output(tmp_path):
    """A symlinked *.log the tool planted in its output mount is never relocated
    into the processed tree (it would carry a link to a host file downstream)."""
    import os
    temp = tmp_path / "logs"; temp.mkdir()
    out = tmp_path / "out"
    secret = tmp_path / "secret"; secret.write_text("HOST SECRET\n")
    (temp / "conn.log").write_text('{"ok":1}\n')            # a real log
    os.symlink(secret, temp / "evil.log")                    # a planted symlink
    produced = zeek._collect(str(temp), str(out))
    assert produced == ["conn.json"]                         # only the real log
    assert not (out / "evil.json").exists()                  # the symlink was skipped
