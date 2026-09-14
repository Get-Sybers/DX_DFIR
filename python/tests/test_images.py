"""Tool-image inventory guard (get_sybers_dxdfir.images) — pure logic, docker
mocked out. Focus: the supply-chain guard must accept a documented digest-pin
override the same way it accepts the :latest tag (regression guard for the
dxdfir_lane preflight that runs require() on every lane image)."""
import pytest

from get_sybers_dxdfir import images

_HARDENED = {"User": images.REQUIRED_USER, "Labels": {images.HARDENED_LABEL: "true"}}


def test_repo_strips_tag_and_digest_keeps_registry_port():
    cases = {
        "get-sybers/goevtx:latest": "get-sybers/goevtx",
        "get-sybers/goevtx@sha256:" + "a" * 64: "get-sybers/goevtx",
        "get-sybers/goevtx:latest@sha256:" + "b" * 64: "get-sybers/goevtx",
        "get-sybers/goevtx": "get-sybers/goevtx",
        # a ':' before the last '/' is a registry port, not a tag — keep it
        "registry.example.com:5000/get-sybers/goevtx:latest":
            "registry.example.com:5000/get-sybers/goevtx",
        "registry.example.com:5000/get-sybers/goevtx@sha256:" + "c" * 64:
            "registry.example.com:5000/get-sybers/goevtx",
    }
    for ref, want in cases.items():
        assert images._repo(ref) == want, ref


def test_require_accepts_digest_pinned_known_image(monkeypatch):
    """A digest-pin override (documented, e.g. dxdfir_evtx_image) must pass the
    guard exactly like its :latest tag — not be rejected as an unknown repo."""
    monkeypatch.setattr(images, "_inspect", lambda img: _HARDENED)
    images.require("get-sybers/goevtx@sha256:" + "a" * 64)  # must not raise
    images.require("get-sybers/goevtx:latest")              # must not raise


def test_require_rejects_unknown_repo(monkeypatch):
    monkeypatch.setattr(images, "_inspect", lambda img: _HARDENED)
    with pytest.raises(RuntimeError):
        images.require("get-sybers/notatool:latest")


def test_require_rejects_unhardened_known_image(monkeypatch):
    monkeypatch.setattr(images, "_inspect",
                        lambda img: {"User": "0:0", "Labels": {}})
    with pytest.raises(RuntimeError):
        images.require("get-sybers/goevtx:latest")


def test_require_passes_through_non_namespace_image(monkeypatch):
    """An operator-supplied non-get-sybers image is out of scope and passes
    untouched (require never inspects it)."""
    def _boom(img):  # would fail the test if inspection were attempted
        raise AssertionError("should not inspect a non-get-sybers image")
    monkeypatch.setattr(images, "_inspect", _boom)
    images.require("docker.io/library/ubuntu:22.04")  # must not raise
