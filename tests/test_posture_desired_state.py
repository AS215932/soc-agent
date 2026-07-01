"""Desired-state loaders parse the real network-operations fixtures."""

from __future__ import annotations

from pathlib import Path

from app.posture.desired_state import DesiredState, content_sha

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "desired_state"


def _ds() -> DesiredState:
    return DesiredState.from_settings(repo_dir=FIXTURES, pin_sha="pinsha123")


def test_frr_conf_loads_and_sha_is_stable():
    ds = _ds()
    frr = ds.frr_conf("cr1-nl1")
    assert frr.exists
    assert "router bgp 215932" in frr.text
    assert frr.path == "configs/cr1-nl1/frr.conf"
    assert frr.content_sha == content_sha(frr.text)
    assert ds.frr_conf("cr1-nl1").content_sha == frr.content_sha  # deterministic


def test_missing_file_is_empty_not_an_error():
    ds = _ds()
    missing = ds.frr_conf("does-not-exist")
    assert missing.exists is False
    assert missing.content_sha == ""


def test_wg_confs_discovered():
    ds = _ds()
    wgs = ds.wg_confs("cr1-nl1")
    assert any(w.path.endswith("wg0.conf") for w in wgs)


def test_manifest_invariants():
    ds = _ds()
    assert ds.asn == 215932
    assert "2a0c:b641:b50::/44" in ds.owned_prefixes
    assert 34872 in ds.transit_asns
    assert "as215932.net" in ds.management_domains


def test_is_owned_address():
    ds = _ds()
    assert ds.is_owned_address("2a0c:b641:b50::a") is True
    assert ds.is_owned_address("2a0c:b641:b50:ff00::1") is True
    assert ds.is_owned_address("2001:4860:4860::8888") is False  # Google DNS, not owned
    assert ds.is_owned_address("not-an-ip") is False
