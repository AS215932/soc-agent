"""Guard the vendored LHP wire contract against drift from the NOC source.

``app/lhp.py`` is vendored verbatim from ``hyrule-noc-agent/app/cases/lhp.py`` so
that a SOC->engineering handoff signs and transitions identically to a NOC one.
Two loops that disagree on this module cannot interoperate. These tests fail
loudly if the vendored copy drifts on any wire-visible surface.

The NOC source path is resolved relative to this repo's sibling checkout; if it
is absent (e.g. CI without the sibling repo) the cross-repo comparison is
skipped, but the self-consistency assertions still run.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from app import lhp as soc_lhp

_NOC_LHP_PATH = Path(__file__).resolve().parents[2] / "hyrule-noc-agent" / "app" / "cases" / "lhp.py"


def _load_noc_lhp():
    if not _NOC_LHP_PATH.exists():
        pytest.skip(f"NOC lhp.py not available at {_NOC_LHP_PATH}")
    spec = importlib.util.spec_from_file_location("noc_lhp_reference", _NOC_LHP_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_vendored_file_is_byte_identical():
    noc_bytes = _NOC_LHP_PATH.read_bytes() if _NOC_LHP_PATH.exists() else None
    if noc_bytes is None:
        pytest.skip("NOC lhp.py not available")
    soc_bytes = (Path(__file__).resolve().parents[1] / "app" / "lhp.py").read_bytes()
    assert soc_bytes == noc_bytes, "app/lhp.py drifted from the NOC LHP wire contract"


def test_schema_version_and_loop_names_match():
    noc = _load_noc_lhp()
    assert soc_lhp.LHP_SCHEMA_VERSION == noc.LHP_SCHEMA_VERSION == "lhp.v1"
    assert soc_lhp.LoopName == noc.LoopName
    assert "soc" in soc_lhp.LoopName.__args__
    assert soc_lhp.VERIFIER_ONLY_HANDOFF_STATUSES == noc.VERIFIER_ONLY_HANDOFF_STATUSES


def test_transition_table_matches():
    noc = _load_noc_lhp()
    assert soc_lhp._ALLOWED_HANDOFF_TRANSITIONS == noc._ALLOWED_HANDOFF_TRANSITIONS


def test_signature_bytes_match_across_copies():
    noc = _load_noc_lhp()
    kwargs = dict(
        secret="shared-secret",
        method="get",
        path="/loop-handoff/v1/soc/handoffs/handoff_abc",
        timestamp="2026-07-01T00:00:00+00:00",
        body={"z": 1, "a": [3, 2, 1], "nested": {"b": True}},
    )
    assert soc_lhp.build_loop_signature(**kwargs) == noc.build_loop_signature(**kwargs)


def test_verifier_only_statuses_gated_to_soc_origin():
    # SOC is an origin loop: as its own verifier it may reach verified/resolved,
    # but a non-origin actor (engineering) may not set them.
    assert soc_lhp.allowed_handoff_transition("implemented", "verified", actor_loop="noc") is True
    assert soc_lhp.allowed_handoff_transition("implemented", "verified", actor_loop="engineering") is False
