"""Red-team tier gate: RT-0/RT-1 allowed; RT-2+ hard-refused."""

from __future__ import annotations

import pytest

from app.config import RedTeamSettings
from app.redteam.policy import RedTeamGate, RedTeamRefused


def _gate(**over) -> RedTeamGate:
    base = dict(enabled=True, max_tier=1, human_gate_tier=2, allow_active_probes=False)
    base.update(over)
    return RedTeamGate(RedTeamSettings(**base))


def test_rt0_and_rt1_allowed_when_enabled():
    gate = _gate()
    assert gate.is_allowed("RT-0") is True
    assert gate.is_allowed("RT-1") is True
    gate.require("RT-0")
    gate.require("RT-1")


def test_rt2_and_above_hard_refused():
    gate = _gate(max_tier=5)  # even if the ceiling is raised, the human gate blocks
    for tier in ("RT-2", "RT-3", "RT-4", "RT-5"):
        assert gate.is_allowed(tier) is False
        with pytest.raises(RedTeamRefused):
            gate.require(tier)


def test_disabled_refuses_everything():
    gate = _gate(enabled=False)
    assert gate.is_allowed("RT-0") is False
    with pytest.raises(RedTeamRefused):
        gate.require("RT-1")


def test_max_tier_zero_refuses_rt1():
    gate = _gate(max_tier=0)
    assert gate.is_allowed("RT-1") is False
    with pytest.raises(RedTeamRefused):
        gate.require("RT-1")


def test_active_probes_flag():
    assert _gate(allow_active_probes=False).active_probes_allowed() is False
    assert _gate(allow_active_probes=True).active_probes_allowed() is True
