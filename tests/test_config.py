"""Config precedence + conservative-default guarantees.

The SOC Agent must ship inert: every behaviour-changing switch defaults off and
``SOC_MODE`` defaults to ``shadow``. These tests are the tripwire against a
default silently flipping on.
"""

from __future__ import annotations

import pytest

from app import config


def test_toml_defaults_are_conservative():
    s = config.load_settings()
    assert s.enabled is False
    assert s.mode == "shadow"
    assert s.posture.enabled is False
    assert s.posture.handoff_enabled is False
    assert s.posture.severity_floor == "HIGH"
    assert s.redteam.enabled is False
    assert s.redteam.allow_active_probes is False
    assert s.redteam.max_tier == 1  # RT-0 + RT-1
    assert s.guardrails.enable_approved_execution is False
    assert s.guardrails.human_gate_all_mutations is True
    assert s.loop_handoff.enabled is False
    assert s.loop_handoff.case_auto_resolve_enabled is False
    assert s.loop_handoff.loop_identity == "soc"
    # The bundled config/soc-agent.toml must parse cleanly.
    assert s.load_errors == []
    assert s.source_path and s.source_path.endswith("soc-agent.toml")


def test_env_overrides_take_precedence(monkeypatch):
    monkeypatch.setenv("SOC_ENABLED", "1")
    monkeypatch.setenv("SOC_MODE", "handoff_dry")
    monkeypatch.setenv("SOC_POSTURE_ENABLED", "true")
    monkeypatch.setenv("SOC_POSTURE_MAX_FINDINGS_PER_DAY", "3")
    monkeypatch.setenv("SOC_POSTURE_SEVERITY_FLOOR", "medium")
    monkeypatch.setenv("SOC_ALLOWED_HOSTS", "cr1-nl1, cr1-de1")
    monkeypatch.setenv("SOC_REDTEAM_MAX_TIER", "0")
    s = config.load_soc_settings()
    assert s.enabled is True
    assert s.mode == "handoff_dry"
    assert s.posture.enabled is True
    assert s.posture.max_findings_per_day == 3
    assert s.posture.severity_floor == "MEDIUM"  # normalized upper
    assert s.posture.allowed_hosts == ["cr1-nl1", "cr1-de1"]
    assert s.redteam.max_tier == 0


def test_invalid_mode_falls_back_to_shadow(monkeypatch):
    monkeypatch.setenv("SOC_MODE", "handoff_live_now_please")
    s = config.load_soc_settings()
    assert s.mode == "shadow"
    assert any("SOC_MODE" in e for e in s.load_errors)


@pytest.mark.parametrize(
    "mode,opens,builds,posts",
    [
        ("shadow", False, False, False),
        ("case_only", True, False, False),
        ("handoff_dry", True, True, False),
        ("handoff_live", True, True, True),
        ("probe_dry", True, True, True),
        ("probe_live", True, True, True),
    ],
)
def test_mode_ladder_predicates(mode, opens, builds, posts):
    assert config.mode_opens_cases(mode) is opens
    assert config.mode_builds_handoff(mode) is builds
    assert config.mode_posts_handoff(mode) is posts


def test_lhp_secret_only_reports_presence(monkeypatch):
    monkeypatch.delenv(config.LHP_ENGINEERING_SECRET_ENV, raising=False)
    assert config.load_loop_handoff_settings().engineering_secret_configured is False
    monkeypatch.setenv(config.LHP_ENGINEERING_SECRET_ENV, "super-secret-value")
    lh = config.load_loop_handoff_settings()
    assert lh.engineering_secret_configured is True
    # The value itself is never surfaced on the settings object.
    assert "super-secret-value" not in repr(lh)
