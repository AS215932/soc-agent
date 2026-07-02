"""Posture governance gate: shadow acts on nothing; floors + budgets bound side
effects; the SOC_MODE ladder decides case/handoff side effects."""

from __future__ import annotations

from app.cases.models import SecurityFinding
from app.config import PostureSettings
from app.posture.governance import evaluate_gate
from app.posture.ledger import DailyLedger


def _finding(severity="HIGH", passed=False, warrants=True) -> SecurityFinding:
    return SecurityFinding(
        check_id="rpki_in_frr",
        key="cr1-nl1",
        category="bgp_rpki",
        severity=severity,
        confidence="confirmed",
        passed=passed,
        warrants_handoff=warrants,
        objective_key="frr-transit-rpki-invalid-reject-v1",
    )


def _settings(**over) -> PostureSettings:
    base = dict(severity_floor="HIGH", max_findings_per_day=8, max_cost_usd_per_day=5.0, handoff_enabled=True)
    base.update(over)
    return PostureSettings(**base)


def test_shadow_acts_on_nothing():
    d = evaluate_gate(_finding(), mode="shadow", settings=_settings(), ledger=DailyLedger())
    assert d.act is False and d.open_case is False and d.build_handoff is False


def test_positive_observation_never_acts():
    d = evaluate_gate(_finding(passed=True), mode="handoff_live", settings=_settings(), ledger=DailyLedger())
    assert d.act is False
    assert "positive" in d.reason


def test_below_severity_floor_is_report_only():
    d = evaluate_gate(_finding(severity="MEDIUM"), mode="case_only", settings=_settings(severity_floor="HIGH"), ledger=DailyLedger())
    assert d.act is False
    assert "floor" in d.reason


def test_case_only_opens_case_but_no_handoff():
    d = evaluate_gate(_finding(), mode="case_only", settings=_settings(), ledger=DailyLedger())
    assert d.act is True
    assert d.open_case is True
    assert d.build_handoff is False
    assert d.post_handoff is False


def test_handoff_dry_builds_but_does_not_post():
    d = evaluate_gate(_finding(), mode="handoff_dry", settings=_settings(), ledger=DailyLedger())
    assert d.build_handoff is True
    assert d.post_handoff is False


def test_handoff_live_builds_and_posts():
    d = evaluate_gate(_finding(), mode="handoff_live", settings=_settings(), ledger=DailyLedger())
    assert d.build_handoff is True
    assert d.post_handoff is True


def test_handoff_requires_warrants_and_enabled():
    # warrants_handoff False -> no handoff even in handoff_live
    d = evaluate_gate(_finding(warrants=False), mode="handoff_live", settings=_settings(), ledger=DailyLedger())
    assert d.build_handoff is False
    # handoff disabled in settings -> no handoff
    d2 = evaluate_gate(_finding(), mode="handoff_live", settings=_settings(handoff_enabled=False), ledger=DailyLedger())
    assert d2.build_handoff is False


def test_daily_budget_exhaustion_blocks():
    ledger = DailyLedger()
    settings = _settings(max_findings_per_day=1)
    ledger.record_finding()
    d = evaluate_gate(_finding(), mode="case_only", settings=settings, ledger=ledger)
    assert d.act is False
    assert "budget" in d.reason
