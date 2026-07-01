"""Posture governance gate: decides what a firing finding is allowed to do.

Mirrors ``hyrule-noc-agent/app/proactive/governance.py:evaluate_gate`` — in
``shadow`` nothing acts; a severity floor and the daily budget bound side
effects; and the ``SOC_MODE`` ladder decides whether a case is opened and whether
an LHP handoff is built and/or posted.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.cases.models import SecurityFinding, severity_rank
from app.config import PostureSettings, mode_builds_handoff, mode_opens_cases, mode_posts_handoff
from app.posture.ledger import DailyLedger


@dataclass
class GateDecision:
    act: bool
    open_case: bool
    build_handoff: bool
    post_handoff: bool
    reason: str


def evaluate_gate(
    finding: SecurityFinding,
    *,
    mode: str,
    settings: PostureSettings,
    ledger: DailyLedger,
) -> GateDecision:
    """Decide the side effects permitted for one firing finding this cycle."""
    if finding.passed:
        return GateDecision(False, False, False, False, "finding is a positive observation (not firing)")

    if mode == "shadow":
        return GateDecision(False, False, False, False, "shadow mode: report only")

    if severity_rank(finding.severity) < severity_rank(settings.severity_floor):
        return GateDecision(False, False, False, False, f"below severity floor {settings.severity_floor}")

    if ledger.findings_remaining(settings.max_findings_per_day) <= 0:
        return GateDecision(False, False, False, False, "daily finding budget exhausted")

    if not ledger.within_cost_budget(settings.cost_usd_per_investigation, settings.max_cost_usd_per_day):
        return GateDecision(False, False, False, False, "daily cost budget exhausted")

    open_case = mode_opens_cases(mode)
    handoff_eligible = (
        finding.warrants_handoff and settings.handoff_enabled and severity_rank(finding.severity) >= severity_rank("HIGH")
    )
    build_handoff = handoff_eligible and mode_builds_handoff(mode)
    post_handoff = handoff_eligible and mode_posts_handoff(mode)
    return GateDecision(
        act=True,
        open_case=open_case,
        build_handoff=build_handoff,
        post_handoff=post_handoff,
        reason="gated ok",
    )
