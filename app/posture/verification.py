"""Verifier close-loop: re-read live telemetry to resolve a fixed case.

A case reaches ``verification_pending`` when the Engineering Loop reports the fix
landed (LHP ``change_applied`` callback) — not on a blind timer. This loop then
targeted-re-scans the exact control for the case's resource and folds the result
in: a healthy read accrues a positive re-check; a *degraded* read or an absent
signal resolves nothing (No-False-All-Clear). Only ``SecurityVerifier`` resolves.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app import log
from app.cases.models import SecurityCase
from app.cases.service import SecurityCaseService
from app.cases.verifier import SecurityVerifier
from app.posture.desired_state import DesiredState
from app.posture.scanner import ScanContext, scan

# Cases actively awaiting a positive re-read before they can resolve.
_VERIFIABLE_STATUSES = frozenset({"verification_pending", "handoff_in_progress"})


@dataclass
class VerificationCycleReport:
    cycle_id: str
    checked: int = 0
    resolved: list[str] = field(default_factory=list)
    still_failing: list[str] = field(default_factory=list)
    degraded: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


class PostureVerificationLoop:
    def __init__(
        self,
        *,
        service: SecurityCaseService,
        verifier: SecurityVerifier,
        mcp_runtime: Any,
        desired_state: DesiredState,
    ) -> None:
        self.service = service
        self.verifier = verifier
        self.mcp_runtime = mcp_runtime
        self.desired_state = desired_state

    async def run_once(self, *, cycle_id: str = "verify") -> VerificationCycleReport:
        report = VerificationCycleReport(cycle_id=cycle_id)
        for case in self.service.store.list_cases():
            if case.status in _VERIFIABLE_STATUSES:
                await self._verify_case(case, report, cycle_id=cycle_id)
        return report

    async def verify_case_now(self, case_id: str, *, cycle_id: str = "verify") -> VerificationCycleReport:
        """Re-verify a single case immediately (e.g. right after a change_applied
        callback) rather than waiting for the next sweep."""
        report = VerificationCycleReport(cycle_id=cycle_id)
        case = self.service.store.get_case(case_id)
        if case is not None and case.status in _VERIFIABLE_STATUSES:
            await self._verify_case(case, report, cycle_id=cycle_id)
        return report

    async def _verify_case(self, case: SecurityCase, report: VerificationCycleReport, *, cycle_id: str) -> None:
        report.checked += 1
        host = case.resource_id
        if not host:
            report.skipped.append(case.case_id)
            return

        ctx = ScanContext(mcp_runtime=self.mcp_runtime, desired_state=self.desired_state, cycle_id=cycle_id)
        scan_report = await scan(ctx, hosts=[host], deep=True)
        match = next((f for f in scan_report.findings if f.fingerprint() == case.fingerprint), None)

        # No-False-All-Clear: a degraded read or an absent signal never resolves.
        if scan_report.degraded or match is None:
            self.service.note_scan_degraded(case.case_id, cycle_id=cycle_id)
            report.degraded.append(case.case_id)
            log.info("soc_verify_degraded", case_id=case.case_id, host=host, matched=match is not None)
            return

        self.service.observe_finding(match, cycle_id=cycle_id)
        result = self.verifier.verify_case(case.case_id)
        if result is not None and result.resolved:
            report.resolved.append(case.case_id)
            log.info("soc_verify_resolved", case_id=case.case_id, host=host)
        elif not match.passed:
            report.still_failing.append(case.case_id)
