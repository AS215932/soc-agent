"""SecurityVerifier — the *only* component that may resolve a SOC case.

Enforces No-False-All-Clear at resolution time: a case resolves only when the
policy's ``can_resolve`` gate is satisfied (enough consecutive healthy positive
re-checks, last scan not degraded). Ships dry-run by default; auto-resolve is a
separate switch. In Phase 6 this is driven off an LHP ``change_applied`` callback
so a handoff's fix is re-verified against live telemetry before the case closes.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.cases.models import SecurityCase, SecurityCaseEvent, utc_now
from app.cases.policy import SecurityCasePolicy
from app.cases.store import SecurityCaseStore


@dataclass
class VerifyResult:
    case: SecurityCase
    would_resolve: bool
    resolved: bool
    reason: str = ""


class SecurityVerifier:
    def __init__(
        self,
        store: SecurityCaseStore,
        policy: SecurityCasePolicy | None = None,
        *,
        dry_run: bool = True,
        auto_resolve: bool = False,
    ) -> None:
        self.store = store
        self.policy = policy or SecurityCasePolicy()
        self.dry_run = dry_run
        self.auto_resolve = auto_resolve

    def verify_case(self, case_id: str, *, reason: str = "positive re-check threshold met") -> VerifyResult | None:
        case = self.store.get_case(case_id)
        if case is None:
            return None
        if case.status in {"resolved", "closed"}:
            return VerifyResult(case=case, would_resolve=False, resolved=False, reason="already terminal")

        would = self.policy.can_resolve(case)
        if not (would and self.auto_resolve and not self.dry_run):
            return VerifyResult(case=case, would_resolve=would, resolved=False, reason="" if would else "gate not met")

        # Verifier is the sole actor permitted to reach ``resolved``.
        self.policy.require_transition(case.status, "resolved", actor="verifier")
        prior = case.status
        case.status = "resolved"
        case.resolved_at = utc_now()
        case.resolution_reason = reason
        case.updated_at = case.resolved_at
        case.handoff_status = "resolved" if case.handoff_ids else case.handoff_status
        self.store.put_case(case)

        # Mark the case's verification objectives as passed.
        for objective in self.store.list_objectives(case_id=case_id):
            objective.status = "pass"
            objective.consecutive_pass_count = case.consecutive_pass_count
            objective.last_checked_at = case.resolved_at
            self.store.put_objective(objective)

        self.store.append_event(
            SecurityCaseEvent(
                case_id=case_id,
                event_type="resolved",
                actor_type="verifier",
                actor_id="soc_verifier",
                payload={
                    "from": prior,
                    "consecutive_pass_count": case.consecutive_pass_count,
                    "required": case.required_consecutive_passes,
                    "reason": reason,
                },
            )
        )
        return VerifyResult(case=case, would_resolve=True, resolved=True, reason=reason)
