"""SecurityCaseService — the single owner of SOC case lifecycle.

Analogue of the NOC ``CaseService``, minimised for the SOC v1 substrate. It is
the only writer of case state *except* for ``resolved``, which is reserved for
``SecurityVerifier`` (No-False-All-Clear). Every mutation appends a
``SecurityCaseEvent`` for the audit trail.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.cases.models import (
    HandoffBundle,
    SecurityCase,
    SecurityCaseEvent,
    SecurityFinding,
    utc_now,
)
from app.cases.policy import SecurityCasePolicy
from app.cases.store import SecurityCaseStore
from app.lhp import (
    CallbackInboxRecord,
    CaseHandoff,
    HandoffUpdate,
    lhp_payload_hash,
    require_handoff_transition,
)

# Map an engineering-loop handoff status onto the SOC case status.
_HANDOFF_TO_CASE_STATUS: dict[str, str] = {
    "accepted": "handoff_in_progress",
    "in_progress": "handoff_in_progress",
    "change_planned": "handoff_in_progress",
    "implemented": "verification_pending",
    "blocked": "blocked",
    "failed": "failed",
    "needs_human": "needs_human",
}


@dataclass
class ObserveResult:
    case: SecurityCase
    created: bool
    changed: bool
    reopened: bool = False


@dataclass
class EngineeringUpdateResult:
    update: HandoffUpdate
    handoff: CaseHandoff | None
    case: SecurityCase | None
    created: bool
    duplicate: bool = False


class SecurityCaseService:
    def __init__(self, store: SecurityCaseStore, policy: SecurityCasePolicy | None = None) -> None:
        self.store = store
        self.policy = policy or SecurityCasePolicy()

    # --- observation ------------------------------------------------------

    def observe_finding(self, finding: SecurityFinding, *, cycle_id: str = "") -> ObserveResult:
        """Fold a confident (non-degraded) check result into case state.

        A firing finding (``passed=False``) opens or refreshes a case and resets
        the No-False-All-Clear pass counter. A passing finding (``passed=True``)
        records a positive re-check on the matching active case but never
        resolves it — that is the verifier's job.
        """
        self.store.put_finding(finding)
        fingerprint = finding.fingerprint()
        existing = self.store.get_case_by_fingerprint(fingerprint)

        if not finding.passed:
            return self._record_failing(finding, existing, cycle_id=cycle_id)
        if existing is not None:
            return self._record_passing(finding, existing, cycle_id=cycle_id)
        # A passing observation with no open case: nothing to track.
        placeholder = self._case_from_finding(finding, fingerprint=fingerprint)
        return ObserveResult(case=placeholder, created=False, changed=False)

    def note_scan_degraded(self, case_id: str, *, cycle_id: str = "") -> None:
        """Carry-forward: the check for this case could not read cleanly this
        cycle. Mark it so the verifier cannot resolve on stale/absent signal."""
        case = self.store.get_case(case_id)
        if case is None:
            return
        case.last_scan_degraded = True
        case.last_scan_cycle_id = cycle_id
        case.last_evaluated_at = utc_now()
        case.updated_at = utc_now()
        self.store.put_case(case)
        self._emit(case_id, "scan_degraded", {"cycle_id": cycle_id})

    # --- lifecycle transitions -------------------------------------------

    def triage(self, case_id: str, *, actor: str = "loop") -> SecurityCase | None:
        return self._transition(case_id, "triaged", actor=actor, event="triaged")

    def mark_needs_human(self, case_id: str, reason: str = "", *, actor: str = "loop") -> SecurityCase | None:
        return self._transition(case_id, "needs_human", actor=actor, event="needs_human", payload={"reason": reason})

    def acknowledge(self, case_id: str, operator: str) -> SecurityCase | None:
        case = self.store.get_case(case_id)
        if case is None:
            return None
        case.acknowledged_by = operator
        case.acknowledged_at = utc_now()
        case.updated_at = utc_now()
        self.store.put_case(case)
        self._emit(case_id, "acknowledged", {"operator": operator}, actor_type="operator", actor_id=operator)
        return case

    def request_handoff(
        self, case_id: str, finding: SecurityFinding, *, required_consecutive_passes: int | None = None
    ) -> HandoffBundle | None:
        """Build + persist the LHP handoff for a finding and move the case to
        ``handoff_requested``. Idempotent by the handoff idempotency key."""
        case = self.store.get_case(case_id)
        if case is None:
            return None
        passes = required_consecutive_passes or case.required_consecutive_passes
        bundle = finding.build_handoff(case, required_consecutive_passes=passes)

        existing = self.store.get_handoff_by_idempotency_key(bundle.handoff.idempotency_key)
        if existing is not None:
            # Already requested; return the existing handoff + its objectives.
            objectives = self.store.list_objectives(handoff_id=existing.handoff_id)
            return HandoffBundle(handoff=existing, objectives=objectives, knowledge_payload=bundle.knowledge_payload)

        self.store.put_handoff(bundle.handoff)
        for objective in bundle.objectives:
            self.store.put_objective(objective)

        if case.status not in {"handoff_requested", "handoff_in_progress"}:
            self.policy.require_transition(case.status, "handoff_requested", actor="loop")
            case.status = "handoff_requested"
        if bundle.handoff.handoff_id not in case.handoff_ids:
            case.handoff_ids.append(bundle.handoff.handoff_id)
        case.handoff_status = bundle.handoff.status
        case.last_handoff_at = utc_now()
        case.updated_at = utc_now()
        self.store.put_case(case)
        self._emit(
            case_id,
            "handoff_requested",
            {"handoff_id": bundle.handoff.handoff_id, "objective_key": bundle.handoff.objective_key},
        )
        return bundle

    def record_issue(self, case_id: str, *, issue_url: str, issue_id: str = "") -> SecurityCase | None:
        case = self.store.get_case(case_id)
        if case is None:
            return None
        case.issue_url = issue_url
        case.issue_id = issue_id
        case.updated_at = utc_now()
        self.store.put_case(case)
        self._emit(case_id, "issue_opened", {"issue_url": issue_url, "issue_id": issue_id})
        return case

    def record_engineering_update(self, update: HandoffUpdate) -> EngineeringUpdateResult:
        """Apply an inbound engineering-loop LHP callback (deduped by
        ``external_event_id``). Engineering may push non-terminal progress; the
        vendored ``HandoffUpdate`` validator already forbids it from setting
        ``verified``/``resolved`` (verifier-only, SOC-owned)."""
        existing = self.store.get_callback(update.external_event_id)
        if existing is not None:
            return EngineeringUpdateResult(
                update=update,
                handoff=self.store.get_handoff(update.handoff_id),
                case=self.store.get_case(update.case_id),
                created=False,
                duplicate=True,
            )

        handoff = self.store.get_handoff(update.handoff_id)
        if handoff is None:
            raise ValueError(f"unknown handoff {update.handoff_id!r}")

        require_handoff_transition(handoff.status, update.status, actor_loop="engineering")
        handoff.status = update.status
        handoff.updated_at = utc_now()
        self.store.put_handoff(handoff)

        case = self.store.get_case(update.case_id)
        if case is not None:
            target = _HANDOFF_TO_CASE_STATUS.get(update.status)
            if update.update_type == "change_applied":
                target = "verification_pending"  # a fix landed → re-verify against live telemetry
            if target and case.status != target and self.policy.allowed_transition(
                case.status, target, actor="engineering"
            ):
                case.status = target
            case.handoff_status = update.status
            case.updated_at = utc_now()
            self.store.put_case(case)
            self._emit(
                case.case_id,
                "engineering_update",
                {"update_type": update.update_type, "status": update.status, "handoff_id": update.handoff_id},
                actor_type="engineering",
                actor_id="engineering_loop",
            )

        self.store.put_callback(
            CallbackInboxRecord(
                source_loop="engineering",
                external_event_id=update.external_event_id,
                payload_hash=lhp_payload_hash(update.model_dump(mode="json")),
                handoff_id=update.handoff_id,
                case_id=update.case_id,
                result_payload={"handoff_status": handoff.status, "case_status": case.status if case else ""},
            )
        )
        return EngineeringUpdateResult(update=update, handoff=handoff, case=case, created=True)

    # --- internals --------------------------------------------------------

    def _record_failing(
        self, finding: SecurityFinding, existing: SecurityCase | None, *, cycle_id: str
    ) -> ObserveResult:
        now = utc_now()
        signature = _finding_signature(finding)
        if existing is None:
            case = self._case_from_finding(finding, fingerprint=finding.fingerprint())
            case.status = "open"
            case.signal_signature = signature
            case.last_observed_failing = now
            case.last_evaluated_at = now
            case.last_scan_cycle_id = cycle_id
            case.last_scan_degraded = False
            case.consecutive_pass_count = 0
            case.finding_ids = [finding.finding_id]
            self.store.put_case(case)
            self._emit(case.case_id, "case_opened", {"finding_id": finding.finding_id, "severity": finding.severity})
            # A finding is itself triage: move open -> triaged so it is resolvable later.
            self._transition(case.case_id, "triaged", actor="loop", event="triaged")
            return ObserveResult(case=self.store.get_case(case.case_id) or case, created=True, changed=True)

        case = existing
        reopened = False
        if case.status in {"resolved", "closed"}:
            self.policy.require_transition(case.status, "open", actor="loop")
            case.status = "open"
            case.resolved_at = ""
            reopened = True
        case.previous_signal_signature = case.signal_signature
        changed = signature != case.signal_signature
        case.signal_signature = signature
        case.severity = finding.severity
        case.confidence = finding.confidence
        case.last_observed_failing = now
        case.last_evaluated_at = now
        case.last_scan_cycle_id = cycle_id
        case.last_scan_degraded = False
        case.consecutive_pass_count = 0  # any fresh failure resets the clean streak
        if finding.finding_id not in case.finding_ids:
            case.finding_ids.append(finding.finding_id)
        case.updated_at = now
        self.store.put_case(case)
        self._emit(
            case.case_id,
            "reopened" if reopened else "refresh_failing",
            {"finding_id": finding.finding_id, "signature_changed": changed},
        )
        if reopened:
            self._transition(case.case_id, "triaged", actor="loop", event="triaged")
        return ObserveResult(case=self.store.get_case(case.case_id) or case, created=False, changed=changed, reopened=reopened)

    def _record_passing(
        self, finding: SecurityFinding, case: SecurityCase, *, cycle_id: str
    ) -> ObserveResult:
        now = utc_now()
        if case.status in {"resolved", "closed"}:
            return ObserveResult(case=case, created=False, changed=False)
        case.last_observed_passing = now
        case.last_evaluated_at = now
        case.last_scan_cycle_id = cycle_id
        case.last_scan_degraded = False
        case.consecutive_pass_count += 1
        case.updated_at = now
        self.store.put_case(case)
        self._emit(
            case.case_id,
            "positive_recheck",
            {"consecutive_pass_count": case.consecutive_pass_count, "required": case.required_consecutive_passes},
        )
        return ObserveResult(case=self.store.get_case(case.case_id) or case, created=False, changed=True)

    def _case_from_finding(self, finding: SecurityFinding, *, fingerprint: str) -> SecurityCase:
        return SecurityCase(
            case_type=finding.case_type,
            category=finding.category,
            control_domain=finding.control_domain,
            title=finding.title,
            summary=finding.summary,
            origin="redteam" if finding.case_type == "redteam_exercise" else "proactive",
            severity=finding.severity,
            confidence=finding.confidence,
            mitre_tactics=list(finding.mitre_tactics),
            mitre_techniques=list(finding.mitre_techniques),
            resource_id=finding.resource,
            site=finding.site,
            fingerprint=fingerprint,
            required_consecutive_passes=self.policy.default_required_consecutive_passes,
            policy_version=self.policy.policy_version,
        )

    def _transition(
        self,
        case_id: str,
        target: str,
        *,
        actor: str,
        event: str,
        payload: dict | None = None,
    ) -> SecurityCase | None:
        case = self.store.get_case(case_id)
        if case is None:
            return None
        if case.status == target:
            return case
        self.policy.require_transition(case.status, target, actor=actor)
        prior = case.status
        case.status = target
        case.updated_at = utc_now()
        self.store.put_case(case)
        self._emit(case_id, event, {**(payload or {}), "from": prior, "to": target}, actor_type=_actor_type(actor))
        return case

    def _emit(
        self,
        case_id: str,
        event_type: str,
        payload: dict,
        *,
        actor_type: str = "loop",
        actor_id: str = "soc_agent_loop",
    ) -> None:
        self.store.append_event(
            SecurityCaseEvent(
                case_id=case_id,
                event_type=event_type,
                actor_type=actor_type,  # type: ignore[arg-type]
                actor_id=actor_id,
                payload=payload,
            )
        )


def _actor_type(actor: str) -> str:
    return {
        "loop": "loop",
        "verifier": "verifier",
        "operator": "operator",
        "engineering": "engineering",
        "system": "system",
    }.get(actor, "loop")


def _finding_signature(finding: SecurityFinding) -> str:
    from app.cases.models import _signature

    return _signature(finding.check_id, finding.key, {"severity": finding.severity, "passed": finding.passed})
