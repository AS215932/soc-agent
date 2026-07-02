"""SecurityVerifier is the sole resolver and enforces No-False-All-Clear."""

from __future__ import annotations

from app.cases.models import SecurityFinding
from app.cases.policy import SecurityCasePolicy
from app.cases.service import SecurityCaseService
from app.cases.store import InMemorySecurityCaseStore
from app.cases.verifier import SecurityVerifier


def _finding(passed: bool) -> SecurityFinding:
    return SecurityFinding(
        check_id="rpki_in_frr",
        key="cr1-nl1:transit",
        category="bgp_rpki",
        severity="HIGH",
        confidence="confirmed",
        passed=passed,
    )


def _fixture(required_passes: int = 3):
    store = InMemorySecurityCaseStore()
    policy = SecurityCasePolicy(default_required_consecutive_passes=required_passes)
    svc = SecurityCaseService(store, policy)
    return store, policy, svc


def test_service_never_reaches_resolved_state():
    store, _policy, svc = _fixture()
    case = svc.observe_finding(_finding(False), cycle_id="c1").case
    for i in range(10):
        svc.observe_finding(_finding(True), cycle_id=f"p{i}")
    # Even with 10 passes, the service did not resolve — that is verifier-only.
    assert store.get_case(case.case_id).status != "resolved"


def test_verifier_resolves_after_required_consecutive_passes():
    store, policy, svc = _fixture(required_passes=3)
    case = svc.observe_finding(_finding(False), cycle_id="c1").case
    verifier = SecurityVerifier(store, policy, dry_run=False, auto_resolve=True)

    svc.observe_finding(_finding(True), cycle_id="p1")
    svc.observe_finding(_finding(True), cycle_id="p2")
    assert verifier.verify_case(case.case_id).resolved is False  # only 2 passes

    svc.observe_finding(_finding(True), cycle_id="p3")
    result = verifier.verify_case(case.case_id)
    assert result.resolved is True
    resolved = store.get_case(case.case_id)
    assert resolved.status == "resolved"
    assert resolved.resolved_at
    # The resolution event was written by the verifier actor.
    events = store.list_events(case.case_id)
    resolved_events = [e for e in events if e.event_type == "resolved"]
    assert resolved_events and resolved_events[0].actor_type == "verifier"


def test_dry_run_never_persists_resolution():
    store, policy, svc = _fixture(required_passes=1)
    case = svc.observe_finding(_finding(False), cycle_id="c1").case
    svc.observe_finding(_finding(True), cycle_id="p1")
    verifier = SecurityVerifier(store, policy, dry_run=True, auto_resolve=True)
    result = verifier.verify_case(case.case_id)
    assert result.would_resolve is True
    assert result.resolved is False
    assert store.get_case(case.case_id).status != "resolved"


def test_degraded_scan_blocks_resolution():
    store, policy, svc = _fixture(required_passes=1)
    case = svc.observe_finding(_finding(False), cycle_id="c1").case
    svc.observe_finding(_finding(True), cycle_id="p1")  # 1 pass, would satisfy count
    svc.note_scan_degraded(case.case_id, cycle_id="c2")  # but the source went degraded
    verifier = SecurityVerifier(store, policy, dry_run=False, auto_resolve=True)
    result = verifier.verify_case(case.case_id)
    assert result.would_resolve is False
    assert store.get_case(case.case_id).status != "resolved"


def test_policy_rejects_non_verifier_resolution():
    policy = SecurityCasePolicy()
    # A non-verifier actor can never transition into resolved.
    assert policy.allowed_transition("verification_pending", "resolved", actor="loop") is False
    assert policy.allowed_transition("verification_pending", "resolved", actor="engineering") is False
    assert policy.allowed_transition("verification_pending", "resolved", actor="verifier") is True
    assert policy.allowed_transition("triaged", "resolved", actor="verifier") is True
