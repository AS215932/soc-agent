"""SecurityCaseService lifecycle + dedup + handoff."""

from __future__ import annotations

from app.cases.models import DesiredStateRef, SecurityEvidence, SecurityFinding
from app.cases.service import SecurityCaseService
from app.cases.store import InMemorySecurityCaseStore, JsonlSecurityCaseStore


def _finding(passed: bool, **over) -> SecurityFinding:
    kw = dict(
        check_id="rpki_in_frr",
        key="cr1-nl1:transit",
        category="bgp_rpki",
        control_domain="rpki_irr",
        title="RPKI-invalid reject missing",
        severity="HIGH",
        confidence="confirmed",
        passed=passed,
        warrants_handoff=True,
        objective_key="frr-transit-rpki-invalid-reject-v1",
        resource="cr1-nl1",
        desired_state_refs=[DesiredStateRef(path="configs/cr1-nl1/frr.conf", content_sha="sha1")],
        evidence=[SecurityEvidence(source_tool="frr_vtysh_cmd", query="show route-map TRANSIT-IN")],
    )
    kw.update(over)
    return SecurityFinding(**kw)


def _svc() -> SecurityCaseService:
    return SecurityCaseService(InMemorySecurityCaseStore())


def test_firing_finding_opens_and_triages_case():
    svc = _svc()
    res = svc.observe_finding(_finding(False), cycle_id="c1")
    assert res.created is True
    assert res.case.status == "triaged"
    assert res.case.severity == "HIGH"
    assert res.case.consecutive_pass_count == 0
    events = [e.event_type for e in svc.store.list_events(res.case.case_id)]
    assert "case_opened" in events and "triaged" in events


def test_refiring_dedupes_by_fingerprint():
    svc = _svc()
    a = svc.observe_finding(_finding(False), cycle_id="c1")
    b = svc.observe_finding(_finding(False, finding_id="secf_second"), cycle_id="c2")
    assert a.case.case_id == b.case.case_id  # same fingerprint -> same case
    assert b.created is False
    assert len(svc.store.list_cases()) == 1


def test_passing_finding_accumulates_but_does_not_resolve():
    svc = _svc()
    opened = svc.observe_finding(_finding(False), cycle_id="c1").case
    for i in range(5):
        svc.observe_finding(_finding(True), cycle_id=f"p{i}")
    case = svc.store.get_case(opened.case_id)
    assert case.consecutive_pass_count == 5
    assert case.status == "triaged"  # service never resolves; verifier does
    assert case.status != "resolved"


def test_fresh_failure_resets_pass_streak():
    svc = _svc()
    svc.observe_finding(_finding(False), cycle_id="c1")
    svc.observe_finding(_finding(True), cycle_id="p1")
    svc.observe_finding(_finding(True), cycle_id="p2")
    case_id = svc.store.list_cases()[0].case_id
    assert svc.store.get_case(case_id).consecutive_pass_count == 2
    svc.observe_finding(_finding(False), cycle_id="c2")  # drift returns
    assert svc.store.get_case(case_id).consecutive_pass_count == 0


def test_degraded_scan_marks_carry_forward():
    svc = _svc()
    case = svc.observe_finding(_finding(False), cycle_id="c1").case
    svc.note_scan_degraded(case.case_id, cycle_id="c2")
    refreshed = svc.store.get_case(case.case_id)
    assert refreshed.last_scan_degraded is True


def test_request_handoff_persists_and_transitions():
    svc = _svc()
    finding = _finding(False)
    case = svc.observe_finding(finding, cycle_id="c1").case
    bundle = svc.request_handoff(case.case_id, finding)
    assert bundle is not None
    refreshed = svc.store.get_case(case.case_id)
    assert refreshed.status == "handoff_requested"
    assert bundle.handoff.handoff_id in refreshed.handoff_ids
    assert svc.store.get_handoff(bundle.handoff.handoff_id) is not None
    assert len(svc.store.list_objectives(handoff_id=bundle.handoff.handoff_id)) == 1


def test_request_handoff_is_idempotent():
    svc = _svc()
    finding = _finding(False)
    case = svc.observe_finding(finding, cycle_id="c1").case
    first = svc.request_handoff(case.case_id, finding)
    second = svc.request_handoff(case.case_id, finding)
    assert first.handoff.handoff_id == second.handoff.handoff_id
    # Only one handoff persisted.
    assert svc.store.get_handoff_by_idempotency_key(first.handoff.idempotency_key) is not None


def test_jsonl_store_survives_reload(tmp_path):
    store = JsonlSecurityCaseStore(tmp_path / "state")
    svc = SecurityCaseService(store)
    finding = _finding(False)
    case = svc.observe_finding(finding, cycle_id="c1").case
    svc.request_handoff(case.case_id, finding)

    # Reload from disk into a fresh store.
    reloaded = JsonlSecurityCaseStore(tmp_path / "state")
    got = reloaded.get_case(case.case_id)
    assert got is not None and got.status == "handoff_requested"
    assert reloaded.get_case_by_fingerprint(finding.fingerprint()) is not None
    assert len(reloaded.list_objectives(case_id=case.case_id)) == 1
