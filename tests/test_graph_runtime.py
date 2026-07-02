"""SOC commander graph: routes, enriches, gates on HITL, terminates at handoff."""

from __future__ import annotations

from pydantic_ai.models.test import TestModel

from app.cases.models import DesiredStateRef, SecurityEvidence, SecurityFinding
from app.graph.nodes import SocGraphRuntime
from app.graph_runtime import SocGraphSession


def _finding_dict(**over) -> dict:
    f = SecurityFinding(
        check_id="rpki_in_frr",
        key="cr1-nl1",
        category="bgp_rpki",
        control_domain="rpki_irr",
        title="RPKI-invalid reject missing",
        severity="HIGH",
        confidence="confirmed",
        passed=False,
        warrants_handoff=True,
        objective_key="frr-transit-rpki-invalid-reject-v1",
        mitre_techniques=["T1557"],
        resource="cr1-nl1",
        desired_state_refs=[DesiredStateRef(path="configs/cr1-nl1/frr.conf", content_sha="sha")],
        evidence=[SecurityEvidence(source_tool="frr_vtysh_cmd", query="show route-map TRANSIT-IN")],
        recommended_remediation=["add rpki reject"],
    )
    d = f.model_dump(mode="json")
    d.update(over)
    return d


async def test_deterministic_run_routes_and_pauses_for_approval():
    session = SocGraphSession(SocGraphRuntime(model=None))
    state = await session.start(_finding_dict(), thread_id="t1", case_id="sec_case_1")
    # graph paused at approval_interrupt
    payload = session.interrupt_payload(state)
    assert payload is not None
    assert payload["approval_state"] == "waiting_approval"
    assert payload["title"] == "RPKI-invalid reject missing"
    assert state["specialist"] == "routing_security"
    assert state["enriched_finding"]["severity"] == "HIGH"


async def test_approve_reaches_handoff_request():
    session = SocGraphSession(SocGraphRuntime(model=None))
    await session.start(_finding_dict(), thread_id="t2", case_id="sec_case_1")
    final = await session.resume({"decision": "approve", "operator": "svag"}, thread_id="t2")
    assert final["approval_state"] == "approved"
    assert final.get("handoff_requested") is True


async def test_reject_ends_without_handoff():
    session = SocGraphSession(SocGraphRuntime(model=None))
    await session.start(_finding_dict(), thread_id="t3", case_id="sec_case_1")
    final = await session.resume({"decision": "reject"}, thread_id="t3")
    assert final["approval_state"] == "rejected"
    assert final.get("handoff_requested") in (None, False)


async def test_evidence_validation_downweights_without_direct_measurement():
    session = SocGraphSession(SocGraphRuntime(model=None))
    # only static/git evidence -> confidence lowered from confirmed
    finding = _finding_dict(evidence=[{"source_tool": "git", "query": "wg0.conf", "label": "", "observed_value": "", "expected_value": "", "detail": ""}])
    state = await session.start(finding, thread_id="t4")
    assert state["evidence_valid"] is False
    assert state["assessment"]["refined_confidence"] != "confirmed"


async def test_specialist_runs_with_test_model():
    # TestModel returns a generated SpecialistAssessment without a live LLM.
    session = SocGraphSession(SocGraphRuntime(model=TestModel()))
    state = await session.start(_finding_dict(), thread_id="t5")
    assert "assessment" in state
    assert session.interrupt_payload(state) is not None  # still reaches HITL gate


async def test_no_execution_node_exists():
    # Defence-in-depth: the SOC graph must never contain an execution/mutation node.
    session = SocGraphSession(SocGraphRuntime(model=None))
    node_names = set(session.graph.get_graph().nodes.keys())
    assert not any("execute" in n or "remediation" in n or "apply" in n for n in node_names)
