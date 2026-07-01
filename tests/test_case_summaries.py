"""Projections to agent-core contracts validate + the LHP fetch payload is
lhp.v1-shaped."""

from __future__ import annotations

from agent_core.contracts.evidence import EvidencePacket
from agent_core.contracts.observatory import CaseSummary, HandoffSummary, VerificationObjectiveSummary

from app.cases.models import DesiredStateRef, SecurityCase, SecurityEvidence, SecurityFinding
from app.cases.summaries import (
    build_lhp_fetch_payload,
    evidence_packet,
    handoff_summary,
    objective_summary,
    security_case_summary,
)


def _finding() -> SecurityFinding:
    return SecurityFinding(
        check_id="rpki_in_frr",
        key="cr1-nl1:transit",
        category="bgp_rpki",
        control_domain="rpki_irr",
        title="RPKI-invalid reject missing",
        severity="HIGH",
        confidence="confirmed",
        passed=False,
        objective_key="frr-transit-rpki-invalid-reject-v1",
        resource="cr1-nl1",
        desired_state_refs=[DesiredStateRef(path="configs/cr1-nl1/frr.conf", content_sha="deadbeef")],
        evidence=[SecurityEvidence(source_tool="frr_vtysh_cmd", query="show route-map TRANSIT-IN", observed_value="permit 10")],
    )


def test_case_summary_projects_and_validates():
    case = SecurityCase(title="RPKI gap", severity="HIGH", resource_id="cr1-nl1", issue_url="https://x/issues/1")
    case.handoff_ids = ["handoff_1"]
    summary = security_case_summary(case)
    assert isinstance(summary, CaseSummary)
    assert summary.kind == "atomic"
    assert summary.severity == "HIGH"
    assert summary.handoff_count == 1
    # round-trips through agent-core validation
    assert CaseSummary.model_validate(summary.model_dump()) == summary


def test_handoff_and_objective_summaries_validate():
    finding = _finding()
    case = SecurityCase(case_id="sec_case_1")
    bundle = finding.build_handoff(case)
    hs = handoff_summary(bundle.handoff)
    assert isinstance(hs, HandoffSummary)
    assert hs.source_loop == "soc" and hs.verifier == "soc"
    os_ = objective_summary(bundle.objectives[0])
    assert isinstance(os_, VerificationObjectiveSummary)
    assert HandoffSummary.model_validate(hs.model_dump()) == hs
    assert VerificationObjectiveSummary.model_validate(os_.model_dump()) == os_


def test_evidence_packet_grounds_in_a0_sources():
    packet = evidence_packet(_finding())
    assert isinstance(packet, EvidencePacket)
    assert packet.authority_max == "A0"
    assert packet.sources[0].authority == "A0"
    assert packet.sources[0].commit_sha == "deadbeef"
    assert packet.tool_results[0].tool == "frr_vtysh_cmd"


def test_lhp_fetch_payload_shape():
    finding = _finding()
    case = SecurityCase(case_id="sec_case_1", status="handoff_requested")
    bundle = finding.build_handoff(case)
    payload = build_lhp_fetch_payload(handoff=bundle.handoff, case=case, objectives=bundle.objectives)
    assert payload["schema_version"] == "lhp.v1"
    assert payload["handoff"]["handoff_id"] == bundle.handoff.handoff_id
    assert payload["handoff"]["source_loop"] == "soc"
    assert payload["case"]["case_id"] == "sec_case_1"
    assert payload["case"]["status"] == "handoff_requested"
    assert len(payload["verification_objectives"]) == 1
    assert payload["knowledge_artifacts"] == []
    assert payload["payload_hash"]
