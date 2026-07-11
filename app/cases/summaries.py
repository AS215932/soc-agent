"""Projections from SOC-local models to shared agent-core contracts, plus the
``lhp.v1`` fetch-payload builder served by ``GET /loop-handoff/v1/soc/...``.

The agent-core DTOs are *read models*: SOC CaseService + LHP-v1 remain the
authoritative operational state. These functions never mutate.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from agent_core.contracts.evidence import EvidencePacket, SourceRef
from agent_core.contracts.observatory import (
    CaseSummary,
    HandoffSummary,
    ObservatoryLink,
    VerificationObjectiveSummary,
)
from agent_core.contracts.tools import ToolResult

from app.lhp import (
    CaseHandoff,
    VerificationObjective,
    assert_lhp_payload_size,
    lhp_payload_hash,
)
from app.cases.models import SecurityCase, SecurityFinding

LHP_SCHEMA_VERSION = "lhp.v1"


def _dt(value: str) -> datetime | None:
    """Parse the SOC-local ISO timestamp for the typed shared read model."""
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def security_case_summary(case: SecurityCase) -> CaseSummary:
    links: list[ObservatoryLink] = [
        ObservatoryLink(kind="case", label="SOC case", ref_id=case.case_id),
    ]
    if case.issue_url:
        links.append(ObservatoryLink(kind="github_issue", label="loop:candidate", url=case.issue_url))
    for handoff_id in case.handoff_ids:
        links.append(ObservatoryLink(kind="handoff", label="Loop handoff", ref_id=handoff_id))
    pending = 0 if case.status in {"resolved", "closed"} else len(case.handoff_ids)
    return CaseSummary(
        case_id=case.case_id,
        case_number=case.case_number,
        kind="atomic",
        status=case.status,
        severity=str(case.severity),
        title=case.title,
        summary=case.summary,
        origin=case.origin,
        resource_id=case.resource_id,
        issue_url=case.issue_url,
        opened_at=_dt(case.opened_at),
        updated_at=_dt(case.updated_at),
        resolved_at=_dt(case.resolved_at),
        trace_ids=list(case.trace_ids),
        handoff_count=len(case.handoff_ids),
        verification_pending_count=pending,
        links=links,
        metadata={
            "case_type": case.case_type,
            "category": case.category,
            "control_domain": case.control_domain,
            "confidence": case.confidence,
            "mitre_tactics": list(case.mitre_tactics),
            "mitre_techniques": list(case.mitre_techniques),
            "fingerprint": case.fingerprint,
            "consecutive_pass_count": case.consecutive_pass_count,
            "required_consecutive_passes": case.required_consecutive_passes,
        },
    )


def handoff_summary(handoff: CaseHandoff) -> HandoffSummary:
    return HandoffSummary(
        handoff_id=handoff.handoff_id,
        case_id=handoff.case_id,
        source_loop=handoff.source_loop,
        target_loop=handoff.target_loop,
        objective=handoff.objective,
        objective_key=handoff.objective_key,
        status=handoff.status,
        owner=handoff.owner,
        verifier=handoff.verifier,
        correlation_id=handoff.correlation_id,
        trace_id=handoff.trace_id,
        created_at=_dt(handoff.created_at),
        updated_at=_dt(handoff.updated_at),
        acceptance_criteria=list(handoff.acceptance_criteria),
        knowledge_context_refs=list(handoff.knowledge_context_refs),
        links=[
            ObservatoryLink(kind="handoff", label="Loop handoff", ref_id=handoff.handoff_id),
            ObservatoryLink(kind="case", label="SOC case", ref_id=handoff.case_id),
        ],
        metadata={"case_type": handoff.case_type},
    )


def objective_summary(objective: VerificationObjective) -> VerificationObjectiveSummary:
    return VerificationObjectiveSummary(
        objective_id=objective.objective_id,
        case_id=objective.case_id,
        handoff_id=objective.handoff_id,
        objective_key=objective.objective_key,
        objective_type=objective.objective_type,
        name=objective.name,
        description=objective.description,
        required_status=objective.required_status,
        status=objective.status,
        required=objective.required,
        consecutive_pass_count=objective.consecutive_pass_count,
        required_consecutive_passes=objective.required_consecutive_passes,
        last_checked_at=_dt(objective.last_checked_at),
        next_check_at=_dt(objective.next_check_at),
        evidence_ref=objective.evidence_ref,
        failure_reason=objective.failure_reason,
    )


def evidence_packet(finding: SecurityFinding) -> EvidencePacket:
    """Ground a finding in agent-core evidence: desired-state files become A0
    SourceRefs; each MCP observation becomes a ToolResult."""
    sources = [
        SourceRef(
            ref=f"{ref.repo}:{ref.path}" if ref.path else ref.repo,
            kind="repo_file",
            authority="A0",
            commit_sha=ref.content_sha or None,
            excerpt=ref.assertion_text or None,
        )
        for ref in finding.desired_state_refs
    ]
    tool_results = [
        ToolResult(
            tool=ev.source_tool or "mcp",
            ok=finding.passed,
            output={"query": ev.query, "observed": ev.observed_value, "expected": ev.expected_value},
        )
        for ev in finding.evidence
        if ev.source_tool
    ]
    return EvidencePacket(
        sources=sources,
        tool_results=tool_results,
        logs=[ev.detail for ev in finding.evidence if ev.detail][:20],
        authority_max="A0" if sources else None,
        metadata={
            "finding_id": finding.finding_id,
            "check_id": finding.check_id,
            "assertion": finding.assertion,
            "passed": finding.passed,
        },
    )


def build_lhp_fetch_payload(
    *,
    handoff: CaseHandoff,
    case: SecurityCase,
    objectives: list[VerificationObjective],
    knowledge_artifacts: list[dict[str, Any]] | None = None,
    max_bytes: int = 65_536,
) -> dict[str, Any]:
    """Assemble the exact ``lhp.v1`` payload the Engineering Loop fetches from
    ``GET /loop-handoff/v1/soc/handoffs/{handoff_id}`` — the SOC analogue of the
    NOC endpoint (``hyrule-noc-agent/app/main.py``)."""
    core = {
        "schema_version": LHP_SCHEMA_VERSION,
        "handoff": handoff.model_dump(mode="json"),
        "case": security_case_summary(case).model_dump(mode="json"),
        "verification_objectives": [objective_summary(o).model_dump(mode="json") for o in objectives[:20]],
        "knowledge_artifacts": list(knowledge_artifacts or [])[:20],
    }
    assert_lhp_payload_size(core, max_bytes=max_bytes)
    return {**core, "payload_hash": lhp_payload_hash(core)}
