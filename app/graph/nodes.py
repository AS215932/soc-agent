"""SOC commander graph nodes.

The graph enriches a deterministic ``SecurityFinding`` with an LLM specialist
assessment, validates evidence, gates on human approval, and terminates at an LHP
handoff request. It never executes a mutation — there is no execution node.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from langgraph.types import interrupt

from app import log
from app.agents.assessments import (
    SpecialistDeps,
    build_specialist_agent,
    deterministic_assessment,
    render_finding_prompt,
)
from app.graph.routing import soc_commander_route
from app.graph.state import SocWorkflowState

_CONFIDENCE_ORDER = ["tentative", "low", "medium", "high", "confirmed"]


@dataclass
class SocGraphRuntime:
    """Runtime deps for the SOC graph. ``model`` is a PydanticAI model (or None
    for the deterministic, model-free path used offline / in CI)."""

    store: Any = None
    mcp_runtime: Any = None
    model: Any = None


class SocNodeRunner:
    def __init__(self, runtime: SocGraphRuntime) -> None:
        self.runtime = runtime

    async def correlate_and_dedupe(self, state: SocWorkflowState) -> dict[str, Any]:
        finding = state.get("finding") or {}
        fingerprint = ""
        # Reuse the SecurityFinding fingerprint if we can reconstruct it cheaply.
        check_id = finding.get("check_id", "")
        key = finding.get("key", "")
        if check_id or key:
            import hashlib

            fingerprint = hashlib.sha256(f"{check_id}|{key}".encode()).hexdigest()[:16]
        return {"fingerprint": fingerprint, "current_step": "correlated"}

    async def recall_history(self, state: SocWorkflowState) -> dict[str, Any]:
        case_context: dict[str, Any] = {}
        case_id = state.get("case_id")
        if self.runtime.store is not None and case_id:
            case = self.runtime.store.get_case(case_id)
            if case is not None:
                case_context = {
                    "status": case.status,
                    "consecutive_pass_count": case.consecutive_pass_count,
                    "handoff_ids": list(case.handoff_ids),
                }
        return {"case_context": case_context, "current_step": "recalled"}

    async def soc_commander_route(self, state: SocWorkflowState) -> dict[str, Any]:
        return soc_commander_route(state)

    async def routing_security_specialist(self, state: SocWorkflowState) -> dict[str, Any]:
        return await self._run_specialist(state, "routing_security")

    async def exposure_specialist(self, state: SocWorkflowState) -> dict[str, Any]:
        return await self._run_specialist(state, "exposure")

    async def crypto_specialist(self, state: SocWorkflowState) -> dict[str, Any]:
        return await self._run_specialist(state, "crypto")

    async def detection_specialist(self, state: SocWorkflowState) -> dict[str, Any]:
        return await self._run_specialist(state, "detection")

    async def _run_specialist(self, state: SocWorkflowState, specialist: str) -> dict[str, Any]:
        finding = state.get("finding") or {}
        if self.runtime.model is None:
            assessment = deterministic_assessment(finding)
        else:
            try:
                agent = build_specialist_agent(specialist)
                toolsets = list(self.runtime.mcp_runtime.toolsets_for(specialist)) if self.runtime.mcp_runtime else []
                result = await agent.run(
                    render_finding_prompt(finding),
                    model=self.runtime.model,
                    deps=SpecialistDeps(specialist=specialist),
                    toolsets=toolsets,
                )
                assessment = result.output
            except Exception as exc:  # a model failure must not crash the graph
                log.warning("soc_specialist_failed", specialist=specialist, error=type(exc).__name__)
                assessment = deterministic_assessment(finding)
        return {
            "specialist": specialist,
            "assessment": assessment.model_dump(mode="json"),
            "current_step": "assessed",
        }

    async def evidence_validation(self, state: SocWorkflowState) -> dict[str, Any]:
        """Down-weight confidence when the finding lacks a direct MCP measurement
        (only static/desired-state evidence)."""
        finding = state.get("finding") or {}
        assessment = dict(state.get("assessment") or {})
        measured = any(
            (ev.get("source_tool") or "") not in {"", "git"} for ev in finding.get("evidence", []) if isinstance(ev, dict)
        )
        note = "direct measurement present" if measured else "no direct measurement — confidence lowered"
        if not measured:
            current = assessment.get("refined_confidence", "medium")
            idx = _CONFIDENCE_ORDER.index(current) if current in _CONFIDENCE_ORDER else 2
            assessment["refined_confidence"] = _CONFIDENCE_ORDER[max(0, idx - 1)]
        return {"assessment": assessment, "evidence_valid": measured, "evidence_note": note, "current_step": "validated"}

    async def finding_build(self, state: SocWorkflowState) -> dict[str, Any]:
        """Merge the specialist assessment back onto the finding to form the
        enriched finding that drives the handoff."""
        finding = dict(state.get("finding") or {})
        assessment = state.get("assessment") or {}
        enriched = dict(finding)
        enriched["severity"] = assessment.get("refined_severity", finding.get("severity"))
        enriched["confidence"] = assessment.get("refined_confidence", finding.get("confidence"))
        if assessment.get("summary"):
            enriched["summary"] = assessment["summary"]
        for field in ("mitre_tactics", "mitre_techniques"):
            if assessment.get(field):
                enriched[field] = assessment[field]
        if assessment.get("recommended_actions"):
            enriched["recommended_remediation"] = assessment["recommended_actions"]
        enriched["warrants_handoff"] = bool(
            finding.get("warrants_handoff") or assessment.get("warrants_handoff")
        )
        return {"enriched_finding": enriched, "current_step": "enriched"}

    async def prepare_approval(self, state: SocWorkflowState) -> dict[str, Any]:
        return {"approval_state": "waiting_approval", "current_step": "prepare_approval"}

    async def approval_interrupt(self, state: SocWorkflowState) -> dict[str, Any]:
        enriched = state.get("enriched_finding") or state.get("finding") or {}
        decision = interrupt(
            {
                "case_id": state.get("case_id", ""),
                "title": enriched.get("title", ""),
                "severity": enriched.get("severity", ""),
                "warrants_handoff": enriched.get("warrants_handoff", False),
                "approval_state": "waiting_approval",
            }
        )
        approved = isinstance(decision, dict) and str(decision.get("decision", "")).lower() in {"approve", "approved", "yes"}
        normalized = decision if isinstance(decision, dict) else {"decision": str(decision)}
        return {
            "operator_decision": normalized,
            "approval_state": "approved" if approved else "rejected",
            "current_step": "approved" if approved else "rejected",
        }

    async def request_handoff(self, state: SocWorkflowState) -> dict[str, Any]:
        # The graph only *flags* that an approved handoff should be requested; the
        # loop performs the actual LHP persistence + issue creation (mode-gated).
        return {"handoff_requested": True, "current_step": "handoff_requested"}
