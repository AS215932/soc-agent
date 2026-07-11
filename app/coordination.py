"""SOC integration with the neutral agent-core LHP-v2 coordinator."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from datetime import datetime
from typing import Any, Literal

from agent_core.contracts import (
    CaseProjection,
    HandoffEnvelope,
    HandoffRecord,
    SourceRef,
    VerificationResult,
)
from agent_core.coordination import CoordinatorClient, CoordinatorError

from app import log
from app.cases.models import HandoffBundle, SecurityCase, SecurityFinding
from app.config import SocAgentSettings

_TERMINAL = frozenset({"completed", "rejected", "failed", "cancelled", "expired"})


def _parse_time(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _stable_key(prefix: str, value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return f"{prefix}:{hashlib.sha256(payload.encode()).hexdigest()[:24]}"


class SocCoordinator:
    def __init__(
        self,
        client: CoordinatorClient,
        *,
        wait_seconds: float = 30.0,
        poll_interval: float = 1.0,
    ) -> None:
        self.client = client
        self.wait_seconds = max(0.0, wait_seconds)
        self.poll_interval = max(0.05, poll_interval)

    @classmethod
    def from_settings(
        cls, settings: SocAgentSettings, *, client: CoordinatorClient | None = None
    ) -> SocCoordinator | None:
        if not settings.coordination.enabled:
            return None
        try:
            active = client or CoordinatorClient.from_env("soc")
        except CoordinatorError as exc:
            log.warning("soc_coordinator_disabled", reason=str(exc))
            return None
        active.timeout = settings.coordination.request_timeout_s
        return cls(
            active,
            wait_seconds=settings.coordination.result_wait_s,
            poll_interval=settings.coordination.poll_interval_s,
        )

    async def publish_case(self, case: SecurityCase) -> CaseProjection | None:
        projection = CaseProjection(
            case_id=case.case_id,
            owner_loop="soc",
            status=case.status,
            severity=case.severity,
            title=case.title,
            summary=case.summary,
            resource_id=case.resource_id,
            opened_at=_parse_time(case.opened_at) or datetime.now().astimezone(),
            updated_at=_parse_time(case.updated_at) or datetime.now().astimezone(),
            resolved_at=_parse_time(case.resolved_at),
            metadata={
                "case_type": case.case_type,
                "control_domain": case.control_domain,
                "fingerprint": case.fingerprint,
                "handoff_ids": list(case.handoff_ids),
                "consecutive_pass_count": case.consecutive_pass_count,
                "required_consecutive_passes": case.required_consecutive_passes,
            },
        )
        try:
            return await self.client.put_case(projection)
        except CoordinatorError as exc:
            log.warning("soc_case_projection_failed", case_id=case.case_id, error=str(exc))
            return None

    async def enrich_with_knowledge(self, finding: SecurityFinding) -> SecurityFinding:
        envelope = HandoffEnvelope(
            source_loop="soc",
            target_loop="knowledge",
            capability="knowledge.context.resolve",
            work_item_id=finding.finding_id,
            intent="Resolve governed SOC context before security triage",
            summary=finding.summary or finding.title,
            risk_level="low",
            approval_tier="none",
            payload={
                "role": "soc_shadow",
                "query": finding.assertion or finding.summary or finding.title,
                "resource": finding.resource,
                "control_domain": finding.control_domain,
                "data_classes": ["sanitized_finding_summary", "source_ref"],
            },
            evidence_refs=self._finding_refs(finding),
            idempotency_key=_stable_key(
                "soc:knowledge-context",
                [finding.fingerprint(), finding.manifest_sha, finding.assertion],
            ),
        )
        record = await self._create_and_wait(envelope)
        if record is None or record.result is None or record.result.outcome != "succeeded":
            return finding
        refs: list[str] = list(finding.context_refs)
        payload = record.result.payload
        for key in ("context_pack_id", "policy_decision_id"):
            value = str(payload.get(key) or "")
            if value:
                refs.append(value)
        citations = payload.get("citations")
        if isinstance(citations, list):
            for citation in citations[:40]:
                if isinstance(citation, dict):
                    value = next(
                        (
                            str(citation.get(key) or "")
                            for key in ("claim_id", "concept_id", "source_uri")
                            if citation.get(key)
                        ),
                        "",
                    )
                    if value:
                        refs.append(value)
        return finding.model_copy(update={"context_refs": list(dict.fromkeys(refs))[:40]})

    async def request_engineering(
        self, case: SecurityCase, finding: SecurityFinding, bundle: HandoffBundle
    ) -> HandoffRecord | None:
        approval_tier: Literal["operator", "senior"] = (
            "senior" if finding.severity == "HIGH" else "operator"
        )
        envelope = HandoffEnvelope(
            handoff_id=bundle.handoff.handoff_id,
            source_loop="soc",
            target_loop="engineering",
            capability="engineering.draft_pr",
            work_item_id=bundle.handoff.handoff_id,
            case_id=case.case_id,
            intent=bundle.handoff.objective,
            summary=finding.summary or finding.title,
            risk_level="high" if finding.severity == "HIGH" else "medium",
            approval_tier=approval_tier,
            payload={
                "repository": "AS215932/network-operations",
                "recommended_remediation": finding.recommended_remediation,
                "acceptance_criteria": bundle.handoff.acceptance_criteria,
                "objective_key": bundle.handoff.objective_key,
                "finding": bundle.knowledge_payload,
            },
            evidence_refs=self._finding_refs(finding),
            context_refs=[SourceRef(ref=ref, kind="knowledge") for ref in finding.context_refs],
            constraints={
                "draft_pr_only": True,
                "production_mutation": False,
                "allowed_repository": "AS215932/network-operations",
            },
            correlation_id=case.case_id,
            idempotency_key=f"{bundle.handoff.idempotency_key}:lhp-v2",
        )
        try:
            return await self.client.create_handoff(envelope)
        except CoordinatorError as exc:
            log.warning("soc_engineering_handoff_failed", case_id=case.case_id, error=str(exc))
            return None

    async def verify_handoffs(self, case: SecurityCase, *, passed: bool, summary: str) -> None:
        for handoff_id in case.handoff_ids:
            try:
                record = await self.client.handoff(handoff_id)
                if record.status not in {"result_submitted", "verification_pending"}:
                    continue
                await self.client.verify(
                    VerificationResult(
                        handoff_id=handoff_id,
                        verdict="passed" if passed else "failed",
                        summary=summary,
                        consecutive_passes=case.consecutive_pass_count,
                        required_consecutive_passes=case.required_consecutive_passes,
                    )
                )
            except CoordinatorError as exc:
                log.warning("soc_handoff_verification_failed", handoff_id=handoff_id, error=str(exc))

    async def propose_learning(self, case: SecurityCase) -> HandoffRecord | None:
        envelope = HandoffEnvelope(
            source_loop="soc",
            target_loop="knowledge",
            capability="knowledge.learning.proposal",
            work_item_id=case.case_id,
            case_id=case.case_id,
            intent="Review a sanitized verified SOC outcome for the Learning Substrate",
            summary=f"Verified SOC outcome: {case.title}",
            risk_level="high" if case.severity == "HIGH" else "medium",
            approval_tier="senior" if case.severity == "HIGH" else "operator",
            payload={
                "event_type": "soc_case_outcome",
                "producer": "soc_shadow",
                "status": "proposed",
                "authority_tier": "A4",
                "subject": case.fingerprint or case.case_id,
                "summary": case.summary or case.title,
                "data_classes": ["sanitized_trace_summary", "source_ref", "okf_concept"],
                "metrics": {
                    "required_consecutive_passes": case.required_consecutive_passes,
                    "observed_consecutive_passes": case.consecutive_pass_count,
                },
                "promotion": {"review_required": True, "target": "okf/curated/lessons"},
                "adversarial_review_required": True,
            },
            context_refs=[SourceRef(ref=case.case_id, kind="soc_case", authority="A4")],
            constraints={
                "no_raw_logs": True,
                "no_secrets": True,
                "human_review_required": True,
                "direct_a1_a2_write": False,
            },
            idempotency_key=f"soc:learning:{case.case_id}:{case.signal_signature}",
        )
        try:
            return await self.client.create_handoff(envelope)
        except CoordinatorError as exc:
            log.warning("soc_learning_proposal_failed", case_id=case.case_id, error=str(exc))
            return None

    async def _create_and_wait(self, envelope: HandoffEnvelope) -> HandoffRecord | None:
        try:
            record = await self.client.create_handoff(envelope)
            if record.result is not None or record.status in _TERMINAL:
                return record
            deadline = time.monotonic() + self.wait_seconds
            while time.monotonic() < deadline:
                await asyncio.sleep(self.poll_interval)
                record = await self.client.handoff(record.envelope.handoff_id)
                if record.result is not None or record.status in _TERMINAL:
                    return record
            log.info("soc_coordinator_wait_timeout", handoff_id=envelope.handoff_id)
            return None
        except CoordinatorError as exc:
            log.warning("soc_coordinator_request_failed", capability=envelope.capability, error=str(exc))
            return None

    @staticmethod
    def _finding_refs(finding: SecurityFinding) -> list[SourceRef]:
        refs: list[SourceRef] = []
        for desired in finding.desired_state_refs[:20]:
            refs.append(
                SourceRef(
                    ref=f"{desired.repo}:{desired.path}#{desired.ref}",
                    kind="desired_state",
                    authority="A0",
                    commit_sha=desired.content_sha or None,
                )
            )
        for evidence in finding.evidence[:20]:
            ref = evidence.source_tool or evidence.query
            if ref:
                refs.append(SourceRef(ref=ref, kind="mcp_observation", authority="A3"))
        return refs


class CoordinatorNocToolClient:
    """Hyrule-MCP-shaped client backed by an automatic read-only NOC handoff."""

    def __init__(self, coordinator: SocCoordinator) -> None:
        self.coordinator = coordinator

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        # One-minute freshness bucket prevents an idempotency key from returning an
        # arbitrarily old snapshot while still collapsing retries in one scan cycle.
        freshness_bucket = int(time.time() // 60)
        envelope = HandoffEnvelope(
            source_loop="soc",
            target_loop="noc",
            capability="noc.network_snapshot.read",
            intent=f"Execute approved read-only diagnostic {name}",
            summary=f"SOC posture snapshot request: {name}",
            approval_tier="none",
            risk_level="low",
            payload={
                "tool": name,
                "arguments": arguments,
                "read_only": True,
                "max_result_bytes": 65_536,
            },
            constraints={
                "mutating_tools": False,
                "bounded_tool_output": True,
                "max_result_bytes": 65_536,
            },
            idempotency_key=_stable_key(
                "soc:noc-snapshot", [name, arguments, freshness_bucket]
            ),
        )
        record = await self.coordinator._create_and_wait(envelope)
        if record is None or record.result is None or record.result.outcome != "succeeded":
            raise CoordinatorError(f"NOC snapshot {name} did not return a successful result")
        result = record.result.payload.get("tool_result")
        if not isinstance(result, dict):
            raise CoordinatorError(f"NOC snapshot {name} returned no structured tool_result")
        return result
