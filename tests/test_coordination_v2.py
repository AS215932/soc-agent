from __future__ import annotations

from typing import Any

import pytest
from agent_core.contracts import (
    ApprovalRecord,
    HandoffEnvelope,
    HandoffRecord,
    HandoffResult,
    ProbePlan,
    SourceRef,
)

from app.cases.models import SecurityCase, SecurityFinding
from app.config import CoordinationSettings, RedTeamSettings, SocAgentSettings
from app.coordination import CoordinatorNocToolClient, SocCoordinator
from app.redteam.active import ActiveProbeExecutor
from app.redteam.policy import RedTeamGate, RedTeamRefused


class FakeCoordinatorClient:
    def __init__(self) -> None:
        self.created: list[HandoffEnvelope] = []
        self.cases: list[Any] = []
        self.records: dict[str, HandoffRecord] = {}

    async def put_case(self, projection):  # type: ignore[no-untyped-def]
        self.cases.append(projection)
        return projection

    async def create_handoff(self, envelope: HandoffEnvelope) -> HandoffRecord:
        self.created.append(envelope)
        existing = next(
            (
                record
                for record in self.records.values()
                if record.envelope.idempotency_key == envelope.idempotency_key
            ),
            None,
        )
        if existing is not None:
            return existing
        result = None
        status = "awaiting_approval" if envelope.approval_tier != "none" else "queued"
        if envelope.capability == "knowledge.context.resolve":
            result = HandoffResult(
                handoff_id=envelope.handoff_id,
                outcome="succeeded",
                payload={
                    "context_pack_id": "ctx_soc_1",
                    "policy_decision_id": "policy_soc_1",
                    "citations": [{"claim_id": "claim_rpki"}],
                },
            )
            status = "result_submitted"
        if envelope.capability == "noc.network_snapshot.read":
            result = HandoffResult(
                handoff_id=envelope.handoff_id,
                outcome="succeeded",
                payload={"tool_result": {"ok": True, "stdout": "safe snapshot"}},
            )
            status = "result_submitted"
        record = HandoffRecord(envelope=envelope, status=status, result=result)
        self.records[envelope.handoff_id] = record
        return record

    async def handoff(self, handoff_id: str) -> HandoffRecord:
        return self.records[handoff_id]


def _coordinator(fake: FakeCoordinatorClient) -> SocCoordinator:
    return SocCoordinator(fake, wait_seconds=0, poll_interval=0.01)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_soc_uses_knowledge_and_publishes_scope_bound_work() -> None:
    fake = FakeCoordinatorClient()
    coordinator = _coordinator(fake)
    finding = SecurityFinding(
        check_id="rpki_in_frr",
        key="cr1-nl1",
        title="RPKI drift",
        summary="Sanitized RPKI drift",
        assertion="RPKI-invalid routes must be rejected",
        resource="cr1-nl1",
        severity="HIGH",
        passed=False,
        warrants_handoff=True,
    )
    enriched = await coordinator.enrich_with_knowledge(finding)
    assert enriched.context_refs == ["ctx_soc_1", "policy_soc_1", "claim_rpki"]

    case = SecurityCase(
        case_id="sec_case_1",
        title=finding.title,
        summary=finding.summary,
        severity="HIGH",
        fingerprint=finding.fingerprint(),
    )
    bundle = finding.build_handoff(case)
    handoff = await coordinator.request_engineering(case, enriched, bundle)
    assert handoff is not None
    assert handoff.envelope.approval_tier == "senior"
    assert handoff.envelope.capability == "engineering.draft_pr"
    assert handoff.envelope.constraints["draft_pr_only"] is True
    assert handoff.envelope.context_refs[0].ref == "ctx_soc_1"

    proposal = await coordinator.propose_learning(case)
    assert proposal is not None
    assert proposal.envelope.target_loop == "knowledge"
    assert proposal.envelope.payload["authority_tier"] == "A4"
    assert proposal.envelope.constraints["direct_a1_a2_write"] is False


@pytest.mark.asyncio
async def test_noc_snapshot_client_returns_only_structured_result() -> None:
    fake = FakeCoordinatorClient()
    client = CoordinatorNocToolClient(_coordinator(fake))
    result = await client.call_tool("frr_vtysh_cmd", {"host": "cr1-nl1", "command": "show rpki"})
    assert result == {"ok": True, "stdout": "safe snapshot"}
    assert fake.created[0].target_loop == "noc"
    assert fake.created[0].approval_tier == "none"
    assert fake.created[0].constraints["mutating_tools"] is False


class OwnedAssets:
    def is_owned_target(self, target: str) -> bool:
        return target == "web.as215932.net"


@pytest.mark.asyncio
async def test_rt2_dry_run_requires_bound_senior_approval() -> None:
    settings = RedTeamSettings(enabled=True, max_tier=2, allow_active_probes=True)
    gate = RedTeamGate(settings)
    plan = ProbePlan(
        probe_kind="tls_handshake",
        targets=["web.as215932.net"],
        ports=[443],
        approved_asset_refs=[SourceRef(ref="okf:asset:web", authority="A1")],
    )
    envelope = HandoffEnvelope(
        source_loop="soc",
        target_loop="soc",
        capability="soc.active_probe.rt2",
        approval_tier="senior",
        risk_level="high",
        payload={"probe_plan": plan.model_dump(mode="json")},
        idempotency_key="probe:web:tls",
    )
    approval = ApprovalRecord(
        handoff_id=envelope.handoff_id,
        scope_hash=envelope.scope_hash,
        decision="approved",
        approver_id="owner-id",
        approver_role="senior",
    )
    record = HandoffRecord(
        envelope=envelope,
        status="claimed",
        claim_owner="soc",
        approval=approval,
    )
    executor = ActiveProbeExecutor(gate, OwnedAssets())  # type: ignore[arg-type]
    report = await executor.execute(record, plan, dry_run=True)
    assert report.dry_run is True
    assert report.requests == 0
    assert report.observations[0]["status"] == "would_run"

    rejected = record.model_copy(
        update={"approval": approval.model_copy(update={"approver_role": "operator"})}
    )
    with pytest.raises(RedTeamRefused, match="senior"):
        await executor.execute(rejected, plan, dry_run=True)


def test_coordination_defaults_off() -> None:
    settings = SocAgentSettings(coordination=CoordinationSettings())
    assert settings.coordination.enabled is False
