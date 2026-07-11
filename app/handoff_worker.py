"""Coordinator inbox worker for non-probe SOC capabilities."""

from __future__ import annotations

from typing import Any

from agent_core.contracts import HandoffResult
from agent_core.coordination import CoordinatorClient, CoordinatorError
from pydantic import ValidationError

from app import log
from app.cases.models import SecurityFinding
from app.cases.service import SecurityCaseService
from app.coordination import SocCoordinator
from app.redteam.exercise import RedTeamRunner


class SocHandoffWorker:
    def __init__(
        self,
        client: CoordinatorClient,
        service: SecurityCaseService,
        coordinator: SocCoordinator,
        redteam: RedTeamRunner,
    ) -> None:
        self.client = client
        self.service = service
        self.coordinator = coordinator
        self.redteam = redteam

    async def run_once(self) -> dict[str, Any]:
        report: dict[str, Any] = {"checked": 0, "completed": [], "failed": []}
        try:
            handoffs = await self.client.inbox(status="queued")
        except CoordinatorError as exc:
            return {**report, "error": str(exc)}
        for record in handoffs:
            capability = record.envelope.capability
            if capability == "soc.active_probe.rt2":
                continue
            if capability not in {"security.triage", "security.attack_path", "security.verify"}:
                continue
            report["checked"] += 1
            handoff_id = record.envelope.handoff_id
            try:
                await self.client.claim(handoff_id)
                await self.client.progress(handoff_id, f"SOC processing {capability}")
                result = await self._dispatch(capability, record.envelope.payload)
                await self.client.submit_result(
                    HandoffResult(
                        handoff_id=handoff_id,
                        outcome="succeeded",
                        summary=str(result.pop("summary", f"SOC completed {capability}")),
                        payload=result,
                    )
                )
                report["completed"].append(handoff_id)
            except Exception as exc:
                log.warning("soc_handoff_failed", handoff_id=handoff_id, error=type(exc).__name__)
                try:
                    await self.client.submit_result(
                        HandoffResult(
                            handoff_id=handoff_id,
                            outcome="failed",
                            summary=f"SOC refused or failed {capability}: {type(exc).__name__}",
                        )
                    )
                except Exception:
                    pass
                report["failed"].append({"handoff_id": handoff_id, "error": str(exc)[:300]})
        return report

    async def _dispatch(self, capability: str, payload: dict[str, Any]) -> dict[str, Any]:
        if capability == "security.triage":
            raw_finding = payload.get("finding", payload)
            try:
                finding = SecurityFinding.model_validate(raw_finding)
            except ValidationError as exc:
                raise ValueError("security.triage requires a contract-valid sanitized finding") from exc
            observed = self.service.observe_finding(finding, cycle_id="coordinator-handoff")
            await self.coordinator.publish_case(observed.case)
            return {
                "summary": "SOC triaged the supplied security finding",
                "case_id": observed.case.case_id,
                "created": observed.created,
                "status": observed.case.status,
            }
        if capability == "security.attack_path":
            raw_findings = payload.get("findings", [])
            findings = [
                SecurityFinding.model_validate(item)
                for item in raw_findings[:50]
                if isinstance(item, dict)
            ]
            exercise, gaps = await self.redteam.run(
                findings,
                objective_id=str(payload.get("objective_id") or "coordinator-handoff"),
            )
            return {
                "summary": "SOC completed passive attack-path modeling",
                "exercise": exercise.model_dump(mode="json"),
                "detection_gaps": [gap.model_dump(mode="json") for gap in gaps],
            }
        case_id = str(payload.get("case_id") or "")
        case = self.service.store.get_case(case_id)
        if case is None:
            raise ValueError("security.verify references an unknown SOC case")
        return {
            "summary": "SOC returned its authoritative verification state",
            "case_id": case.case_id,
            "status": case.status,
            "consecutive_pass_count": case.consecutive_pass_count,
            "required_consecutive_passes": case.required_consecutive_passes,
            "last_scan_degraded": case.last_scan_degraded,
        }
