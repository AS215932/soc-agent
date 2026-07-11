"""Bounded RT-2 executor for individually senior-approved coordinator work."""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass, field
from time import monotonic
from typing import Any
from urllib.parse import urlparse

import httpx
from agent_core.contracts import HandoffResult, ProbePlan, VerificationResult
from agent_core.coordination import CoordinatorClient, CoordinatorError

from app import log
from app.config import mode_executes_active_probes
from app.redteam.policy import RedTeamGate, RedTeamRefused
from app.redteam.validators import NonInvasiveValidator


def _host(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"//{target}", scheme="https")
    return parsed.hostname or target


@dataclass
class ActiveProbeReport:
    handoff_id: str
    probe_kind: str
    dry_run: bool
    requests: int = 0
    observations: list[dict[str, Any]] = field(default_factory=list)
    refused: str = ""
    duration_seconds: float = 0.0


class ActiveProbeExecutor:
    def __init__(self, gate: RedTeamGate, ownership: NonInvasiveValidator) -> None:
        self.gate = gate
        self.ownership = ownership

    async def execute(self, record: Any, plan: ProbePlan, *, dry_run: bool) -> ActiveProbeReport:
        started = monotonic()
        report = ActiveProbeReport(
            handoff_id=record.envelope.handoff_id,
            probe_kind=plan.probe_kind,
            dry_run=dry_run,
        )
        self.gate.require_approved_rt2(record)
        if not any(ref.authority in {"A0", "A1"} for ref in plan.approved_asset_refs):
            raise RedTeamRefused("RT-2 requires an A0/A1 owned-asset citation")
        for target in plan.targets:
            if not self.ownership.is_owned_target(target):
                raise RedTeamRefused(f"RT-2 target {target!r} is not an approved owned asset")
        if dry_run:
            report.observations.append(
                {
                    "status": "would_run",
                    "targets": list(plan.targets),
                    "ports": list(plan.ports),
                    "max_requests": plan.max_requests,
                }
            )
            report.duration_seconds = monotonic() - started
            return report

        async with asyncio.timeout(plan.max_duration_seconds):
            for target in plan.targets:
                if plan.probe_kind == "tcp_connect_sweep":
                    for port in plan.ports:
                        await self._rate_limit(report, plan)
                        report.observations.append(await self._tcp_connect(target, port))
                elif plan.probe_kind == "tls_handshake":
                    for port in plan.ports:
                        await self._rate_limit(report, plan)
                        report.observations.append(await self._tls_handshake(target, port))
                elif plan.probe_kind == "http_headers":
                    await self._rate_limit(report, plan)
                    report.observations.append(await self._http_headers(target))
                elif plan.probe_kind == "dns_consistency":
                    await self._rate_limit(report, plan)
                    report.observations.append(await self._dns(target))
        report.duration_seconds = monotonic() - started
        return report

    @staticmethod
    async def _rate_limit(report: ActiveProbeReport, plan: ProbePlan) -> None:
        if report.requests >= plan.max_requests:
            raise RedTeamRefused("RT-2 max_requests budget exhausted")
        if report.requests:
            await asyncio.sleep(1.0 / plan.requests_per_second_per_target)
        report.requests += 1

    @staticmethod
    async def _tcp_connect(target: str, port: int) -> dict[str, Any]:
        host = _host(target)
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3)
            del reader
            writer.close()
            await writer.wait_closed()
            return {"target": host, "port": port, "check": "tcp_connect", "reachable": True}
        except Exception as exc:
            return {
                "target": host,
                "port": port,
                "check": "tcp_connect",
                "reachable": False,
                "error": type(exc).__name__,
            }

    @staticmethod
    async def _tls_handshake(target: str, port: int) -> dict[str, Any]:
        host = _host(target)
        context = ssl.create_default_context()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=host), timeout=5
            )
            del reader
            ssl_object = writer.get_extra_info("ssl_object")
            observation = {
                "target": host,
                "port": port,
                "check": "tls_handshake",
                "negotiated": True,
                "protocol": ssl_object.version() if ssl_object else "unknown",
                "cipher": ssl_object.cipher()[0] if ssl_object and ssl_object.cipher() else "unknown",
            }
            writer.close()
            await writer.wait_closed()
            return observation
        except Exception as exc:
            return {
                "target": host,
                "port": port,
                "check": "tls_handshake",
                "negotiated": False,
                "error": type(exc).__name__,
            }

    @staticmethod
    async def _http_headers(target: str) -> dict[str, Any]:
        url = target if "://" in target else f"https://{target}"
        try:
            async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
                response = await client.head(url)
            return {
                "target": url,
                "check": "http_headers",
                "status": response.status_code,
                "hsts": "strict-transport-security" in response.headers,
                "redirect": response.headers.get("location", "")[:300],
            }
        except Exception as exc:
            return {"target": url, "check": "http_headers", "error": type(exc).__name__}

    @staticmethod
    async def _dns(target: str) -> dict[str, Any]:
        host = _host(target)
        try:
            rows = await asyncio.get_running_loop().getaddrinfo(host, None)
            addresses = sorted({str(row[4][0]) for row in rows})[:20]
            return {"target": host, "check": "dns_consistency", "addresses": addresses}
        except Exception as exc:
            return {"target": host, "check": "dns_consistency", "error": type(exc).__name__}


class SocProbeWorker:
    def __init__(
        self,
        client: CoordinatorClient,
        executor: ActiveProbeExecutor,
        *,
        mode: str,
    ) -> None:
        self.client = client
        self.executor = executor
        self.mode = mode

    async def run_once(self) -> dict[str, Any]:
        report: dict[str, Any] = {"checked": 0, "completed": [], "failed": []}
        try:
            handoffs = await self.client.inbox(status="queued")
        except CoordinatorError as exc:
            return {**report, "error": str(exc)}
        for item in handoffs:
            if item.envelope.capability != "soc.active_probe.rt2":
                continue
            report["checked"] += 1
            handoff_id = item.envelope.handoff_id
            try:
                claimed = await self.client.claim(handoff_id, lease_seconds=600)
                await self.client.progress(handoff_id, "validating approved RT-2 scope")
                raw_plan = claimed.envelope.payload.get("probe_plan", claimed.envelope.payload)
                plan = ProbePlan.model_validate(raw_plan)
                execution = await self.executor.execute(
                    claimed,
                    plan,
                    dry_run=not mode_executes_active_probes(self.mode),
                )
                submitted = await self.client.submit_result(
                    HandoffResult(
                        handoff_id=handoff_id,
                        outcome="succeeded",
                        summary="RT-2 dry plan validated"
                        if execution.dry_run
                        else "Approved RT-2 probe completed within bounds",
                        payload={
                            "dry_run": execution.dry_run,
                            "probe_kind": execution.probe_kind,
                            "requests": execution.requests,
                            "observations": execution.observations,
                            "duration_seconds": execution.duration_seconds,
                        },
                    )
                )
                if submitted.status == "result_submitted":
                    await self.client.verify(
                        VerificationResult(
                            handoff_id=handoff_id,
                            verdict="passed",
                            summary="SOC verified probe executor budget and scope completion",
                        )
                    )
                report["completed"].append(handoff_id)
            except Exception as exc:
                log.warning("soc_rt2_failed", handoff_id=handoff_id, error=type(exc).__name__)
                report["failed"].append({"handoff_id": handoff_id, "error": str(exc)[:300]})
        return report
