"""Local SOC control CLI.

``socctl posture run-once [--shadow]`` is the read-only shadow-canary entrypoint:
it runs one posture cycle against the live Hyrule MCP (read-only tools only),
prints the cycle report as JSON, and — in shadow — writes nothing and opens no
issues.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import os
import sys
from typing import Any

from app.config import load_soc_settings


def _build_loop(settings, *, force_shadow: bool):
    from app.cases.runtime import build_case_service_runtime
    from app.mcp_runtime import SocMCPRuntime
    from app.posture.desired_state import DesiredState
    from app.posture.loop import PostureLoop
    from app.posture.ledger import DailyLedger
    from app.coordination import CoordinatorNocToolClient, SocCoordinator
    from app.graph.nodes import SocGraphRuntime
    from app.redteam.exercise import RedTeamRunner
    from app.redteam.policy import RedTeamGate
    from app.redteam.validators import NonInvasiveValidator

    if force_shadow:
        settings = dataclasses.replace(settings, mode="shadow")

    coordinator = SocCoordinator.from_settings(settings)
    client: Any = CoordinatorNocToolClient(coordinator) if coordinator is not None else None
    disabled = os.getenv("SOC_AGENT_DISABLE_MCP", "").strip().lower() in {"1", "true", "yes", "on"}
    if not disabled and client is None:
        try:
            from app.tools.mcp_client import HyruleMCPClient

            client = HyruleMCPClient.from_env()
        except Exception as exc:  # no daemon configured -> degraded scan
            print(f"warning: MCP client unavailable ({type(exc).__name__}); scan will be degraded", file=sys.stderr)

    mcp_runtime = SocMCPRuntime(client, enable_heavy_probes=settings.posture.enable_heavy_probes)
    desired_state = DesiredState.from_settings(
        repo_dir=settings.posture.network_operations_dir or ".",
        manifest_path=settings.posture.golden_manifest_path or None,
        pin_sha=settings.posture.network_operations_pin_sha,
    )
    runtime = build_case_service_runtime(settings)
    ledger = DailyLedger.load(settings.posture.state_dir)
    graph_runtime = SocGraphRuntime(store=runtime.store, mcp_runtime=mcp_runtime)
    redteam_gate = RedTeamGate(settings.redteam)
    validator = NonInvasiveValidator(
        desired_state,
        redteam_gate,
        allowed_hosts=settings.posture.allowed_hosts,
    )
    return PostureLoop(
        settings=settings,
        service=runtime.service,
        mcp_runtime=mcp_runtime,
        desired_state=desired_state,
        ledger=ledger,
        graph_runtime=graph_runtime,
        coordinator=coordinator,
        redteam_runner=RedTeamRunner(desired_state, redteam_gate, validator=validator),
    )


async def _run_once(settings, *, force_shadow: bool, hosts: list[str] | None) -> dict[str, Any]:
    loop = _build_loop(settings, force_shadow=force_shadow)
    report = await loop.run_once(hosts=hosts, cycle_id="socctl")
    return dataclasses.asdict(report)


async def _verify(settings) -> dict[str, Any]:
    from app.cases.runtime import build_case_service_runtime
    from app.mcp_runtime import SocMCPRuntime
    from app.posture.desired_state import DesiredState
    from app.posture.verification import PostureVerificationLoop
    from app.coordination import CoordinatorNocToolClient, SocCoordinator

    runtime = build_case_service_runtime(settings)
    coordinator = SocCoordinator.from_settings(settings)
    client: Any = CoordinatorNocToolClient(coordinator) if coordinator is not None else None
    if client is None and os.getenv("SOC_AGENT_DISABLE_MCP", "").strip().lower() not in {"1", "true", "yes", "on"}:
        try:
            from app.tools.mcp_client import HyruleMCPClient

            client = HyruleMCPClient.from_env()
        except Exception as exc:
            print(f"warning: MCP client unavailable ({type(exc).__name__})", file=sys.stderr)
    mcp_runtime = SocMCPRuntime(client, enable_heavy_probes=settings.posture.enable_heavy_probes)
    desired_state = DesiredState.from_settings(
        repo_dir=settings.posture.network_operations_dir or ".",
        manifest_path=settings.posture.golden_manifest_path or None,
        pin_sha=settings.posture.network_operations_pin_sha,
    )
    loop = PostureVerificationLoop(
        service=runtime.service,
        verifier=runtime.verifier,
        mcp_runtime=mcp_runtime,
        desired_state=desired_state,
        coordinator=coordinator,
    )
    report = await loop.run_once(cycle_id="socctl-verify")
    return dataclasses.asdict(report)


async def _run_probes(settings) -> dict[str, Any]:
    from app.coordination import SocCoordinator
    from app.posture.desired_state import DesiredState
    from app.redteam.active import ActiveProbeExecutor, SocProbeWorker
    from app.redteam.policy import RedTeamGate
    from app.redteam.validators import NonInvasiveValidator

    coordinator = SocCoordinator.from_settings(settings)
    if coordinator is None:
        return {"checked": 0, "completed": [], "failed": [], "error": "coordinator is disabled"}
    desired_state = DesiredState.from_settings(
        repo_dir=settings.posture.network_operations_dir or ".",
        manifest_path=settings.posture.golden_manifest_path or None,
        pin_sha=settings.posture.network_operations_pin_sha,
    )
    gate = RedTeamGate(settings.redteam)
    ownership = NonInvasiveValidator(
        desired_state,
        gate,
        allowed_hosts=settings.posture.allowed_hosts,
    )
    worker = SocProbeWorker(
        coordinator.client,
        ActiveProbeExecutor(gate, ownership),
        mode=settings.mode,
    )
    return await worker.run_once()


async def _run_handoffs(settings) -> dict[str, Any]:
    from app.handoff_worker import SocHandoffWorker

    loop = _build_loop(settings, force_shadow=False)
    if loop.coordinator is None or loop.redteam_runner is None:
        return {"checked": 0, "completed": [], "failed": [], "error": "coordinator is disabled"}
    worker = SocHandoffWorker(
        loop.coordinator.client,
        loop.service,
        loop.coordinator,
        loop.redteam_runner,
    )
    return await worker.run_once()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="socctl", description="SOC Agent control CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="Print SOC settings/status")

    posture = sub.add_parser("posture", help="Posture scanner controls")
    posture_sub = posture.add_subparsers(dest="posture_command", required=True)
    run_once = posture_sub.add_parser("run-once", help="Run one posture cycle")
    run_once.add_argument("--shadow", action="store_true", help="Force shadow mode (no side effects)")
    run_once.add_argument("--hosts", default="", help="Comma-separated host override")
    posture_sub.add_parser("verify", help="Re-verify cases awaiting a positive re-read")

    probes = sub.add_parser("probes", help="Process senior-approved RT-2 probe work")
    probes_sub = probes.add_subparsers(dest="probes_command", required=True)
    probes_sub.add_parser("run-once", help="Process queued probe plans once")

    handoffs = sub.add_parser("handoffs", help="Process generic inbound LHP-v2 handoffs")
    handoffs_sub = handoffs.add_subparsers(dest="handoffs_command", required=True)
    handoffs_sub.add_parser("run-once", help="Process queued SOC capability requests once")

    args = parser.parse_args(argv)
    settings = load_soc_settings()

    if args.command == "status":
        print(
            json.dumps(
                {
                    "enabled": settings.enabled,
                    "mode": settings.mode,
                    "posture_enabled": settings.posture.enabled,
                    "severity_floor": settings.posture.severity_floor,
                    "allowed_hosts": settings.posture.allowed_hosts,
                    "network_operations_dir": settings.posture.network_operations_dir,
                    "lhp_enabled": settings.loop_handoff.enabled,
                    "coordinator_enabled": settings.coordination.enabled,
                    "active_probe_execution": settings.mode == "probe_live",
                },
                indent=2,
            )
        )
        return 0

    if args.command == "posture" and args.posture_command == "run-once":
        hosts = [h.strip() for h in args.hosts.split(",") if h.strip()] or None
        report = asyncio.run(_run_once(settings, force_shadow=args.shadow, hosts=hosts))
        print(json.dumps(report, indent=2))
        return 0

    if args.command == "posture" and args.posture_command == "verify":
        print(json.dumps(asyncio.run(_verify(settings)), indent=2))
        return 0

    if args.command == "probes" and args.probes_command == "run-once":
        print(json.dumps(asyncio.run(_run_probes(settings)), indent=2))
        return 0

    if args.command == "handoffs" and args.handoffs_command == "run-once":
        print(json.dumps(asyncio.run(_run_handoffs(settings)), indent=2))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
