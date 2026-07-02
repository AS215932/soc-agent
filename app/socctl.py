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

    if force_shadow:
        settings = dataclasses.replace(settings, mode="shadow")

    client = None
    disabled = os.getenv("SOC_AGENT_DISABLE_MCP", "").strip().lower() in {"1", "true", "yes", "on"}
    if not disabled:
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
    return PostureLoop(
        settings=settings,
        service=runtime.service,
        mcp_runtime=mcp_runtime,
        desired_state=desired_state,
        ledger=ledger,
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

    runtime = build_case_service_runtime(settings)
    client = None
    if os.getenv("SOC_AGENT_DISABLE_MCP", "").strip().lower() not in {"1", "true", "yes", "on"}:
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
        service=runtime.service, verifier=runtime.verifier, mcp_runtime=mcp_runtime, desired_state=desired_state
    )
    report = await loop.run_once(cycle_id="socctl-verify")
    return dataclasses.asdict(report)


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

    parser.print_help()
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
