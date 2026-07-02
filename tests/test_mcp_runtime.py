"""SOC MCP allowlists exclude every mutating tool; enforcement is real."""

from __future__ import annotations

import pytest

from app.mcp_runtime import (
    FORBIDDEN_TOOLS,
    SOC_CRYPTO_TOOLS,
    SOC_FIREWALL_TOOLS,
    SOC_HEAVY_TOOLS,
    SOC_POSTURE_TOOLS,
    SOC_ROUTING_TOOLS,
    SOC_TRIAGE_TOOLS,
    ForbiddenToolError,
    MCPDisabledError,
    SocMCPRuntime,
    soc_allowlist,
)

MUTATING = {"os_systemd_restart", "os_service_restart", "icinga_acknowledge_alert", "ssh_run_command"}
ALL_SOC_SETS = [SOC_TRIAGE_TOOLS, SOC_ROUTING_TOOLS, SOC_FIREWALL_TOOLS, SOC_CRYPTO_TOOLS, SOC_POSTURE_TOOLS]


def test_no_mutating_tool_in_any_soc_set():
    for tool_set in ALL_SOC_SETS:
        assert not (tool_set & MUTATING), f"mutating tool leaked into {tool_set}"
    assert MUTATING <= FORBIDDEN_TOOLS


def test_heavy_probes_stripped_unless_enabled():
    default = soc_allowlist("routing_security", enable_heavy=False)
    assert not (default & SOC_HEAVY_TOOLS)
    posture_all = soc_allowlist(None, enable_heavy=True)
    # even with heavy enabled, forbidden tools never appear
    assert not (posture_all & FORBIDDEN_TOOLS)


async def test_call_tool_refuses_forbidden_tool():
    class _Client:
        async def call_tool(self, name, args):
            return {"ok": True, "stdout": "should not reach"}

    rt = SocMCPRuntime(_Client(), disabled=False)
    with pytest.raises(ForbiddenToolError):
        await rt.call_tool("hyrule", "os_systemd_restart", {"host": "cr1-nl1", "unit": "frr"})
    with pytest.raises(ForbiddenToolError):
        await rt.call_tool("hyrule", "ssh_run_command", {"host": "cr1-nl1", "command": "id"})


async def test_call_tool_allows_read_only_and_delegates():
    class _Client:
        async def call_tool(self, name, args):
            return {"ok": True, "stdout": f"ran {name}"}

    rt = SocMCPRuntime(_Client(), disabled=False)
    resp = await rt.call_tool("hyrule", "frr_vtysh_cmd", {"host": "cr1-nl1", "command": "show running-config"})
    assert resp["stdout"] == "ran frr_vtysh_cmd"


async def test_disabled_runtime_raises():
    rt = SocMCPRuntime(None, disabled=True)
    with pytest.raises(MCPDisabledError):
        await rt.call_tool("hyrule", "wg_show", {"host": "cr1-nl1"})


async def test_heavy_tool_blocked_unless_runtime_enables_it():
    class _Client:
        async def call_tool(self, name, args):
            return {"ok": True, "stdout": "capture"}

    rt = SocMCPRuntime(_Client(), disabled=False, enable_heavy_probes=False)
    with pytest.raises(ForbiddenToolError):
        await rt.call_tool("hyrule", "tcpdump_capture", {"host": "cr1-nl1", "iface": "wg0", "filter": "icmp6"})
    rt_heavy = SocMCPRuntime(_Client(), disabled=False, enable_heavy_probes=True)
    assert (await rt_heavy.call_tool("hyrule", "tcpdump_capture", {"host": "cr1-nl1", "iface": "wg0", "filter": "icmp6"}))["ok"]
