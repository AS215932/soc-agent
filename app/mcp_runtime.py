"""SOC Agent MCP runtime: per-role **read-only** tool allowlists + enforcement.

The security guarantee is defence-in-depth: even if a graph node or scanner asks
for a mutating tool, ``SocMCPRuntime.call_tool`` refuses it. No SOC allowlist
contains a mutating tool (``os_systemd_restart``, ``os_service_restart``,
``icinga_acknowledge_alert``) or the broad ``ssh_run_command``; a test asserts
this. Heavy read-only probes are stripped unless explicitly enabled.
"""

from __future__ import annotations

import os
from typing import Any

from app import log

# --- read-only allowlists (mirror the shape of noc mcp_runtime TRIAGE/BGP/...) ---

SOC_TRIAGE_TOOLS = {
    "icinga_list_problems",
    "icinga_get_host_state",
    "prometheus_list_targets",
    "prometheus_query",
}
SOC_ROUTING_TOOLS = {
    "frr_vtysh_cmd",
    "path_explain",
    "ecmp_path_select",
    "prometheus_query",
    "socket_listeners",
}
SOC_FIREWALL_TOOLS = {
    "firewall_state",
    "pf_log_tail",
    "nft_log_tail",
    "socket_listeners",
    "ndp_state",
    "arp_state",
    "path_explain",
    "prometheus_query",
}
SOC_CRYPTO_TOOLS = {
    "wg_show",
    "vault_agent_status",
    "socket_listeners",
    "os_service_status",
    "os_systemd_status",
    "os_rcctl_check",
}
SOC_DNS_TOOLS = {
    "dns_dig",
    "knot_zone_status",
}

# Heavy read-only probes: consume real resources / edge toward RT-2. Stripped
# unless SOC_ENABLE_HEAVY_PROBES=1.
SOC_HEAVY_TOOLS = {
    "tcpdump_capture",
    "system_tcpdump",
    "dns_probe_burst",
    "multi_source_probe",
}

# Tools that must NEVER appear in a SOC allowlist. ``call_tool`` hard-refuses
# them regardless of caller.
FORBIDDEN_TOOLS = {
    "os_systemd_restart",
    "os_service_restart",
    "icinga_acknowledge_alert",
    "ssh_run_command",
    "prepare_commit_confirm",
    "confirm_change",
    "rollback_change",
}

_SPECIALIST_SETS: dict[str, set[str]] = {
    "triage": SOC_TRIAGE_TOOLS,
    "routing_security": SOC_ROUTING_TOOLS,
    "exposure": SOC_FIREWALL_TOOLS,
    "crypto": SOC_CRYPTO_TOOLS,
    "detection": SOC_TRIAGE_TOOLS,
    "dns": SOC_DNS_TOOLS,
}

# The union the posture scanner may call.
SOC_POSTURE_TOOLS = (
    SOC_ROUTING_TOOLS | SOC_FIREWALL_TOOLS | SOC_CRYPTO_TOOLS | SOC_DNS_TOOLS | SOC_TRIAGE_TOOLS
)

SOC_READ_ONLY_TOOLS = SOC_POSTURE_TOOLS | SOC_HEAVY_TOOLS


def soc_allowlist(specialist: str | None, *, enable_heavy: bool = False) -> set[str]:
    """The read-only tool set for a specialist (or the full posture union)."""
    base = _SPECIALIST_SETS.get(specialist or "", SOC_POSTURE_TOOLS)
    tools = set(base)
    if not enable_heavy:
        tools -= SOC_HEAVY_TOOLS
    # Belt-and-braces: never expose a forbidden tool even if a set is mis-edited.
    return tools - FORBIDDEN_TOOLS


class MCPDisabledError(RuntimeError):
    """Raised when MCP access is disabled (tests / shadow without a daemon)."""


class ForbiddenToolError(RuntimeError):
    """Raised when a mutating / non-allowlisted tool is requested."""


class SocMCPRuntime:
    """Read-only façade over a Hyrule MCP client.

    ``client`` is any object exposing ``async call_tool(name, arguments)``. When
    MCP is disabled (``SOC_AGENT_DISABLE_MCP`` or no client), ``call_tool``
    raises ``MCPDisabledError`` so the scanner degrades cleanly.
    """

    def __init__(
        self,
        client: Any | None = None,
        *,
        disabled: bool | None = None,
        enable_heavy_probes: bool = False,
    ) -> None:
        self._client = client
        self.enable_heavy_probes = enable_heavy_probes
        if disabled is None:
            disabled = os.getenv("SOC_AGENT_DISABLE_MCP", "").strip().lower() in {"1", "true", "yes", "on"}
        self.disabled = disabled

    def allowed_tools(self, specialist: str | None = None) -> set[str]:
        return soc_allowlist(specialist, enable_heavy=self.enable_heavy_probes)

    def toolsets_for(self, specialist: str | None = None) -> list[Any]:
        """PydanticAI toolsets a specialist may use. v1 specialists reason over
        the finding's embedded (already-collected) MCP evidence, so this is empty;
        live-tool-augmented specialists are a follow-up. The method exists so the
        graph can bind toolsets without a signature change later."""
        return []

    def is_allowed(self, name: str) -> bool:
        if name in FORBIDDEN_TOOLS:
            return False
        if name in SOC_HEAVY_TOOLS and not self.enable_heavy_probes:
            return False
        return name in SOC_READ_ONLY_TOOLS

    async def call_tool(self, source: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if not self.is_allowed(name):
            raise ForbiddenToolError(f"tool {name!r} is not in the SOC read-only allowlist")
        if self.disabled or self._client is None:
            raise MCPDisabledError("MCP access is disabled for the SOC Agent (SOC_AGENT_DISABLE_MCP)")
        result = await self._client.call_tool(name, arguments)
        if not isinstance(result, dict):
            log.warning("soc_mcp_unexpected_result", tool=name, type=type(result).__name__)
            return {"ok": False, "summary": "unexpected MCP result", "stdout": ""}
        return result
