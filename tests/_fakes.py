"""Test doubles for the SOC Agent (no live MCP)."""

from __future__ import annotations

from typing import Any, Callable

from app.mcp_runtime import SOC_READ_ONLY_TOOLS


class FakeMCPRuntime:
    """A ``SocMCPRuntime``-shaped double driven by a handler callable.

    ``handler(name, arguments) -> dict`` returns the canned MCP result. Raise
    inside the handler to simulate a tool failure (the scanner will mark the
    cycle degraded). Records every call for assertions.
    """

    def __init__(self, handler: Callable[[str, dict[str, Any]], dict[str, Any]], *, enable_heavy_probes: bool = False) -> None:
        self._handler = handler
        self.enable_heavy_probes = enable_heavy_probes
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(self, source: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((name, dict(arguments)))
        return self._handler(name, arguments)


def ok(stdout: str = "", *, data: dict[str, Any] | None = None, tool: str = "t", host: str = "h") -> dict[str, Any]:
    result: dict[str, Any] = {"ok": True, "tool": tool, "target": host, "summary": "ok", "stdout": stdout, "exit_code": 0}
    if data is not None:
        result["data"] = data
    return result


def fail(summary: str = "failed", *, tool: str = "t", host: str = "h") -> dict[str, Any]:
    return {"ok": False, "tool": tool, "target": host, "summary": summary, "stdout": "", "exit_code": 1}


# The read-only tool set the SOC agent may call (used by allowlist assertions).
READ_ONLY = SOC_READ_ONLY_TOOLS
