"""Lean read-only Hyrule MCP client.

Connects to the Hyrule MCP daemon over streamable HTTP (the deployed loopback
transport, ``http://127.0.0.1:8765/mcp``) or stdio, calls a single tool, and
returns the tool's structured result dict. Deliberately minimal — the SOC Agent
only ever *reads*, on a slow (minutes) cadence, so a fresh session per call is
acceptable and avoids long-lived-session reconnect complexity.

Offline tests never construct this client: ``SocMCPRuntime`` short-circuits when
``SOC_AGENT_DISABLE_MCP`` is set, and unit tests inject a fake runtime.
"""

from __future__ import annotations

import json
import shlex
from typing import Any


class HyruleMCPClient:
    def __init__(self, *, url: str | None = None, command: list[str] | None = None) -> None:
        if not url and not command:
            raise ValueError("HyruleMCPClient requires either a url or a command")
        self.url = url
        self.command = command

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "HyruleMCPClient":
        import os

        env = env or dict(os.environ)
        url = (env.get("HYRULE_MCP_URL") or "").strip()
        if url:
            return cls(url=url)
        cmd = (env.get("HYRULE_MCP_CMD") or "").strip()
        if cmd:
            return cls(command=shlex.split(cmd))
        raise ValueError("Set HYRULE_MCP_URL or HYRULE_MCP_CMD to reach the Hyrule MCP daemon")

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        from mcp.client.session import ClientSession

        if self.url:
            from mcp.client.streamable_http import streamablehttp_client

            async with streamablehttp_client(self.url) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return _parse_result(await session.call_tool(name, arguments))
        else:
            from mcp.client.stdio import StdioServerParameters, stdio_client

            if self.command is None:
                raise ValueError("Set HYRULE_MCP_CMD to use stdio mode")
            params = StdioServerParameters(command=self.command[0], args=list(self.command[1:]))
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return _parse_result(await session.call_tool(name, arguments))


def _parse_result(result: Any) -> dict[str, Any]:
    """Extract the tool's dict payload from an MCP CallToolResult.

    FastMCP returns structured content plus a text mirror; prefer the structured
    form, fall back to JSON-parsing the first text block.
    """
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        # FastMCP wraps a bare return value under {"result": ...}; unwrap if so.
        if set(structured.keys()) == {"result"} and isinstance(structured["result"], dict):
            return structured["result"]
        return structured
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return parsed
            except (TypeError, ValueError):
                continue
    return {"ok": False, "summary": "unparseable MCP result", "stdout": ""}
