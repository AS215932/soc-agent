"""Driver for the SOC commander graph with human-in-the-loop resume.

A ``SocGraphSession`` holds one compiled graph + checkpointer so a run can pause
at ``approval_interrupt`` and later resume with the operator's decision on the
same ``thread_id``.
"""

from __future__ import annotations

from typing import Any

from langgraph.types import Command

from app.graph.graph import build_graph
from app.graph.nodes import SocGraphRuntime


class SocGraphSession:
    def __init__(self, runtime: SocGraphRuntime, *, checkpointer: Any | None = None) -> None:
        self.runtime = runtime
        self.graph = build_graph(runtime, checkpointer=checkpointer)

    @staticmethod
    def _config(thread_id: str) -> dict[str, Any]:
        return {"configurable": {"thread_id": thread_id}}

    async def start(self, finding: dict[str, Any], *, thread_id: str, case_id: str = "") -> dict[str, Any]:
        state = await self.graph.ainvoke(
            {"finding": finding, "case_id": case_id, "thread_id": thread_id},
            config=self._config(thread_id),
        )
        return state

    async def resume(self, decision: Any, *, thread_id: str) -> dict[str, Any]:
        return await self.graph.ainvoke(Command(resume=decision), config=self._config(thread_id))

    @staticmethod
    def interrupt_payload(state: dict[str, Any]) -> dict[str, Any] | None:
        interrupts = state.get("__interrupt__")
        if not interrupts:
            return None
        first = interrupts[0]
        value = getattr(first, "value", None)
        return value if isinstance(value, dict) else {"value": value}

    def is_waiting_for_approval(self, state: dict[str, Any]) -> bool:
        return self.interrupt_payload(state) is not None
