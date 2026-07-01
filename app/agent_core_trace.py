"""Best-effort agent-core TraceEvent emission for SOC Agent runs.

Emission is strictly best-effort: a missing ``agent-core`` install, collector
failures, invalid payload shapes, and file/HTTP errors are all swallowed so SOC
governance gates and scan/graph execution can never be affected by observability
delivery. Mirrors ``hyrule-noc-agent/app/agent_core_trace.py`` with SOC-shaped
events and the SOC correlation flag.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Mapping
from typing import Any

FLAG_ENV = "HYRULE_SOC_AGENT_CORE_TRACE"
_TRUTHY = {"1", "true", "yes", "on"}
GRAPH_ID = "soc-agent"


def enabled() -> bool:
    return os.environ.get(FLAG_ENV, "").strip().lower() in _TRUTHY


def emit_case_trace(state: Mapping[str, Any], *, phase: str) -> int:
    """Emit TraceEvents for a SOC case/graph state; return delivered count.

    ``state`` is any mapping carrying SOC correlation keys (``case_id``,
    ``handoff_id``, ``objective_id``) and optional summary fields
    (``title``/``summary``/``severity``/``finding_count``). Returns 0 when the
    flag is off or agent-core is unavailable.
    """
    if not enabled():
        return 0
    try:
        sink_mod = importlib.import_module("agent_core.tracing.sink")
        sink = sink_mod.sink_from_env(FLAG_ENV)
        count = 0
        for event in _events_from_state(state, phase=phase):
            if sink.emit(event):
                count += 1
        return count
    except Exception:
        return 0


def _events_from_state(state: Mapping[str, Any], *, phase: str) -> list[Any]:
    tracing_mod = importlib.import_module("agent_core.contracts.tracing")
    TraceEvent = tracing_mod.TraceEvent
    run_id = _string_or_none(state.get("case_id")) or _string_or_none(state.get("run_id"))
    trace_id = _string_or_none(state.get("trace_id")) or run_id
    summary_event = TraceEvent(
        **_correlation_fields(state),
        event_type="soc_case_summary",
        graph_id=GRAPH_ID,
        node_id="soc_runtime",
        agent_role="soc_analyst",
        environment="production",
        run_id=run_id,
        trace_id=trace_id,
        summary=_case_summary(state, phase=phase),
        payload={
            "phase": phase,
            "case_id": state.get("case_id"),
            "case_type": state.get("case_type"),
            "severity": state.get("severity"),
            "confidence": state.get("confidence"),
            "case_status": state.get("status") or state.get("case_status"),
            "finding_count": len(_listish(state.get("finding_ids") or state.get("findings"))),
            # Findings are derived from untrusted telemetry; never re-fed to a model raw.
            "untrusted_loop_text": True,
            "model_consumption_allowed": False,
        },
    )
    return [summary_event]


def _case_summary(state: Mapping[str, Any], *, phase: str) -> str:
    title = state.get("title") or state.get("summary")
    if title:
        return f"{phase}: {_safe_text(title)}"
    case_id = state.get("case_id") or "case"
    return f"{phase}: SOC case {case_id}"


def _correlation_fields(state: Mapping[str, Any]) -> dict[str, Any]:
    case_id = _safe_token(state.get("case_id"))
    handoff_id = _safe_token(state.get("handoff_id"))
    objective_id = _safe_token(state.get("objective_id"))
    links = []
    if case_id:
        links.append({"kind": "case", "label": "SOC case", "ref_id": case_id})
    if handoff_id:
        links.append({"kind": "handoff", "label": "Loop handoff", "ref_id": handoff_id})
    if objective_id:
        links.append({"kind": "verification", "label": "Verification objective", "ref_id": objective_id})
    return {"case_id": case_id, "handoff_id": handoff_id, "objective_id": objective_id, "links": links}


def _safe_text(value: Any, *, limit: int = 120) -> str:
    text = _string_or_none(value) or ""
    text = " ".join(text.split())
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def _safe_token(value: Any, *, limit: int = 180) -> str | None:
    text = _safe_text(value, limit=limit)
    if not text:
        return None
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:/@+-")
    return "".join(char if char in allowed else "_" for char in text)


def _listish(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
