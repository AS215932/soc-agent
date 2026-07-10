"""Best-effort agent-core TraceEvent emission for SOC Agent runs.

Emission is strictly best-effort: a missing ``agent-core`` install, collector
failures, invalid payload shapes, and file/HTTP errors are all swallowed so SOC
governance gates and scan/graph execution can never be affected by observability
delivery. Mirrors ``hyrule-noc-agent/app/agent_core_trace.py`` with SOC-shaped
events and the SOC correlation flag.
"""

from __future__ import annotations

import importlib
import hashlib
import json
import os
from collections.abc import Mapping, Sequence
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


def emit_loop_decision_envelopes(
    insights: Sequence[Mapping[str, Any]],
    *,
    input_event: Mapping[str, Any] | None = None,
) -> int:
    """Emit one LoopDecisionEnvelope TraceEvent per private insight record."""
    if not enabled() or not insights:
        return 0
    try:
        sink_mod = importlib.import_module("agent_core.tracing.sink")
        sink = sink_mod.sink_from_env(FLAG_ENV)
        count = 0
        for insight in insights:
            event = _loop_decision_event(insight, input_event=input_event or {})
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


def _loop_decision_event(insight: Mapping[str, Any], *, input_event: Mapping[str, Any]) -> Any:
    contracts = importlib.import_module("agent_core.contracts")
    TraceEvent = getattr(contracts, "TraceEvent")
    LoopDecisionEnvelope = getattr(contracts, "LoopDecisionEnvelope")
    InsightDecisionRecord = getattr(contracts, "InsightDecisionRecord")

    validated = InsightDecisionRecord.model_validate(dict(insight))
    # Correlate with the posture cycle when the insight carries no explicit
    # trace id (mirrors the case-trace fallback) so consumers can join the
    # insight stream back to its cycle.
    trace_id = validated.trace_id or _string_or_none(input_event.get("cycle_id"))
    envelope = LoopDecisionEnvelope(
        envelope_id=f"ldec_soc_{_stable_hash([validated.insight_id, validated.fingerprint, validated.action_selected])}",
        loop="soc",
        environment="production",
        graph_id=GRAPH_ID,
        node_id="posture_loop",
        agent_role="soc_analyst",
        run_id=_string_or_none(input_event.get("cycle_id")) or validated.run_id,
        trace_id=trace_id,
        input_event={
            **_jsonish(dict(input_event)),
            "candidate_type": validated.candidate_type,
            "candidate_source": validated.candidate_source,
        },
        retrieved_context=validated.evidence_refs,
        decision=validated.action_selected,
        evidence_refs=validated.evidence_refs,
        proposed_action={
            "candidate_type": validated.candidate_type,
            "candidate_source": validated.candidate_source,
            "why_now": validated.why_now,
            "support_fact_count": len(validated.support_facts),
        },
        human_outcome=validated.human_feedback,
        governance=validated.governance,
        insight_id=validated.insight_id,
        case_id=validated.case_id,
        meta_case_id=validated.meta_case_id,
        fingerprint=validated.fingerprint,
        policy_version=validated.policy_version,
    )
    return TraceEvent(
        event_type="loop_decision_envelope",
        graph_id=GRAPH_ID,
        node_id="loop_decision_envelope",
        agent_role="soc_analyst",
        environment="production",
        run_id=envelope.run_id,
        trace_id=envelope.trace_id,
        case_id=envelope.case_id,
        summary=f"SOC loop decision envelope for {validated.insight_id}",
        payload={
            # The envelope alone drops sampling_class/utility/cost/support_facts;
            # IDQ/CGS evaluation needs the full record, so ship both together.
            "loop_decision_envelope": envelope.model_dump(mode="json"),
            "insight_decision_record": validated.model_dump(mode="json"),
            # support_facts derive from finding text (untrusted telemetry) —
            # same guard fields the case trace carries, so downstream consumers
            # never treat this payload as model-safe input.
            "untrusted_loop_text": True,
            "model_consumption_allowed": False,
        },
    )


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


def _jsonish(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _jsonish(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonish(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)


def _stable_hash(parts: list[Any]) -> str:
    payload = json.dumps(_jsonish(parts), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
