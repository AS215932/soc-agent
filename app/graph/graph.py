"""Assemble the SOC commander graph.

correlate → recall → route → {specialist} → evidence_validation → finding_build →
prepare_approval → approval_interrupt → {request_handoff | END}

There is deliberately no execution node: the SOC Agent terminates at a handoff
request and never mutates production.
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from app.graph.nodes import SocGraphRuntime, SocNodeRunner
from app.graph.routing import route_specialist
from app.graph.state import SocWorkflowState

_SPECIALISTS = ("routing_security", "exposure", "crypto", "detection")


def build_graph(runtime: SocGraphRuntime, *, checkpointer: Any | None = None):
    nodes = SocNodeRunner(runtime)
    workflow = StateGraph(SocWorkflowState)

    workflow.add_node("correlate_and_dedupe", nodes.correlate_and_dedupe)
    workflow.add_node("recall_history", nodes.recall_history)
    workflow.add_node("soc_commander_route", nodes.soc_commander_route)
    workflow.add_node("routing_security_specialist", nodes.routing_security_specialist)
    workflow.add_node("exposure_specialist", nodes.exposure_specialist)
    workflow.add_node("crypto_specialist", nodes.crypto_specialist)
    workflow.add_node("detection_specialist", nodes.detection_specialist)
    workflow.add_node("evidence_validation", nodes.evidence_validation)
    workflow.add_node("finding_build", nodes.finding_build)
    workflow.add_node("prepare_approval", nodes.prepare_approval)
    workflow.add_node("approval_interrupt", nodes.approval_interrupt)
    workflow.add_node("request_handoff", nodes.request_handoff)

    workflow.add_edge(START, "correlate_and_dedupe")
    workflow.add_edge("correlate_and_dedupe", "recall_history")
    workflow.add_edge("recall_history", "soc_commander_route")
    workflow.add_conditional_edges(
        "soc_commander_route",
        route_specialist,
        {f"{s}_specialist": f"{s}_specialist" for s in _SPECIALISTS},
    )
    for s in _SPECIALISTS:
        workflow.add_edge(f"{s}_specialist", "evidence_validation")
    workflow.add_edge("evidence_validation", "finding_build")
    workflow.add_edge("finding_build", "prepare_approval")
    workflow.add_edge("prepare_approval", "approval_interrupt")
    workflow.add_conditional_edges(
        "approval_interrupt",
        _route_after_approval,
        {"request_handoff": "request_handoff", "end": END},
    )
    workflow.add_edge("request_handoff", END)

    if checkpointer is None:
        from langgraph.checkpoint.memory import MemorySaver

        checkpointer = MemorySaver()
    return workflow.compile(checkpointer=checkpointer)


def _route_after_approval(state: SocWorkflowState) -> str:
    approved = state.get("approval_state") == "approved"
    warrants = bool((state.get("enriched_finding") or {}).get("warrants_handoff"))
    return "request_handoff" if (approved and warrants) else "end"
