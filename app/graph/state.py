"""SOC commander graph state — JSON-safe only.

Runtime dependencies (clients, agents, models, toolsets) must never be stored in
state; they live on ``SocGraphRuntime`` and are threaded at invocation time.
"""

from __future__ import annotations

import json
from typing import Any, Literal, TypedDict

JsonDict = dict[str, Any]


class SocWorkflowState(TypedDict, total=False):
    # identity / context
    case_id: str
    fingerprint: str
    thread_id: str
    current_step: str
    finding: JsonDict            # the seed SecurityFinding (json)
    case_context: JsonDict       # prior case status, if any

    # routing
    specialist: Literal["routing_security", "exposure", "crypto", "detection"]
    routing_reason: str

    # specialist output
    assessment: JsonDict
    evidence_valid: bool
    evidence_note: str

    # enriched result
    enriched_finding: JsonDict

    # human-in-the-loop
    approval_state: str          # waiting_approval | approved | rejected
    operator_decision: JsonDict | None

    # outcome
    handoff_requested: bool
    errors: list[JsonDict]


def assert_json_serializable_state(state: dict[str, Any]) -> None:
    if "model" in state or "runtime" in state:
        raise TypeError("runtime objects (model/runtime) must not be persisted in SocWorkflowState")
    json.dumps(state)
