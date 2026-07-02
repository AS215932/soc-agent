"""Best-effort agent-core tracing: off by default, correlation-carrying when on."""

from __future__ import annotations

from app import agent_core_trace


def test_disabled_by_default_emits_nothing(monkeypatch):
    monkeypatch.delenv(agent_core_trace.FLAG_ENV, raising=False)
    assert agent_core_trace.enabled() is False
    assert agent_core_trace.emit_case_trace({"case_id": "sec_case_1"}, phase="scan") == 0


def test_enabled_emits_to_jsonl_sink(monkeypatch, tmp_path):
    path = tmp_path / "trace.jsonl"
    monkeypatch.setenv(agent_core_trace.FLAG_ENV, "1")
    monkeypatch.setenv(f"{agent_core_trace.FLAG_ENV}_PATH", str(path))
    state = {
        "case_id": "sec_case_abc",
        "handoff_id": "handoff_xyz",
        "case_type": "control_drift",
        "severity": "HIGH",
        "status": "handoff_requested",
        "finding_ids": ["secf_1", "secf_2"],
        "title": "RPKI-invalid reject missing on transit",
    }
    delivered = agent_core_trace.emit_case_trace(state, phase="handoff")
    assert delivered == 1
    lines = [line for line in path.read_text().splitlines() if line.strip()]
    assert len(lines) == 1
    import json

    event = json.loads(lines[0])
    assert event["case_id"] == "sec_case_abc"
    assert event["handoff_id"] == "handoff_xyz"
    assert event["graph_id"] == "soc-agent"
    assert event["event_type"] == "soc_case_summary"
    # Untrusted-loop-text guard is stamped so downstream never re-feeds it to a model.
    assert event["payload"]["model_consumption_allowed"] is False
