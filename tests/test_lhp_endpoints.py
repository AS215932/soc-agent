"""SOC LHP-v1 origin endpoints: signed fetch + signed callback, with the
verifier-only guarantee (engineering cannot set verified/resolved)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.cases.models import SecurityFinding
from app.cases.runtime import build_in_memory_runtime
from app.lhp import HandoffUpdate, build_loop_signature
from app.main import app, get_runtime

SECRET = "soc-engineering-shared-secret-value"


def _finding() -> SecurityFinding:
    return SecurityFinding(
        check_id="rpki_in_frr",
        key="cr1-nl1",
        category="bgp_rpki",
        severity="HIGH",
        confidence="confirmed",
        passed=False,
        warrants_handoff=True,
        objective_key="frr-transit-rpki-invalid-reject-v1",
        title="RPKI-invalid reject missing",
    )


@pytest.fixture
def seeded(monkeypatch):
    monkeypatch.setenv("SOC_LHP_ENABLED", "1")
    monkeypatch.setenv("SOC_LHP_ENGINEERING_SECRET", SECRET)
    runtime = build_in_memory_runtime()
    finding = _finding()
    case = runtime.service.observe_finding(finding, cycle_id="c1").case
    bundle = runtime.service.request_handoff(case.case_id, finding)
    app.dependency_overrides[get_runtime] = lambda: runtime
    yield runtime, case, bundle
    app.dependency_overrides.clear()


def _headers(method: str, path: str, body) -> dict[str, str]:
    ts = datetime.now(timezone.utc).isoformat()
    return {
        "x-noc-loop-identity": "engineering",
        "x-noc-loop-timestamp": ts,
        "x-noc-loop-signature": build_loop_signature(secret=SECRET, method=method, path=path, timestamp=ts, body=body),
        "content-type": "application/json",
    }


def test_fetch_returns_lhp_payload(seeded):
    _, case, bundle = seeded
    client = TestClient(app)
    path = f"/loop-handoff/v1/soc/handoffs/{bundle.handoff.handoff_id}"
    resp = client.get(path, headers=_headers("GET", path, {}))
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["schema_version"] == "lhp.v1"
    assert payload["handoff"]["handoff_id"] == bundle.handoff.handoff_id
    assert payload["handoff"]["source_loop"] == "soc"
    assert payload["case"]["case_id"] == case.case_id
    assert len(payload["verification_objectives"]) == 1
    assert payload["payload_hash"]


def test_fetch_rejects_bad_signature(seeded):
    _, _, bundle = seeded
    client = TestClient(app)
    path = f"/loop-handoff/v1/soc/handoffs/{bundle.handoff.handoff_id}"
    headers = _headers("GET", path, {})
    headers["x-noc-loop-signature"] = "deadbeef"
    assert client.get(path, headers=headers).status_code == 401


def test_fetch_rejects_wrong_identity(seeded):
    _, _, bundle = seeded
    client = TestClient(app)
    path = f"/loop-handoff/v1/soc/handoffs/{bundle.handoff.handoff_id}"
    headers = _headers("GET", path, {})
    headers["x-noc-loop-identity"] = "knowledge"
    assert client.get(path, headers=headers).status_code == 401


def test_disabled_lhp_returns_404(seeded, monkeypatch):
    _, _, bundle = seeded
    monkeypatch.setenv("SOC_LHP_ENABLED", "0")
    client = TestClient(app)
    path = f"/loop-handoff/v1/soc/handoffs/{bundle.handoff.handoff_id}"
    assert client.get(path, headers=_headers("GET", path, {})).status_code == 404


def _callback_body(case_id: str, handoff_id: str, *, update_type="accepted", status="accepted", event="evt-1") -> dict:
    update = HandoffUpdate(
        handoff_id=handoff_id,
        case_id=case_id,
        source_loop="engineering",
        update_type=update_type,
        status=status,
        external_event_id=event,
        correlation_id="corr-1",
    )
    return update.model_dump(mode="json")


def test_callback_accepts_engineering_progress(seeded):
    runtime, case, bundle = seeded
    client = TestClient(app)
    path = "/webhook/engineering-loop/handoff-update"
    body = _callback_body(case.case_id, bundle.handoff.handoff_id)
    resp = client.post(path, json=body, headers=_headers("POST", path, body))
    assert resp.status_code == 200
    assert resp.json()["status"] == "accepted"
    assert runtime.store.get_handoff(bundle.handoff.handoff_id).status == "accepted"
    assert runtime.store.get_case(case.case_id).status == "handoff_in_progress"


def test_callback_dedupes_on_repeat(seeded):
    _, case, bundle = seeded
    client = TestClient(app)
    path = "/webhook/engineering-loop/handoff-update"
    body = _callback_body(case.case_id, bundle.handoff.handoff_id, event="dup-evt")
    headers = _headers("POST", path, body)
    first = client.post(path, json=body, headers=headers)
    second = client.post(path, json=body, headers=_headers("POST", path, body))
    assert first.json()["status"] == "accepted"
    assert second.json()["status"] == "duplicate"


def test_callback_rejects_verifier_only_status(seeded):
    _, case, bundle = seeded
    client = TestClient(app)
    path = "/webhook/engineering-loop/handoff-update"
    # Engineering trying to set verified/resolved must be rejected (422). Build the
    # raw dict directly — constructing a HandoffUpdate here would raise first.
    body = {
        "schema_version": "lhp.v1",
        "handoff_id": bundle.handoff.handoff_id,
        "case_id": case.case_id,
        "source_loop": "engineering",
        "update_type": "implemented",
        "status": "resolved",
        "external_event_id": "evil",
        "correlation_id": "corr-1",
    }
    resp = client.post(path, json=body, headers=_headers("POST", path, body))
    assert resp.status_code == 422


def test_callback_rejects_non_engineering_source(seeded):
    _, case, bundle = seeded
    client = TestClient(app)
    path = "/webhook/engineering-loop/handoff-update"
    body = _callback_body(case.case_id, bundle.handoff.handoff_id)
    body["source_loop"] = "soc"
    resp = client.post(path, json=body, headers=_headers("POST", path, body))
    assert resp.status_code == 422
