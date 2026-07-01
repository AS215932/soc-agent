"""SOC Agent FastAPI service.

Exposes the SOC side of LHP-v1 as an *origin* loop:

- ``GET  /loop-handoff/v1/soc/handoffs/{handoff_id}`` — the Engineering Loop
  fetches the authoritative ``lhp.v1`` handoff payload (HMAC-authenticated).
- ``POST /webhook/engineering-loop/handoff-update`` — signed non-terminal
  progress callbacks from the Engineering Loop (it can never set
  ``verified``/``resolved`` — those are SOC-verifier-owned).

Plus ``/health`` and token-gated control endpoints. All LHP traffic is
HMAC-SHA256 signed over ``METHOD\\npath\\ntimestamp\\ncanonical-json-body`` with a
±300s timestamp window and the ``x-noc-loop-*`` headers the engineering client
already sends.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request

from app import log
from app.cases.runtime import CaseServiceRuntime, build_case_service_runtime
from app.cases.summaries import build_lhp_fetch_payload
from app.config import (
    LHP_ENGINEERING_SECRET_ENV,
    load_loop_handoff_settings,
    load_soc_settings,
)
from app.lhp import (
    HandoffUpdate,
    assert_lhp_payload_size,
    verify_loop_signature,
)

app = FastAPI(title="AS215932 SOC Agent")

_RUNTIME: CaseServiceRuntime | None = None


def get_runtime() -> CaseServiceRuntime:
    global _RUNTIME
    if _RUNTIME is None:
        _RUNTIME = build_case_service_runtime()
    return _RUNTIME


@app.get("/health")
async def health() -> dict[str, Any]:
    settings = load_soc_settings()
    return {
        "status": "ok",
        "service": "soc-agent",
        "enabled": settings.enabled,
        "mode": settings.mode,
        "posture_enabled": settings.posture.enabled,
        "lhp_enabled": settings.loop_handoff.enabled,
    }


# --- LHP-v1 origin endpoints ------------------------------------------------


@app.get("/loop-handoff/v1/soc/handoffs/{handoff_id}")
async def soc_lhp_handoff_fetch(handoff_id: str, request: Request, runtime: CaseServiceRuntime = Depends(get_runtime)):
    _require_lhp_loop_request(request, body={})
    handoff = runtime.store.get_handoff(handoff_id)
    if handoff is None or handoff.target_loop != "engineering" or handoff.source_loop != "soc":
        raise HTTPException(status_code=404, detail="LHP handoff not found")
    case = runtime.store.get_case(handoff.case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="LHP case not found")
    objectives = runtime.store.list_objectives(handoff_id=handoff.handoff_id)
    return build_lhp_fetch_payload(
        handoff=handoff,
        case=case,
        objectives=objectives,
        max_bytes=load_loop_handoff_settings().callback_max_bytes,
    )


@app.post("/webhook/engineering-loop/handoff-update")
async def soc_lhp_handoff_update(request: Request, runtime: CaseServiceRuntime = Depends(get_runtime)):
    settings = load_loop_handoff_settings()
    raw = await request.body()
    if len(raw) > max(0, settings.callback_max_bytes):
        raise HTTPException(status_code=413, detail="LHP callback payload too large")
    try:
        body = json.loads(raw.decode("utf-8") or "{}")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail="Invalid JSON callback payload") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="Callback payload must be an object")
    assert_lhp_payload_size(body, max_bytes=settings.callback_max_bytes)
    _require_lhp_loop_request(request, body=body)
    if body.get("schema_version") != "lhp.v1":
        raise HTTPException(status_code=422, detail="schema_version must be lhp.v1")
    try:
        update = HandoffUpdate.model_validate(body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid LHP callback payload") from exc
    if update.source_loop != "engineering":
        raise HTTPException(status_code=422, detail="source_loop must be engineering")
    try:
        result = runtime.service.record_engineering_update(update)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid LHP handoff transition") from exc
    return {
        "status": "duplicate" if result.duplicate else "accepted",
        "handoff_id": update.handoff_id,
        "handoff_status": result.handoff.status if result.handoff else "",
        "case_status": result.case.status if result.case else "",
    }


# --- control ----------------------------------------------------------------


@app.get("/control/soc/status")
async def control_status(runtime: CaseServiceRuntime = Depends(get_runtime)) -> dict[str, Any]:
    settings = load_soc_settings()
    open_cases = [c for c in runtime.store.list_cases() if c.status not in {"resolved", "closed"}]
    return {
        "enabled": settings.enabled,
        "mode": settings.mode,
        "open_cases": len(open_cases),
        "cases": [
            {"case_id": c.case_id, "status": c.status, "severity": c.severity, "title": c.title}
            for c in open_cases[:50]
        ],
    }


# --- LHP request enforcement ------------------------------------------------


def _require_lhp_loop_request(request: Request, *, body: dict) -> None:
    settings = load_loop_handoff_settings()
    if not settings.enabled:
        raise HTTPException(status_code=404, detail="LHP is not enabled")
    secret = os.getenv(LHP_ENGINEERING_SECRET_ENV, "").strip()
    if not secret:
        raise HTTPException(status_code=503, detail="LHP Engineering shared secret is not configured")
    identity = request.headers.get("x-noc-loop-identity", "").strip()
    if identity != "engineering":
        raise HTTPException(status_code=401, detail="Invalid loop identity")
    timestamp = request.headers.get("x-noc-loop-timestamp", "").strip()
    if not _lhp_timestamp_fresh(timestamp):
        raise HTTPException(status_code=401, detail="Invalid loop timestamp")
    signature = request.headers.get("x-noc-loop-signature")
    if not verify_loop_signature(
        secret=secret,
        method=request.method,
        path=request.url.path,
        timestamp=timestamp,
        body=body,
        signature=signature,
    ):
        raise HTTPException(status_code=401, detail="Invalid loop signature")


def _lhp_timestamp_fresh(value: str, *, max_skew_s: int = 300) -> bool:
    if not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    delta = abs((datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds())
    return delta <= max_skew_s


def main() -> None:  # pragma: no cover - server entry point
    import uvicorn

    host = os.getenv("SOC_AGENT_HOST", "127.0.0.1")
    port = int(os.getenv("SOC_AGENT_PORT", "8781"))
    log.info("soc_agent_starting", host=host, port=port)
    uvicorn.run(app, host=host, port=port)
