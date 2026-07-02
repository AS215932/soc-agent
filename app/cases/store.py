"""Persistence for the SOC case substrate.

A ``SecurityCaseStore`` Protocol plus two implementations: an in-memory store
(tests / shadow) and an append-only JSONL store (durable across restarts without
a database). Postgres can be layered later behind the same Protocol.

Operations are synchronous: they are fast local dict/file operations. The async
posture loop calls them inline.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Protocol, runtime_checkable

from app.lhp import CallbackInboxRecord, CaseHandoff, VerificationObjective
from app.cases.models import (
    SecurityCase,
    SecurityCaseEvent,
    SecurityFinding,
)


@runtime_checkable
class SecurityCaseStore(Protocol):
    # cases
    def get_case(self, case_id: str) -> SecurityCase | None: ...
    def get_case_by_fingerprint(self, fingerprint: str) -> SecurityCase | None: ...
    def put_case(self, case: SecurityCase) -> None: ...
    def list_cases(self, *, status: str | None = None) -> list[SecurityCase]: ...

    # append-only audit
    def append_event(self, event: SecurityCaseEvent) -> None: ...
    def list_events(self, case_id: str) -> list[SecurityCaseEvent]: ...

    # findings
    def put_finding(self, finding: SecurityFinding) -> None: ...
    def get_finding(self, finding_id: str) -> SecurityFinding | None: ...

    # LHP handoffs + verification objectives (served by the fetch endpoint)
    def put_handoff(self, handoff: CaseHandoff) -> None: ...
    def get_handoff(self, handoff_id: str) -> CaseHandoff | None: ...
    def get_handoff_by_idempotency_key(self, idempotency_key: str) -> CaseHandoff | None: ...
    def put_objective(self, objective: VerificationObjective) -> None: ...
    def list_objectives(self, *, handoff_id: str | None = None, case_id: str | None = None) -> list[VerificationObjective]: ...

    # cross-loop callback dedup
    def get_callback(self, external_event_id: str) -> CallbackInboxRecord | None: ...
    def put_callback(self, record: CallbackInboxRecord) -> None: ...


class InMemorySecurityCaseStore:
    """Reference store — everything in dicts. Fully deterministic for tests."""

    def __init__(self) -> None:
        self._cases: dict[str, SecurityCase] = {}
        self._events: list[SecurityCaseEvent] = []
        self._findings: dict[str, SecurityFinding] = {}
        self._handoffs: dict[str, CaseHandoff] = {}
        self._objectives: dict[str, VerificationObjective] = {}
        self._callbacks: dict[str, CallbackInboxRecord] = {}
        self._lock = threading.RLock()

    def get_case(self, case_id: str) -> SecurityCase | None:
        with self._lock:
            case = self._cases.get(case_id)
            return case.model_copy(deep=True) if case else None

    def get_case_by_fingerprint(self, fingerprint: str) -> SecurityCase | None:
        if not fingerprint:
            return None
        with self._lock:
            for case in self._cases.values():
                if case.fingerprint == fingerprint:
                    return case.model_copy(deep=True)
        return None

    def put_case(self, case: SecurityCase) -> None:
        with self._lock:
            self._cases[case.case_id] = case.model_copy(deep=True)

    def list_cases(self, *, status: str | None = None) -> list[SecurityCase]:
        with self._lock:
            cases = [c.model_copy(deep=True) for c in self._cases.values()]
        if status is not None:
            cases = [c for c in cases if c.status == status]
        return sorted(cases, key=lambda c: c.opened_at)

    def append_event(self, event: SecurityCaseEvent) -> None:
        with self._lock:
            self._events.append(event.model_copy(deep=True))

    def list_events(self, case_id: str) -> list[SecurityCaseEvent]:
        with self._lock:
            return [e.model_copy(deep=True) for e in self._events if e.case_id == case_id]

    def put_finding(self, finding: SecurityFinding) -> None:
        with self._lock:
            self._findings[finding.finding_id] = finding.model_copy(deep=True)

    def get_finding(self, finding_id: str) -> SecurityFinding | None:
        with self._lock:
            found = self._findings.get(finding_id)
            return found.model_copy(deep=True) if found else None

    def put_handoff(self, handoff: CaseHandoff) -> None:
        with self._lock:
            self._handoffs[handoff.handoff_id] = handoff.model_copy(deep=True)

    def get_handoff(self, handoff_id: str) -> CaseHandoff | None:
        with self._lock:
            found = self._handoffs.get(handoff_id)
            return found.model_copy(deep=True) if found else None

    def get_handoff_by_idempotency_key(self, idempotency_key: str) -> CaseHandoff | None:
        if not idempotency_key:
            return None
        with self._lock:
            for handoff in self._handoffs.values():
                if handoff.idempotency_key == idempotency_key:
                    return handoff.model_copy(deep=True)
        return None

    def put_objective(self, objective: VerificationObjective) -> None:
        with self._lock:
            self._objectives[objective.objective_id] = objective.model_copy(deep=True)

    def list_objectives(
        self, *, handoff_id: str | None = None, case_id: str | None = None
    ) -> list[VerificationObjective]:
        with self._lock:
            objectives = [o.model_copy(deep=True) for o in self._objectives.values()]
        if handoff_id is not None:
            objectives = [o for o in objectives if o.handoff_id == handoff_id]
        if case_id is not None:
            objectives = [o for o in objectives if o.case_id == case_id]
        return sorted(objectives, key=lambda o: o.created_at)

    def get_callback(self, external_event_id: str) -> CallbackInboxRecord | None:
        if not external_event_id:
            return None
        with self._lock:
            found = self._callbacks.get(external_event_id)
            return found.model_copy(deep=True) if found else None

    def put_callback(self, record: CallbackInboxRecord) -> None:
        with self._lock:
            self._callbacks[record.external_event_id] = record.model_copy(deep=True)


class JsonlSecurityCaseStore(InMemorySecurityCaseStore):
    """Durable append-only JSONL store. Loads a last-write-wins snapshot on init
    and appends every mutation. Events are pure append; cases/findings/handoffs/
    objectives are last-write-wins by id."""

    def __init__(self, state_dir: str | Path) -> None:
        super().__init__()
        self._dir = Path(state_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._files = {
            "cases": self._dir / "cases.jsonl",
            "events": self._dir / "events.jsonl",
            "findings": self._dir / "findings.jsonl",
            "handoffs": self._dir / "handoffs.jsonl",
            "objectives": self._dir / "objectives.jsonl",
            "callbacks": self._dir / "callbacks.jsonl",
        }
        self._load()

    def _load(self) -> None:
        for case in _read_jsonl(self._files["cases"], SecurityCase):
            self._cases[case.case_id] = case
        for event in _read_jsonl(self._files["events"], SecurityCaseEvent):
            self._events.append(event)
        for finding in _read_jsonl(self._files["findings"], SecurityFinding):
            self._findings[finding.finding_id] = finding
        for handoff in _read_jsonl(self._files["handoffs"], CaseHandoff):
            self._handoffs[handoff.handoff_id] = handoff
        for objective in _read_jsonl(self._files["objectives"], VerificationObjective):
            self._objectives[objective.objective_id] = objective
        for callback in _read_jsonl(self._files["callbacks"], CallbackInboxRecord):
            self._callbacks[callback.external_event_id] = callback

    def _append(self, kind: str, model) -> None:  # type: ignore[no-untyped-def]
        with self._files[kind].open("a", encoding="utf-8") as handle:
            handle.write(model.model_dump_json() + "\n")

    def put_case(self, case: SecurityCase) -> None:
        super().put_case(case)
        self._append("cases", case)

    def append_event(self, event: SecurityCaseEvent) -> None:
        super().append_event(event)
        self._append("events", event)

    def put_finding(self, finding: SecurityFinding) -> None:
        super().put_finding(finding)
        self._append("findings", finding)

    def put_handoff(self, handoff: CaseHandoff) -> None:
        super().put_handoff(handoff)
        self._append("handoffs", handoff)

    def put_objective(self, objective: VerificationObjective) -> None:
        super().put_objective(objective)
        self._append("objectives", objective)

    def put_callback(self, record: CallbackInboxRecord) -> None:
        super().put_callback(record)
        self._append("callbacks", record)


def _read_jsonl(path: Path, model):  # type: ignore[no-untyped-def]
    if not path.exists():
        return []
    out = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(model.model_validate(json.loads(line)))
            except Exception:
                # A corrupt trailing line (e.g. crash mid-write) must not brick load.
                continue
    return out
