"""Postgres implementation of the synchronous SOC case-store protocol.

The posture loop's domain service is deliberately synchronous.  A small
psycopg connection pool preserves that interface while allowing the timer,
verification worker, and API service to share authoritative state safely.
"""

from __future__ import annotations

from typing import TypeVar

from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool
from pydantic import BaseModel

from app.cases.models import SecurityCase, SecurityCaseEvent, SecurityFinding
from app.lhp import CallbackInboxRecord, CaseHandoff, VerificationObjective

ModelT = TypeVar("ModelT", bound=BaseModel)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS soc_objects (
    kind text NOT NULL,
    object_id text NOT NULL,
    fingerprint text NOT NULL DEFAULT '',
    payload jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, object_id)
);
CREATE INDEX IF NOT EXISTS soc_objects_kind_fingerprint_idx
    ON soc_objects (kind, fingerprint) WHERE fingerprint <> '';
CREATE TABLE IF NOT EXISTS soc_case_events (
    event_id text PRIMARY KEY,
    case_id text NOT NULL,
    occurred_at timestamptz NOT NULL,
    payload jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS soc_case_events_case_idx
    ON soc_case_events (case_id, occurred_at, event_id);
"""


class PostgresSecurityCaseStore:
    """Concurrency-safe authoritative store used by deployed SOC processes."""

    def __init__(self, database_url: str, *, min_size: int = 1, max_size: int = 4) -> None:
        if not database_url.startswith(("postgres://", "postgresql://")):
            raise ValueError("SOC_DATABASE_URL must be a PostgreSQL connection URL")
        self.pool = ConnectionPool(database_url, min_size=min_size, max_size=max_size)
        with self.pool.connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(_SCHEMA)
            connection.commit()

    def close(self) -> None:
        self.pool.close()

    def _put(self, kind: str, object_id: str, model: BaseModel, *, fingerprint: str = "") -> None:
        payload = model.model_dump(mode="json")
        with self.pool.connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO soc_objects (kind, object_id, fingerprint, payload)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (kind, object_id) DO UPDATE SET
                        fingerprint = EXCLUDED.fingerprint,
                        payload = EXCLUDED.payload,
                        updated_at = now()
                    """,
                    (kind, object_id, fingerprint, Jsonb(payload)),
                )
            connection.commit()

    def _get(self, kind: str, object_id: str, model: type[ModelT]) -> ModelT | None:
        with self.pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM soc_objects WHERE kind = %s AND object_id = %s",
                (kind, object_id),
            )
            row = cursor.fetchone()
        return model.model_validate(row[0]) if row else None

    def _get_by_fingerprint(
        self, kind: str, fingerprint: str, model: type[ModelT]
    ) -> ModelT | None:
        with self.pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT payload FROM soc_objects
                WHERE kind = %s AND fingerprint = %s
                ORDER BY updated_at DESC LIMIT 1
                """,
                (kind, fingerprint),
            )
            row = cursor.fetchone()
        return model.model_validate(row[0]) if row else None

    def _list(self, kind: str, model: type[ModelT]) -> list[ModelT]:
        with self.pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM soc_objects WHERE kind = %s ORDER BY updated_at",
                (kind,),
            )
            rows = cursor.fetchall()
        return [model.model_validate(row[0]) for row in rows]

    def get_case(self, case_id: str) -> SecurityCase | None:
        return self._get("case", case_id, SecurityCase)

    def get_case_by_fingerprint(self, fingerprint: str) -> SecurityCase | None:
        if not fingerprint:
            return None
        return self._get_by_fingerprint("case", fingerprint, SecurityCase)

    def put_case(self, case: SecurityCase) -> None:
        self._put("case", case.case_id, case, fingerprint=case.fingerprint)

    def list_cases(self, *, status: str | None = None) -> list[SecurityCase]:
        cases = self._list("case", SecurityCase)
        if status is not None:
            cases = [case for case in cases if case.status == status]
        return sorted(cases, key=lambda case: case.opened_at)

    def append_event(self, event: SecurityCaseEvent) -> None:
        with self.pool.connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO soc_case_events (event_id, case_id, occurred_at, payload)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (event_id) DO NOTHING
                    """,
                    (event.event_id, event.case_id, event.occurred_at, Jsonb(event.model_dump(mode="json"))),
                )
            connection.commit()

    def list_events(self, case_id: str) -> list[SecurityCaseEvent]:
        with self.pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT payload FROM soc_case_events
                WHERE case_id = %s ORDER BY occurred_at, event_id
                """,
                (case_id,),
            )
            rows = cursor.fetchall()
        return [SecurityCaseEvent.model_validate(row[0]) for row in rows]

    def put_finding(self, finding: SecurityFinding) -> None:
        self._put("finding", finding.finding_id, finding, fingerprint=finding.fingerprint())

    def get_finding(self, finding_id: str) -> SecurityFinding | None:
        return self._get("finding", finding_id, SecurityFinding)

    def put_handoff(self, handoff: CaseHandoff) -> None:
        self._put("handoff", handoff.handoff_id, handoff, fingerprint=handoff.idempotency_key)

    def get_handoff(self, handoff_id: str) -> CaseHandoff | None:
        return self._get("handoff", handoff_id, CaseHandoff)

    def get_handoff_by_idempotency_key(self, idempotency_key: str) -> CaseHandoff | None:
        if not idempotency_key:
            return None
        return self._get_by_fingerprint("handoff", idempotency_key, CaseHandoff)

    def put_objective(self, objective: VerificationObjective) -> None:
        self._put("objective", objective.objective_id, objective)

    def list_objectives(
        self, *, handoff_id: str | None = None, case_id: str | None = None
    ) -> list[VerificationObjective]:
        objectives = self._list("objective", VerificationObjective)
        if handoff_id is not None:
            objectives = [item for item in objectives if item.handoff_id == handoff_id]
        if case_id is not None:
            objectives = [item for item in objectives if item.case_id == case_id]
        return sorted(objectives, key=lambda item: item.created_at)

    def get_callback(self, external_event_id: str) -> CallbackInboxRecord | None:
        return self._get("callback", external_event_id, CallbackInboxRecord)

    def put_callback(self, record: CallbackInboxRecord) -> None:
        self._put("callback", record.external_event_id, record)
