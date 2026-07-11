"""Case-service runtime assembly.

Bundles the store + service + verifier and builds them from settings. Uses the
durable JSONL store when a posture state dir is configured, else the in-memory
store (tests / ephemeral shadow).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from app.cases.policy import SecurityCasePolicy
from app.cases.service import SecurityCaseService
from app.cases.store import InMemorySecurityCaseStore, JsonlSecurityCaseStore, SecurityCaseStore
from app.cases.verifier import SecurityVerifier
from app.config import SocAgentSettings, load_soc_settings


@dataclass
class CaseServiceRuntime:
    store: SecurityCaseStore
    service: SecurityCaseService
    verifier: SecurityVerifier
    policy: SecurityCasePolicy


def build_case_service_runtime(settings: SocAgentSettings | None = None) -> CaseServiceRuntime:
    settings = settings or load_soc_settings()
    policy = SecurityCasePolicy(
        default_required_consecutive_passes=settings.posture.required_consecutive_passes,
    )
    state_dir = settings.posture.state_dir
    store: SecurityCaseStore
    database_url = os.getenv("SOC_DATABASE_URL", "").strip()
    if database_url:
        from app.cases.postgres import PostgresSecurityCaseStore

        store = PostgresSecurityCaseStore(database_url)
    elif state_dir:
        try:
            store = JsonlSecurityCaseStore(state_dir)
        except OSError:
            store = InMemorySecurityCaseStore()
    else:
        store = InMemorySecurityCaseStore()
    service = SecurityCaseService(store, policy)
    verifier = SecurityVerifier(
        store,
        policy,
        dry_run=settings.loop_handoff.case_verification_dry_run,
        auto_resolve=settings.loop_handoff.case_auto_resolve_enabled,
    )
    return CaseServiceRuntime(store=store, service=service, verifier=verifier, policy=policy)


def build_in_memory_runtime(policy: SecurityCasePolicy | None = None) -> CaseServiceRuntime:
    """A fully in-memory runtime for tests."""
    policy = policy or SecurityCasePolicy()
    store = InMemorySecurityCaseStore()
    service = SecurityCaseService(store, policy)
    verifier = SecurityVerifier(store, policy, dry_run=False, auto_resolve=True)
    return CaseServiceRuntime(store=store, service=service, verifier=verifier, policy=policy)
