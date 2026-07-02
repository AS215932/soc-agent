"""JSON-safe data models for the SOC Agent case substrate.

Mirrors ``hyrule-noc-agent/app/proactive/models.py`` and ``app/cases/models.py``
conventions: ``ConfigDict(extra="forbid")``, ISO-string timestamps, and a single
``model_validator`` that scrubs untrusted telemetry text before it can reach any
Discord/LLM/issue channel. ``SecurityFinding`` is LHP-ready from day one — its
``build_handoff`` produces the exact ``lhp.v1`` ``CaseHandoff`` +
``VerificationObjective`` shapes the Engineering Loop fetches.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.lhp import (
    CaseHandoff,
    VerificationObjective,
    sanitize_lhp_payload,
)

# --- vocabulary -------------------------------------------------------------

Severity = Literal["HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SocConfidence = Literal["confirmed", "high", "medium", "low", "tentative"]
SocCaseType = Literal[
    "security_incident",
    "security_finding",
    "detection_gap",
    "redteam_exercise",
    "abuse_case",
    "control_drift",
]
ControlDomain = Literal[
    "edge_firewall",
    "vault_hygiene",
    "wireguard_crypto",
    "rpki_irr",
    "customer_isolation",
    "detection",
    "other",
]
FindingCategory = Literal[
    "bgp_rpki",
    "firewall",
    "listening_ports",
    "wireguard",
    "vault",
    "dns",
    "tls",
    "isolation",
    "detection",
    "other",
]
SecurityOrigin = Literal["passive", "proactive", "redteam", "unknown"]
ObservationStatus = Literal["firing", "clean", "resolved", "unknown"]
SourceHealth = Literal["healthy", "degraded", "unknown", "failed"]
# Subset of the lhp.v1 CaseStatus vocabulary, security-flavoured.
SecurityCaseStatus = Literal[
    "open",
    "triaged",
    "context_requested",
    "handoff_requested",
    "handoff_in_progress",
    "verification_pending",
    "investigating",
    "waiting_approval",
    "blocked",
    "failed",
    "needs_human",
    "resolved",
    "closed",
]

_SEVERITY_RANK: dict[str, int] = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
_CONFIDENCE_RANK: dict[str, int] = {
    "tentative": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "confirmed": 5,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sanitize_label(value: object, *, limit: int = 200) -> str:
    """Defang an untrusted telemetry value before it is embedded into case/finding
    text (which becomes Discord output, an LHP payload, and ultimately LLM prompt
    context). Collapse whitespace (kills newline-based prompt injection), drop
    non-printable characters, and cap length to bound prompt bloat."""
    text = " ".join(str(value).split())
    text = "".join(ch for ch in text if ch.isprintable())
    return text[:limit]


def severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(str(severity or "").upper(), 0)


def confidence_rank(confidence: str) -> int:
    return _CONFIDENCE_RANK.get(str(confidence or "").lower(), 0)


# --- desired-state / evidence ----------------------------------------------


class DesiredStateRef(BaseModel):
    """Grounds a proactive finding in an authoritative desired-state artifact.

    ``content_sha`` pins *which version* of the desired state was compared so a
    stale checkout can never masquerade as fresh drift.
    """

    model_config = ConfigDict(extra="forbid")

    repo: str = "AS215932/network-operations"
    path: str = ""
    ref: str = Field(default="", description="Line anchor / section, e.g. 'router bgp 215932 / TRANSIT-IN'.")
    content_sha: str = ""
    assertion_text: str = Field(default="", description="What the desired state requires.")

    @model_validator(mode="after")
    def _scrub(self) -> "DesiredStateRef":
        self.path = sanitize_label(self.path, limit=300)
        self.ref = sanitize_label(self.ref, limit=200)
        self.assertion_text = sanitize_label(self.assertion_text, limit=500)
        return self


class SecurityEvidence(BaseModel):
    """One read-only observation backing a finding. ``observed_value`` /
    ``label`` / ``detail`` are attacker-influencable telemetry and are scrubbed;
    ``query`` / ``source_tool`` are loop-authored."""

    model_config = ConfigDict(extra="forbid")

    label: str = ""
    source_tool: str = Field(default="", description="MCP tool name that produced the value.")
    query: str = Field(default="", description="Command / PromQL / dig arg (loop-authored).")
    observed_value: str = ""
    expected_value: str = ""
    detail: str = ""

    @model_validator(mode="after")
    def _scrub(self) -> "SecurityEvidence":
        self.label = sanitize_label(self.label, limit=200)
        self.observed_value = sanitize_label(self.observed_value, limit=400)
        self.detail = sanitize_label(self.detail, limit=400)
        return self


@dataclass
class HandoffBundle:
    """What a finding contributes to a cross-loop handoff."""

    handoff: CaseHandoff
    objectives: list[VerificationObjective]
    knowledge_payload: dict[str, Any]


# --- finding ----------------------------------------------------------------


class SecurityFinding(BaseModel):
    """The LHP-ready unit emitted by a posture check or red-team hypothesis.

    A ``passed=False`` finding fires. ``warrants_handoff`` gates LHP eligibility.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    finding_id: str = Field(default_factory=lambda: f"secf_{uuid4().hex[:12]}")
    check_id: str = ""
    key: str = Field(default="", description="Stable identity within a check, e.g. 'cr1-nl1:2a0c:b640:8::ffff'.")
    category: FindingCategory = "other"
    case_type: SocCaseType = "control_drift"
    control_domain: ControlDomain = "other"
    title: str = ""
    summary: str = ""
    severity: Severity = "UNKNOWN"
    confidence: SocConfidence = "medium"
    # Advisory MITRE ATT&CK metadata (bounded strings), e.g. ["T1557", "T1565.003"].
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    resource: str = Field(default="", description="Host / router / service the finding concerns.")
    site: str = ""
    desired_state_refs: list[DesiredStateRef] = Field(default_factory=list)
    observed_state: dict[str, Any] = Field(default_factory=dict)
    evidence: list[SecurityEvidence] = Field(default_factory=list)
    assertion: str = Field(default="", description="The pass/fail rule in words.")
    passed: bool = True
    recommended_remediation: list[str] = Field(default_factory=list)
    warrants_handoff: bool = False
    objective_key: str = Field(default="", description="Stable LHP objective key, e.g. 'frr-transit-rpki-invalid-reject-v1'.")
    verification_objective_type: str = "posture_recheck"
    acceptance_criteria: list[str] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)
    # agent-core SourceRef refs are attached at projection time (summaries.py).
    detected_at: str = Field(default_factory=utc_now)
    score: float = Field(default=0.0, ge=0.0)
    manifest_sha: str = ""

    @model_validator(mode="after")
    def _scrub_and_score(self) -> "SecurityFinding":
        self.key = sanitize_label(self.key, limit=200)
        self.title = sanitize_label(self.title, limit=200)
        self.resource = sanitize_label(self.resource, limit=120)
        self.site = sanitize_label(self.site, limit=80)
        self.summary = sanitize_label(self.summary, limit=600)
        self.assertion = sanitize_label(self.assertion, limit=500)
        self.mitre_tactics = [sanitize_label(t, limit=40) for t in self.mitre_tactics][:20]
        self.mitre_techniques = [sanitize_label(t, limit=40) for t in self.mitre_techniques][:20]
        self.observed_state = _bounded_mapping(self.observed_state)
        if not self.score:
            # Rank by severity then confidence so the loop acts on the most
            # certain, most severe drift first.
            self.score = float(severity_rank(self.severity) * 10 + confidence_rank(self.confidence))
        return self

    def fingerprint(self) -> str:
        """Stable identity for issue idempotency + case dedup."""
        return hashlib.sha256(f"{self.check_id}|{self.key}".encode("utf-8")).hexdigest()[:16]

    def build_handoff(self, case: "SecurityCase", *, required_consecutive_passes: int = 3) -> HandoffBundle:
        """Produce the lhp.v1 CaseHandoff + VerificationObjective(s) for this
        finding. SOC is the origin loop and its own verifier.

        Generalises ``hyrule-noc-agent/app/proactive/lhp.py:build_disk_handoff_request``.
        """
        objective = self.title or self.summary or f"Remediate {self.check_id}"
        knowledge_payload = sanitize_lhp_payload(
            {
                "finding_id": self.finding_id,
                "severity": self.severity,
                "confidence": self.confidence,
                "control_domain": self.control_domain,
                "category": self.category,
                "mitre_tactics": self.mitre_tactics,
                "mitre_techniques": self.mitre_techniques,
                "assertion": self.assertion,
                "desired_state_refs": [ref.model_dump(mode="json") for ref in self.desired_state_refs],
                "evidence": [ev.model_dump(mode="json") for ev in self.evidence],
                "recommended_remediation": self.recommended_remediation,
                "manifest_sha": self.manifest_sha,
            }
        )
        handoff = CaseHandoff(
            case_id=case.case_id,
            source_loop="soc",
            target_loop="engineering",
            objective=objective,
            objective_key=self.objective_key or f"{self.check_id}-remediation-v1",
            status="requested",
            verifier="soc",
            idempotency_key=f"{case.case_id}:engineering:{self.objective_key or self.check_id}:v1",
            fingerprint=self.fingerprint(),
            resource={"resource": self.resource, "site": self.site, "category": self.category},
            case_type=self.case_type,
            constraints=self.constraints or ["do_not_mutate_prod", "human_approval_before_change"],
            acceptance_criteria=self.acceptance_criteria,
            payload=knowledge_payload if isinstance(knowledge_payload, dict) else {},
            created_by="soc_agent_loop",
        )
        objectives = [
            VerificationObjective(
                case_id=case.case_id,
                handoff_id=handoff.handoff_id,
                objective_key=self.objective_key or f"{self.check_id}-recheck-v1",
                objective_type=self.verification_objective_type,
                name=f"Re-check: {objective}",
                description=self.assertion or "Positive re-check that the control drift is closed.",
                required_consecutive_passes=required_consecutive_passes,
            )
        ]
        return HandoffBundle(handoff=handoff, objectives=objectives, knowledge_payload=knowledge_payload)


# --- observation ------------------------------------------------------------


class SecurityObservation(BaseModel):
    """Normalised evidence from any source (scan/metric/log). Gives the loop the
    positive-recovery signal required by the No-False-All-Clear invariant."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    observation_id: str = Field(default_factory=lambda: f"secobs_{uuid4().hex[:12]}")
    source: str = ""
    detector: str = Field(default="", description="check_id or signal detector.")
    entity: str = ""
    resource: str = ""
    site: str = ""
    severity: Severity = "UNKNOWN"
    status: ObservationStatus = "unknown"
    observed_at: str = Field(default_factory=utc_now)
    received_at: str = Field(default_factory=utc_now)
    scan_cycle_id: str = ""
    signal_snapshot: dict[str, Any] = Field(default_factory=dict)
    signal_signature: str = ""
    source_health: SourceHealth = "unknown"
    confidence: SocConfidence = "medium"

    @model_validator(mode="after")
    def _fill(self) -> "SecurityObservation":
        self.entity = sanitize_label(self.entity, limit=200)
        self.resource = sanitize_label(self.resource, limit=120)
        self.signal_snapshot = _bounded_mapping(self.signal_snapshot)
        if not self.signal_signature:
            self.signal_signature = _signature(self.detector, self.entity, self.signal_snapshot)
        return self

    @property
    def is_positive_clean(self) -> bool:
        """A genuine recovery signal: explicitly clean AND from a healthy source.
        Source-degraded 'clean' is NOT positive-clean evidence."""
        return self.status in {"clean", "resolved"} and self.source_health not in {"degraded", "failed"}


# --- case -------------------------------------------------------------------


class SecurityCase(BaseModel):
    """The durable SOC case record (analogue of ``AtomicCaseProjection``)."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    case_id: str = Field(default_factory=lambda: f"sec_case_{uuid4().hex[:12]}")
    case_number: str = ""
    case_type: SocCaseType = "control_drift"
    category: FindingCategory = "other"
    control_domain: ControlDomain = "other"
    title: str = ""
    summary: str = ""
    origin: SecurityOrigin = "proactive"
    status: SecurityCaseStatus = "open"
    severity: Severity = "UNKNOWN"
    confidence: SocConfidence = "medium"
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    resource_id: str = ""
    site: str = ""
    finding_ids: list[str] = Field(default_factory=list)
    fingerprint: str = ""

    # change-detection / No-False-All-Clear
    signal_snapshot: dict[str, Any] = Field(default_factory=dict)
    signal_signature: str = ""
    previous_signal_signature: str = ""
    last_observed_failing: str = ""
    last_observed_passing: str = ""
    last_evaluated_at: str = ""
    last_scan_cycle_id: str = ""
    last_scan_degraded: bool = False
    consecutive_pass_count: int = Field(default=0, ge=0)
    required_consecutive_passes: int = Field(default=3, ge=1)

    # external links
    issue_url: str = ""
    issue_id: str = ""
    handoff_ids: list[str] = Field(default_factory=list)
    handoff_status: str = ""
    last_handoff_at: str = ""

    # ops
    acknowledged_by: str = ""
    acknowledged_at: str = ""
    snoozed_until: str = ""
    suppressed_until: str = ""
    suppression_reason: str = ""
    trace_ids: list[str] = Field(default_factory=list)

    # lifecycle
    opened_at: str = Field(default_factory=utc_now)
    updated_at: str = Field(default_factory=utc_now)
    resolved_at: str = ""
    closed_at: str = ""
    resolution_reason: str = ""
    policy_version: str = "1"

    @model_validator(mode="after")
    def _scrub(self) -> "SecurityCase":
        self.title = sanitize_label(self.title, limit=200)
        self.resource_id = sanitize_label(self.resource_id, limit=120)
        self.summary = sanitize_label(self.summary, limit=600)
        self.signal_snapshot = _bounded_mapping(self.signal_snapshot)
        return self


class SecurityCaseEvent(BaseModel):
    """Append-only audit record for every case decision / gate / handoff."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    event_id: str = Field(default_factory=lambda: f"secev_{uuid4().hex[:12]}")
    case_id: str
    event_type: str
    actor_type: Literal["loop", "operator", "verifier", "system", "engineering", "unknown"] = "loop"
    actor_id: str = "soc_agent_loop"
    occurred_at: str = Field(default_factory=utc_now)
    correlation_id: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _bound(self) -> "SecurityCaseEvent":
        self.event_type = sanitize_label(self.event_type, limit=80)
        self.payload = _bounded_mapping(self.payload)
        return self


# --- helpers ----------------------------------------------------------------


def _signature(*parts: Any) -> str:
    material = "|".join(_stable(p) for p in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _stable(value: Any) -> str:
    import json

    if isinstance(value, dict):
        return json.dumps(_bounded_mapping(value), sort_keys=True, separators=(",", ":"))
    return sanitize_label(value, limit=400)


def _bounded_mapping(value: Any, *, max_items: int = 100) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    out: dict[str, Any] = {}
    for key, child in list(value.items())[:max_items]:
        out[sanitize_label(key, limit=80)] = _bounded_value(child)
    return out


def _bounded_value(value: Any, *, depth: int = 4) -> Any:
    if depth <= 0:
        return sanitize_label(value, limit=400)
    if isinstance(value, bool | int | float) or value is None:
        return value
    if isinstance(value, str):
        return sanitize_label(value, limit=400)
    if isinstance(value, list | tuple | set):
        return [_bounded_value(item, depth=depth - 1) for item in list(value)[:50]]
    if isinstance(value, dict):
        return {sanitize_label(k, limit=80): _bounded_value(v, depth=depth - 1) for k, v in list(value.items())[:100]}
    return sanitize_label(value, limit=400)
