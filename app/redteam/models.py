"""Red-team data models — all JSON-safe, all read-only artifacts."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.cases.models import SocConfidence, sanitize_label

RedTeamTier = Literal["RT-0", "RT-1", "RT-2", "RT-3", "RT-4", "RT-5"]

_TIER_NUM: dict[str, int] = {"RT-0": 0, "RT-1": 1, "RT-2": 2, "RT-3": 3, "RT-4": 4, "RT-5": 5}


def tier_num(tier: str) -> int:
    return _TIER_NUM.get(str(tier), 99)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AttackPathHypothesis(BaseModel):
    """A modeled adversary path (RT-0). No action is taken to validate it."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    hypothesis_id: str = Field(default_factory=lambda: f"rtpath_{uuid4().hex[:12]}")
    title: str = ""
    tier: RedTeamTier = "RT-0"
    precondition: str = ""
    action: str = ""
    impact: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    mitre_tactic: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    would_detect: bool = False
    detection_signal: str = ""
    confidence: SocConfidence = "medium"
    evidence_refs: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _scrub(self) -> "AttackPathHypothesis":
        self.title = sanitize_label(self.title, limit=200)
        self.precondition = sanitize_label(self.precondition, limit=400)
        self.impact = sanitize_label(self.impact, limit=400)
        self.affected_assets = [sanitize_label(a, limit=120) for a in self.affected_assets][:32]
        return self


class RedTeamObjective(BaseModel):
    """A scoped red-team objective with hard safety rails (from the design doc)."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    objective_id: str = Field(default_factory=lambda: f"rt_{uuid4().hex[:12]}")
    title: str = ""
    safety_tier: RedTeamTier = "RT-0"
    allowed_assets: list[str] = Field(default_factory=list)
    denied_assets: list[str] = Field(default_factory=list)
    destructive_actions_allowed: bool = False
    credential_access_allowed: bool = False
    lateral_movement_allowed: bool = False
    data_exfiltration_allowed: bool = False
    human_approval_required: bool = False
    created_at: str = Field(default_factory=utc_now)


class ValidationResult(BaseModel):
    """One non-invasive RT-1 validation result."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    target: str = ""
    check: str = ""
    tier: RedTeamTier = "RT-1"
    observed: str = ""
    expected: str = ""
    passed: bool = True
    note: str = ""
    created_at: str = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _scrub(self) -> "ValidationResult":
        self.observed = sanitize_label(self.observed, limit=400)
        self.note = sanitize_label(self.note, limit=400)
        return self


class RedTeamExercise(BaseModel):
    """The record of one red-team cycle: hypotheses (RT-0) + validations (RT-1)."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    exercise_id: str = Field(default_factory=lambda: f"rtex_{uuid4().hex[:12]}")
    tier: RedTeamTier = "RT-0"
    objective_id: str = ""
    hypotheses: list[AttackPathHypothesis] = Field(default_factory=list)
    validations: list[ValidationResult] = Field(default_factory=list)
    refused: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now)
