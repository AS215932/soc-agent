"""Red-team tier gate.

Enforces the core rule: RT-0 and RT-1 (read-only) are permitted up to
``SOC_REDTEAM_MAX_TIER``; any tier at or above ``SOC_REDTEAM_HUMAN_GATE_TIER``
(default 2) is **hard-refused** — v1 has no executor for active probing/exploit,
so there is nothing to gate; the request simply cannot be run.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.config import RedTeamSettings
from app.redteam.models import tier_num
from agent_core.contracts import HandoffRecord


class RedTeamRefused(RuntimeError):
    """Raised when a requested tier is not permitted / has no executor."""


@dataclass(frozen=True)
class RedTeamGate:
    settings: RedTeamSettings

    def is_allowed(self, tier: str) -> bool:
        if not self.settings.enabled:
            return False
        n = tier_num(tier)
        # Never above the ceiling, and never at/above the human-gate tier (no executor exists).
        return n <= self.settings.max_tier and n < self.settings.human_gate_tier

    def requires_human_gate(self, tier: str) -> bool:
        return tier_num(tier) >= self.settings.human_gate_tier

    def require(self, tier: str) -> None:
        if self.requires_human_gate(tier):
            raise RedTeamRefused(
                f"tier {tier} requires an explicit human gate and has no executor in v1 (hard-refused)"
            )
        if not self.is_allowed(tier):
            raise RedTeamRefused(f"tier {tier} is not permitted (enabled={self.settings.enabled}, max={self.settings.max_tier})")

    def active_probes_allowed(self) -> bool:
        return self.settings.enabled and self.settings.allow_active_probes

    def require_approved_rt2(self, record: HandoffRecord) -> None:
        """Authorize only a coordinator-bound, senior-approved RT-2 work item."""

        if not self.settings.enabled or not self.settings.allow_active_probes:
            raise RedTeamRefused("RT-2 executor is disabled by the global kill switch")
        if self.settings.max_tier < 2:
            raise RedTeamRefused("RT-2 exceeds SOC_REDTEAM_MAX_TIER")
        if record.envelope.capability != "soc.active_probe.rt2":
            raise RedTeamRefused("handoff does not request the RT-2 capability")
        approval = record.approval
        if approval is None or approval.decision != "approved" or approval.approver_role != "senior":
            raise RedTeamRefused("RT-2 requires an immutable senior Observatory approval")
        if approval.scope_hash != record.envelope.scope_hash:
            raise RedTeamRefused("RT-2 approval scope hash does not match the probe plan")
