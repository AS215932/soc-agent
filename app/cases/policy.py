"""SecurityCase state-machine policy.

Encodes three invariants:

1. **Verifier owns resolution.** Only the ``verifier`` actor may move a case to
   ``resolved`` (parity with the LHP ``VERIFIER_ONLY_HANDOFF_STATUSES`` rule,
   generalised to the SOC origin loop).
2. **No-False-All-Clear.** A control-drift case resolves only after
   ``required_consecutive_passes`` consecutive *positive* re-checks from a
   healthy source; a degraded scan can never resolve it.
3. **Bounded transitions.** Status only moves along an explicit graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.cases.models import SecurityCase

Actor = str  # "loop" | "verifier" | "operator" | "engineering" | "system"

VERIFIER_ONLY_STATUSES = frozenset({"resolved"})

_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "open": frozenset(
        {"triaged", "context_requested", "investigating", "handoff_requested", "blocked", "needs_human", "closed"}
    ),
    "triaged": frozenset(
        {"handoff_requested", "investigating", "waiting_approval", "blocked", "needs_human", "resolved", "closed"}
    ),
    "context_requested": frozenset({"triaged", "investigating", "needs_human", "closed"}),
    "investigating": frozenset(
        {"triaged", "waiting_approval", "handoff_requested", "blocked", "needs_human", "resolved", "closed"}
    ),
    "waiting_approval": frozenset({"handoff_requested", "blocked", "needs_human", "closed"}),
    "handoff_requested": frozenset(
        {"handoff_in_progress", "verification_pending", "blocked", "failed", "needs_human", "closed"}
    ),
    "handoff_in_progress": frozenset(
        {"verification_pending", "blocked", "failed", "needs_human", "resolved", "closed"}
    ),
    "verification_pending": frozenset({"resolved", "failed", "needs_human", "handoff_in_progress", "closed"}),
    "blocked": frozenset({"triaged", "handoff_requested", "needs_human", "failed", "closed"}),
    "failed": frozenset({"triaged", "handoff_requested", "needs_human", "closed"}),
    "needs_human": frozenset({"triaged", "investigating", "handoff_requested", "closed"}),
    "resolved": frozenset({"open", "closed"}),  # a re-firing drift reopens
    "closed": frozenset({"open"}),
}


@dataclass(frozen=True)
class SecurityCasePolicy:
    policy_version: str = "1"
    require_positive_clean_for_resolve: bool = True
    default_required_consecutive_passes: int = 3
    # Statuses considered "still failing" for reopening logic.
    active_statuses: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "open",
                "triaged",
                "context_requested",
                "investigating",
                "waiting_approval",
                "handoff_requested",
                "handoff_in_progress",
                "verification_pending",
                "blocked",
                "failed",
                "needs_human",
            }
        )
    )

    def allowed_transition(self, current: str, target: str, *, actor: Actor = "loop") -> bool:
        if target in VERIFIER_ONLY_STATUSES:
            # Only the verifier may resolve, and it may do so from any active
            # status (a self-healed shadow case as well as a post-handoff fix).
            if actor != "verifier":
                return False
            return current == target or current in self.active_statuses
        if current == target:
            return True
        return target in _ALLOWED_TRANSITIONS.get(current, frozenset())

    def require_transition(self, current: str, target: str, *, actor: Actor = "loop") -> None:
        if not self.allowed_transition(current, target, actor=actor):
            raise ValueError(f"invalid SecurityCase transition {current!r} -> {target!r} for actor {actor!r}")

    def can_resolve(self, case: SecurityCase) -> bool:
        """No-False-All-Clear gate: enough consecutive healthy passes, and the
        last scan was not degraded."""
        if case.last_scan_degraded:
            return False
        required = case.required_consecutive_passes or self.default_required_consecutive_passes
        if self.require_positive_clean_for_resolve and not case.last_observed_passing:
            return False
        return case.consecutive_pass_count >= required
