"""Compose one red-team exercise: RT-0 modeling (+ optional RT-1 validation).

Single entrypoint for the loop/graph. Enforces the tier gate up front: a request
for a tier with no executor (>= human-gate tier) is recorded as ``refused``, never
attempted. RT-1 validation runs only when explicitly requested *and* permitted.
"""

from __future__ import annotations

from app.cases.models import SecurityFinding
from app.posture.desired_state import DesiredState
from app.redteam.attack_paths import detection_gap_findings, model_attack_paths
from app.redteam.models import RedTeamExercise
from app.redteam.policy import RedTeamGate, RedTeamRefused
from app.redteam.validators import NonInvasiveValidator


class RedTeamRunner:
    def __init__(self, desired_state: DesiredState, gate: RedTeamGate, *, validator: NonInvasiveValidator | None = None):
        self.desired_state = desired_state
        self.gate = gate
        self.validator = validator

    async def run(
        self,
        findings: list[SecurityFinding],
        *,
        objective_id: str = "",
        rt1_targets: list[str] | None = None,
        manifest_sha: str = "",
    ) -> tuple[RedTeamExercise, list[SecurityFinding]]:
        """Return the exercise record + any detection_gap findings it surfaced."""
        exercise = RedTeamExercise(tier="RT-0", objective_id=objective_id)

        # RT-0 is always safe (no packets); still gate it so a disabled red-team is a no-op.
        if not self.gate.is_allowed("RT-0"):
            exercise.refused.append("RT-0 not permitted (red-team disabled)")
            return exercise, []
        exercise.hypotheses = model_attack_paths(self.desired_state, findings)
        gaps = detection_gap_findings(exercise.hypotheses, manifest_sha=manifest_sha)

        # RT-1 is opt-in and read-only; refuse cleanly if not permitted.
        if rt1_targets:
            try:
                self.gate.require("RT-1")
            except RedTeamRefused as exc:
                exercise.refused.append(str(exc))
            else:
                if self.validator is None:
                    exercise.refused.append("RT-1 requested but no validator configured")
                else:
                    exercise.tier = "RT-1"
                    exercise.validations = await self.validator.run(rt1_targets)
        return exercise, gaps
