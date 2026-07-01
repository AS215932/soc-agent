"""RedTeamRunner: composes RT-0 (+ opt-in RT-1), refuses cleanly, zero side effects."""

from __future__ import annotations

from app.cases.models import SecurityFinding
from app.config import RedTeamSettings
from app.posture.desired_state import DesiredState
from app.redteam.exercise import RedTeamRunner
from app.redteam.policy import RedTeamGate
from app.redteam.validators import NonInvasiveValidator


def _ds() -> DesiredState:
    return DesiredState(
        repo_dir=".",
        manifest={
            "owned_prefixes": ["2a0c:b641:b50::/44"],
            "management_domains": ["as215932.net"],
        },
    )


def _gate(**over) -> RedTeamGate:
    base = dict(enabled=True, max_tier=1, human_gate_tier=2, allow_active_probes=False)
    base.update(over)
    return RedTeamGate(RedTeamSettings(**base))


def _firing() -> SecurityFinding:
    return SecurityFinding(
        check_id="rpki_in_frr", key="cr1-nl1", category="bgp_rpki", severity="HIGH",
        confidence="confirmed", passed=False, resource="cr1-nl1", finding_id="secf_1",
    )


async def test_rt0_only_when_no_targets():
    runner = RedTeamRunner(_ds(), _gate())
    exercise, gaps = await runner.run([_firing()])
    assert exercise.tier == "RT-0"
    assert len(exercise.hypotheses) == 1
    assert len(gaps) == 1
    assert exercise.validations == []
    assert exercise.refused == []


async def test_rt1_runs_when_requested_and_permitted():
    async def fetch(url):
        return 200, {"Strict-Transport-Security": "max-age=1"}

    validator = NonInvasiveValidator(_ds(), _gate(), fetcher=fetch)
    runner = RedTeamRunner(_ds(), _gate(), validator=validator)
    exercise, _ = await runner.run([_firing()], rt1_targets=["https://as215932.net/"])
    assert exercise.tier == "RT-1"
    assert len(exercise.validations) == 1
    assert exercise.validations[0].passed is True


async def test_disabled_redteam_is_noop():
    runner = RedTeamRunner(_ds(), _gate(enabled=False))
    exercise, gaps = await runner.run([_firing()])
    assert exercise.hypotheses == []
    assert gaps == []
    assert exercise.refused


async def test_rt1_without_validator_is_refused():
    runner = RedTeamRunner(_ds(), _gate())
    exercise, _ = await runner.run([_firing()], rt1_targets=["https://as215932.net/"])
    assert exercise.tier == "RT-0"  # never escalated
    assert any("no validator" in r for r in exercise.refused)
