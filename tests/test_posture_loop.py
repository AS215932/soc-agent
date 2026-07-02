"""PostureLoop across the SOC_MODE ladder: shadow → case_only → handoff_dry →
handoff_live, plus No-False-All-Clear resolution over two cycles."""

from __future__ import annotations

import dataclasses
from pathlib import Path

from agent_core.contracts import InsightDecisionRecord

from app.cases.policy import SecurityCasePolicy
from app.cases.service import SecurityCaseService
from app.cases.store import InMemorySecurityCaseStore
from app.cases.verifier import SecurityVerifier
from app.config import PostureSettings, SocAgentSettings
from app.posture.desired_state import DesiredState
from app.posture.loop import PostureLoop
from tests._fakes import FakeMCPRuntime, fail, ok
from tests.test_posture_scanner import REAL_FRR, WG_SHOW_MATCH

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "desired_state"

MANIFEST = {
    "asn": 215932,
    "owned_prefixes": ["2a0c:b641:b50::/44"],
    "core_routers": ["cr1-nl1"],
    "transit_asns": [34872],
    "management_domains": ["as215932.net"],
    "listener_allowlist": {"cr1-nl1": [179]},
}


def _rpki_firing_handler(name, args):
    if name == "frr_vtysh_cmd" and "running-config" in args["command"]:
        return ok(REAL_FRR)
    if name == "frr_vtysh_cmd":
        return ok("No RPKI cache connection configured")
    if name == "wg_show":
        return ok(WG_SHOW_MATCH)
    if name == "socket_listeners":
        return ok(data={"listeners": [{"address": "2a0c:b641:b50::a", "port": 179}]})
    if name == "dns_dig" and args.get("query_type") == "AAAA":
        return ok(data={"answers": [{"type": "AAAA", "data": "2a0c:b641:b50::100"}]})
    if name == "dns_dig":
        return ok(data={"answers": []})
    return fail()


class _FakeHandoff:
    def __init__(self):
        self.calls = []

    async def ensure_candidate_issue(self, finding, case, handoff, *, base_url=""):
        self.calls.append({"finding": finding.check_id, "case": case.case_id, "handoff": handoff.handoff_id})
        return f"https://github.com/AS215932/network-operations/issues/{len(self.calls)}"


def _settings(mode: str) -> SocAgentSettings:
    posture = PostureSettings(
        enabled=True,
        severity_floor="HIGH",
        handoff_enabled=True,
        max_findings_per_cycle=3,
        required_consecutive_passes=2,
        allowed_hosts=["cr1-nl1"],
        max_hosts_per_cycle=1,
        state_dir="",  # in-memory ledger
    )
    return SocAgentSettings(enabled=True, mode=mode, posture=posture)


def _loop(mode: str, *, handoff=None, service=None):
    service = service or SecurityCaseService(
        InMemorySecurityCaseStore(), SecurityCasePolicy(default_required_consecutive_passes=2)
    )
    ds = DesiredState(repo_dir=FIXTURES, manifest=MANIFEST, pin_sha="pin1")
    return PostureLoop(
        settings=_settings(mode),
        service=service,
        mcp_runtime=FakeMCPRuntime(_rpki_firing_handler),
        desired_state=ds,
        handoff=handoff,
    )


async def test_shadow_writes_nothing():
    loop = _loop("shadow")
    report = await loop.run_once(cycle_id="c1")
    assert report.cases_opened == 0
    assert report.issues_opened == 0
    assert loop.service.store.list_cases() == []
    assert any("FIRING" in s for s in report.shadow_findings)
    assert report.private_insights
    assert all(item["governance"]["sensitivity_class"] == "private" for item in report.private_insights)
    assert all(item["governance"]["learning_allowed"] is False for item in report.private_insights)
    assert all(item["governance"]["never_learn"] is True for item in report.private_insights)


async def test_private_insights_validate_against_agent_core_contract():
    loop = _loop("shadow")
    report = await loop.run_once(cycle_id="c1")

    assert report.private_insights
    for insight in report.private_insights:
        validated = InsightDecisionRecord.model_validate(insight)
        assert validated.loop == "soc"
        assert validated.governance.never_learn is True


async def test_case_only_opens_case_no_handoff():
    loop = _loop("case_only")
    report = await loop.run_once(cycle_id="c1")
    assert report.cases_opened == 1
    assert report.handoffs_built == 0
    assert report.issues_opened == 0
    assert report.private_insights[0]["action_selected"] == "notify"
    assert report.private_insights[0]["governance"]["adversarial_review_required"] is True
    cases = loop.service.store.list_cases()
    assert len(cases) == 1 and cases[0].status == "triaged"


async def test_handoff_dry_builds_but_does_not_post():
    handoff = _FakeHandoff()
    loop = _loop("handoff_dry", handoff=handoff)
    report = await loop.run_once(cycle_id="c1")
    assert report.handoffs_built == 1
    assert report.issues_opened == 0
    assert handoff.calls == []  # never POSTs in dry mode
    # the handoff object was persisted
    case = loop.service.store.list_cases()[0]
    assert case.status == "handoff_requested"
    assert case.handoff_ids


async def test_handoff_live_opens_issue():
    handoff = _FakeHandoff()
    loop = _loop("handoff_live", handoff=handoff)
    report = await loop.run_once(cycle_id="c1")
    assert report.handoffs_built == 1
    assert report.issues_opened == 1
    assert len(handoff.calls) == 1
    case = loop.service.store.list_cases()[0]
    assert case.issue_url


async def test_no_false_all_clear_resolution_over_cycles():
    service = SecurityCaseService(
        InMemorySecurityCaseStore(), SecurityCasePolicy(default_required_consecutive_passes=2)
    )
    verifier = SecurityVerifier(service.store, service.policy, dry_run=False, auto_resolve=True)

    # cycle 1: RPKI firing -> case opened
    loop_fire = _loop("case_only", service=service)
    await loop_fire.run_once(cycle_id="c1")
    case_id = service.store.list_cases()[0].case_id
    assert verifier.verify_case(case_id).resolved is False

    # cycles 2 & 3: RPKI now healthy -> positive re-checks accumulate
    def healthy(name, args):
        if name == "frr_vtysh_cmd" and "running-config" in args["command"]:
            from tests.test_posture_scanner import RPKI_OK_CONFIG

            return ok(RPKI_OK_CONFIG)
        if name == "frr_vtysh_cmd":
            return ok("RPKI cache connection to 127.0.0.1:3323 is connected")
        return _rpki_firing_handler(name, args)

    loop_ok = _loop("case_only", service=service)
    loop_ok.mcp_runtime = FakeMCPRuntime(healthy)
    await loop_ok.run_once(cycle_id="c2")
    assert verifier.verify_case(case_id).resolved is False  # 1 pass, need 2
    await loop_ok.run_once(cycle_id="c3")
    result = verifier.verify_case(case_id)
    assert result.resolved is True
    assert service.store.get_case(case_id).status == "resolved"
