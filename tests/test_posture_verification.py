"""Verifier close-loop: change_applied callback → re-read live FRR → resolve only
on repeated healthy passes; degraded/still-failing reads never resolve."""

from __future__ import annotations

from pathlib import Path

from app.cases.models import SecurityFinding
from app.cases.policy import SecurityCasePolicy
from app.cases.runtime import CaseServiceRuntime
from app.cases.service import SecurityCaseService
from app.cases.store import InMemorySecurityCaseStore
from app.cases.verifier import SecurityVerifier
from app.lhp import HandoffUpdate
from app.posture.desired_state import DesiredState
from app.posture.verification import PostureVerificationLoop
from tests._fakes import FakeMCPRuntime, fail, ok
from tests.test_posture_scanner import REAL_FRR, RPKI_OK_CONFIG

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "desired_state"

MANIFEST = {"asn": 215932, "owned_prefixes": ["2a0c:b641:b50::/44"], "core_routers": ["cr1-nl1"]}


def _runtime(passes: int = 2) -> CaseServiceRuntime:
    policy = SecurityCasePolicy(default_required_consecutive_passes=passes)
    store = InMemorySecurityCaseStore()
    service = SecurityCaseService(store, policy)
    verifier = SecurityVerifier(store, policy, dry_run=False, auto_resolve=True)
    return CaseServiceRuntime(store=store, service=service, verifier=verifier, policy=policy)


def _rpki_finding() -> SecurityFinding:
    return SecurityFinding(
        check_id="rpki_in_frr", key="cr1-nl1", category="bgp_rpki", control_domain="rpki_irr",
        severity="HIGH", confidence="confirmed", passed=False, warrants_handoff=True,
        objective_key="frr-transit-rpki-invalid-reject-v1", title="RPKI reject missing", resource="cr1-nl1",
    )


def _ds() -> DesiredState:
    return DesiredState(repo_dir=FIXTURES, manifest=MANIFEST, pin_sha="pin1")


def _healthy(name, args):
    if name == "frr_vtysh_cmd" and "running-config" in args["command"]:
        return ok(RPKI_OK_CONFIG)
    if name == "frr_vtysh_cmd":
        return ok("RPKI cache connection to 127.0.0.1:3323 is connected")
    return fail()


def _still_broken(name, args):
    if name == "frr_vtysh_cmd" and "running-config" in args["command"]:
        return ok(REAL_FRR)  # the fix did not land
    if name == "frr_vtysh_cmd":
        return ok("No RPKI cache connection configured")
    return fail()


def _degraded(name, args):
    return fail()  # every read fails -> ctx.degraded


def _seed_through_change_applied(rt: CaseServiceRuntime):
    finding = _rpki_finding()
    case = rt.service.observe_finding(finding, cycle_id="c1").case
    rt.service.request_handoff(case.case_id, finding)
    handoff_id = rt.store.get_case(case.case_id).handoff_ids[0]
    # engineering: accepted -> in_progress -> change_applied(implemented)
    steps = [("accepted", "accepted"), ("investigating", "in_progress"), ("change_applied", "implemented")]
    for i, (ut, st) in enumerate(steps):
        rt.service.record_engineering_update(
            HandoffUpdate(
                handoff_id=handoff_id, case_id=case.case_id, source_loop="engineering",
                update_type=ut, status=st, external_event_id=f"evt-{i}", correlation_id="corr",
            )
        )
    return case.case_id


def test_change_applied_moves_case_to_verification_pending():
    rt = _runtime()
    case_id = _seed_through_change_applied(rt)
    assert rt.store.get_case(case_id).status == "verification_pending"


async def test_resolves_only_after_repeated_healthy_reads():
    rt = _runtime(passes=2)
    case_id = _seed_through_change_applied(rt)
    loop = PostureVerificationLoop(
        service=rt.service, verifier=rt.verifier, mcp_runtime=FakeMCPRuntime(_healthy), desired_state=_ds()
    )
    r1 = await loop.verify_case_now(case_id)
    assert r1.resolved == []  # 1 healthy pass, need 2
    assert rt.store.get_case(case_id).status == "verification_pending"
    r2 = await loop.verify_case_now(case_id)
    assert r2.resolved == [case_id]
    assert rt.store.get_case(case_id).status == "resolved"


async def test_degraded_read_never_resolves():
    rt = _runtime(passes=1)
    case_id = _seed_through_change_applied(rt)
    loop = PostureVerificationLoop(
        service=rt.service, verifier=rt.verifier, mcp_runtime=FakeMCPRuntime(_degraded), desired_state=_ds()
    )
    for _ in range(3):
        report = await loop.verify_case_now(case_id)
    assert report.degraded == [case_id]
    assert rt.store.get_case(case_id).status == "verification_pending"
    assert rt.store.get_case(case_id).last_scan_degraded is True


async def test_still_failing_read_does_not_resolve():
    rt = _runtime(passes=1)
    case_id = _seed_through_change_applied(rt)
    loop = PostureVerificationLoop(
        service=rt.service, verifier=rt.verifier, mcp_runtime=FakeMCPRuntime(_still_broken), desired_state=_ds()
    )
    report = await loop.verify_case_now(case_id)
    assert report.resolved == []
    assert case_id in report.still_failing
    # the fix regressed the case back to an active (non-resolved) status
    assert rt.store.get_case(case_id).status != "resolved"


async def test_run_once_sweeps_all_pending():
    rt = _runtime(passes=1)
    case_id = _seed_through_change_applied(rt)
    loop = PostureVerificationLoop(
        service=rt.service, verifier=rt.verifier, mcp_runtime=FakeMCPRuntime(_healthy), desired_state=_ds()
    )
    report = await loop.run_once()
    assert report.checked == 1
    assert report.resolved == [case_id]
