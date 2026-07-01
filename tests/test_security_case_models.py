"""SecurityCase / SecurityFinding schema behaviour."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.cases.models import (
    DesiredStateRef,
    SecurityCase,
    SecurityEvidence,
    SecurityFinding,
    SecurityObservation,
    sanitize_label,
)


def _rpki_finding(**over) -> SecurityFinding:
    kw = dict(
        check_id="rpki_in_frr",
        key="cr1-nl1:2a0c:b640:8::ffff",
        category="bgp_rpki",
        control_domain="rpki_irr",
        title="Transit eBGP missing RPKI-invalid reject",
        severity="HIGH",
        confidence="confirmed",
        passed=False,
        warrants_handoff=True,
        objective_key="frr-transit-rpki-invalid-reject-v1",
        mitre_techniques=["T1557", "T1565.003"],
        resource="cr1-nl1",
        desired_state_refs=[DesiredStateRef(path="configs/cr1-nl1/frr.conf", ref="TRANSIT-IN", content_sha="abc123")],
        evidence=[SecurityEvidence(source_tool="frr_vtysh_cmd", query="show route-map TRANSIT-IN", observed_value="permit 10 match as-path 1")],
        acceptance_criteria=["transit eBGP drops RPKI-invalid"],
    )
    kw.update(over)
    return SecurityFinding(**kw)


def test_extra_forbid():
    with pytest.raises(ValidationError):
        SecurityFinding(check_id="x", key="y", nonsense_field=1)


def test_fingerprint_is_stable_and_identity_based():
    a = _rpki_finding()
    b = _rpki_finding(finding_id="secf_different", severity="MEDIUM")  # same check_id+key
    c = _rpki_finding(key="cr1-de1:other")
    assert a.fingerprint() == b.fingerprint()  # identity = check_id|key, not the volatile fields
    assert a.fingerprint() != c.fingerprint()
    assert len(a.fingerprint()) == 16


def test_score_ranks_by_severity_then_confidence():
    high_conf = _rpki_finding(severity="HIGH", confidence="confirmed")
    high_tent = _rpki_finding(severity="HIGH", confidence="tentative")
    med = _rpki_finding(severity="MEDIUM", confidence="confirmed")
    assert high_conf.score > high_tent.score > med.score


def test_untrusted_text_is_scrubbed():
    f = _rpki_finding(
        title="line1\nline2\x07inject",
        resource="cr1-nl1\n`rm -rf`",
    )
    assert "\n" not in f.title and "\x07" not in f.title
    assert "\n" not in f.resource


def test_sanitize_label_collapses_and_bounds():
    assert sanitize_label("a\n\n b\tc") == "a b c"
    assert len(sanitize_label("x" * 999, limit=50)) == 50


def test_observation_positive_clean_requires_healthy_source():
    clean_healthy = SecurityObservation(detector="rpki_in_frr", status="clean", source_health="healthy")
    clean_degraded = SecurityObservation(detector="rpki_in_frr", status="clean", source_health="degraded")
    firing = SecurityObservation(detector="rpki_in_frr", status="firing", source_health="healthy")
    assert clean_healthy.is_positive_clean is True
    assert clean_degraded.is_positive_clean is False  # source-degraded clean is not positive-clean
    assert firing.is_positive_clean is False


def test_build_handoff_is_lhp_shaped():
    finding = _rpki_finding()
    case = SecurityCase(case_id="sec_case_x", fingerprint=finding.fingerprint())
    bundle = finding.build_handoff(case, required_consecutive_passes=3)
    h = bundle.handoff
    assert h.source_loop == "soc"
    assert h.target_loop == "engineering"
    assert h.verifier == "soc"
    assert h.case_id == "sec_case_x"
    assert h.objective_key == "frr-transit-rpki-invalid-reject-v1"
    assert h.idempotency_key == "sec_case_x:engineering:frr-transit-rpki-invalid-reject-v1:v1"
    assert h.fingerprint == finding.fingerprint()
    assert "do_not_mutate_prod" in h.constraints or h.constraints  # constraints present
    assert len(bundle.objectives) == 1
    assert bundle.objectives[0].handoff_id == h.handoff_id
    assert bundle.objectives[0].required_consecutive_passes == 3


def test_json_round_trip():
    finding = _rpki_finding()
    assert SecurityFinding.model_validate_json(finding.model_dump_json()) == finding
    case = SecurityCase(title="t", severity="HIGH")
    assert SecurityCase.model_validate_json(case.model_dump_json()) == case
