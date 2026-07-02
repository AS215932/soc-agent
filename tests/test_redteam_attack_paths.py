"""RT-0 attack-path modeling: deterministic, zero side effects, feeds detection gaps."""

from __future__ import annotations

from pathlib import Path

from app.cases.models import SecurityFinding
from app.posture.desired_state import DesiredState
from app.redteam.attack_paths import detection_gap_findings, model_attack_paths

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "desired_state"


def _ds(detections=None) -> DesiredState:
    manifest = {"asn": 215932, "owned_prefixes": ["2a0c:b641:b50::/44"], "management_domains": ["as215932.net"]}
    if detections is not None:
        manifest["detections"] = detections
    return DesiredState(repo_dir=FIXTURES, manifest=manifest)


def _rpki_firing() -> SecurityFinding:
    return SecurityFinding(
        check_id="rpki_in_frr", key="cr1-nl1", category="bgp_rpki", severity="HIGH",
        confidence="confirmed", passed=False, resource="cr1-nl1", finding_id="secf_rpki",
    )


def test_models_hypothesis_from_firing_finding():
    hyps = model_attack_paths(_ds(), [_rpki_firing()])
    assert len(hyps) == 1
    h = hyps[0]
    assert h.tier == "RT-0"
    assert "hijack" in h.title
    assert "T1557" in h.mitre_techniques
    assert h.affected_assets == ["cr1-nl1"]
    assert h.would_detect is False  # no detections declared
    assert h.evidence_refs == ["secf_rpki"]


def test_passing_findings_produce_no_hypotheses():
    passing = SecurityFinding(check_id="rpki_in_frr", key="cr1-nl1", category="bgp_rpki", passed=True)
    assert model_attack_paths(_ds(), [passing]) == []


def test_would_detect_true_when_detection_declared():
    hyps = model_attack_paths(_ds(detections=["bgp_origin_validation_monitoring"]), [_rpki_firing()])
    assert hyps[0].would_detect is True
    assert hyps[0].detection_signal == "bgp_origin_validation_monitoring"


def test_detection_gap_findings_emitted_for_undetected_paths():
    hyps = model_attack_paths(_ds(), [_rpki_firing()])
    gaps = detection_gap_findings(hyps, manifest_sha="pin1")
    assert len(gaps) == 1
    g = gaps[0]
    assert g.case_type == "detection_gap"
    assert g.category == "detection"
    assert g.passed is False
    assert g.severity == "HIGH"
    assert g.objective_key.startswith("detection-gap-")


def test_detected_paths_produce_no_gap():
    hyps = model_attack_paths(_ds(detections=["bgp_origin_validation_monitoring"]), [_rpki_firing()])
    assert detection_gap_findings(hyps) == []
