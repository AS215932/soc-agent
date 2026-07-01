"""RT-0: passive attack-path modeling.

Reasons over desired state + posture findings to produce
``AttackPathHypothesis`` records — no packets, no probes. Where a plausible path
would not be detected, it emits a ``detection_gap`` ``SecurityFinding`` so the
gap becomes trackable work (purple-team, not just red-team).
"""

from __future__ import annotations

from dataclasses import dataclass

from app.cases.models import SecurityEvidence, SecurityFinding
from app.posture.desired_state import DesiredState
from app.redteam.models import AttackPathHypothesis


@dataclass(frozen=True)
class _PathTemplate:
    title: str
    precondition: str
    action: str
    impact: str
    mitre_tactic: str
    mitre_techniques: tuple[str, ...]
    required_detection: str
    severity: str


# category (of the firing finding) -> the attack path it enables
_TEMPLATES: dict[str, _PathTemplate] = {
    "bgp_rpki": _PathTemplate(
        title="RPKI-invalid route hijack of owned prefixes",
        precondition="a transit/IXP peer accepts routes without RPKI-invalid rejection or a maximum-prefix cap",
        action="adversary originates an RPKI-invalid (or more-specific) announcement for an AS215932 prefix",
        impact="traffic to owned prefixes is intercepted or blackholed (adversary-in-the-middle)",
        mitre_tactic="TA0040 Impact",
        mitre_techniques=("T1557", "T1565.003"),
        required_detection="bgp_origin_validation_monitoring",
        severity="HIGH",
    ),
    "listening_ports": _PathTemplate(
        title="management-plane reachable from an untrusted segment",
        precondition="a management service listens on a public/customer-facing address",
        action="adversary connects to the exposed listener and attempts authentication/exploit",
        impact="unauthorized access attempt against the control/management plane",
        mitre_tactic="TA0001 Initial Access",
        mitre_techniques=("T1046", "T1190"),
        required_detection="auth_anomaly_monitoring",
        severity="HIGH",
    ),
    "wireguard": _PathTemplate(
        title="unauthorized WireGuard overlay tunnel",
        precondition="a live WireGuard peer is present that is not in the committed configuration",
        action="adversary maintains an overlay tunnel to sniff or inject control-plane traffic",
        impact="control-plane adversary-in-the-middle / traffic capture",
        mitre_tactic="TA0009 Collection",
        mitre_techniques=("T1557", "T1040"),
        required_detection="wireguard_peer_monitoring",
        severity="HIGH",
    ),
    "dns": _PathTemplate(
        title="traffic redirection via off-prefix DNS record",
        precondition="an as215932.net record resolves outside owned prefixes",
        action="adversary controls the off-prefix target and receives redirected traffic",
        impact="phishing / interception of traffic intended for AS215932 services",
        mitre_tactic="TA0001 Initial Access",
        mitre_techniques=("T1583.001", "T1071"),
        required_detection="dns_ownership_monitoring",
        severity="MEDIUM",
    ),
}


def model_attack_paths(
    desired_state: DesiredState, findings: list[SecurityFinding]
) -> list[AttackPathHypothesis]:
    """Model RT-0 hypotheses from the firing findings. Deterministic, no side effects."""
    detections = {str(d) for d in desired_state.manifest.get("detections", [])}
    hypotheses: list[AttackPathHypothesis] = []
    for finding in findings:
        if finding.passed:
            continue
        template = _TEMPLATES.get(finding.category)
        if template is None:
            continue
        would_detect = template.required_detection in detections
        hypotheses.append(
            AttackPathHypothesis(
                title=template.title,
                tier="RT-0",
                precondition=template.precondition,
                action=template.action,
                impact=template.impact,
                affected_assets=[finding.resource] if finding.resource else [],
                mitre_tactic=template.mitre_tactic,
                mitre_techniques=list(template.mitre_techniques),
                would_detect=would_detect,
                detection_signal=template.required_detection if would_detect else "",
                confidence=finding.confidence,
                evidence_refs=[finding.finding_id],
            )
        )
    return hypotheses


def detection_gap_findings(
    hypotheses: list[AttackPathHypothesis], *, manifest_sha: str = ""
) -> list[SecurityFinding]:
    """For each modeled path we would NOT detect, emit a detection_gap finding."""
    findings: list[SecurityFinding] = []
    for hyp in hypotheses:
        if hyp.would_detect:
            continue
        template = next((t for t in _TEMPLATES.values() if t.title == hyp.title), None)
        severity = template.severity if template else "MEDIUM"
        asset = hyp.affected_assets[0] if hyp.affected_assets else "as215932"
        findings.append(
            SecurityFinding(
                check_id="detection_gap",
                key=f"{hyp.title}:{asset}",
                category="detection",
                control_domain="detection",
                case_type="detection_gap",
                title=f"Detection gap: {hyp.title}",
                summary=f"No detection for a plausible attack path: {hyp.impact}",
                severity=severity,
                confidence=hyp.confidence,
                mitre_tactics=[hyp.mitre_tactic.split()[0]] if hyp.mitre_tactic else [],
                mitre_techniques=list(hyp.mitre_techniques),
                resource=asset,
                observed_state={"hypothesis_id": hyp.hypothesis_id, "precondition": hyp.precondition},
                evidence=[
                    SecurityEvidence(
                        source_tool="redteam_rt0",
                        query="attack-path modeling",
                        observed_value="no detection signal",
                        expected_value="an alert/telemetry that would fire on this path",
                        detail=hyp.action,
                    )
                ],
                assertion="Every modeled attack path has a corresponding detection.",
                passed=False,
                recommended_remediation=[
                    f"Add detection for: {hyp.title} (e.g. {_detection_hint(hyp.title)}).",
                ],
                warrants_handoff=False,  # detection engineering is tracked, then handed off deliberately
                objective_key=f"detection-gap-{_slug(hyp.title)}-v1",
                verification_objective_type="detection_present",
                manifest_sha=manifest_sha,
            )
        )
    return findings


def _detection_hint(title: str) -> str:
    return {
        "RPKI-invalid route hijack of owned prefixes": "external BGP origin/visibility monitoring + RPKI ROV alerts",
        "management-plane reachable from an untrusted segment": "auth-failure/anomaly alerting on management services",
        "unauthorized WireGuard overlay tunnel": "wg peer-set drift alerting from wg_show",
        "traffic redirection via off-prefix DNS record": "periodic as215932.net owned-prefix DNS check",
    }.get(title, "an alert that fires on this path")


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in text.lower()).strip("-")[:60]
