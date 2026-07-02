"""SOC commander routing — classify a finding to a security specialist.

This is the reusable "commander" seam: swap the mapping to change which
specialist owns which finding category. A ``specialist_hint`` on the finding
(set by the scanner or an operator) overrides the category mapping.
"""

from __future__ import annotations

from app.graph.state import SocWorkflowState

_CATEGORY_TO_SPECIALIST: dict[str, str] = {
    "bgp_rpki": "routing_security",
    "dns": "routing_security",
    "firewall": "exposure",
    "listening_ports": "exposure",
    "isolation": "exposure",
    "wireguard": "crypto",
    "vault": "crypto",
    "tls": "crypto",
    "detection": "detection",
}

VALID_SPECIALISTS = {"routing_security", "exposure", "crypto", "detection"}


def classify_specialist(finding: dict) -> tuple[str, str]:
    hint = str(finding.get("specialist_hint") or "").strip()
    if hint in VALID_SPECIALISTS:
        return hint, f"specialist_hint={hint}"
    category = str(finding.get("category") or "other")
    specialist = _CATEGORY_TO_SPECIALIST.get(category, "exposure")
    return specialist, f"category={category}"


def soc_commander_route(state: SocWorkflowState) -> dict:
    finding = state.get("finding") or {}
    specialist, reason = classify_specialist(finding)
    return {"specialist": specialist, "routing_reason": reason, "current_step": "routed"}


def route_specialist(state: SocWorkflowState) -> str:
    specialist = state.get("specialist") or "exposure"
    return f"{specialist}_specialist"
