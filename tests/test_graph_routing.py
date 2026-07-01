"""SOC commander routing maps finding categories to specialists."""

from __future__ import annotations

from app.graph.routing import classify_specialist, route_specialist, soc_commander_route


def test_category_mapping():
    assert classify_specialist({"category": "bgp_rpki"})[0] == "routing_security"
    assert classify_specialist({"category": "dns"})[0] == "routing_security"
    assert classify_specialist({"category": "listening_ports"})[0] == "exposure"
    assert classify_specialist({"category": "wireguard"})[0] == "crypto"
    assert classify_specialist({"category": "vault"})[0] == "crypto"
    assert classify_specialist({"category": "detection"})[0] == "detection"
    # unknown -> exposure default
    assert classify_specialist({"category": "other"})[0] == "exposure"


def test_specialist_hint_overrides_category():
    specialist, reason = classify_specialist({"category": "bgp_rpki", "specialist_hint": "crypto"})
    assert specialist == "crypto"
    assert "specialist_hint" in reason


def test_route_functions():
    updates = soc_commander_route({"finding": {"category": "bgp_rpki"}})
    assert updates["specialist"] == "routing_security"
    assert route_specialist(updates) == "routing_security_specialist"
