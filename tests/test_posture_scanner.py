"""Posture checks fire on drift and pass on a healthy fixture.

The lead RPKI check is asserted against the *real* cr1-nl1/frr.conf fixture (which
has no rpki/maximum-prefix and `no bgp ebgp-requires-policy`) and against a
synthetic RPKI-configured variant.
"""

from __future__ import annotations

from pathlib import Path

from app.posture.desired_state import DesiredState
from app.posture.scanner import (
    ScanContext,
    check_dns_ownership,
    check_listening_ports,
    check_rpki_in_frr,
    check_wireguard_hygiene,
    parse_bgp_config,
    scan,
)
from tests._fakes import FakeMCPRuntime, fail, ok

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "desired_state"
REAL_FRR = (FIXTURES / "configs" / "cr1-nl1" / "frr.conf").read_text()

RPKI_OK_CONFIG = """
router bgp 215932
 no bgp default ipv4-unicast
 neighbor 2a0c:b640:8::ffff remote-as 34872
 address-family ipv6 unicast
  neighbor 2a0c:b640:8::ffff activate
  neighbor 2a0c:b640:8::ffff route-map TRANSIT-IN in
  neighbor 2a0c:b640:8::ffff maximum-prefix 1000
 exit-address-family
exit
!
route-map TRANSIT-IN deny 5
 match rpki invalid
exit
route-map TRANSIT-IN permit 10
 match as-path 1
exit
!
"""

MANIFEST = {
    "asn": 215932,
    "owned_prefixes": ["2a0c:b641:b50::/44"],
    "core_routers": ["cr1-nl1", "cr1-de1", "cr1-ch1", "rtr"],
    "transit_asns": [34872],
    "management_domains": ["as215932.net"],
    "wireguard_handshake_max_age_s": 300,
    "listener_allowlist": {"cr1-nl1": [179, 22]},
}


def _ds() -> DesiredState:
    return DesiredState(repo_dir=FIXTURES, manifest=MANIFEST, pin_sha="pin-abc")


def _ctx(handler) -> ScanContext:
    return ScanContext(mcp_runtime=FakeMCPRuntime(handler), desired_state=_ds(), cycle_id="c1")


# --- RPKI lead check --------------------------------------------------------


def test_parse_bgp_finds_transit_neighbor_and_no_ebgp_policy():
    view = parse_bgp_config(REAL_FRR)
    assert view.local_asn == 215932
    assert view.ebgp_requires_policy is False
    ebgp = [n for n in view.neighbors.values() if n.remote_as != 215932]
    assert [n.ip for n in ebgp] == ["2a0c:b640:8::ffff"]
    assert ebgp[0].route_map_in == "TRANSIT-IN"
    assert ebgp[0].max_prefix is False


async def test_rpki_check_fires_on_real_config():
    def handler(name, args):
        if name == "frr_vtysh_cmd" and "running-config" in args["command"]:
            return ok(REAL_FRR)
        if name == "frr_vtysh_cmd" and "rpki" in args["command"]:
            return ok("No RPKI cache connection configured")
        return fail()

    findings = await check_rpki_in_frr(_ctx(handler), ["cr1-nl1"])
    assert len(findings) == 1
    f = findings[0]
    assert f.passed is False
    assert f.severity == "HIGH"
    assert f.confidence == "confirmed"
    assert f.warrants_handoff is True
    assert f.objective_key == "frr-transit-rpki-invalid-reject-v1"
    assert f.observed_state["failing_neighbors"] == ["2a0c:b640:8::ffff"]
    assert f.desired_state_refs[0].content_sha  # grounded + pinned
    assert "T1557" in f.mitre_techniques


async def test_rpki_check_passes_on_rpki_configured_variant():
    def handler(name, args):
        if name == "frr_vtysh_cmd" and "running-config" in args["command"]:
            return ok(RPKI_OK_CONFIG)
        if name == "frr_vtysh_cmd" and "rpki" in args["command"]:
            return ok("RPKI cache connection to 127.0.0.1:3323 is connected")
        return fail()

    findings = await check_rpki_in_frr(_ctx(handler), ["cr1-nl1"])
    assert len(findings) == 1
    assert findings[0].passed is True
    assert findings[0].severity == "LOW"
    assert findings[0].warrants_handoff is False


async def test_rpki_check_degrades_not_passes_on_tool_failure():
    def handler(name, args):
        raise RuntimeError("mcp down")

    ctx = _ctx(handler)
    findings = await check_rpki_in_frr(ctx, ["cr1-nl1"])
    assert findings == []           # no finding emitted...
    assert ctx.degraded is True     # ...and the cycle is flagged degraded (never a silent pass)


# --- WireGuard --------------------------------------------------------------

WG_SHOW_MATCH = """interface: wg0
  public key: SELFKEY0000000000000000000000000000000000=
  listening port: 1337
peer: 09IpW/eDRkZLZU25yWtK+TtH8TfkQsC7etgndKW0A0s=
  endpoint: [2a0c:b640:10::213]:1337
  allowed ips: ::/0
  latest handshake: 30 seconds ago
"""

WG_SHOW_UNKNOWN = WG_SHOW_MATCH + """peer: ROGUEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  endpoint: [2001:db8::66]:51820
  allowed ips: ::/0
  latest handshake: 5 seconds ago
"""


async def test_wireguard_placeholder_key_is_not_flagged_and_peers_match():
    def handler(name, args):
        if name == "wg_show":
            return ok(WG_SHOW_MATCH)
        return fail()

    findings = await check_wireguard_hygiene(_ctx(handler), ["cr1-nl1"])
    # real wg0.conf uses <PRIVATE_KEY> placeholder -> no plaintext-key finding
    assert all(f.key.endswith(":peers") for f in findings)
    assert findings[0].passed is True


async def test_wireguard_unknown_peer_fires_high_and_warrants_handoff():
    def handler(name, args):
        if name == "wg_show":
            return ok(WG_SHOW_UNKNOWN)
        return fail()

    findings = await check_wireguard_hygiene(_ctx(handler), ["cr1-nl1"])
    peers = next(f for f in findings if f.key.endswith(":peers"))
    assert peers.passed is False
    assert peers.severity == "HIGH"
    assert peers.warrants_handoff is True
    assert "ROGUEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" in peers.observed_state["unknown_peers"]


# --- listening ports --------------------------------------------------------


async def test_listening_ports_flags_unexpected_bind():
    def handler(name, args):
        if name == "socket_listeners":
            return ok(data={"listeners": [
                {"address": "2a0c:b641:b50::a", "port": 179},   # allowlisted (BGP)
                {"address": "::", "port": 8765},                # NOT allowlisted
                {"address": "::1", "port": 9999},               # loopback -> ignored
            ]})
        return fail()

    findings = await check_listening_ports(_ctx(handler), ["cr1-nl1"])
    f = findings[0]
    assert f.passed is False
    assert any(x["port"] == 8765 for x in f.observed_state["unexpected"])
    assert all(x["port"] != 9999 for x in f.observed_state["unexpected"])  # loopback excluded
    assert f.warrants_handoff is False  # shadow until allowlist curated


# --- DNS ownership ----------------------------------------------------------


async def test_dns_ownership_fires_on_off_prefix_record():
    def handler(name, args):
        if name == "dns_dig" and args.get("query_type") == "AAAA":
            return ok(data={"answers": [{"type": "AAAA", "data": "2606:4700::1"}]})  # Cloudflare, not owned
        if name == "dns_dig":
            return ok(data={"answers": []})
        return fail()

    findings = await check_dns_ownership(_ctx(handler), ["cr1-nl1"])
    assert findings[0].passed is False
    assert "2606:4700::1" in findings[0].observed_state["off_prefix"]


async def test_dns_ownership_passes_on_owned_record():
    def handler(name, args):
        if name == "dns_dig" and args.get("query_type") == "AAAA":
            return ok(data={"answers": [{"type": "AAAA", "data": "2a0c:b641:b50::100"}]})
        if name == "dns_dig":
            return ok(data={"answers": []})
        return fail()

    findings = await check_dns_ownership(_ctx(handler), ["cr1-nl1"])
    assert findings[0].passed is True


# --- orchestration ----------------------------------------------------------


async def test_scan_runs_all_checks_and_isolates_failures():
    def handler(name, args):
        if name == "frr_vtysh_cmd" and "running-config" in args["command"]:
            return ok(REAL_FRR)
        if name == "frr_vtysh_cmd":
            return ok("No RPKI cache connection configured")
        if name == "wg_show":
            return ok(WG_SHOW_MATCH)
        if name == "socket_listeners":
            return ok(data={"listeners": [{"address": "::", "port": 8765}]})
        if name == "dns_dig" and args.get("query_type") == "AAAA":
            return ok(data={"answers": [{"type": "AAAA", "data": "2a0c:b641:b50::100"}]})
        if name == "dns_dig":
            return ok(data={"answers": []})
        return fail()

    report = await scan(_ctx(handler), hosts=["cr1-nl1"], deep=True)
    check_ids = {f.check_id for f in report.findings}
    assert {"rpki_in_frr", "wireguard_hygiene", "listening_ports", "dns_ownership"} <= check_ids
    # the RPKI drift is the canonical firing finding
    assert any(f.check_id == "rpki_in_frr" and not f.passed for f in report.firing)
