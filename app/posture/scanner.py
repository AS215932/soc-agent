"""The posture engine: read-only desired-state-vs-live checks → SecurityFindings.

Every check is wrapped so a single failure degrades to "no findings from this
check" (and marks the cycle ``degraded``) rather than crashing the scan. A check
emits a firing finding (``passed=False``) when a control has drifted, and a
positive finding (``passed=True``) when the control is healthy — the latter is
what lets the verifier resolve a case under No-False-All-Clear.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from app import log
from app.cases.models import DesiredStateRef, SecurityEvidence, SecurityFinding
from app.posture.desired_state import DesiredState

# --- MCP result helpers -----------------------------------------------------


def _ok(resp: Any) -> bool:
    return isinstance(resp, dict) and resp.get("ok") is not False


def _stdout(resp: Any) -> str:
    if not isinstance(resp, dict):
        return ""
    return str(resp.get("stdout") or "")


def _data(resp: Any) -> dict[str, Any]:
    if isinstance(resp, dict) and isinstance(resp.get("data"), dict):
        return resp["data"]
    return {}


# --- scan context -----------------------------------------------------------


@dataclass
class ScanContext:
    mcp_runtime: Any
    desired_state: DesiredState
    cycle_id: str = ""
    # Set when any tool read failed this cycle so the loop can tell a *degraded*
    # scan from a genuinely clean one and never resolve on absent signal.
    degraded: bool = False

    async def _call(self, tool: str, args: dict[str, Any]) -> dict[str, Any] | None:
        try:
            return await self.mcp_runtime.call_tool("hyrule", tool, args)
        except Exception as exc:
            log.warning("soc_posture_tool_failed", tool=tool, error=type(exc).__name__)
            self.degraded = True
            return None

    async def frr(self, host: str, command: str) -> dict[str, Any] | None:
        return await self._call("frr_vtysh_cmd", {"host": host, "command": command})

    async def sockets(self, host: str) -> dict[str, Any] | None:
        return await self._call("socket_listeners", {"host": host})

    async def wg(self, host: str) -> dict[str, Any] | None:
        return await self._call("wg_show", {"host": host})

    async def dig(self, host: str, target: str, query_type: str = "AAAA") -> dict[str, Any] | None:
        return await self._call("dns_dig", {"host": host, "target": target, "query_type": query_type})


@dataclass
class ScanReport:
    findings: list[SecurityFinding] = field(default_factory=list)
    degraded: bool = False
    checks_run: list[str] = field(default_factory=list)

    @property
    def firing(self) -> list[SecurityFinding]:
        return [f for f in self.findings if not f.passed]

    @property
    def passing(self) -> list[SecurityFinding]:
        return [f for f in self.findings if f.passed]


PostureCheck = Callable[[ScanContext, list[str]], Awaitable[list[SecurityFinding]]]


# ===========================================================================
# Check 1 (LEAD): RPKI / prefix-filter completeness on eBGP neighbors
# ===========================================================================


@dataclass
class _Neighbor:
    ip: str
    remote_as: int
    route_map_in: str = ""
    max_prefix: bool = False


@dataclass
class _BgpView:
    local_asn: int = 0
    ebgp_requires_policy: bool = True
    neighbors: dict[str, _Neighbor] = field(default_factory=dict)
    route_maps: dict[str, list[str]] = field(default_factory=dict)


_RE_ROUTER_BGP = re.compile(r"^\s*router bgp (\d+)", re.M)
_RE_NEIGH_REMOTE = re.compile(r"^\s*neighbor (\S+) remote-as (\d+)", re.M)
_RE_NEIGH_RMAP_IN = re.compile(r"^\s*neighbor (\S+) route-map (\S+) in\b", re.M)
_RE_NEIGH_MAXPREFIX = re.compile(r"^\s*neighbor (\S+) maximum-prefix\b", re.M)
_RE_ROUTE_MAP_HDR = re.compile(r"^\s*route-map (\S+) (?:permit|deny) \d+", re.M)


def parse_bgp_config(text: str) -> _BgpView:
    view = _BgpView()
    m = _RE_ROUTER_BGP.search(text)
    if m:
        view.local_asn = int(m.group(1))
    if re.search(r"^\s*no bgp ebgp-requires-policy\b", text, re.M):
        view.ebgp_requires_policy = False
    for ip, asn in _RE_NEIGH_REMOTE.findall(text):
        view.neighbors[ip] = _Neighbor(ip=ip, remote_as=int(asn))
    for ip, rmap in _RE_NEIGH_RMAP_IN.findall(text):
        if ip in view.neighbors:
            view.neighbors[ip].route_map_in = rmap
    for ip in _RE_NEIGH_MAXPREFIX.findall(text):
        if ip in view.neighbors:
            view.neighbors[ip].max_prefix = True

    # Accumulate every clause body per route-map name.
    lines = text.splitlines()
    current: str | None = None
    for line in lines:
        header = _RE_ROUTE_MAP_HDR.match(line)
        if header:
            current = header.group(1)
            view.route_maps.setdefault(current, [])
            continue
        if current is not None:
            if re.match(r"^\s*(exit\b|!|route-map |router |interface |address-family |line )", line) and not line.startswith(" "):
                current = None
            elif line.startswith(" "):
                view.route_maps[current].append(line.strip())
            else:
                current = None
    return view


def _route_map_rejects_rpki(view: _BgpView, name: str) -> bool:
    body = view.route_maps.get(name, [])
    return any("rpki" in clause.lower() for clause in body)


def _rpki_cache_active(resp: dict[str, Any] | None) -> bool:
    if not _ok(resp):
        return False
    text = _stdout(resp).lower()
    if "no rpki" in text or "not configured" in text or not text.strip():
        return False
    return "connected" in text or "established" in text or "session" in text


async def check_rpki_in_frr(ctx: ScanContext, hosts: list[str]) -> list[SecurityFinding]:
    """LEAD check: an eBGP neighbor must reject RPKI-invalid routes (via an
    active validator or an inbound route-map) **and** cap prefixes."""
    findings: list[SecurityFinding] = []
    core_routers = set(ctx.desired_state.manifest.get("core_routers", [])) or set(hosts)
    for host in hosts:
        if host not in core_routers:
            continue
        running = await ctx.frr(host, "show running-config")
        if not _ok(running):
            continue  # degraded already set by ctx._call
        view = parse_bgp_config(_stdout(running))
        local_asn = view.local_asn or ctx.desired_state.asn
        ebgp = [n for n in view.neighbors.values() if n.remote_as != local_asn]
        if not ebgp:
            continue

        rpki_cache = await ctx.frr(host, "show rpki cache-connection")
        rpki_active = _rpki_cache_active(rpki_cache)

        desired_file = ctx.desired_state.frr_conf(host)
        ds_ref = DesiredStateRef(
            repo=desired_file.repo,
            path=desired_file.path,
            ref=f"router bgp {local_asn}",
            content_sha=desired_file.content_sha,
            assertion_text="eBGP neighbors reject RPKI-invalid routes and set maximum-prefix",
        )

        failing: list[_Neighbor] = []
        for nb in ebgp:
            rmap_rejects = bool(nb.route_map_in) and _route_map_rejects_rpki(view, nb.route_map_in)
            if not (rpki_active or rmap_rejects) or not nb.max_prefix:
                failing.append(nb)

        passed = not failing
        evidence = [
            SecurityEvidence(
                source_tool="frr_vtysh_cmd",
                query="show rpki cache-connection",
                observed_value="active validator" if rpki_active else "no RPKI validator connected",
                expected_value="RPKI-to-Router cache connected OR inbound route-map rejects rpki invalid",
            )
        ]
        for nb in (failing or ebgp):
            evidence.append(
                SecurityEvidence(
                    source_tool="frr_vtysh_cmd",
                    query=f"show running-config (neighbor {nb.ip})",
                    observed_value=(
                        f"remote-as {nb.remote_as} route-map-in={nb.route_map_in or 'none'} "
                        f"maximum-prefix={'yes' if nb.max_prefix else 'no'}"
                    ),
                    expected_value="rpki-invalid reject + maximum-prefix",
                    detail=f"ebgp-requires-policy={'on' if view.ebgp_requires_policy else 'OFF'}",
                )
            )

        findings.append(
            SecurityFinding(
                check_id="rpki_in_frr",
                key=host,
                category="bgp_rpki",
                control_domain="rpki_irr",
                case_type="control_drift",
                title=f"{host}: eBGP transit missing RPKI-invalid reject / maximum-prefix"
                if not passed
                else f"{host}: eBGP RPKI/prefix filtering present",
                summary=(
                    f"{len(failing)} of {len(ebgp)} eBGP neighbor(s) on {host} lack RPKI-invalid "
                    "reject and/or maximum-prefix."
                )
                if not passed
                else f"All {len(ebgp)} eBGP neighbor(s) on {host} reject RPKI-invalid and cap prefixes.",
                severity="HIGH" if not passed else "LOW",
                confidence="confirmed",
                mitre_tactics=["TA0001", "TA0040"],
                mitre_techniques=["T1557", "T1565.003"],
                resource=host,
                site=host,
                desired_state_refs=[ds_ref],
                observed_state={
                    "local_asn": local_asn,
                    "ebgp_neighbors": [nb.ip for nb in ebgp],
                    "failing_neighbors": [nb.ip for nb in failing],
                    "rpki_cache_active": rpki_active,
                    "ebgp_requires_policy": view.ebgp_requires_policy,
                },
                evidence=evidence,
                assertion="Every eBGP neighbor rejects RPKI-invalid routes and sets maximum-prefix.",
                passed=passed,
                recommended_remediation=[
                    "Deploy an RPKI-to-Router validator (e.g. Routinator/StayRTR) and reference it in FRR, OR",
                    "Add an inbound route-map clause that denies `match rpki invalid` on each transit/IXP neighbor.",
                    "Set `neighbor <peer> maximum-prefix <N>` on transit/IXP sessions.",
                    "Justify or remove `no bgp ebgp-requires-policy`.",
                ],
                warrants_handoff=not passed,
                objective_key="frr-transit-rpki-invalid-reject-v1",
                verification_objective_type="frr_rpki_config_present",
                acceptance_criteria=[
                    "eBGP neighbors drop RPKI-invalid routes (validator or route-map)",
                    "maximum-prefix cap on transit/IXP neighbors",
                    "ebgp-requires-policy justified or removed",
                ],
                constraints=[
                    "do_not_mutate_prod",
                    "human_approval_before_frr_change",
                    "routing_change_needs_maintenance_window",
                ],
                manifest_sha=ctx.desired_state.pin_sha,
            )
        )
    return findings


# ===========================================================================
# Check 2: WireGuard hygiene (committed plaintext key / peer drift)
# ===========================================================================

_RE_WG_PRIVATE = re.compile(r"^\s*PrivateKey\s*=\s*(\S+)", re.M)
_RE_WG_PUBLIC = re.compile(r"^\s*PublicKey\s*=\s*(\S+)", re.M)
_RE_B64_KEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")


def _parse_wg_show_peers(text: str) -> dict[str, dict[str, str]]:
    peers: dict[str, dict[str, str]] = {}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("peer:"):
            current = line.split(":", 1)[1].strip()
            peers[current] = {}
        elif current and ":" in line:
            key, _, value = line.partition(":")
            peers[current][key.strip()] = value.strip()
    return peers


async def check_wireguard_hygiene(ctx: ScanContext, hosts: list[str]) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    core_routers = set(ctx.desired_state.manifest.get("core_routers", [])) or set(hosts)
    for host in hosts:
        if host not in core_routers:
            continue
        wg_files = ctx.desired_state.wg_confs(host)
        if not wg_files:
            continue

        # (a) committed plaintext key — a static (non-MCP) check, always confident.
        desired_pubkeys: set[str] = set()
        plaintext_files: list[str] = []
        for f in wg_files:
            for value in _RE_WG_PRIVATE.findall(f.text):
                if _RE_B64_KEY.match(value):
                    plaintext_files.append(f.path)
            desired_pubkeys.update(_RE_WG_PUBLIC.findall(f.text))

        if plaintext_files:
            findings.append(
                _finding_wg(
                    host,
                    passed=False,
                    key_suffix="plaintext-key",
                    title=f"{host}: committed WireGuard private key in git",
                    summary=f"Non-placeholder PrivateKey committed in: {', '.join(plaintext_files)}",
                    severity="HIGH",
                    confidence="confirmed",
                    techniques=["T1552.001"],
                    refs=[
                        DesiredStateRef(path=p, assertion_text="PrivateKey must be a Vault-rendered <PRIVATE_KEY> placeholder")
                        for p in plaintext_files
                    ],
                    evidence=[
                        SecurityEvidence(
                            source_tool="git",
                            query=p,
                            observed_value="committed base64 private key",
                            expected_value="<PRIVATE_KEY> placeholder",
                        )
                        for p in plaintext_files
                    ],
                    observed={"plaintext_key_files": plaintext_files},
                    objective_key="wireguard-no-committed-private-keys-v1",
                    remediation=[
                        "Remove the committed key, rotate it in Vault, and render it via vault-agent.",
                    ],
                    warrants_handoff=True,
                    manifest_sha=ctx.desired_state.pin_sha,
                )
            )

        # (b) peer-set drift vs live wg show.
        resp = await ctx.wg(host)
        if not _ok(resp):
            continue
        live = _parse_wg_show_peers(_stdout(resp))
        live_pubkeys = set(live.keys())
        unknown = live_pubkeys - desired_pubkeys
        missing = desired_pubkeys - live_pubkeys
        drift = bool(unknown or missing)
        findings.append(
            _finding_wg(
                host,
                passed=not drift,
                key_suffix="peers",
                title=f"{host}: WireGuard peer-set drift" if drift else f"{host}: WireGuard peers match desired",
                summary=(
                    f"unknown peers={sorted(unknown)} missing peers={sorted(missing)}"
                    if drift
                    else f"{len(live_pubkeys)} live peer(s) match desired config."
                ),
                severity="HIGH" if unknown else ("MEDIUM" if drift else "LOW"),
                confidence="high",
                techniques=["T1557", "T1040"],
                refs=[DesiredStateRef(path=f.path, content_sha=f.content_sha, assertion_text="live peers == committed peers") for f in wg_files],
                evidence=[
                    SecurityEvidence(
                        source_tool="wg_show",
                        query=f"wg show ({host})",
                        observed_value=f"{len(live_pubkeys)} live peers",
                        expected_value=f"{len(desired_pubkeys)} desired peers",
                        detail=f"unknown={sorted(unknown)} missing={sorted(missing)}",
                    )
                ],
                observed={"unknown_peers": sorted(unknown), "missing_peers": sorted(missing)},
                objective_key="wireguard-peer-set-matches-desired-v1",
                remediation=["Reconcile the live WireGuard peer set with the committed configs; investigate any unknown peer as a potential unauthorized tunnel."],
                warrants_handoff=bool(unknown),
                manifest_sha=ctx.desired_state.pin_sha,
            )
        )
    return findings


def _finding_wg(host, *, passed, key_suffix, title, summary, severity, confidence, techniques, refs, evidence, observed, objective_key, remediation, warrants_handoff, manifest_sha) -> SecurityFinding:  # type: ignore[no-untyped-def]
    return SecurityFinding(
        check_id="wireguard_hygiene",
        key=f"{host}:{key_suffix}",
        category="wireguard",
        control_domain="wireguard_crypto",
        case_type="control_drift" if passed or key_suffix == "peers" else "security_finding",
        title=title,
        summary=summary,
        severity=severity,
        confidence=confidence,
        mitre_techniques=techniques,
        resource=host,
        site=host,
        desired_state_refs=refs,
        observed_state=observed,
        evidence=evidence,
        assertion="WireGuard keys are Vault-rendered and the live peer set matches the committed configs.",
        passed=passed,
        recommended_remediation=remediation,
        warrants_handoff=warrants_handoff,
        objective_key=objective_key,
        verification_objective_type="wireguard_posture",
        acceptance_criteria=["no committed private keys", "live peers == desired peers"],
        constraints=["do_not_mutate_prod", "human_approval_before_change"],
        manifest_sha=manifest_sha,
    )


# ===========================================================================
# Check 3: untracked listening surface
# ===========================================================================


def _parse_listeners(resp: dict[str, Any]) -> list[dict[str, Any]]:
    """Prefer a structured ``data.listeners`` list; fall back to regex over
    stdout capturing ``address:port`` LISTEN sockets."""
    data = _data(resp)
    if isinstance(data.get("listeners"), list):
        return [x for x in data["listeners"] if isinstance(x, dict)]
    listeners: list[dict[str, Any]] = []
    for line in _stdout(resp).splitlines():
        if "LISTEN" not in line and "tcp" not in line.lower():
            continue
        m = re.search(r"(\[?[0-9a-fA-F:.\*]+\]?):(\d{1,5})\b", line)
        if m:
            listeners.append({"address": m.group(1).strip("[]"), "port": int(m.group(2)), "raw": line.strip()})
    return listeners


def _is_local_bind(address: str) -> bool:
    a = address.strip("[]")
    return a in {"127.0.0.1", "::1", "localhost"} or a.startswith("127.") or a.startswith("fe80")


async def check_listening_ports(ctx: ScanContext, hosts: list[str]) -> list[SecurityFinding]:
    """Flag non-loopback listeners absent from the per-host allowlist. Runs in
    shadow until the allowlist is curated (Open Question 4)."""
    findings: list[SecurityFinding] = []
    allowlists = ctx.desired_state.manifest.get("listener_allowlist", {})
    for host in hosts:
        allow = set(int(p) for p in allowlists.get(host, []))
        resp = await ctx.sockets(host)
        if not _ok(resp):
            continue
        listeners = _parse_listeners(resp)
        unexpected = [
            listener
            for listener in listeners
            if not _is_local_bind(str(listener.get("address", "")))
            and int(listener.get("port", 0)) not in allow
        ]
        passed = not unexpected
        findings.append(
            SecurityFinding(
                check_id="listening_ports",
                key=host,
                category="listening_ports",
                control_domain="edge_firewall",
                case_type="security_finding" if not passed else "control_drift",
                title=f"{host}: untracked listening port(s)" if not passed else f"{host}: listening surface matches allowlist",
                summary=(
                    f"{len(unexpected)} non-loopback listener(s) not in the allowlist: "
                    + ", ".join(f"{x.get('address')}:{x.get('port')}" for x in unexpected[:8])
                )
                if not passed
                else f"All {len(listeners)} listener(s) on {host} are loopback or allowlisted.",
                severity="HIGH" if not passed else "LOW",
                confidence="high",
                mitre_techniques=["T1046", "T1571"],
                resource=host,
                site=host,
                observed_state={"unexpected": unexpected[:16], "allowlist": sorted(allow)},
                evidence=[
                    SecurityEvidence(
                        source_tool="socket_listeners",
                        query=f"socket_listeners ({host})",
                        observed_value=f"{len(listeners)} listeners, {len(unexpected)} unexpected",
                        expected_value="only loopback or allowlisted ports",
                    )
                ],
                assertion="Every non-loopback listening socket maps to an allowlisted service/port.",
                passed=passed,
                recommended_remediation=[
                    "Confirm the service is intended; add it to the host allowlist or close the port via pf/nft.",
                ],
                warrants_handoff=False,  # shadow until allowlist is curated
                objective_key="listening-surface-allowlisted-v1",
                verification_objective_type="listening_surface",
                manifest_sha=ctx.desired_state.pin_sha,
            )
        )
    return findings


# ===========================================================================
# Check 4: as215932.net points only at owned prefixes
# ===========================================================================


def _parse_dns_answers(resp: dict[str, Any]) -> list[str]:
    """Prefer structured ``data.answers``; fall back to parsing a dig ANSWER
    SECTION from stdout."""
    data = _data(resp)
    answers = data.get("answers")
    if isinstance(answers, list):
        out = []
        for a in answers:
            if isinstance(a, dict) and a.get("data"):
                out.append(str(a["data"]))
            elif isinstance(a, str):
                out.append(a)
        return out
    out = []
    in_answer = False
    for line in _stdout(resp).splitlines():
        if line.startswith(";; ANSWER SECTION"):
            in_answer = True
            continue
        if in_answer:
            if not line.strip() or line.startswith(";;"):
                break
            parts = line.split()
            if len(parts) >= 5 and parts[3] in {"A", "AAAA"}:
                out.append(parts[4])
    return out


async def check_dns_ownership(ctx: ScanContext, hosts: list[str]) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    if not hosts:
        return findings
    resolver_host = hosts[0]  # any host that can run dig
    for domain in ctx.desired_state.management_domains:
        addresses: list[str] = []
        for qtype in ("AAAA", "A"):
            resp = await ctx.dig(resolver_host, domain, qtype)
            if not _ok(resp):
                continue
            addresses.extend(_parse_dns_answers(resp))
        if not addresses:
            continue
        off_prefix = [a for a in addresses if not ctx.desired_state.is_owned_address(a)]
        passed = not off_prefix
        findings.append(
            SecurityFinding(
                check_id="dns_ownership",
                key=domain,
                category="dns",
                control_domain="customer_isolation",
                case_type="control_drift",
                title=f"{domain}: record(s) point outside owned prefixes" if not passed else f"{domain}: records within owned space",
                summary=(f"{len(off_prefix)} record(s) outside owned prefixes: {', '.join(off_prefix[:6])}") if not passed else f"All {len(addresses)} address record(s) for {domain} are within owned prefixes.",
                severity="MEDIUM" if not passed else "LOW",
                confidence="high",
                mitre_techniques=["T1583.001"],
                resource=domain,
                desired_state_refs=[
                    DesiredStateRef(
                        path="AGENTS.md",
                        ref="domain policy",
                        assertion_text=f"{domain} records must point only at AS215932-owned prefixes",
                    )
                ],
                observed_state={"addresses": addresses[:32], "off_prefix": off_prefix[:32], "owned_prefixes": ctx.desired_state.owned_prefixes},
                evidence=[
                    SecurityEvidence(
                        source_tool="dns_dig",
                        query=f"dig {domain} AAAA/A",
                        observed_value=", ".join(addresses[:8]),
                        expected_value=f"within {ctx.desired_state.owned_prefixes}",
                    )
                ],
                assertion=f"Every {domain} address record resolves inside an AS215932-owned prefix.",
                passed=passed,
                recommended_remediation=["Repoint or remove records that resolve outside owned prefixes."],
                warrants_handoff=not passed,
                objective_key="dns-owned-prefixes-only-v1",
                verification_objective_type="dns_ownership",
                manifest_sha=ctx.desired_state.pin_sha,
            )
        )
    return findings


# ===========================================================================
# Orchestration
# ===========================================================================

CHEAP_CHECKS: tuple[PostureCheck, ...] = (
    check_rpki_in_frr,
    check_wireguard_hygiene,
    check_dns_ownership,
)
DEEP_CHECKS: tuple[PostureCheck, ...] = (check_listening_ports,)
DEEP_CHECK_IDS = frozenset({"listening_ports"})
ALL_CHECKS: tuple[PostureCheck, ...] = CHEAP_CHECKS + DEEP_CHECKS


async def scan(ctx: ScanContext, *, hosts: list[str], deep: bool = True) -> ScanReport:
    """Run each check with per-check isolation and collect findings."""
    report = ScanReport()
    checks = ALL_CHECKS if deep else CHEAP_CHECKS
    for check in checks:
        name = check.__name__
        try:
            found = await check(ctx, hosts)
        except Exception as exc:
            log.warning("soc_posture_check_crashed", check=name, error=type(exc).__name__)
            ctx.degraded = True
            found = []
        report.checks_run.append(name)
        report.findings.extend(found)
    report.degraded = ctx.degraded
    return report
