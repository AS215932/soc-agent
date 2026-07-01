"""RT-1: non-invasive read-only validation on known-owned assets.

Version/config/header checks via a plain GET — no auth attempts, no fuzzing, no
payloads. Enforces the owned-asset allowlist (a non-owned target is refused) and
the tier gate. The default live fetcher is additionally gated behind
``SOC_REDTEAM_ALLOW_ACTIVE_PROBES``; tests inject a fake fetcher.
"""

from __future__ import annotations

from typing import Awaitable, Callable
from urllib.parse import urlparse

from app.posture.desired_state import DesiredState
from app.redteam.models import ValidationResult
from app.redteam.policy import RedTeamGate, RedTeamRefused

# url -> (status_code, headers)
Fetcher = Callable[[str], Awaitable[tuple[int, dict[str, str]]]]


class NonInvasiveValidator:
    def __init__(
        self,
        desired_state: DesiredState,
        gate: RedTeamGate,
        *,
        fetcher: Fetcher | None = None,
        allowed_hosts: list[str] | None = None,
    ) -> None:
        self.desired_state = desired_state
        self.gate = gate
        self._fetch = fetcher or self._default_fetch
        manifest_allow = desired_state.manifest.get("redteam_allowed_assets", [])
        self.allowed_hosts = {str(h).lower() for h in (allowed_hosts or manifest_allow)}

    def _host(self, target: str) -> str:
        parsed = urlparse(target if "://" in target else f"//{target}", scheme="https")
        return (parsed.hostname or "").lower()

    def is_owned_target(self, target: str) -> bool:
        host = self._host(target)
        if not host:
            return False
        if host in self.allowed_hosts:
            return True
        # IP literal within an owned prefix
        if self.desired_state.is_owned_address(host):
            return True
        # owned management domain (or subdomain thereof)
        for domain in self.desired_state.management_domains:
            d = domain.lower()
            if host == d or host.endswith(f".{d}"):
                return True
        return False

    async def validate_security_headers(self, url: str) -> ValidationResult:
        """Non-invasive header check on an owned HTTPS endpoint."""
        self.gate.require("RT-1")
        if not self.is_owned_target(url):
            raise RedTeamRefused(f"target {url!r} is not in the owned-asset allowlist")
        status, headers = await self._fetch(url)
        lower = {k.lower(): v for k, v in headers.items()}
        missing = [h for h in ("strict-transport-security",) if h not in lower]
        server_disclosure = lower.get("server", "")
        passed = not missing and not server_disclosure
        note_bits = []
        if missing:
            note_bits.append(f"missing: {', '.join(missing)}")
        if server_disclosure:
            note_bits.append(f"server header discloses: {server_disclosure}")
        return ValidationResult(
            target=url,
            check="http_security_headers",
            tier="RT-1",
            observed=f"status={status} " + "; ".join(note_bits) if note_bits else f"status={status} ok",
            expected="HSTS present, no server-version disclosure",
            passed=passed,
            note="; ".join(note_bits),
        )

    async def run(self, targets: list[str]) -> list[ValidationResult]:
        """Validate each owned target; non-owned targets are refused (recorded as
        a failed 'scope_refused' result rather than probed)."""
        results: list[ValidationResult] = []
        for target in targets:
            if not self.is_owned_target(target):
                results.append(
                    ValidationResult(
                        target=target, check="scope_refused", tier="RT-1", passed=False,
                        observed="not in owned-asset allowlist", expected="owned asset", note="refused",
                    )
                )
                continue
            try:
                results.append(await self.validate_security_headers(target))
            except RedTeamRefused as exc:
                results.append(
                    ValidationResult(target=target, check="refused", tier="RT-1", passed=False, note=str(exc))
                )
        return results

    async def _default_fetch(self, url: str) -> tuple[int, dict[str, str]]:
        if not self.gate.active_probes_allowed():
            raise RedTeamRefused("live RT-1 probes require SOC_REDTEAM_ALLOW_ACTIVE_PROBES=1")
        import httpx

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            resp = await client.get(url)
            return resp.status_code, {k: v for k, v in resp.headers.items()}
