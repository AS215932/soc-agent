"""RT-1 non-invasive validators: owned-asset allowlist + tier gate + zero writes."""

from __future__ import annotations

import pytest

from app.config import RedTeamSettings
from app.posture.desired_state import DesiredState
from app.redteam.policy import RedTeamGate, RedTeamRefused
from app.redteam.validators import NonInvasiveValidator


def _ds() -> DesiredState:
    return DesiredState(
        repo_dir=".",
        manifest={
            "owned_prefixes": ["2a0c:b641:b50::/44"],
            "management_domains": ["as215932.net"],
            "redteam_allowed_assets": ["status.as215932.net"],
        },
    )


def _gate(**over) -> RedTeamGate:
    base = dict(enabled=True, max_tier=1, human_gate_tier=2, allow_active_probes=False)
    base.update(over)
    return RedTeamGate(RedTeamSettings(**base))


def _fetcher(headers):
    async def fetch(url):
        return 200, headers

    return fetch


def test_owned_target_recognition():
    v = NonInvasiveValidator(_ds(), _gate(), fetcher=_fetcher({}))
    assert v.is_owned_target("https://as215932.net/") is True
    assert v.is_owned_target("https://sub.as215932.net/x") is True
    assert v.is_owned_target("status.as215932.net") is True  # explicit allowlist
    assert v.is_owned_target("https://[2a0c:b641:b50::5]/") is True  # owned prefix
    assert v.is_owned_target("https://evil.example.com/") is False


async def test_non_owned_target_is_refused_not_probed():
    calls = []

    async def spy(url):
        calls.append(url)
        return 200, {}

    v = NonInvasiveValidator(_ds(), _gate(), fetcher=spy)
    results = await v.run(["https://evil.example.com/"])
    assert results[0].check == "scope_refused"
    assert results[0].passed is False
    assert calls == []  # the non-owned target was never fetched


async def test_missing_hsts_fails_validation():
    v = NonInvasiveValidator(_ds(), _gate(), fetcher=_fetcher({"Server": "nginx/1.2.3"}))
    result = await v.validate_security_headers("https://as215932.net/")
    assert result.passed is False
    assert "strict-transport-security" in result.note
    assert "nginx" in result.note


async def test_clean_headers_pass_validation():
    v = NonInvasiveValidator(_ds(), _gate(), fetcher=_fetcher({"Strict-Transport-Security": "max-age=63072000"}))
    result = await v.validate_security_headers("https://as215932.net/")
    assert result.passed is True
    assert result.tier == "RT-1"


async def test_disabled_tier_refuses_validation():
    v = NonInvasiveValidator(_ds(), _gate(enabled=False), fetcher=_fetcher({}))
    with pytest.raises(RedTeamRefused):
        await v.validate_security_headers("https://as215932.net/")


async def test_default_fetch_refused_without_active_probes():
    # No injected fetcher -> default live fetch is gated behind allow_active_probes.
    v = NonInvasiveValidator(_ds(), _gate(allow_active_probes=False))
    with pytest.raises(RedTeamRefused):
        await v._default_fetch("https://as215932.net/")
