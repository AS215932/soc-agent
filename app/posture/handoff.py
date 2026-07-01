"""The engineering-loop handoff bridge for SOC findings.

When an approved SOC finding needs a config/docs change, the loop opens a
``loop:candidate`` GitHub issue carrying the evidence chain, an LHP-v1 pointer to
the authoritative handoff payload, and ``soc-*`` correlation markers. A human
promotes it to ``loop:approved``; the engineering-loop daemon then drafts the PR
(merge stays human). SOC **never** applies ``loop:approved`` itself.

Idempotent by a fingerprint marker in the issue body. Ships disabled
(``SOC_POSTURE_HANDOFF_ENABLED``) and needs an issues-scoped GitHub identity.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable

from app import log
from app.cases.models import SecurityCase, SecurityFinding, utc_now
from app.lhp import CaseHandoff

CANDIDATE_LABELS = ["loop:candidate", "agentic-isp", "security"]
_API_BASE = "https://api.github.com"

# async (method, path, *, params, json[, headers]) -> (status_code, body)
Requester = Callable[..., Awaitable[tuple[int, Any]]]
TokenProvider = Callable[[], Awaitable[str]]


def finding_marker(finding: SecurityFinding) -> str:
    return f"soc-fingerprint:{finding.fingerprint()}"


def build_security_issue_body(
    finding: SecurityFinding,
    case: SecurityCase,
    handoff: CaseHandoff,
    *,
    base_url: str = "",
) -> str:
    """Render the loop:candidate body: human summary + evidence + LHP pointer +
    correlation markers. The authoritative payload is fetched out-of-band from
    ``GET /loop-handoff/v1/soc/handoffs/{handoff_id}``."""
    fetch_path = f"/loop-handoff/v1/soc/handoffs/{handoff.handoff_id}"
    pointer = {
        "schema_version": "lhp.v1",
        "handoff_id": handoff.handoff_id,
        "case_id": case.case_id,
        "source_loop": "soc",
        "fetch_path": fetch_path,
        "base_url": base_url or "",
    }
    lines = [
        f"_Filed by the AS215932 SOC loop ({finding.check_id})._",
        "",
        f"## Finding\n{finding.summary or finding.title}",
        f"\n## Assertion\n{finding.assertion}",
    ]
    if finding.evidence:
        lines.append("\n## Evidence")
        for ev in finding.evidence:
            bits = [b for b in (ev.label, ev.observed_value, ev.expected_value, ev.query, ev.detail) if b]
            lines.append(f"- {' · '.join(bits)}")
    if finding.recommended_remediation:
        lines.append("\n## Recommended remediation")
        lines.extend(f"- {c}" for c in finding.recommended_remediation)
    if handoff.acceptance_criteria:
        lines.append("\n## Acceptance criteria")
        lines.extend(f"- {c}" for c in handoff.acceptance_criteria)
    lines.append("\n## Context")
    lines.append(
        f"- resource: `{finding.resource}` · domain: `{finding.control_domain}` · "
        f"severity: `{finding.severity}` · confidence: `{finding.confidence}`"
    )
    if finding.mitre_techniques:
        lines.append(f"- ATT&CK: `{', '.join(finding.mitre_techniques)}`")
    for ref in finding.desired_state_refs:
        lines.append(f"- desired state: `{ref.repo}:{ref.path}` @ `{ref.content_sha or 'unpinned'}`")
    lines.append(f"- SOC case: `{case.case_id}`")
    lines.append(
        "\n> Read-only SOC finding. Promote to `loop:approved` to let the engineering-loop draft a PR; "
        "merge and production apply stay human-gated. The SOC loop never sets `loop:approved`."
    )
    lines.append("\n## LHP-v1 pointer\n```json")
    lines.append(json.dumps(pointer, sort_keys=True))
    lines.append("```")
    lines.append(f"\n<!-- soc-case-id:{case.case_id} -->")
    lines.append(f"<!-- soc-lhp-handoff-id:{handoff.handoff_id} -->")
    lines.append(f"<!-- {finding_marker(finding)} -->")
    return "\n".join(lines)


class GitHubHandoff:
    def __init__(
        self,
        *,
        repo: str,
        token: str | None = None,
        token_provider: TokenProvider | None = None,
        requester: Requester | None = None,
        api_base: str = _API_BASE,
    ) -> None:
        self.repo = repo
        self._token = token
        self._token_provider = token_provider
        self._authed = bool(token) or token_provider is not None
        self.api_base = api_base.rstrip("/")
        self._request = requester or self._default_request

    async def _current_token(self) -> str:
        if self._token_provider is not None:
            return await self._token_provider()
        return self._token or ""

    async def ensure_candidate_issue(
        self,
        finding: SecurityFinding,
        case: SecurityCase,
        handoff: CaseHandoff,
        *,
        base_url: str = "",
    ) -> str | None:
        """Open or refresh the loop:candidate issue for this finding. Returns the
        issue URL, or ``None`` when unauthenticated / on error. Never applies
        ``loop:approved``."""
        if not self._authed or not self.repo:
            return None
        marker = finding_marker(finding)
        title = f"[soc] {finding.title}"[:240]
        body = build_security_issue_body(finding, case, handoff, base_url=base_url)
        refresh = f"Still firing as of {utc_now()} (SOC case `{case.case_id}`)."
        try:
            existing = await self._find_open_issue(marker)
            if existing is not None:
                await self._comment(int(existing["number"]), refresh)
                log.info("soc_handoff_refreshed", repo=self.repo, number=existing.get("number"))
                return existing.get("html_url")
            url = await self._create_issue(title=title, body=body)
            log.info("soc_handoff_created", repo=self.repo, url=url)
            return url
        except Exception as exc:
            log.warning("soc_handoff_failed", repo=self.repo, error=type(exc).__name__)
            return None

    async def _find_open_issue(self, marker: str) -> dict[str, Any] | None:
        query = f'repo:{self.repo} is:issue is:open label:loop:candidate "{marker}"'
        status, body = await self._request("GET", "/search/issues", params={"q": query, "per_page": 20})
        if status != 200 or not isinstance(body, dict):
            return None
        for item in body.get("items", []):
            if isinstance(item, dict) and marker in str(item.get("body") or ""):
                return item
        return None

    async def _create_issue(self, *, title: str, body: str) -> str | None:
        payload = {"title": title[:240], "body": body, "labels": CANDIDATE_LABELS}
        status, resp = await self._request("POST", f"/repos/{self.repo}/issues", json=payload)
        if status not in (200, 201) or not isinstance(resp, dict):
            log.warning("soc_handoff_create_rejected", repo=self.repo, status=status)
            return None
        return resp.get("html_url")

    async def _comment(self, number: int, text: str) -> None:
        await self._request("POST", f"/repos/{self.repo}/issues/{number}/comments", json={"body": text})

    async def _default_request(self, method: str, path: str, *, params: Any = None, json: Any = None):
        import httpx

        token = await self._current_token()
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.request(method, f"{self.api_base}{path}", params=params, json=json, headers=_gh_headers(token))
            try:
                decoded = response.json()
            except Exception:
                decoded = {}
            return response.status_code, decoded


def _gh_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _read_app_private_key() -> str:
    path = os.getenv("SOC_GITHUB_APP_PRIVATE_KEY_PATH", "").strip()
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            return ""
    return os.getenv("SOC_GITHUB_APP_PRIVATE_KEY", "").replace("\\n", "\n").strip()


def handoff_from_env(repo: str) -> GitHubHandoff | None:
    """Build a SOC handoff client from its own least-privilege identity
    (``SOC_GITHUB_APP_*`` preferred, else ``SOC_GITHUB_TOKEN``). ``None`` if
    neither is configured."""
    app_id = os.getenv("SOC_GITHUB_APP_ID", "").strip()
    private_key = _read_app_private_key()
    if app_id and private_key:
        auth = _GitHubAppAuth(app_id=app_id, private_key=private_key, repo=repo)
        return GitHubHandoff(repo=repo, token_provider=auth.token)
    token = os.getenv("SOC_GITHUB_TOKEN", "").strip()
    if token:
        return GitHubHandoff(repo=repo, token=token)
    return None


class _GitHubAppAuth:
    """Mints short-lived GitHub App installation tokens (least-privilege, auto-rotating)."""

    def __init__(self, *, app_id: str, private_key: str, repo: str, requester: Requester | None = None, api_base: str = _API_BASE) -> None:
        self.app_id = str(app_id)
        self.private_key = private_key
        self.repo = repo
        self.api_base = api_base.rstrip("/")
        self._request = requester or self._default_request
        self._cached_token = ""
        self._expires_at = 0.0

    async def token(self) -> str:
        now = time.time()
        if self._cached_token and now < self._expires_at - 300:
            return self._cached_token
        jwt_token = self._make_jwt(now)
        installation_id = await self._resolve_installation_id(jwt_token)
        tok, exp = await self._mint(jwt_token, installation_id)
        self._cached_token, self._expires_at = tok, exp
        return tok

    def _make_jwt(self, now: float) -> str:
        import jwt

        payload = {"iat": int(now) - 60, "exp": int(now) + 540, "iss": self.app_id}
        return jwt.encode(payload, self.private_key, algorithm="RS256")

    async def _resolve_installation_id(self, jwt_token: str) -> int:
        status, body = await self._request("GET", f"/repos/{self.repo}/installation", headers=_gh_headers(jwt_token))
        if status != 200 or not isinstance(body, dict) or "id" not in body:
            raise RuntimeError(f"could not resolve app installation for {self.repo} (status {status})")
        return int(body["id"])

    async def _mint(self, jwt_token: str, installation_id: int) -> tuple[str, float]:
        status, body = await self._request("POST", f"/app/installations/{installation_id}/access_tokens", headers=_gh_headers(jwt_token))
        if status not in (200, 201) or not isinstance(body, dict) or "token" not in body:
            raise RuntimeError(f"could not mint installation token (status {status})")
        return str(body["token"]), (_parse_iso(body.get("expires_at")) or time.time() + 3600)

    async def _default_request(self, method: str, path: str, *, params: Any = None, json: Any = None, headers: Any = None):
        import httpx

        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.request(method, f"{self.api_base}{path}", params=params, json=json, headers=headers or {})
            try:
                decoded = response.json()
            except Exception:
                decoded = {}
            return response.status_code, decoded


def _parse_iso(value: Any) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None
