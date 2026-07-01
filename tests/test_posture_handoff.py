"""loop:candidate issue rendering + idempotency; never applies loop:approved."""

from __future__ import annotations

import json

from app.cases.models import DesiredStateRef, SecurityCase, SecurityEvidence, SecurityFinding
from app.posture.handoff import CANDIDATE_LABELS, GitHubHandoff, build_security_issue_body, finding_marker


def _finding() -> SecurityFinding:
    return SecurityFinding(
        check_id="rpki_in_frr",
        key="cr1-nl1",
        category="bgp_rpki",
        control_domain="rpki_irr",
        title="RPKI-invalid reject missing",
        summary="transit eBGP lacks rpki reject",
        severity="HIGH",
        confidence="confirmed",
        passed=False,
        warrants_handoff=True,
        objective_key="frr-transit-rpki-invalid-reject-v1",
        mitre_techniques=["T1557"],
        resource="cr1-nl1",
        desired_state_refs=[DesiredStateRef(path="configs/cr1-nl1/frr.conf", content_sha="deadbeef")],
        evidence=[SecurityEvidence(source_tool="frr_vtysh_cmd", query="show route-map TRANSIT-IN")],
        recommended_remediation=["add rpki reject"],
        acceptance_criteria=["transit eBGP drops RPKI-invalid"],
    )


def test_never_applies_loop_approved():
    assert "loop:candidate" in CANDIDATE_LABELS
    assert "loop:approved" not in CANDIDATE_LABELS
    assert "security" in CANDIDATE_LABELS


def test_issue_body_has_pointer_and_markers():
    finding = _finding()
    case = SecurityCase(case_id="sec_case_9", title="x")
    bundle = finding.build_handoff(case)
    body = build_security_issue_body(finding, case, bundle.handoff, base_url="https://soc.servify.network")
    assert f"<!-- soc-case-id:{case.case_id} -->" in body
    assert f"<!-- soc-lhp-handoff-id:{bundle.handoff.handoff_id} -->" in body
    assert f"<!-- {finding_marker(finding)} -->" in body
    # LHP pointer JSON is present and correct
    start = body.index("```json") + len("```json")
    end = body.index("```", start)
    pointer = json.loads(body[start:end].strip())
    assert pointer["schema_version"] == "lhp.v1"
    assert pointer["source_loop"] == "soc"
    assert pointer["fetch_path"] == f"/loop-handoff/v1/soc/handoffs/{bundle.handoff.handoff_id}"
    # The body references loop:approved only as human guidance; SOC never applies
    # it as a *label* (asserted in test_never_applies_loop_approved).
    assert "Promote to `loop:approved`" in body


class _FakeRequester:
    def __init__(self, existing: bool = False):
        self.existing = existing
        self.calls: list[tuple[str, str]] = []

    async def __call__(self, method, path, *, params=None, json=None):
        self.calls.append((method, path))
        if path == "/search/issues":
            items = []
            if self.existing:
                items = [{"number": 42, "html_url": "https://github.com/x/y/issues/42", "body": params["q"]}]
            return 200, {"items": items}
        if path.endswith("/issues"):
            return 201, {"html_url": "https://github.com/x/y/issues/99"}
        if path.endswith("/comments"):
            return 201, {}
        return 404, {}


async def test_creates_issue_when_none_exists():
    finding = _finding()
    case = SecurityCase(case_id="c1")
    bundle = finding.build_handoff(case)
    req = _FakeRequester(existing=False)
    gh = GitHubHandoff(repo="AS215932/network-operations", token="t", requester=req)
    url = await gh.ensure_candidate_issue(finding, case, bundle.handoff)
    assert url == "https://github.com/x/y/issues/99"
    assert any(p.endswith("/issues") and m == "POST" for m, p in req.calls)


async def test_refreshes_existing_issue_idempotently():
    finding = _finding()
    case = SecurityCase(case_id="c1")
    bundle = finding.build_handoff(case)
    req = _FakeRequester(existing=True)
    gh = GitHubHandoff(repo="AS215932/network-operations", token="t", requester=req)
    url = await gh.ensure_candidate_issue(finding, case, bundle.handoff)
    assert url == "https://github.com/x/y/issues/42"
    # refresh path: a comment, not a new issue
    assert any(p.endswith("/comments") for _, p in req.calls)
    assert not any(p.endswith("/issues") and m == "POST" for m, p in req.calls)


async def test_unauthenticated_handoff_is_noop():
    finding = _finding()
    case = SecurityCase(case_id="c1")
    bundle = finding.build_handoff(case)
    gh = GitHubHandoff(repo="AS215932/network-operations")  # no token/provider
    assert await gh.ensure_candidate_issue(finding, case, bundle.handoff) is None
