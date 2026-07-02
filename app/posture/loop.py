"""The proactive posture loop: scan → gate → case → (enrich) → mode-gated handoff.

One ``run_once`` cycle. Read-only and side-effect-bounded by ``SOC_MODE`` and the
governance gate: ``shadow`` writes nothing; ``case_only`` opens cases;
``handoff_dry`` builds the LHP handoff but never POSTs; ``handoff_live`` opens the
``loop:candidate`` issue. Positive observations accumulate toward resolution
(No-False-All-Clear); the verifier — not this loop — resolves cases.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app import log
from app.agent_core_trace import emit_loop_decision_envelopes
from app.cases.models import SecurityFinding
from app.cases.service import SecurityCaseService
from app.config import SocAgentSettings
from app.graph.nodes import SocGraphRuntime
from app.graph_runtime import SocGraphSession
from app.posture.desired_state import DesiredState
from app.posture.governance import evaluate_gate
from app.posture.ledger import DailyLedger
from app.posture.scanner import ScanContext, scan


@dataclass
class PostureCycleReport:
    cycle_id: str
    mode: str
    scanned_hosts: list[str] = field(default_factory=list)
    degraded: bool = False
    firing_count: int = 0
    positive_observations: int = 0
    cases_opened: int = 0
    cases_refreshed: int = 0
    handoffs_built: int = 0
    issues_opened: int = 0
    deferred: int = 0
    gated_out: list[dict[str, str]] = field(default_factory=list)
    shadow_findings: list[str] = field(default_factory=list)
    private_insights: list[dict[str, Any]] = field(default_factory=list)


class PostureLoop:
    def __init__(
        self,
        *,
        settings: SocAgentSettings,
        service: SecurityCaseService,
        mcp_runtime: Any,
        desired_state: DesiredState,
        ledger: DailyLedger | None = None,
        handoff: Any = None,
        graph_runtime: SocGraphRuntime | None = None,
        control_public_url: str = "",
    ) -> None:
        self.settings = settings
        self.service = service
        self.mcp_runtime = mcp_runtime
        self.desired_state = desired_state
        self.ledger = ledger or DailyLedger.load(settings.posture.state_dir)
        self.handoff = handoff
        self.graph_runtime = graph_runtime
        self.control_public_url = control_public_url

    def _hosts(self, override: list[str] | None) -> list[str]:
        hosts = override if override is not None else list(self.settings.posture.allowed_hosts)
        cap = self.settings.posture.max_hosts_per_cycle
        return hosts[: max(1, cap)] if cap else hosts

    async def run_once(self, *, hosts: list[str] | None = None, cycle_id: str = "cycle") -> PostureCycleReport:
        posture = self.settings.posture
        mode = self.settings.mode
        report = PostureCycleReport(cycle_id=cycle_id, mode=mode)
        scan_hosts = self._hosts(hosts)
        report.scanned_hosts = scan_hosts

        ctx = ScanContext(mcp_runtime=self.mcp_runtime, desired_state=self.desired_state, cycle_id=cycle_id)
        scan_report = await scan(ctx, hosts=scan_hosts, deep=True)
        report.degraded = scan_report.degraded
        report.firing_count = len(scan_report.firing)

        # shadow: report only, no store writes.
        if mode == "shadow":
            report.shadow_findings = [f"{f.check_id}:{f.key} ({'FIRING' if not f.passed else 'ok'})" for f in scan_report.findings]
            report.private_insights = [
                _private_insight_for_finding(
                    finding,
                    cycle_id=cycle_id,
                    action_selected="stay_silent",
                    sampling_class="withheld_logged" if not finding.passed else "sampled_quiet_interval",
                    why_now="shadow mode: report only; no SOC persistence or learned suppression",
                )
                for finding in scan_report.findings
            ]
            emit_loop_decision_envelopes(report.private_insights, input_event=_input_event(report))
            return report

        # Positive observations accumulate toward resolution.
        for finding in scan_report.passing:
            self.service.observe_finding(finding, cycle_id=cycle_id)
            report.positive_observations += 1

        acted = 0
        for finding in sorted(scan_report.firing, key=lambda f: -f.score):
            decision = evaluate_gate(finding, mode=mode, settings=posture, ledger=self.ledger)
            if not decision.act:
                report.gated_out.append({"check": finding.check_id, "key": finding.key, "reason": decision.reason})
                report.private_insights.append(
                    _private_insight_for_finding(
                        finding,
                        cycle_id=cycle_id,
                        action_selected="stay_silent",
                        sampling_class="withheld_logged",
                        why_now=decision.reason,
                    )
                )
                continue
            if acted >= posture.max_findings_per_cycle:
                report.deferred += 1
                report.private_insights.append(
                    _private_insight_for_finding(
                        finding,
                        cycle_id=cycle_id,
                        action_selected="stay_silent",
                        sampling_class="withheld_logged",
                        why_now="per-cycle finding cap reached",
                    )
                )
                continue

            enriched = await self._enrich(finding, cycle_id=cycle_id)
            result = self.service.observe_finding(enriched, cycle_id=cycle_id)
            case = result.case
            self.ledger.record_finding(cost=posture.cost_usd_per_investigation)
            acted += 1
            if result.created:
                report.cases_opened += 1
            else:
                report.cases_refreshed += 1
            report.private_insights.append(
                _private_insight_for_finding(
                    enriched,
                    cycle_id=cycle_id,
                    action_selected="draft" if decision.build_handoff else "notify",
                    sampling_class="surfaced",
                    why_now=decision.reason,
                    case_id=case.case_id,
                )
            )

            if decision.build_handoff:
                bundle = self.service.request_handoff(case.case_id, enriched)
                if bundle is not None:
                    report.handoffs_built += 1
                    if decision.post_handoff and self.handoff is not None:
                        url = await self.handoff.ensure_candidate_issue(
                            enriched, case, bundle.handoff, base_url=self.control_public_url
                        )
                        if url:
                            self.service.record_issue(case.case_id, issue_url=url)
                            report.issues_opened += 1
        emit_loop_decision_envelopes(report.private_insights, input_event=_input_event(report))
        return report

    async def _enrich(self, finding: SecurityFinding, *, cycle_id: str) -> SecurityFinding:
        """Run the SOC commander graph to enrich the finding (routing + specialist
        assessment + evidence validation). The graph pauses at the HITL gate; the
        loop reads the enriched finding but does not resume — the ``loop:candidate``
        issue + human promotion to ``loop:approved`` is the real approval gate."""
        if self.graph_runtime is None:
            return finding
        try:
            session = SocGraphSession(self.graph_runtime)
            state = await session.start(
                finding.model_dump(mode="json"),
                thread_id=f"{cycle_id}:{finding.fingerprint()}",
            )
            enriched = state.get("enriched_finding")
            if isinstance(enriched, dict):
                return SecurityFinding.model_validate(enriched)
        except Exception as exc:
            log.warning("soc_posture_enrich_failed", error=type(exc).__name__)
        return finding


def _private_insight_for_finding(
    finding: SecurityFinding,
    *,
    cycle_id: str,
    action_selected: str,
    sampling_class: str,
    why_now: str,
    case_id: str | None = None,
) -> dict[str, Any]:
    support_facts = [finding.summary or finding.title, finding.assertion]
    support_facts.extend(ev.detail or ev.observed_value for ev in finding.evidence[:6])
    fingerprint = finding.fingerprint()
    insight_key = f"{cycle_id}:{fingerprint}:{action_selected}:{why_now}"
    return {
        "schema_version": "0.1.0",
        "insight_id": f"ins_soc_{hashlib.sha256(insight_key.encode('utf-8')).hexdigest()[:16]}",
        "loop": "soc",
        "created_at": datetime.now(UTC).isoformat(),
        "fingerprint": fingerprint,
        "case_id": case_id,
        "sampling_class": sampling_class,
        "candidate_type": finding.case_type,
        "candidate_source": f"soc_posture:{finding.check_id}",
        "evidence_refs": _evidence_refs_for_finding(finding),
        "action_space": ["notify", "question", "draft", "stay_silent"],
        "action_selected": action_selected,
        "why_now": why_now,
        "support_facts": [fact for fact in support_facts if fact][:8],
        "expected_utility": {
            "total": min(1.0, max(0.0, finding.score / 40.0)),
            "components": {"finding_score": finding.score},
            "rationale": [finding.severity, finding.confidence],
        },
        "interruption_cost": {
            "total": 0.4 if action_selected == "stay_silent" else 0.25,
            "components": {"soc_adversarial_review": 0.4 if action_selected == "stay_silent" else 0.25},
            "rationale": ["SOC insight policy is not learned from untrusted telemetry in v1."],
        },
        "risk_class": _risk_class_for_severity(finding.severity),
        "policy_version": "soc-private-insight.v1",
        "budget_context": {"cycle_id": cycle_id},
        "governance": {
            "sensitivity_class": "private",
            "approval_tier": "operator",
            "risk_class": _risk_class_for_severity(finding.severity),
            "adversarial_review_required": True,
            "learning_allowed": False,
            "never_learn": True,
            "policy_ids": ["soc-private-insight.v1"],
            "rationale": "SOC insight policy is not learned from untrusted telemetry in v1.",
        },
    }


def _input_event(report: PostureCycleReport) -> dict[str, Any]:
    return {
        "cycle_id": report.cycle_id,
        "mode": report.mode,
        "scanned_hosts": report.scanned_hosts,
        "degraded": report.degraded,
        "firing_count": report.firing_count,
        "positive_observations": report.positive_observations,
        "cases_opened": report.cases_opened,
        "handoffs_built": report.handoffs_built,
        "issues_opened": report.issues_opened,
        "deferred": report.deferred,
    }


def _evidence_refs_for_finding(finding: SecurityFinding) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    for desired in finding.desired_state_refs[:6]:
        ref = f"{desired.repo}:{desired.path}"
        if desired.ref:
            ref = f"{ref}#{desired.ref}"
        refs.append({"kind": "desired_state", "ref": ref})
    for evidence in finding.evidence[:6]:
        ref = evidence.source_tool or evidence.query or evidence.label
        if ref:
            refs.append({"kind": "mcp", "ref": ref})
    return refs


def _risk_class_for_severity(severity: str) -> str:
    mapping = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    return mapping.get(str(severity or "").upper(), "medium")
