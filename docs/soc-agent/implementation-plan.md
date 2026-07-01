# SOC Agent — First Iteration Implementation Plan (AS215932)

## Context

AS215932 already runs a NOC/Engineering agentic stack: `hyrule-noc-agent` (reactive + proactive
network-ops loop), `engineering-loop` (drafts PRs, stops at human sign-off), `network-operations`
(human-gated promotion + `production` GitHub Environment deploy gate), and `agent-core` (shared
pydantic contracts + TraceSink + collector). What's missing is the **security-side equivalent**: a
loop that asks "is the network defensible, observable, and resilient against a competent adversary?"
rather than "is it healthy?".

This plan builds the **SOC Agent** as a security governance loop that continuously (a) triages
security signals into SecurityCases and (b) proactively diffs desired security state against live
telemetry to find control drift / attack paths, then hands safe, reviewable remediation to the
Engineering Loop via LHP-v1 — **never becoming an ungated production attacker**. Its core policy:
*may autonomously discover, reason, model attack paths, and run read-only / explicitly-safe
validations; may NOT autonomously exploit prod, mutate prod, rotate secrets, block traffic, contact
customers, or deploy without human approval.*

The substrate was designed for this: `LoopName` in `hyrule-noc-agent/app/cases/lhp.py:30` and
`LoopKind` in `agent-core/agent_core/contracts/observatory.py:20` already include `"soc"`.

**Concrete first win, already verified in live config:** `network-operations/configs/cr1-nl1/frr.conf`
has `no bgp ebgp-requires-policy` (line 45), `no bgp network import-check` (line 47), and a
`TRANSIT-IN` route-map (lines 119-121) that only filters bogon ASNs — **no `rpki` clause, no
`maximum-prefix`** — despite `docs/network-flows.md`/`CLAUDE.md` claiming RPKI validation. This is
the SOC Agent's canonical lead finding.

## Decisions locked (this iteration)

1. **Location:** a **separate `hyrule-soc-agent` repo** (its own systemd unit, Vault policy, MCP
   principal, loop secret). Imports `agent-core` contracts; reuses `hyrule-noc-agent` *patterns* by
   copying. The LHP wire module is **vendored verbatim** with a parity test (see Risk 1).
2. **Finish line:** build+test the full path **through `handoff_live`** (real `loop:candidate` issue
   creation, live `GET /loop-handoff/v1/soc/...` fetch + signed callback). Operational enablement
   still climbs the `SOC_MODE` ladder gated by a live shadow canary — code built ≠ flag flipped.
3. **Reasoning engine:** build the **LangGraph LLM specialist graph now** (SOC commander router +
   PydanticAI security specialists), layered on top of deterministic posture scanners that seed
   observations. Findings are LLM-enriched/triaged/correlated; the deterministic checks remain the
   ground truth so the system is still replayable.
4. **Red-team:** **RT-0 (passive attack-path modeling) + RT-1 (non-invasive read-only validation)**
   on known-owned assets. `redteam/policy.py` hard-refuses tier ≥ 2 (no executor exists in v1).

## Architecture at a glance

```
security signal ─┐                          ┌─ shadow: log only
                 ├─ intake/normalize ─┐     ├─ case_only: open SecurityCase
proactive scan ──┘   (SecurityObs)    ├─►  graph (LLM commander→specialists→
                                      │     evidence-validation→finding→HITL approval)
                                      │        │
                                      │        ├─ handoff_dry: build LHP handoff + render issue body
                                      │        └─ handoff_live: open loop:candidate issue + serve
                                      │                          GET /loop-handoff/v1/soc/... 
                                      │                          → human promotes to loop:approved
                                      │                          → engineering-loop drafts PR
                                      │                          → human merge + production gate
                                      └─ verifier: re-check after fix → resolved (SOC-owned only)
```

## Repo scaffold (mirrors `hyrule-noc-agent` naming/conventions)

```
hyrule-soc-agent/
  pyproject.toml            # name="soc-agent"; requires-python ">=3.14"; scripts: soc-agent, socctl
  README.md  TESTING.md
  config/soc-agent.toml     # [model] [providers.*] [posture] [redteam] [loop_handoff] — all off/shadow
  app/
    __init__.py             # structlog: log = get_logger().bind(service="soc-agent")
    main.py                 # FastAPI: intake + LHP fetch/callback + control + /health
    config.py               # frozen dataclasses + SOC_* env overrides (mirror noc app/config.py)
    lhp.py                  # VENDORED copy of noc app/cases/lhp.py; parity-tested; source_loop="soc"
    cases/
      models.py             # SecurityCase, SecurityFinding, SecurityObservation, SecurityCaseEvent + enums
      store.py              # SecurityCaseStore Protocol + InMemory + JSONL (+ Postgres later)
      service.py            # SecurityCaseService: open/refresh/triage/attach-evidence/request-handoff
      policy.py             # SecurityCasePolicy: transitions; verifier-owns-resolved; No-False-All-Clear
      verifier.py           # SecurityVerifier: ONLY writer of verified/resolved
      summaries.py          # SecurityCase→CaseSummary; Finding→Handoff/VerificationObjective/EvidencePacket
    posture/
      models.py  desired_state.py  scanner.py  governance.py  ledger.py  loop.py  handoff.py  suppressions.py
    graph/                  # ACTIVE LLM runtime (see "LLM specialist graph")
      state.py  routing.py  nodes.py  graph.py
    agents/                 # PydanticAI specialist builders + system prompts
      commander.py  routing_security.py  exposure.py  crypto.py  detection.py  threat_intel.py
    redteam/
      models.py  attack_paths.py  validators.py  policy.py    # RT-0 modeling + RT-1 read-only checks
    mcp_runtime.py          # SocMCPRuntime + SOC read-only allowlists (no mutating tools)
    tools/mcp_client.py     # vendored HyruleMCPClient
    agent_core_trace.py     # FLAG_ENV="HYRULE_SOC_AGENT_CORE_TRACE"; GRAPH_ID="soc-agent"
    discord.py  socctl.py
  docs/soc-agent/
    architecture.md  security-scope.md  posture-checks.md  redteam-safety-policy.md
    case-schema.md  rollout.md
  tests/                    # flat, 1:1 file-per-module; conftest sets SOC_AGENT_DISABLE_MCP=1
    fixtures/mcp/  fixtures/desired_state/
```

**Dependencies** (`pyproject.toml`): `fastapi`, `uvicorn[standard]`, `pydantic>=2.10`, `httpx`,
`mcp>=1.27`, `structlog`, `python-dotenv`, `pyjwt[crypto]`, `pydantic-ai>=1.0`, `langgraph>=1.0`,
`langgraph-checkpoint-redis`, and `agent-core` via `[tool.uv.sources] agent-core = { git = ..., tag = "v0.5.0" }`.
Ruff `line-length=120`, `target-version="py314"`. Postgres/asyncpg is an optional extra (deferred).

## Phased implementation

Each phase is independently testable and lands CI-green before the next. Build in `shadow`
throughout; operational enablement of later modes is a separate, human-gated step.

**Phase 0 — Scaffold & contracts.** `git init`; `pyproject.toml`; `app/__init__.py` (structlog);
`config.py` with the full `SOC_*` flag set (all off/shadow); vendor `lhp.py` +
`tests/test_lhp_contract_parity.py` asserting `LHP_SCHEMA_VERSION`, `_ALLOWED_HANDOFF_TRANSITIONS`,
and `build_loop_signature(...)` bytes match noc's copy; `agent_core_trace.py`; docs skeleton.

**Phase 1 — SecurityCase substrate.** `cases/models.py` (schemas below), `store.py` (in-memory +
JSONL), `service.py`, `policy.py`, `verifier.py`, `summaries.py` (agent-core mappings). Tests:
model round-trips + `extra="forbid"`, fingerprint stability, verifier is sole `resolved` writer,
No-False-All-Clear (degraded scan never resolves; N consecutive healthy passes required).

**Phase 2 — Read-only MCP + deterministic posture scanner.** `mcp_runtime.py` (SOC read-only
allowlists — no mutating tools in any set), `posture/desired_state.py` (loaders for `frr.conf`,
`pf.bogons*`, `wg*.conf`, `host_vars`, golden manifest — content/SHA-stamped), `posture/scanner.py`
with checks 1–5 (below), `governance.py`, `ledger.py`. Tests use a `FakeMCPRuntime` + captured
fixtures: the RPKI check **FIRES** on the real `cr1-nl1/frr.conf` fixture and **PASSES** on a
synthetic RPKI-configured one (fires/passes pair per check).

**Phase 3 — LLM specialist graph.** `graph/` + `agents/`: SOC commander router → specialists →
evidence-validation → finding-build → HITL `approval_interrupt` → handoff. Deterministic findings
from Phase 2 seed the graph; specialists enrich/triage/correlate and attach ATT&CK context. Tests
with a stub model (no live LLM in CI), mirroring `hyrule-noc-agent/tests/test_graph_runtime.py`.

**Phase 4 — Proactive loop + LHP handoff (through handoff_live).** `posture/loop.py`
(`PostureLoop.run_once`: scan → gate → open/refresh case → graph → mode-gated handoff),
`posture/handoff.py` (render + open `loop:candidate` issue with LHP pointer JSON + `soc-case-id` /
`soc-lhp-handoff-id` markers, idempotent by fingerprint, **never applies `loop:approved`**),
`main.py` LHP endpoints: `GET /loop-handoff/v1/soc/handoffs/{id}` (serves `lhp.v1` payload) +
signed `POST /webhook/engineering-loop/handoff-update`. Tests across all four `SOC_MODE`s with a
fake requester recording (not sending) the POST.

**Phase 5 — Red-team RT-0/RT-1.** `redteam/attack_paths.py` (RT-0: reason over desired-state +
telemetry → `AttackPathHypothesis`, zero packets), `redteam/validators.py` (RT-1: non-invasive
version/config/header checks on known-owned assets via read-only MCP tools + `httpx` GET),
`redteam/policy.py` (tier gate: RT-0/RT-1 allowed read-only; **tier ≥ 2 hard-refused**). RT-1 scope
is an explicit allowlist in `docs/soc-agent/redteam-safety-policy.md`. Tests assert zero side
effects and that a tier-2 request is refused.

**Phase 6 — Verifier close-loop + shadow canary.** Wire `SecurityVerifier` re-check off an LHP
`change_applied` callback (not just a timer) so a fix's SOC case only resolves on positive re-read
of live FRR post-deploy. Then run `socctl posture run-once` with `SOC_ENABLED=1 SOC_MODE=shadow`
against real MCP (read-only) — the go/no-go before flipping `case_only` → `handoff_dry` →
`handoff_live` in production.

## SecurityCase / SecurityFinding schemas

All models: `pydantic.BaseModel`, `model_config = ConfigDict(extra="forbid")`, `schema_version: int = 1`,
JSON-safe. Untrusted telemetry text runs through a `sanitize_label`-style validator (copy from
`hyrule-noc-agent/app/proactive/models.py`).

**Vocab (`Literal`s):** `Severity = HIGH|MEDIUM|LOW|UNKNOWN`;
`SocConfidence = confirmed|high|medium|low|tentative`;
`SocCaseType = security_incident|security_finding|detection_gap|redteam_exercise|abuse_case|control_drift`;
`ControlDomain = edge_firewall|vault_hygiene|wireguard_crypto|rpki_irr|customer_isolation|detection|other`;
`FindingCategory = bgp_rpki|firewall|listening_ports|wireguard|vault|dns|tls|isolation|detection|other`;
`SecurityOrigin = passive|proactive|redteam|unknown`;
`ObservationStatus = firing|clean|resolved|unknown`; `SourceHealth = healthy|degraded|unknown|failed`;
`SecurityCaseStatus` = subset of `lhp.v1` CaseStatus (`open, triaged, handoff_requested,
handoff_in_progress, verification_pending, blocked, failed, needs_human, investigating,
waiting_approval, resolved, closed`).

- **`DesiredStateRef`** — `repo, path, ref (line/section anchor), content_sha, assertion_text`.
- **`SecurityEvidence`** — `label, source_tool (MCP name), query, observed_value, expected_value, detail`
  (observed/label/detail scrubbed; query/source_tool loop-authored).
- **`SecurityFinding`** (LHP-ready from day one) — `finding_id, check_id, key, category, case_type,
  control_domain, title, summary, severity, confidence, mitre_tactics[], mitre_techniques[],
  resource, site, desired_state_refs[], observed_state (bounded), evidence[], assertion, passed,
  recommended_remediation[], warrants_handoff, objective_key, acceptance_criteria[], constraints[]
  (e.g. do_not_mutate_prod, human_approval_before_frr_change), source_refs[] (agent-core SourceRef),
  detected_at, score, manifest_sha`. Methods: `fingerprint()` = `sha256(f"{check_id}|{key}")[:16]`;
  `build_handoff(case) -> (CaseHandoff, list[VerificationObjective], knowledge_payload)` — generalize
  `hyrule-noc-agent/app/proactive/lhp.py:build_disk_handoff_request`: `source_loop="soc"`,
  `target_loop="engineering"`, `verifier="soc"`,
  `idempotency_key=f"{case_id}:engineering:{objective_key}:v1"`, evidence via vendored
  `sanitize_lhp_payload`.
- **`SecurityObservation`** (No-False-All-Clear) — `observation_id, source, detector, entity,
  resource, site, severity, status, observed_at, received_at, scan_cycle_id, signal_snapshot,
  signal_signature, source_health, confidence`; property `is_positive_clean = status in
  {clean,resolved} and source_health not in {degraded,failed}`.
- **`SecurityCase`** — identity/lifecycle fields + change-detection (`signal_signature,
  previous_signal_signature, last_observed_failing, last_observed_passing, consecutive_pass_count`),
  external links (`issue_url, handoff_status`), ops (`acknowledged_*, snoozed_until,
  suppressed_until`), `trace_ids`, `policy_version`.
- **`SecurityCaseEvent`** — append-only audit (`event_id, case_id, event_type, actor_type, actor_id,
  occurred_at, correlation_id, payload`).

**LHP fetch payload** (`summaries.py`, served by `GET /loop-handoff/v1/soc/handoffs/{id}`, exact noc
shape from `hyrule-noc-agent/app/main.py`):
`{schema_version:"lhp.v1", handoff: CaseHandoff (source_loop="soc", target_loop="engineering"),
case: security_case_summary→agent_core CaseSummary, verification_objectives:[≤20], knowledge_artifacts:[]}`
with `assert_lhp_payload_size` + `lhp_payload_hash`.

## Posture checks (deterministic ground truth; Phase 2)

`ScanContext` mirrors `hyrule-noc-agent/app/proactive/scanner.py` — `mcp_runtime`, `settings`, a
`degraded` flag set on any failed MCP call, helper coros (`frr/sockets/wg/dig`). Each
`PostureCheck` is wrapped so one failure ⇒ "no findings from this check," never a crashed cycle.
Checks emit `passed=True` positive observations too, so the verifier can resolve only on repeated
healthy passes.

1. **LEAD — `check_rpki_in_frr`** (HIGH, `confirmed`). Desired: `configs/{cr1-nl1,cr1-de1,cr1-ch1}/frr.conf`
   + auditor rule "reject BGP configs missing RPKI validation / inbound prefix filtering." MCP:
   `frr_vtysh_cmd` (`show bgp ipv6 unicast summary`, `show rpki cache-connection`, `show route-map
   TRANSIT-IN`). Fails when a transit eBGP neighbor has no RPKI validation state **and** `TRANSIT-IN`
   doesn't reject `rpki invalid` **and** no `maximum-prefix` **and** `no bgp ebgp-requires-policy` is
   in effect. `objective_key="frr-transit-rpki-invalid-reject-v1"`; `mitre_techniques=["T1557","T1565.003"]`;
   `warrants_handoff=True`; `constraints=[do_not_mutate_prod, human_approval_before_frr_change,
   routing_change_needs_maintenance_window]`. **The finding must state both candidate targets** (deploy
   validator + reject invalids, vs minimum hardening: `maximum-prefix` + stricter inbound filter +
   justify/remove `no bgp ebgp-requires-policy`) and note whether a validator/RTR is even deployed —
   see Open Question 1.
2. **`check_listening_ports`** (HIGH public / MEDIUM mgmt). Desired: `host_vars/*.yml` declared
   services + firewall templates + a curated per-host allowlist. MCP: `socket_listeners`. Fails on
   any non-loopback listener absent from the allowlist. Keep in shadow until the allowlist is seeded
   (Open Question 4). `mitre_techniques=["T1046","T1571"]`.
3. **`check_wireguard_hygiene`** (HIGH plaintext-key `confirmed` / MEDIUM drift). Desired:
   `configs/*/wg*.conf` (keys must be `<PRIVATE_KEY>` Vault placeholders). MCP: `wg_show`. Fails on
   a committed non-placeholder key, peer-set drift, or stale handshake. `mitre_techniques=["T1552.001"]`.
4. **`check_dns_ownership`** (MEDIUM). Desired: `network-operations/AGENTS.md` invariant "as215932.net
   points only at owned prefixes" + golden manifest `prefixes: ["2a0c:b641:b50::/44"]`. MCP:
   `knot_zone_status` + `dns_dig`. Fails on any address record outside owned space. `["T1583.001"]`.
5. **`check_vault_hygiene`** (stretch; DEEP). Desired: golden manifest + auditor "no plaintext
   secrets outside Vault." MCP: `vault_agent_status` + git-side scan reusing vendored
   `_SECRET_TEXT_PATTERNS`. Overlaps CI secret-scanning — off until de-duped (Open Question 5).

`scanner.py` splits `CHEAP_CHECKS` (1–4) from `DEEP_CHECKS` (5) with a `DEEP_CHECK_IDS`
carry-forward set (mirror `proactive/scanner.py`).

## LLM specialist graph (Phase 3)

Mirror `hyrule-noc-agent/app/graph/{graph,routing,nodes,state}.py`. `WorkflowState` is a JSON-safe
TypedDict. Nodes:
`correlate_and_dedupe → recall_history → soc_commander_route →` (conditional) one of
`{routing_security_specialist | exposure_specialist | crypto_specialist | detection_specialist}`
`→ threat_intel_enrich → evidence_validation → finding_build → prepare_approval →
approval_interrupt →` (conditional) `{request_handoff | END}`. Specialists are PydanticAI agents
(`agents/*.py`, adapting the existing `engineering-loop/docs/agent-loops/senior-security-cryptographic-auditor.md`
role prompt) bound to **per-specialist SOC read-only MCP toolsets** via `mcp_runtime.toolsets_for(specialist)`.
`soc_commander_route` in `routing.py` classifies by finding category/`specialist_hint` (the reusable
"commander" seam). HITL is a LangGraph `interrupt()` in `approval_interrupt`; there is **no**
`execute_approved_remediation` node — SOC never mutates prod, so the graph terminates at handoff.
`evidence_validation` down-weights confidence when there's no direct measurement. Redis checkpointer
(`langgraph-checkpoint-redis`) for resume, like noc.

## Red-team RT-0 + RT-1 (Phase 5)

- **RT-0 (`attack_paths.py`)** — reason over desired-state + telemetry to produce
  `AttackPathHypothesis` records (precondition → impact → ATT&CK mapping → would-we-detect-it). Zero
  packets. Feeds `detection_gap` cases when a plausible path has no detection.
- **RT-1 (`validators.py`)** — non-invasive validation on **known-owned assets only** (explicit
  allowlist): version/config/header checks via read-only MCP tools + `httpx` GET (no auth attempts,
  no fuzzing, rate-limited by `SOC_POSTURE_MAX_PROBES_PER_HOST_PER_CYCLE`).
- **`policy.py`** — `RedTeamTier RT0..RT5`; `SOC_REDTEAM_MAX_TIER` default 1; tier ≥ 2 (any active
  exploit/probe, Caldera/Atomic, credential access, lateral movement) **hard-refused — no executor
  exists**. `SOC_HEAVY_TOOLS` (`tcpdump_capture, dns_probe_burst, multi_source_probe`) stripped
  unless `SOC_REDTEAM_ALLOW_ACTIVE_PROBES=1` (default off). Rules-of-engagement + owned-asset
  allowlist documented in `docs/soc-agent/redteam-safety-policy.md`.

## Config / flags (`SOC_*`, all conservative/off)

Frozen dataclasses in `config.py`; precedence env > TOML table > default; secrets are env-var
**names** only. Selected flags:

- **Master/rollout:** `SOC_ENABLED=False`; `SOC_MODE="shadow"` (`shadow|case_only|handoff_dry|handoff_live`,
  authoritative over legacy `*_SHADOW`); `SOC_AGENT_DISABLE_MCP` (tests set `1`).
- **Posture:** `SOC_POSTURE_ENABLED=False`, `SOC_POSTURE_INTERVAL_S=900`, `SOC_POSTURE_DEEP_SCAN_S=3600`,
  `SOC_POSTURE_MAX_FINDINGS_PER_CYCLE=1`, `..._PER_DAY=8`, `SOC_POSTURE_MAX_COST_USD_PER_DAY=5.0`,
  `SOC_POSTURE_SEVERITY_FLOOR="HIGH"`, `SOC_POSTURE_MAX_PROBES_PER_HOST_PER_CYCLE=4`,
  `SOC_POSTURE_REQUIRED_CONSECUTIVE_PASSES=3`, `SOC_POSTURE_FINDING_COOLDOWN_S=21600`,
  `SOC_POSTURE_HANDOFF_ENABLED=False`, `SOC_POSTURE_HANDOFF_REPO="AS215932/network-operations"`,
  `SOC_NETWORK_OPERATIONS_DIR`, `SOC_NETWORK_OPERATIONS_PIN_SHA`, `SOC_GOLDEN_MANIFEST_PATH`,
  `SOC_POSTURE_STATE_DIR="/var/lib/soc-agent/posture"`.
- **Red-team:** `SOC_REDTEAM_ENABLED=False`, `SOC_REDTEAM_MAX_TIER=1`, `SOC_REDTEAM_HUMAN_GATE_TIER=2`,
  `SOC_REDTEAM_ALLOW_ACTIVE_PROBES=False`.
- **Human gates / policy:** `SOC_ENABLE_APPROVED_EXECUTION=False`, `SOC_HUMAN_GATE_ALL_MUTATIONS=True`.
- **LHP:** `SOC_LHP_ENABLED=False`, `SOC_LHP_ENGINEERING_SECRET` (env-var name, distinct from
  `NOC_LHP_ENGINEERING_SECRET`), `SOC_LHP_LOOP_IDENTITY="soc"`,
  `SOC_ENGINEERING_HANDOFF_DELIVERY_ENABLED=False`, `SOC_ENGINEERING_HANDOFF_TRANSPORT="github_issue"`,
  `SOC_CASE_VERIFICATION_ENABLED=False`, `SOC_CASE_VERIFICATION_DRY_RUN=True`,
  `SOC_CASE_AUTO_RESOLVE_ENABLED=False`, `SOC_CASE_VERIFICATION_REQUIRED_CONSECUTIVE_PASSES=3`.
- **Identity/tracing (the isolation point):** `HYRULE_MCP_URL`/`HYRULE_MCP_CMD` (SOC's **own** MCP
  principal + read-only Vault policy; SOC deploy must **never** set `HYRULE_MCP_ENABLE_ACTIONS`);
  `SOC_GITHUB_APP_ID`/`SOC_GITHUB_APP_PRIVATE_KEY_PATH`/`SOC_GITHUB_TOKEN` (issues-scoped);
  `HYRULE_SOC_AGENT_CORE_TRACE` (+ `_COLLECTOR_URL/_TOKEN/_PATH`) via `sink_from_env`.

**`mcp_runtime.py` allowlists** (read-only only; mutating tools `os_systemd_restart`,
`os_service_restart`, `icinga_acknowledge_alert` **absent from every SOC set** — enforced by test):
`SOC_TRIAGE_TOOLS`, `SOC_ROUTING_TOOLS` (`frr_vtysh_cmd, path_explain, prometheus_query,
socket_listeners`), `SOC_FIREWALL_TOOLS` (`firewall_state, pf_log_tail, nft_log_tail,
socket_listeners, ndp_state, arp_state`), `SOC_CRYPTO_TOOLS` (`wg_show, vault_agent_status,
socket_listeners, os_service_status`), `SOC_POSTURE_TOOLS` (union used by the scanner),
`SOC_HEAVY_TOOLS` (stripped unless `SOC_REDTEAM_ALLOW_ACTIVE_PROBES=1`).

## Guardrails (the SOC Agent is itself a high-value target)

- Per-graph-node read-only tool allowlists (above); no node has a mutating tool.
- Every issue/log/email/CTI string treated as untrusted → vendored `sanitize_lhp_payload` /
  `safe_text` before it enters a model channel (prompt-injection defense).
- No raw secrets/log dumps stored — references + sanitized summaries only.
- Per-day budget + per-host probe caps; kill switches (`SOC_ENABLED=0`, `SOC_REDTEAM_ENABLED=0`,
  `SOC_REDTEAM_ALLOW_ACTIVE_PROBES=0`).
- Append-only `SecurityCaseEvent` audit for every decision, skipped gate, tool call, handoff.
- SOC credentials are read-only and never deploy credentials; `loop:approved` stays a human gate;
  merges + `production` GitHub Environment approval remain human-gated in `network-operations`.

## Verification

Offline-first, mirroring `hyrule-noc-agent` conventions (pytest + pytest-asyncio, flat `tests/`,
`conftest.py` sets `SOC_AGENT_DISABLE_MCP=1`, `FakeMCPRuntime` + captured fixtures):

- **Contract:** `test_lhp_contract_parity.py` (vendored `lhp.py` == noc's for schema version,
  transition table, signature bytes).
- **Cases:** model round-trips + `extra="forbid"`; verifier is sole `resolved` writer;
  No-False-All-Clear (degraded scan doesn't resolve; N healthy passes required);
  `SecurityCase→CaseSummary` / `Finding→Handoff/VerificationObjective` / `EvidencePacket` validate
  against agent-core.
- **Scanner:** RPKI check FIRES on real `cr1-nl1/frr.conf` fixture, PASSES on synthetic
  RPKI-configured fixture; fires/passes pair per check; governance (shadow ⇒ 0 acts, severity floor,
  budget exhaustion, per-host probe cap).
- **Graph:** stub-model run of commander→specialist→finding→approval_interrupt; no live LLM in CI.
- **Loop/handoff:** all four `SOC_MODE`s (shadow report-only, case_only, handoff_dry no-POST,
  handoff_live records POST via fake requester); issue body carries markers + LHP pointer, **never**
  applies `loop:approved`, idempotent by fingerprint; `GET /loop-handoff/v1/soc/handoffs/{id}`
  schema-asserts the `lhp.v1` payload.
- **Red-team:** RT-0 produces hypotheses with zero side effects; RT-1 stays within owned-asset
  allowlist; tier-2 request refused.
- **Tracing:** flag off ⇒ 0 events; on ⇒ `TraceEvent` carries `case_id`/`handoff_id`.
- **Fixture capture:** one-time `socctl` capture of real `frr_vtysh_cmd`/`socket_listeners`/`wg_show`/
  `dns_dig` into `tests/fixtures/mcp/` + desired-state snippets into `tests/fixtures/desired_state/`.
- **Live shadow canary (go/no-go):** `socctl posture run-once` with `SOC_ENABLED=1 SOC_MODE=shadow`
  against real `hyrule` MCP (read-only) — confirms live telemetry parses and the RPKI finding fires
  against real routers with zero side effects, before enabling `case_only`.

## Open questions / risks to resolve during build

1. **RPKI check target (blocks lead finding's acceptance_criteria).** Docs claim RPKI validation;
   `frr.conf` implements none; no validator/RTR is in the golden manifest (`configs/rtr/` is the ovh1
   router, not a Routinator). Decide the desired target: "deploy validator + reject RPKI-invalid" (a
   real infra project) vs "minimum hardening: `maximum-prefix` + stricter inbound filter +
   justify/remove `no bgp ebgp-requires-policy`". Also: does transit AS34872 (Servperso) already
   RPKI-filter upstream, lowering severity? The finding will surface both; a human picks.
2. **MCP identity separation (the crux of the separate-repo decision).** Confirm `hyrule-mcp` can
   issue a distinct SOC principal/token with a read-only Vault policy, and that the SOC deploy
   provably never sets `HYRULE_MCP_ENABLE_ACTIONS`. Operator/infra dependency.
3. **LHP module drift.** Fast-follow: hoist `lhp.py` into `agent_core.lhp` so both loops import it
   and the parity test retires. Confirm.
4. **Listening-ports allowlist bootstrap.** Check 2 flags many ports until curated; seed from a
   one-time human-reviewed capture and keep it in shadow until then.
5. **Cross-loop dedup + overlap.** NOC and SOC could both file on the same host (fingerprint markers
   are per-loop); CI secret-scanning + Icinga bogon-egress already cover parts of checks 2/5. Confirm
   SOC checks are additive (config-vs-live drift) and add cross-loop issue dedup before `handoff_live`.
6. **SOC vs NOC ownership boundary.** Suggested rule: SOC owns posture/control/attack-path; NOC owns
   availability/reliability; dual-nature (e.g. TLS expiry) stays with NOC.
7. **Case-store durability before `handoff_live`.** v1 uses in-memory/JSONL; verification/resolution
   must survive restarts before live handoff. Decide JSONL vs SOC Postgres schema vs shared extract.
8. **Desired-state freshness.** SOC reads a local `network-operations` checkout; pin
   `SOC_NETWORK_OPERATIONS_PIN_SHA` into every finding's `content_sha`/`manifest_sha` and define who
   owns the refresh, to avoid false drift from a stale checkout.
