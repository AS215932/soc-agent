# SOC Agent architecture

The SOC Agent is a **security governance loop** for AS215932, built as a peer of
the NOC Agent and Engineering Loop. It reuses the same substrate patterns
(CaseService state machine, LHP-v1 cross-loop handoff, per-role read-only MCP
tool allowlists, best-effort agent-core tracing) but specialises them for a
security-audit domain with its own credentials, blast radius, and kill switches.

## Two modes

- **Passive (night-shift analyst).** Security signals → normalise → classify →
  enrich → correlate → `SecurityCase`. (v1 ships a thin intake; correlation is v2.)
- **Proactive (SOC lead / red-team manager).** On a schedule: diff desired
  security state against live telemetry, model attack paths, rank risk, and hand
  safe remediation to the Engineering Loop, then verify after the fix ships.

## Data flow

```
security signal ─┐                         ┌─ shadow: log only
                 ├─ intake/normalize ─┐    ├─ case_only: open SecurityCase
proactive scan ──┘  (SecurityObs)     ├─► graph (SOC commander → specialists →
                                      │    evidence-validation → finding → HITL)
                                      │       │
                                      │       ├─ handoff_dry: build LHP + render issue
                                      │       └─ handoff_live: open loop:candidate + serve
                                      │                         GET /loop-handoff/v1/soc/...
                                      └─ verifier: re-check after fix → resolved (SOC-owned)
```

## Key invariants

1. **No-False-All-Clear.** A control-drift case resolves only on repeated
   *positive* re-observation (N consecutive healthy passes), never on absence of
   signal or a degraded scan. The `SecurityVerifier` is the only writer of
   `verified`/`resolved`.
2. **Read-only by construction.** Every MCP tool allowlist excludes mutating
   tools; no graph node holds a mutation tool; the deploy never sets
   `HYRULE_MCP_ENABLE_ACTIONS`.
3. **Untrusted telemetry.** Alerts, logs, configs, and issue text are treated as
   untrusted and passed through the vendored `sanitize_lhp_*` helpers before they
   enter any model channel (prompt-injection defence).
4. **Human gates preserved.** SOC files `loop:candidate` only; `loop:approved`,
   merge, and production deploy stay human-gated.

## Reused substrate

- `app/lhp.py` — vendored verbatim from `hyrule-noc-agent/app/cases/lhp.py`
  (the cross-loop wire contract: HMAC signing, transition table, sanitizers).
  Guarded by `tests/test_lhp_contract_parity.py`. Fast-follow: hoist into
  `agent_core.lhp` so all loops share one copy.
- `agent_core.contracts` — `CaseSummary`, `HandoffSummary`,
  `VerificationObjectiveSummary`, `EvidencePacket`/`SourceRef` (projection
  targets; `LoopKind` already includes `"soc"`).
- `agent_core.tracing` — `TraceEvent` + `sink_from_env` via
  `app/agent_core_trace.py` (`HYRULE_SOC_AGENT_CORE_TRACE`, `GRAPH_ID="soc-agent"`).
