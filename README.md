# hyrule-soc-agent

AS215932's **SOC Agent** — the security-side sibling of the [NOC Agent](../hyrule-noc-agent)
and [Engineering Loop](../engineering-loop). It is a continuously-running
*security governance loop* that asks **"is the network defensible, observable,
and resilient against a competent adversary?"** — not "is it healthy?".

The SOC Agent:

- **Triages** security signals into typed `SecurityCase`s (night-shift analyst).
- **Proactively** diffs desired security state (the `network-operations` repo +
  golden manifest) against live telemetry (Hyrule MCP, read-only) to surface
  control drift and attack paths (`SecurityFinding`s).
- **Models** attack paths (RT-0) and runs non-invasive read-only validations
  (RT-1) against known-owned assets.
- **Hands off** safe, reviewable work to SOC, NOC, Engineering, or Knowledge
  through the shared **agent-core LHP-v2 coordinator** — and verifies outcomes
  before closure. LHP-v1/GitHub issues remain migration-only compatibility.

## Core policy (non-negotiable)

> The SOC Agent may autonomously discover, reason, model attack paths, and run
> read-only / explicitly-safe validations. It may **not** autonomously exploit
> production, mutate production, rotate secrets, block traffic, contact
> customers, or deploy changes without human approval.

It never enables `HYRULE_MCP_ENABLE_ACTIONS`, never mints a signed MCP
`action_authorization`, and never applies `loop:approved` (that stays a human /
Reliability-Governor gate). Merges and production deploys remain human-gated by
`network-operations` branch protection and the `production` GitHub Environment.

## Rollout ladder (`SOC_MODE`)

`shadow` → `case_only` → `handoff_dry` → `handoff_live` → `probe_dry` →
`probe_live`. Each rung is a strict
superset of the previous one's side effects. Enablement is a deliberate,
human-gated climb, gated by a live read-only shadow canary.

| Mode | Scans | Opens `SecurityCase` | Builds LHP handoff | External action |
|------|:-:|:-:|:-:|:-:|
| `shadow` | ✅ (report only) | — | — | — |
| `case_only` | ✅ | ✅ | — | — |
| `handoff_dry` | ✅ | ✅ | ✅ (no POST) | — |
| `handoff_live` | ✅ | ✅ | ✅ | Coordinator submission |
| `probe_dry` | ✅ | ✅ | ✅ | Senior-approved RT-2 plans validate without packets |
| `probe_live` | ✅ | ✅ | ✅ | Individually approved, bounded RT-2 probes may execute |

## Layout

```
app/
  config.py            SOC_* settings (env > TOML > default; all off/shadow)
  coordination.py      shared agent-core LHP-v2 case/handoff/Knowledge adapter
  lhp.py               LHP-v1 compatibility contract for staged migration
  cases/               SecurityCase substrate (models, store, service, policy, verifier)
  posture/             proactive read-only scanner + LHP handoff + verifier close-loop
  graph/ + agents/     LangGraph SOC-commander + PydanticAI security specialists
  redteam/             RT-0/RT-1 plus senior-approved, bounded RT-2 worker
  mcp_runtime.py       SOC read-only MCP tool allowlists (no mutating tools)
  main.py              FastAPI: LHP-v1 origin endpoints (fetch + signed callback) + /health
  socctl.py            local CLI: status, posture run-once, posture verify
  agent_core_trace.py  best-effort agent-core TraceEvent emission
docs/soc-agent/        architecture, security-scope, posture-checks, redteam-safety, rollout
```

## Running

```sh
socctl status                              # print effective SOC settings
socctl posture run-once --shadow           # one read-only scan cycle (the shadow canary)
socctl posture verify                      # re-read live telemetry for cases awaiting verification
socctl handoffs run-once                   # process inbound SOC capability requests
socctl probes run-once                     # process approved RT-2 work (dry/live by SOC_MODE)
soc-agent                                  # serve the FastAPI LHP endpoints (SOC_AGENT_HOST/PORT)
```

Deployed processes use `HYRULE_COORDINATOR_URL`, `HYRULE_COORDINATOR_KEY_ID`,
and `HYRULE_COORDINATOR_SECRET`. `SOC_DATABASE_URL` selects the shared Postgres
case store; without it, JSONL remains a development/rollback backend.

See `docs/soc-agent/` for architecture and the red-team safety policy, and
`TESTING.md` for how to run the suite.
