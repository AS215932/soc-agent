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
- **Hands off** safe, reviewable remediation to the Engineering Loop via
  **LHP-v1** as `loop:candidate` GitHub issues — and **verifies** the fix after
  it ships.

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

`shadow` → `case_only` → `handoff_dry` → `handoff_live`. Each rung is a strict
superset of the previous one's side effects. Enablement is a deliberate,
human-gated climb, gated by a live read-only shadow canary.

| Mode | Scans | Opens `SecurityCase` | Builds LHP handoff | Opens `loop:candidate` issue |
|------|:-:|:-:|:-:|:-:|
| `shadow` | ✅ (report only) | — | — | — |
| `case_only` | ✅ | ✅ | — | — |
| `handoff_dry` | ✅ | ✅ | ✅ (no POST) | — |
| `handoff_live` | ✅ | ✅ | ✅ | ✅ |

## Layout

```
app/
  config.py            SOC_* settings (env > TOML > default; all off/shadow)
  lhp.py               VENDORED verbatim from noc app/cases/lhp.py (wire contract)
  cases/               SecurityCase substrate (models, store, service, policy, verifier)
  posture/             proactive read-only scanner + LHP handoff + verifier close-loop
  graph/ + agents/     LangGraph SOC-commander + PydanticAI security specialists
  redteam/             RT-0 attack-path modeling + RT-1 read-only validation
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
soc-agent                                  # serve the FastAPI LHP endpoints (SOC_AGENT_HOST/PORT)
```

The Engineering Loop fetches a handoff from `GET /loop-handoff/v1/soc/handoffs/{id}`
and reports progress to `POST /webhook/engineering-loop/handoff-update` — both
HMAC-signed with `SOC_LHP_ENGINEERING_SECRET`.

See `docs/soc-agent/` for architecture and the red-team safety policy, and
`TESTING.md` for how to run the suite.
