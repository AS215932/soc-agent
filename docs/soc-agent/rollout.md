# SOC Agent rollout

Enablement climbs the `SOC_MODE` ladder deliberately, one rung at a time, each
gated by a human and (for the first rung) a live read-only shadow canary.

| Mode | Side effects | Gate to advance |
|------|--------------|-----------------|
| `shadow` | Scans, logs findings, emits traces. No cases, no external writes. | Shadow canary: `socctl posture run-once --shadow` against live MCP shows the expected findings (e.g. the RPKI-in-FRR gap) with zero side effects. |
| `case_only` | Persists `SecurityCase`s. Still no external writes. | Operator review of the opened cases; No-False-All-Clear behaviour confirmed over ≥1 resolve cycle. |
| `handoff_dry` | Builds the LHP-v1 handoff + renders the `loop:candidate` issue body. **Does not POST.** Serves `GET /loop-handoff/v1/soc/handoffs/{id}`. | Operator review of the rendered issue body + handoff JSON + acceptance criteria. |
| `handoff_live` | Opens the `loop:candidate` issue (idempotent by fingerprint). Never applies `loop:approved`. | Standing operator sign-off; cross-loop dedup with NOC confirmed. |

## Verifier close-loop

A handed-off case does **not** resolve on a timer. When the Engineering Loop
reports the fix landed, it POSTs an LHP `change_applied` callback to
`POST /webhook/engineering-loop/handoff-update`; the case moves to
`verification_pending`. The verifier close-loop (`socctl posture verify`, or the
posture timer) then targeted-re-reads the exact control for that resource:

- a **healthy** read accrues one positive re-check;
- `SOC_CASE_VERIFICATION_REQUIRED_CONSECUTIVE_PASSES` consecutive healthy reads
  are required before `SecurityVerifier` — the *only* resolver — closes the case;
- a **degraded** read or an **absent** signal resolves nothing (No-False-All-Clear).

Engineering can never set `verified`/`resolved` (the vendored `HandoffUpdate`
validator forbids it); resolution is SOC-owned. Ships `SOC_CASE_VERIFICATION_DRY_RUN=1`.

## Kill switches

- `SOC_ENABLED=0` — master off.
- `SOC_POSTURE_ENABLED=0` — no proactive scanning.
- `SOC_REDTEAM_ENABLED=0` / `SOC_REDTEAM_ALLOW_ACTIVE_PROBES=0` — no red-team / no active probes.
- `SOC_LHP_ENABLED=0` — no cross-loop handoff traffic.

## Identity separation (the crux)

The SOC Agent runs as its own deployable with its **own** GitHub identity
(issues-scoped), its **own** LHP HMAC secret (`SOC_LHP_ENGINEERING_SECRET`,
distinct from NOC's), and ideally its **own** read-only Hyrule MCP principal.
The deploy must provably never set `HYRULE_MCP_ENABLE_ACTIONS`.
