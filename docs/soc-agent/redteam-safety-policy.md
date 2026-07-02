# Red-team safety policy

The SOC Agent's red-team capability is **tiered** and hard-gated. v1 ships RT-0
and RT-1 only.

| Tier | Name | Allowed in v1? | Description |
|------|------|:-:|-------------|
| RT-0 | Passive attack-path modeling | ✅ default | Reason over desired-state + telemetry; produce `AttackPathHypothesis`. **Zero packets.** |
| RT-1 | Non-invasive read-only validation | ✅ (owned assets only) | Version/config/header checks via read-only MCP tools + `httpx` GET. No auth attempts, no fuzzing. Rate-limited. |
| RT-2 | Rate-limited active checks | ❌ hard-refused | No executor exists in v1. |
| RT-3 | Lab exploit validation | ❌ | Requires an isolated range (does not exist). |
| RT-4 | Production-safe adversary emulation | ❌ | Caldera/Atomic — deferred. |
| RT-5 | Real exploit chain in production | ❌ never a default path | — |

## Rules of engagement (RT-1)

- **Owned-asset allowlist only.** Targets must be on the explicit list below;
  anything else is refused.
- No credential access, lateral movement, data exfiltration, or destructive
  action — enforced by the absence of any such tool and by `redteam/policy.py`.
- Bounded by `SOC_POSTURE_MAX_PROBES_PER_HOST_PER_CYCLE`;
  `SOC_REDTEAM_ALLOW_ACTIVE_PROBES` stays off by default.
- `SOC_REDTEAM_MAX_TIER` (default 1) is the ceiling; `redteam/policy.py`
  refuses any tier ≥ `SOC_REDTEAM_HUMAN_GATE_TIER` (default 2).

### Owned-asset allowlist

> Populated in Phase 5 from the `SOC_ALLOWED_HOSTS` set (AS215932-owned routers
> and management hosts). Customer-facing / third-party assets are excluded.
