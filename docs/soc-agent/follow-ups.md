# SOC Agent — next logical follow-ups

All six build phases are complete (121 tests, ruff clean) and the code path runs
**through `handoff_live`** — but nothing is operationally enabled. Enablement
climbs the `SOC_MODE` ladder behind a live shadow canary. This is the ordered
worklist to get from "built" to "running in `case_only`, then `handoff_live`,"
plus the cross-repo and hardening items surfaced during the build.

## A. Operator / infra dependencies (block `handoff_live`)

1. **Own read-only MCP principal** (plan Open Question 2 — the crux of the
   separate-repo decision). `hyrule-mcp` must issue a distinct SOC principal/token
   bound to a **read-only Vault policy**, and the SOC deploy must **provably never**
   set `HYRULE_MCP_ENABLE_ACTIONS`. Until this exists, SOC borrows credentials and
   the isolation guarantee is only enforced in code, not in identity.
2. **Own LHP HMAC secret + GitHub identity.** Provision `SOC_LHP_ENGINEERING_SECRET`
   (distinct from NOC's) in Vault, and an **issues-scoped** GitHub App/token
   (`SOC_GITHUB_APP_ID` / `SOC_GITHUB_APP_PRIVATE_KEY_PATH`) — never a deploy
   credential.
3. **Case-store durability before `handoff_live`** (Open Question 7). v1 uses
   in-memory / JSONL; verification and resolution state must survive restarts
   before live handoff. Decide JSONL-on-disk vs a SOC Postgres schema (mirror the
   agent-core collector's Postgres-on-loop pattern).
4. **Live shadow canary (go/no-go).** Run `socctl posture run-once --shadow`
   (`SOC_ENABLED=1 SOC_MODE=shadow`) against the real Hyrule MCP: confirm the
   RPKI-in-FRR finding fires against live `cr1-nl1`/`cr1-de1`/`cr1-ch1` with zero
   side effects, then step `case_only → handoff_dry → handoff_live`.

## B. Cross-repo (LHP interop)

5. **Hoist `lhp.py` into `agent_core.lhp`** (Open Question 3). Today `app/lhp.py` is
   vendored byte-identical from `noc-agent` with a parity test. Its `HandoffUpdate`
   validator **hardcodes `source_loop=="noc"` as the sole loop permitted to set
   `verified`/`resolved`**, so SOC cannot emit an outbound `resolved` LHP callback —
   **SOC resolution is internal-only in v1**. Hoisting the module and generalizing
   the verifier-only rule (any origin loop verifies its own handoffs) retires the
   parity test and unblocks outbound verification notices.
6. **Teach `engineering-loop` to consume SOC-origin handoffs.** Its
   `parse_lhp_pointer` validates the fetch path starts with
   `/loop-handoff/v1/engineering/…`; SOC serves `/loop-handoff/v1/soc/handoffs/{id}`
   with `source_loop:"soc"` and `soc-case-id` / `soc-lhp-handoff-id` markers. The
   engineering loop needs to accept the `soc` path prefix and marker set before it
   can fetch a SOC handoff and draft the PR.
7. **Cross-loop issue dedup** (Open Question 5). NOC and SOC can both file on the
   same host (fingerprint markers are per-loop). Add cross-loop dedup before
   `handoff_live`, and confirm SOC checks are additive (config-vs-live drift) rather
   than duplicating CI secret-scanning / Icinga bogon-egress coverage.

## C. Finding fidelity / content

8. **RPKI remediation target** (Open Question 1 — blocks the lead finding's
   `acceptance_criteria`). Decide "deploy validator/RTR + reject RPKI-invalid" (a
   real infra project) vs "minimum hardening: `maximum-prefix` + stricter
   `TRANSIT-IN` + justify/remove `no bgp ebgp-requires-policy`." Also confirm
   whether transit AS34872 (Servperso) already RPKI-filters upstream (lowers
   severity). The finding surfaces both; a human picks.
9. **Seed the golden-manifest `detections` list.** RT-0 marks every modeled attack
   path a `detection_gap` when the manifest declares no matching detection — today
   the list is empty, so every path is a gap. Enumerate the real detections
   (Icinga bogon-egress, auth-anomaly, wg peer monitoring, DNS ownership) so gaps
   are true gaps.
10. **Listening-ports allowlist bootstrap** (Open Question 4). `check_listening_ports`
    flags many ports until curated. Seed a per-host allowlist from a one-time
    human-reviewed `socket_listeners` capture; keep the check in shadow until then.
11. **Desired-state freshness** (Open Question 8). SOC reads a local
    `network-operations` checkout. Own the refresh and pin
    `SOC_NETWORK_OPERATIONS_PIN_SHA` into every finding's `content_sha`/`manifest_sha`
    so stale checkouts can't produce false drift.

## D. Engineering / build hygiene

12. **Real dependency environment + CI.** There is no committed lockfile/venv (the
    offline `uv` install failed on missing transitive wheels); the suite currently
    runs via the NOC venv + `PYTHONPATH` (see `scripts/test.sh`). Once network is
    available, resolve a `uv.lock` with the full dep set (langgraph, pydantic-ai,
    fastapi, pyjwt[crypto]) and add a GitHub Actions workflow that runs `ruff` +
    `pytest` on every PR.
13. **Wire the live specialist model.** The graph runs offline with a deterministic
    fallback / `TestModel`; wire the real provider config (`[model]`/`[providers.*]`)
    and a Redis checkpointer for resumable HITL, matching NOC.
14. **Outstanding scanners.** `check_vault_hygiene` (Open Question 5, DEEP, overlaps
    CI secret-scanning — keep off until de-duped) and the `posture/suppressions.py`
    seam from the scaffold are not yet implemented.
