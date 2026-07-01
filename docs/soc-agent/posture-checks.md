# Posture checks

Each check diffs a desired-state source (the `network-operations` repo + golden
manifest, treated as authoritative) against live Hyrule MCP telemetry
(read-only) and emits a `SecurityFinding`. A failed *read* yields DEGRADED (never
a silent PASS), and a case resolves only after N consecutive healthy passes
(No-False-All-Clear).

> Populated in Phase 2. Lead check: `check_rpki_in_frr`.

| # | check_id | Domain | Desired-state | MCP tool(s) | Fails when |
|---|----------|--------|---------------|-------------|------------|
| 1 | `rpki_in_frr` | routing | `configs/*/frr.conf` | `frr_vtysh_cmd` | transit eBGP neighbor has no RPKI-invalid reject **and** no `maximum-prefix` **and** `no bgp ebgp-requires-policy` |
| 2 | `listening_ports` | exposure | `host_vars/*`, firewall templates | `socket_listeners` | listener not in the per-host allowlist |
| 3 | `wireguard_hygiene` | crypto | `configs/*/wg*.conf` | `wg_show` | committed plaintext key / peer drift / stale handshake |
| 4 | `dns_ownership` | dns | `AGENTS.md` invariant, manifest | `dns_dig`, `knot_zone_status` | `as215932.net` record outside owned prefixes |
| 5 | `vault_hygiene` | secrets | manifest | `vault_agent_status` | agent degraded / plaintext secret in tracked file |
