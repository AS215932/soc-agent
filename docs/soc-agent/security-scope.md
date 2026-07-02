# SOC Agent security scope

The domains the SOC Agent is responsible for on AS215932, aligned to the
`senior-security-cryptographic-auditor` role and NIST CSF 2.0 (Identify /
Protect / Detect / Respond / Recover).

| Domain | AS215932 examples | Desired-state source |
|--------|-------------------|----------------------|
| Routing security | RPKI/ROV, IRR-backed prefix filtering, `maximum-prefix`, bogon filters, route leaks | `network-operations/configs/*/frr.conf`, golden manifest |
| Control-plane | FRR, OSPFv3, WireGuard mesh, SSH/VPN access, management-plane exposure | `configs/*/wg*.conf`, `docs/network-flows.md` |
| Secret hygiene | Vault-agent health, no plaintext secrets outside Vault | golden manifest, `host_vars/*` |
| DNS integrity | `as215932.net` points only at owned prefixes, DNSSEC, AXFR exposure | `AGENTS.md` invariant, zone files |
| Detection engineering | alert/telemetry coverage for modelled attack paths | Icinga/Prometheus config |
| Supply-chain | branch protection, required checks, runner privilege | GitHub settings |

## Ownership boundary vs the NOC Agent

- **SOC owns** posture, control coverage, attack-path, detection-gap findings.
- **NOC owns** availability/reliability.
- Dual-nature signals (e.g. TLS expiry is both reliability and a control) stay
  with **NOC** to avoid duplicate cases; SOC defers.

Cross-loop issue dedup (NOC and SOC could both file on the same host) is required
before `handoff_live`.
