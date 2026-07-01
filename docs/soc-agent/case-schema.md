# SecurityCase / SecurityFinding schema

> Populated in Phase 1 alongside `app/cases/models.py`.

The SOC case substrate mirrors the NOC `AtomicCaseProjection`/`Hotspot` shapes
but is security-specialised and LHP-ready from day one.

- **`SecurityFinding`** — the LHP-ready unit emitted by a posture check or
  red-team hypothesis. Carries `severity`/`confidence`, MITRE ATT&CK
  tactic/technique metadata, `desired_state_refs`, sanitised `evidence`, a
  pass/fail `assertion`, and a `build_handoff()` that produces a `CaseHandoff`
  (`source_loop="soc"`, `target_loop="engineering"`, `verifier="soc"`) plus
  `VerificationObjective`s.
- **`SecurityCase`** — the durable record with change-detection fields and the
  No-False-All-Clear counters (`consecutive_pass_count`,
  `required_consecutive_passes`, `last_observed_failing`/`passing`).
- **`SecurityObservation`** — normalised evidence with an `is_positive_clean`
  property gating resolution.

Case-type vocabulary: `security_incident`, `security_finding`, `detection_gap`,
`redteam_exercise`, `abuse_case`, `control_drift` (proactive scanner default).

Projections to `agent_core.contracts` (`CaseSummary`, `HandoffSummary`,
`VerificationObjectiveSummary`, `EvidencePacket`/`SourceRef`) live in
`app/cases/summaries.py`.
