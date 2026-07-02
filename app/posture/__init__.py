"""Proactive posture scanner: read-only desired-state-vs-live control-drift checks.

Each check diffs an authoritative desired-state artifact (the ``network-operations``
repo + golden manifest) against live Hyrule MCP telemetry and emits a
``SecurityFinding``. A failed *read* degrades the cycle (never a silent pass), and
resolution requires repeated positive re-checks (No-False-All-Clear).
"""
