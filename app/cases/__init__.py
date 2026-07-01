"""SOC Agent security-case substrate.

A deliberately small, security-specialised analogue of the NOC CaseService: the
``SecurityCase`` durable record, the ``SecurityFinding`` LHP-ready unit, an
in-memory / JSONL store, a policy state machine, and the verifier that alone may
move a case to ``resolved``. Cross-loop wire types (``CaseHandoff``,
``VerificationObjective``) come from the vendored ``app.lhp`` module.
"""
