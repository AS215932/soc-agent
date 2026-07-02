# Testing the SOC Agent

The suite is offline-first: `tests/conftest.py` sets `SOC_AGENT_DISABLE_MCP=1`,
so no test ever contacts the live Hyrule MCP daemon. Checks are exercised with a
`FakeMCPRuntime` fed captured fixtures under `tests/fixtures/`.

## Interpreter

The canonical install is `uv sync` (resolves `agent-core` from its pinned git
tag — needs network). For **local offline development** the SOC repo reuses the
NOC agent's already-resolved venv (identical Python 3.14 + production dependency
versions), with the SOC repo on `PYTHONPATH` so its `app` package wins over the
NOC editable install:

```sh
export SOCPY=/home/svag/Dev/hyrule-noc-agent/.venv/bin/python
PYTHONPATH="$PWD" "$SOCPY" -m pytest -q
```

A convenience wrapper is provided:

```sh
./scripts/test.sh            # runs the whole suite
./scripts/test.sh tests/test_config.py -q
```

## Conventions (mirrors hyrule-noc-agent)

- Flat `tests/` directory, one test file per module (`test_<module>.py`).
- `pytest` + `pytest-asyncio` (`asyncio_mode = "auto"`, no per-test decorators).
- The vendored `app/lhp.py` is guarded by `tests/test_lhp_contract_parity.py`,
  which fails if it drifts from `hyrule-noc-agent/app/cases/lhp.py`.

## Live shadow canary (manual, opt-in)

Before enabling `case_only` in production, run the read-only posture scan once
against the live MCP:

```sh
SOC_ENABLED=1 SOC_MODE=shadow HYRULE_MCP_URL=http://127.0.0.1:8765/mcp \
  "$SOCPY" -m app.socctl posture run-once --shadow
```

It prints findings JSON, opens no issues, and mutates nothing.
