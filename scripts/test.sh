#!/usr/bin/env bash
# Run the SOC Agent test suite using the NOC agent's resolved venv (offline dev).
# See TESTING.md. Pass through any pytest args, e.g. ./scripts/test.sh tests/test_config.py -q
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOCPY="${SOCPY:-/home/svag/Dev/hyrule-noc-agent/.venv/bin/python}"

if [[ ! -x "$SOCPY" ]]; then
  echo "error: interpreter not found at $SOCPY (set SOCPY=/path/to/python)" >&2
  exit 1
fi

cd "$REPO_ROOT"
exec env PYTHONPATH="$REPO_ROOT" "$SOCPY" -m pytest "${@:-tests/}"
