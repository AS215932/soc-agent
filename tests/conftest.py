import os
import sys
from pathlib import Path

# The SOC agent never talks to the live MCP daemon during tests.
os.environ.setdefault("SOC_AGENT_DISABLE_MCP", "1")

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
