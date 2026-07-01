"""Daily budget ledger for the posture loop.

Tracks findings acted-on and estimated cost per UTC day, plus per-host probe
counts within a cycle, so the loop cannot exceed ``SOC_POSTURE_MAX_*`` limits.
Persisted as a tiny JSON file under the posture state dir so limits survive
restarts within a day.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


@dataclass
class DailyLedger:
    state_path: Path | None = None
    day: str = field(default_factory=_today)
    findings_acted: int = 0
    cost_usd: float = 0.0
    _probes: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    @classmethod
    def load(cls, state_dir: str | Path | None) -> "DailyLedger":
        if not state_dir:
            return cls()
        path = Path(state_dir) / "ledger.json"
        ledger = cls(state_path=path)
        if path.exists():
            try:
                data = json.loads(path.read_text())
                if data.get("day") == ledger.day:
                    ledger.findings_acted = int(data.get("findings_acted", 0))
                    ledger.cost_usd = float(data.get("cost_usd", 0.0))
            except (OSError, ValueError):
                pass
        return ledger

    def _roll_day(self) -> None:
        today = _today()
        if today != self.day:
            self.day = today
            self.findings_acted = 0
            self.cost_usd = 0.0
            self._probes.clear()

    def findings_remaining(self, max_per_day: int) -> int:
        self._roll_day()
        return max(0, max_per_day - self.findings_acted)

    def within_cost_budget(self, next_cost: float, max_cost_per_day: float) -> bool:
        self._roll_day()
        return (self.cost_usd + max(0.0, next_cost)) <= max_cost_per_day

    def record_finding(self, *, cost: float = 0.0) -> None:
        self._roll_day()
        self.findings_acted += 1
        self.cost_usd += max(0.0, cost)
        self._persist()

    def probe(self, host: str) -> int:
        self._roll_day()
        self._probes[host] += 1
        return self._probes[host]

    def probes_for(self, host: str) -> int:
        return self._probes.get(host, 0)

    def reset_cycle_probes(self) -> None:
        self._probes.clear()

    def _persist(self) -> None:
        if not self.state_path:
            return
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(
                json.dumps({"day": self.day, "findings_acted": self.findings_acted, "cost_usd": self.cost_usd})
            )
        except OSError:
            pass
