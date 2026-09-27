"""Per-run cost/token budget. Cost comes from Claude Code's result message (total_cost_usd)."""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path

from .data_types import Usage


class BudgetExceeded(RuntimeError):
    pass


DOWNGRADE_THRESHOLD = 0.8


def default_budget_usd() -> float:
    try:
        return float(os.getenv("TAC_RUN_BUDGET_USD", "5"))
    except ValueError:
        return 5.0


class Budget:
    def __init__(self, limit_usd: float, spent: Usage | None = None) -> None:
        self.limit_usd = limit_usd
        self.spent = spent or Usage()

    @property
    def fraction_used(self) -> float:
        if self.limit_usd <= 0:
            return 0.0
        return self.spent.cost_usd / self.limit_usd

    @property
    def under_pressure(self) -> bool:
        return self.fraction_used >= DOWNGRADE_THRESHOLD

    @property
    def exhausted(self) -> bool:
        return self.limit_usd > 0 and self.spent.cost_usd >= self.limit_usd

    def check(self) -> None:
        if self.exhausted:
            raise BudgetExceeded(
                f"run budget exhausted: ${self.spent.cost_usd:.4f} of ${self.limit_usd:.2f}"
            )

    def record(self, usage: Usage) -> None:
        self.spent = self.spent.add(usage)


# ----------------------------------------------------------------------------- ledger
# Spend is recorded append-only, one line per agent call, under a file lock. Budget checks
# and the state file both read from here, so a stale ADWState save can never erase spend.
def _ledger(adw_id: str) -> Path:
    from .utils import run_dir

    return run_dir(adw_id) / "usage.jsonl"


def record_usage(adw_id: str, usage: Usage, command: str = "") -> None:
    path = _ledger(adw_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        fh.write(json.dumps({"command": command, **usage.model_dump()}) + "\n")
        fcntl.flock(fh, fcntl.LOCK_UN)


def spent(adw_id: str) -> Usage:
    path = _ledger(adw_id)
    total = Usage()
    if not path.exists():
        return total
    for line in path.read_text().splitlines():
        if line.strip():
            row = json.loads(line)
            row.pop("command", None)
            total = total.add(Usage.model_validate(row))
    return total
