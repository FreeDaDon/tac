"""Per-run cost/token budget. Cost comes from Claude Code's result message (total_cost_usd)."""

from __future__ import annotations

import os

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
