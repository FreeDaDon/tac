"""Route each slash command to the cheapest model that can do it well.

Task classes:
  mechanical - classification, naming, commit messages: small model is enough
  standard   - tests, review, docs, domain analysis
  heavy      - planning, implementation, repair: benefits from the strongest model
The model set (base|heavy) shifts the heavy class; budget pressure downgrades it.
"""

from __future__ import annotations

from typing import Literal

from .data_types import ModelName, ModelSet

TaskClass = Literal["mechanical", "standard", "heavy"]

COMMAND_CLASS: dict[str, TaskClass] = {
    "/classify_issue": "mechanical",
    "/generate_branch_name": "mechanical",
    "/commit": "mechanical",
    "/test": "standard",
    "/test_e2e": "standard",
    "/review": "standard",
    "/document": "standard",
    "/redteam": "standard",
    "/reflect": "standard",
    "/optimize": "standard",
    "/soc_triage": "standard",
    "/soc_tune_rule": "heavy",
    "/iam_access_review": "standard",
    "/iam_policy_fix": "heavy",
    "/devops_iac_plan": "heavy",
    "/devops_drift_review": "standard",
    "/feature": "heavy",
    "/bug": "heavy",
    "/chore": "heavy",
    "/patch": "heavy",
    "/implement": "heavy",
    "/resolve_failed_test": "heavy",
    "/resolve_failed_e2e_test": "heavy",
}

ROUTING: dict[ModelSet, dict[TaskClass, ModelName]] = {
    "base": {"mechanical": "haiku", "standard": "sonnet", "heavy": "sonnet"},
    "heavy": {"mechanical": "haiku", "standard": "sonnet", "heavy": "opus"},
}


def task_class(slash_command: str) -> TaskClass:
    return COMMAND_CLASS.get(slash_command, "standard")


def route(slash_command: str, model_set: ModelSet = "base", budget_pressure: bool = False) -> ModelName:
    model = ROUTING[model_set][task_class(slash_command)]
    if budget_pressure and model == "opus":
        return "sonnet"
    return model
