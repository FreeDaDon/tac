"""Narrow self-healing: one failing test -> one focused repair agent -> re-run.

Never a broad regeneration pass. The loop stops when everything passes, attempts run out,
or the failure set stops changing (no progress).
"""

from __future__ import annotations

import json
from collections.abc import Callable

from . import telemetry
from .agent import execute_template, write_input_file
from .data_types import AgentRequest, RetryCode


def repair_loop(
    adw_id: str,
    working_dir: str,
    run_tests: Callable[[], list],
    resolve_command: str,
    max_attempts: int,
    label: str = "test",
) -> tuple[bool, list]:
    previous: set[str] | None = None
    results: list = []
    for attempt in range(1, max_attempts + 1):
        results = run_tests()
        failures = [r for r in results if not r.passed]
        telemetry.emit(adw_id, "repair", phase=label, message=f"attempt {attempt}: {len(failures)} failing",
                       attempt=attempt, failing=[f.test_name for f in failures][:20])
        if not failures:
            return True, results
        current = {f.test_name for f in failures}
        if previous is not None and current == previous:
            telemetry.emit(adw_id, "repair", phase=label, message="no progress; stopping repair loop")
            return False, results
        if attempt == max_attempts:
            break
        previous = current
        for idx, failure in enumerate(failures):
            path = write_input_file(adw_id, f"{label}_failure_{attempt}_{idx}.json",
                                    json.dumps(failure.model_dump(), indent=2))
            resp = execute_template(AgentRequest(
                adw_id=adw_id, agent_name=f"{label}_resolver_{attempt}_{idx}",
                slash_command=resolve_command, args=[path], working_dir=working_dir,
            ))
            if resp.retry_code == RetryCode.BUDGET_EXCEEDED:
                return False, results
    return False, results
