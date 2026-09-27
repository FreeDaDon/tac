"""Shared CLI plumbing for workflow scripts: exit codes and state loading."""

from __future__ import annotations

import sys
from collections.abc import Callable

from . import telemetry
from .budget import BudgetExceeded
from .security import SecurityError
from .state import ADWState

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_BUDGET = 3


def require_state(adw_id: str) -> ADWState:
    state = ADWState.load(adw_id)
    if state is None:
        raise SystemExit(f"no state for adw_id {adw_id}; run adw_plan_iso first")
    return state


def main_wrapper(fn: Callable[[], bool], adw_id_hint: Callable[[], str | None] = lambda: None) -> None:
    """Run a workflow entrypoint and convert its outcome to a process exit code."""
    try:
        ok = fn()
    except BudgetExceeded as exc:
        _report(adw_id_hint(), f"budget exceeded: {exc}")
        sys.exit(EXIT_BUDGET)
    except SecurityError as exc:
        _report(adw_id_hint(), f"security validation failed: {exc}")
        sys.exit(EXIT_USAGE)
    except Exception as exc:
        _report(adw_id_hint(), f"{type(exc).__name__}: {exc}")
        sys.exit(EXIT_FAILED)
    sys.exit(EXIT_OK if ok else EXIT_FAILED)


def _report(adw_id: str | None, message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    if adw_id:
        try:
            telemetry.emit(adw_id, "error", message=message[:1000])
        except Exception:  # noqa: BLE001, S110
            pass
