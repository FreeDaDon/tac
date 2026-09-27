"""Persistent ADW state: agent/runs/<adw_id>/state.json, atomic writes, file locking."""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .data_types import ADWStateData, GateReport, Usage, utcnow
from .security import validate_adw_id
from .utils import run_dir


class ADWState:
    def __init__(self, adw_id: str, **initial: Any) -> None:
        self.adw_id = validate_adw_id(adw_id)
        self.data = ADWStateData(adw_id=self.adw_id, **initial)

    # --- paths -----------------------------------------------------------------
    @property
    def dir(self) -> Path:
        return run_dir(self.adw_id)

    @property
    def path(self) -> Path:
        return self.dir / "state.json"

    # --- access ----------------------------------------------------------------
    def get(self, key: str, default: Any = None) -> Any:
        value = getattr(self.data, key, None)
        if value is None and self.data.model_extra:
            value = self.data.model_extra.get(key)
        return default if value is None else value

    def update(self, **kwargs: Any) -> ADWState:
        merged = self.data.model_dump()
        merged.update(kwargs)
        self.data = ADWStateData.model_validate(merged)
        return self

    def append_adw(self, workflow: str) -> None:
        # every invocation is recorded (repeats included): the Attempts KPI counts them
        self.data.all_adws.append(workflow)

    def set_phase(self, phase: str, status: str) -> None:
        self.data.phases[phase] = status

    def add_usage(self, usage: Usage) -> None:
        self.data.usage = self.data.usage.add(usage)

    def gate_report(self) -> GateReport:
        if self.data.gate_report is None:
            self.data.gate_report = GateReport(adw_id=self.adw_id)
        return self.data.gate_report

    def working_dir(self) -> str:
        from .utils import project_root

        return self.data.worktree_path or str(project_root())

    # --- persistence -----------------------------------------------------------
    @contextmanager
    def _lock(self) -> Iterator[None]:
        self.dir.mkdir(parents=True, exist_ok=True)
        with open(self.dir / ".lock", "w") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)

    def save(self, step: str | None = None) -> None:
        self.data.updated = utcnow()
        if step:
            self.data.phases.setdefault(step, "running")
        payload = self.data.model_dump_json(indent=2)
        with self._lock():
            fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".state.", suffix=".tmp")
            try:
                with os.fdopen(fd, "w") as fh:
                    fh.write(payload)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self.path)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise

    def reload(self) -> ADWState:
        loaded = ADWState.load(self.adw_id)
        if loaded:
            self.data = loaded.data
        return self

    @classmethod
    def load(cls, adw_id: str) -> ADWState | None:
        path = run_dir(validate_adw_id(adw_id)) / "state.json"
        if not path.exists():
            return None
        state = cls.__new__(cls)
        state.adw_id = adw_id
        state.data = ADWStateData.model_validate(json.loads(path.read_text()))
        return state

    @classmethod
    def load_or_create(cls, adw_id: str, **initial: Any) -> ADWState:
        return cls.load(adw_id) or cls(adw_id, **initial)

    def public_summary(self) -> dict[str, Any]:
        """Redacted view safe to post to GitHub (no local paths, no raw outputs)."""
        d = self.data
        return {
            "adw_id": d.adw_id,
            "domain": d.domain,
            "issue_class": d.issue_class,
            "branch_name": d.branch_name,
            "model_set": d.model_set,
            "phases": d.phases,
            "cost_usd": round(d.usage.cost_usd, 4),
            "gates": {g.name: g.status for g in (d.gate_report.gates if d.gate_report else [])},
        }
