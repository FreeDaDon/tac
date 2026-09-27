"""Read ADW runs from the filesystem (agent/runs/<adw_id>/). Tolerant of partial or corrupt files."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from adws.adw_modules.data_types import ADWStateData, GateReport

ADW_ID_RE = re.compile(r"^[a-f0-9]{8}$")
MAX_EVENTS_BYTES = 5 * 1024 * 1024
MAX_EVENTS = 2000


def is_valid_adw_id(adw_id: str) -> bool:
    return bool(ADW_ID_RE.match(adw_id))


def runs_dir(root: Path) -> Path:
    return root / "agent" / "runs"


def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def read_state(root: Path, adw_id: str) -> tuple[dict[str, Any] | None, str | None]:
    """Return (state dict, error). Falls back to the raw JSON when it fails schema validation."""
    path = runs_dir(root) / adw_id / "state.json"
    if not path.is_file():
        return None, "state.json missing"
    try:
        raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"unreadable state.json: {exc.__class__.__name__}"
    if not isinstance(raw, dict):
        return None, "state.json is not an object"
    try:
        return ADWStateData.model_validate(raw).model_dump(mode="json"), None
    except Exception:  # noqa: BLE001 - pydantic ValidationError; keep what we can
        raw.setdefault("adw_id", adw_id)
        return raw, "state.json failed schema validation"


def gate_report(root: Path, adw_id: str, state: dict[str, Any] | None) -> dict[str, Any] | None:
    report = (state or {}).get("gate_report")
    if not report:
        path = runs_dir(root) / adw_id / "gate_report.json"
        if path.is_file():
            try:
                report = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                report = None
    if not isinstance(report, dict):
        return None
    try:
        return GateReport.model_validate(report).model_dump(mode="json")
    except Exception:  # noqa: BLE001
        return None


def gates_summary(report: dict[str, Any] | None) -> dict[str, Any]:
    counts = {"passed": 0, "failed": 0, "skipped": 0, "error": 0}
    gates = (report or {}).get("gates") or []
    for g in gates:
        status = g.get("status")
        if status in counts:
            counts[status] += 1
    required = [g for g in gates if g.get("required_for_zte", True)]
    all_green = bool(required) and all(g.get("status") == "passed" for g in required)
    return {**counts, "total": len(gates), "all_green": all_green}


def summarize(root: Path, adw_id: str) -> dict[str, Any]:
    state, error = read_state(root, adw_id)
    s = state or {}
    usage = _as_dict(s.get("usage"))
    cost = _num(usage.get("cost_usd"))
    budget = _num(s.get("budget_usd"), 5.0)
    report = gate_report(root, adw_id, state)
    phases = _as_dict(s.get("phases"))
    raw_adws = s.get("all_adws")
    all_adws: list[Any] = raw_adws if isinstance(raw_adws, list) else []
    return {
        "adw_id": adw_id,
        "domain": s.get("domain"),
        "issue_number": s.get("issue_number"),
        "issue_title": s.get("issue_title"),
        "issue_class": s.get("issue_class"),
        "branch_name": s.get("branch_name"),
        "model_set": s.get("model_set"),
        "phases": {str(k): str(v) for k, v in phases.items()},
        "gates": gates_summary(report),
        "cost_usd": round(cost, 6),
        "budget_usd": budget,
        "budget_fraction": round(cost / budget, 4) if budget > 0 else 0.0,
        "attempts": len(all_adws),
        "workflows": [str(w) for w in all_adws],
        "backend_port": s.get("backend_port"),
        "frontend_port": s.get("frontend_port"),
        "created": s.get("created"),
        "updated": s.get("updated"),
        "error": error,
    }


def list_run_ids(root: Path) -> list[str]:
    base = runs_dir(root)
    if not base.is_dir():
        return []
    return sorted(p.name for p in base.iterdir() if p.is_dir() and is_valid_adw_id(p.name))


def list_runs(root: Path) -> list[dict[str, Any]]:
    runs = [summarize(root, adw_id) for adw_id in list_run_ids(root)]
    runs.sort(key=lambda r: str(r.get("updated") or ""), reverse=True)
    return runs


def read_events(root: Path, adw_id: str, limit: int = MAX_EVENTS) -> list[dict[str, Any]]:
    """Parse events.jsonl (oldest first), skipping corrupt lines; large files are tailed."""
    path = runs_dir(root) / adw_id / "events.jsonl"
    if not path.is_file():
        return []
    try:
        with open(path, "rb") as fh:
            size = fh.seek(0, 2)
            start = max(0, size - MAX_EVENTS_BYTES)
            fh.seek(start)
            blob = fh.read()
    except OSError:
        return []
    lines = blob.decode("utf-8", errors="replace").splitlines()
    if start > 0 and lines:
        lines = lines[1:]  # first line is probably partial
    events: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            events.append(item)
    return events[-limit:]


def run_detail(root: Path, adw_id: str) -> dict[str, Any] | None:
    if not (runs_dir(root) / adw_id).is_dir():
        return None
    state, _ = read_state(root, adw_id)
    return {
        "summary": summarize(root, adw_id),
        "state": state,
        "gate_report": gate_report(root, adw_id, state),
        "events": read_events(root, adw_id),
    }


def budget(root: Path) -> dict[str, Any]:
    rows = []
    total_cost = total_budget = 0.0
    over = warn = 0
    for r in list_runs(root):
        frac = r["budget_fraction"]
        status = "over" if frac >= 1 else "warn" if frac >= 0.8 else "ok"
        over += status == "over"
        warn += status == "warn"
        total_cost += r["cost_usd"]
        total_budget += r["budget_usd"]
        rows.append(
            {
                "adw_id": r["adw_id"],
                "cost_usd": r["cost_usd"],
                "budget_usd": r["budget_usd"],
                "fraction": frac,
                "status": status,
            }
        )
    return {
        "runs": rows,
        "totals": {
            "runs": len(rows),
            "cost_usd": round(total_cost, 6),
            "budget_usd": round(total_budget, 6),
            "over_budget": over,
            "near_budget": warn,
        },
    }
