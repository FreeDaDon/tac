#!/usr/bin/env -S uv run
"""Todone task queue (TAC-8 app2), parsed deterministically instead of by an agent.

tasks.md format:
    ## Queue <name>
    - [ ] pending task description {heavy}
    - [⏰] blocked until every task above it in this queue is done
    - [🟡 ab12cd34] in progress
    - [✅ ab12cd34] done
    - [❌ ab12cd34] failed: reason

Each eligible task becomes a local issue file and an adw_sdlc_iso run (use {plan} tag for plan-only).

Usage: uv run adws/adw_triggers/trigger_todone.py [--tasks tasks.md] [--interval 30] [--once]
"""

from __future__ import annotations

import argparse
import fcntl
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from adws.adw_modules.state import ADWState
from adws.adw_modules.utils import make_adw_id, project_root, runs_dir
from adws.adw_triggers.launcher import launch

TASK_RE = re.compile(r"^- \[(?P<mark>[^\]]*)\]\s*(?P<text>.*)$")
TAG_RE = re.compile(r"\{(\w+)\}")


@dataclass
class Task:
    line_no: int
    status: str  # pending | blocked | running | done | failed
    text: str
    adw_id: str = ""
    tags: set[str] = field(default_factory=set)


def parse_mark(mark: str) -> tuple[str, str]:
    mark = mark.strip()
    if not mark:
        return "pending", ""
    parts = mark.split()
    symbol, adw = parts[0], parts[1] if len(parts) > 1 else ""
    return {"⏰": "blocked", "🟡": "running", "✅": "done", "❌": "failed"}.get(symbol, "pending"), adw


def parse_tasks(text: str) -> dict[str, list[Task]]:
    queues: dict[str, list[Task]] = {}
    current = "default"
    for i, line in enumerate(text.splitlines()):
        if line.startswith("## "):
            current = line[3:].strip().removeprefix("Queue ").strip()
            continue
        m = TASK_RE.match(line)
        if not m:
            continue
        status, adw = parse_mark(m["mark"])
        body = m["text"].split(" failed:")[0]
        queues.setdefault(current, []).append(
            Task(i, status, TAG_RE.sub("", body).strip(), adw, set(TAG_RE.findall(body))))
    return queues


def eligible(queues: dict[str, list[Task]]) -> list[Task]:
    out = []
    for tasks in queues.values():
        for idx, t in enumerate(tasks):
            if t.status == "pending":
                out.append(t)
            elif t.status == "blocked" and all(p.status == "done" for p in tasks[:idx]):
                out.append(t)
    return out


def set_mark(lines: list[str], task: Task, mark: str, suffix: str = "") -> None:
    tags = " ".join(f"{{{t}}}" for t in sorted(task.tags))
    lines[task.line_no] = f"- [{mark}] {task.text}" + (f" {tags}" if tags else "") + suffix


def refresh_running(lines: list[str], queues: dict[str, list[Task]]) -> None:
    for tasks in queues.values():
        for t in tasks:
            if t.status != "running" or not t.adw_id:
                continue
            state = ADWState.load(t.adw_id)
            if not state:
                continue
            phases = state.data.phases
            if any(s == "failed" for s in phases.values()):
                failed = next(p for p, s in phases.items() if s == "failed")
                set_mark(lines, t, f"❌ {t.adw_id}", f" failed: {failed} phase")
            elif phases.get("document") == "passed" or (("plan" in t.tags) and phases.get("plan") == "passed"):
                set_mark(lines, t, f"✅ {t.adw_id}")


def process(tasks_file: Path, max_concurrent: int = 3) -> list[str]:
    started = []
    with open(tasks_file, "r+") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        text = fh.read()
        lines = text.splitlines()
        queues = parse_tasks(text)
        refresh_running(lines, queues)
        for task in eligible(queues):
            adw_id = make_adw_id()
            issue_dir = runs_dir() / "_triggers" / "todone"
            issue_dir.mkdir(parents=True, exist_ok=True)
            issue_file = issue_dir / f"{adw_id}.md"
            issue_file.write_text(f"# {task.text[:120]}\n\n{task.text}\n")
            workflow = "adw_plan_iso" if "plan" in task.tags else "adw_sdlc_iso"
            try:
                launch(workflow, issue_file=str(issue_file), adw_id=adw_id,
                       model_set="heavy" if "heavy" in task.tags else "base", max_concurrent=max_concurrent)
            except RuntimeError:
                break
            set_mark(lines, task, f"🟡 {adw_id}")
            started.append(adw_id)
        fh.seek(0)
        fh.write("\n".join(lines) + "\n")
        fh.truncate()
        fcntl.flock(fh, fcntl.LOCK_UN)
    return started


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--tasks", default=str(project_root() / "tasks.md"))
    p.add_argument("--interval", type=int, default=30)
    p.add_argument("--max-concurrent", type=int, default=3)
    p.add_argument("--once", action="store_true")
    a = p.parse_args()
    while True:
        print(f"started: {process(Path(a.tasks), a.max_concurrent)}")
        if a.once:
            return
        time.sleep(a.interval)


if __name__ == "__main__":
    main()
