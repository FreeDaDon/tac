#!/usr/bin/env -S uv run
"""Polling trigger: open issues labeled `tac:sdlc` / `tac:plan` / `tac:zte` by an allowlisted author.

Each issue is launched once (tracked in agent/runs/_triggers/cron_seen.json), asynchronously.

Usage: uv run adws/adw_triggers/trigger_cron.py [--interval 60] [--once]
"""

from __future__ import annotations

import argparse
import json
import time

from adws.adw_modules.github import gh, repo_path
from adws.adw_modules.utils import runs_dir
from adws.adw_triggers.launcher import launch
from adws.adw_triggers.trigger_webhook import decide


def _seen_path():
    path = runs_dir() / "_triggers" / "cron_seen.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def poll_once() -> list[str]:
    seen_path = _seen_path()
    seen = set(json.loads(seen_path.read_text())) if seen_path.exists() else set()
    issues = json.loads(gh("issue", "list", "-R", repo_path(), "--state", "open", "--limit", "50",
                           "--json", "number,labels,author"))
    launched = []
    for issue in issues:
        number = str(issue["number"])
        if number in seen:
            continue
        payload = {"action": "opened", "issue": {"number": issue["number"], "labels": issue.get("labels", []),
                                                 "user": {"login": (issue.get("author") or {}).get("login", "")}}}
        decision = decide("issues", payload)
        if not decision:
            continue
        try:
            launch(decision[0], issue=number, model_set=decision[1])
        except RuntimeError:
            break  # concurrency limit: try again next poll
        seen.add(number)
        launched.append(number)
    seen_path.write_text(json.dumps(sorted(seen)))
    return launched


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--interval", type=int, default=60)
    p.add_argument("--once", action="store_true")
    a = p.parse_args()
    while True:
        print(f"launched: {poll_once()}")
        if a.once:
            return
        time.sleep(a.interval)


if __name__ == "__main__":
    main()
