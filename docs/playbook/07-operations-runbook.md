# 07 — Operations runbook

## Setup (once)
```bash
cp .env.sample .env            # fill ANTHROPIC_API_KEY, GITHUB_*, TAC_TRIGGER_ALLOWED_USERS
uv sync
(cd app/client && npm ci && npm run build)
scripts/check.sh               # all gates green before any agent runs
```

## Daily commands
| Goal | Command |
|---|---|
| Dashboard | `scripts/start.sh` then open http://127.0.0.1:8000 |
| Full SDLC from a GitHub issue | `uv run adws/adw_sdlc_iso.py --issue 42` |
| Full SDLC from a local issue | `uv run adws/adw_sdlc_iso.py --issue-file specs/examples/issue.md` |
| Heavy models for a hard issue | add `--model-set heavy` |
| Resume after a failure or budget stop | `uv run adws/adw_sdlc_iso.py --adw-id <id> --resume` |
| One phase only | `uv run adws/adw_test_iso.py --adw-id <id>` (also build, review, redteam, document) |
| Zero-Touch (see 04) | `TAC_ZTE_ENABLED=1 uv run adws/adw_sdlc_zte_iso.py --issue 42` |
| Check ship locks without merging | `uv run adws/adw_ship_iso.py --adw-id <id> --dry-run` |
| SOC triage | `uv run adws/adw_domain_iso.py --pack soc --input /path/auth.log` |
| IAM review with a PR | `uv run adws/adw_domain_iso.py --pack iam --input /path/iam/ --propose` |
| Deterministic only (no model) | add `--no-agent` |
| Offline dry run (no cost) | prefix with `TAC_AGENT_RUNNER=mock` |
| Queue work | edit `tasks.md`, then `uv run adws/adw_triggers/trigger_todone.py` |
| Webhook | `GITHUB_WEBHOOK_SECRET=... uv run adws/adw_triggers/trigger_webhook.py` behind your tunnel |
| List runs | `scripts/list_runs.sh` |
| Clean up a run | `scripts/purge_tree.sh <id> --delete-branch` |

Exit codes: `0` passed, `1` failed, `2` security or usage error, `3` budget exceeded.

## Triage a failed run
1. `scripts/list_runs.sh` shows which phase is `failed`.
2. `agent/runs/<id>/<phase>/execution.log` and `events.jsonl` show what happened, and in what order.
3. For each agent call, `agent/runs/<id>/<agent_name>/prompt.md` holds what it was asked and `raw_output.jsonl` holds what it did.
4. Failed gates are in `state.json → gate_report`. Unit test details are in `test_reports/junit.xml`.
5. Fix by hand in `trees/<id>` if needed, commit there, then run `--resume`.

## Common failures
| Symptom | Cause | Fix |
|---|---|---|
| `no free port slot` | 50 stale worktrees | `scripts/purge_tree.sh` finished runs |
| `unclassifiable issue` | issue too vague, or injection-laden | rewrite the issue; this is working as intended |
| `planner did not write the plan` | model ignored the output path | rerun; if repeated, try `--model-set heavy` |
| Repair loop stops with "no progress" | same failures after a fix attempt | a human is needed; see the failing test in junit.xml |
| `BUDGET_EXCEEDED` | run hit `TAC_RUN_BUDGET_USD` | inspect why (usually repair loops), raise the budget, `--resume` |
| Hook blocks a legitimate command | `pre_tool_use.py` regex hit | run that step yourself; don't loosen the hook for agents |

## Maintenance
- **Weekly:** review `agent/lessons/`. Delete wrong lessons, merge duplicates, commit the rest.
- **Weekly:** read `agent/agentic_kpis.md`. Is Attempts trending down and gate pass rate trending up?
- **Monthly:** rotate `GITHUB_WEBHOOK_SECRET` and `GITHUB_PAT`, `uv lock --upgrade`, `npm update`, and re-run `scripts/check.sh`.
- `agent/cache.db` is safe to delete at any time.
