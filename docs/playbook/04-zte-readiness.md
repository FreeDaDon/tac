# 04 — Zero-Touch Engineering readiness

ZTE removes the human **Review** from PITER, leaving PITE: the agent merges its own work. That is
only safe when the gates are stronger than your review would have been. This toolkit keeps
auto-merge locked until each of the following is true.

## The five ship locks (`adws/adw_ship_iso.py::ship_blockers`)

| # | Lock | Why |
|---|---|---|
| 1 | `TAC_ZTE_ENABLED=1` | An explicit operator decision. The default is off. |
| 2 | The domain ship policy is `zte_allowed` | Only `swe`. `devops` and `iam` are `pr_only`, `soc` is `report_only`. Infrastructure, identity and detection changes always get a human. |
| 3 | Every required gate passed | `lint, types, unit, client, e2e, spec_review, redteam, secret_scan`, read from the persisted `GateReport`, not from the presence of state fields (the tac-7 bug). |
| 4 | E2E not skipped, budget not exhausted | A skipped check is not a passed check. |
| 5 | The PR exists and its CI checks are green | GitHub is the last independent verifier. The merge is a server-side squash, and your local checkout is never touched. |

Triggering ZTE from GitHub additionally requires an allowlisted author **and** the `tac:zte`
label (`trigger_webhook.decide`).

## Graduation ladder (from TAC-7)

1. **In-loop.** You prompt and review everything.
2. **Out-loop (PITER).** Run `adw_sdlc_iso` and review the PR yourself.
3. **ZTE for chores**, once chores reach a ≥90% clean pass rate over at least 10 runs.
4. **ZTE for bugs**, at the same bar.
5. **ZTE for features**, only with E2E coverage of the touched surface.

Measure the rungs with `agent/agentic_kpis.md`:

- **Attempts** should be 1–2.
- **Streak** should be climbing.
- **Gate pass rate** should be ≥ 0.9.
- **Presence** is the average attempts: how often you had to step back in.

Do not move a class of work up the ladder on a feeling. Move it on the numbers.

## Pre-flight checklist before setting `TAC_ZTE_ENABLED=1`

- [ ] CI (`.github/workflows/ci.yml`) is required on `main` via branch protection.
- [ ] Branch protection blocks direct pushes to `main`. The toolkit never pushes to base, but enforce it anyway.
- [ ] E2E specs exist for every user-facing flow the class of work touches.
- [ ] `TAC_TRIGGER_ALLOWED_USERS` is set and minimal, and the webhook secret has been rotated recently.
- [ ] ADWs run in a disposable container or VM without cloud credentials. A worktree is not a sandbox.
- [ ] `TAC_RUN_BUDGET_USD` is set to a value you would accept losing on a bad run.
- [ ] You have a rollback path: `git revert` of the squash commit, plus a deploy pipeline that follows `main`.
- [ ] The last 10 runs of this work class have ≥90% clean passes in `agentic_kpis.md`.

## What ZTE still cannot catch

- A spec that is wrong. The review checks the build against the plan, not against reality.
- Product or UX judgment calls.
- Security issues outside what the red-team agent and scanners look for.

Keep ZTE to work where a bad merge is cheap to revert.
