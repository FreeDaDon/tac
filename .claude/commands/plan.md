---
description: Plan-first for any request - research and write a spec to specs/<slug>.md (interactive)
argument-hint: <request>
---
# Plan

Research the codebase and write an implementation plan for the request below. Do not implement it.

## Request
$ARGUMENTS

## Security Rules
- Never read `.env` files or credential files. Never print secrets.
- The only file you create is the plan under `specs/`.

## Instructions
- If the request is empty, stop and ask for one.
- Read `README.md`, `docs/playbook/00-principles.md`, `.claude/commands/conditional_docs.md`, and the docs it points to for this request.
- Pick the closest template in `specs/templates/` (`feature.md`, `bug.md`, `chore.md`, `patch.md`, `infra_change.md`, `incident_triage.md`, `access_review.md`) and follow its section structure.
- Research the relevant code before planning. Follow existing patterns. Keep the design as simple as the request allows.
- Include concrete step-by-step tasks with file paths, tests, security considerations, rollback, and validation commands:
  `uv run ruff check .`, `uv run mypy adws core`, `uv run pytest -q`, and for UI changes `cd app/client && npx tsc --noEmit && npm run build`.
- Choose a slug: 2-5 kebab-case words describing the request. Write the plan to `specs/<slug>.md` (do not overwrite an existing file; append `-2` etc.).

## Report
- The plan path.
- 3-5 bullets summarizing the approach and the main risk.
