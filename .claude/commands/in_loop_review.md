---
description: Check out an agent branch and start the app for a human review (interactive)
argument-hint: <branch_name>
---
# In-Loop Review

Quickly check out an agent's branch and start the dashboard so a human can inspect the work.

## Variables
branch: $ARGUMENTS

## Instructions
- If `branch` is empty, stop and report that a branch argument is required.
- Run `git status --porcelain`. If the working tree has uncommitted changes, stop and tell the user; do not stash or discard anything.
- `git fetch origin` then `git checkout <branch>` (use `git worktree list` first: if the branch is already checked out in `trees/<adw_id>/`, review it there instead of checking it out).
- Run `/install` steps if dependencies changed (`pyproject.toml`, `uv.lock`, `app/client/package-lock.json` differ from the base branch).
- Start the app as described in `.claude/commands/start.md` (rebuild the client first with `cd app/client && npm run build` if `app/client` changed).
- Find the plan for this branch under `specs/` (name contains the issue number / adw id) and list its Acceptance Criteria.

## Report
- Branch, commit, and the URL to open.
- The spec path and its acceptance criteria as a checklist for the human reviewer.
- `git diff --stat` against the base branch.
