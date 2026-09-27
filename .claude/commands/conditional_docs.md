---
description: Map of documentation to the conditions under which it should be read
---
# Conditional Documentation Guide

Use this to decide which documentation to read for the task at hand. Read a document only if one of its
conditions matches your task. Do not read everything: context is a budget.

## Instructions
- Review the task you have been given.
- For each entry below, check its conditions. Read the document only if at least one condition matches.
- New feature docs are added under `docs/features/` by `/document`, which appends an entry here.

## Conditional Documentation

- README.md
  - Conditions:
    - When first understanding the project structure
    - When you need the commands to install, start, test or run workflows

- docs/playbook/00-principles.md
  - Conditions:
    - When planning any feature, bug or chore
    - When designing a new ADW, slash command or gate
    - When deciding what to automate or where a change belongs (agentic layer vs application layer)

- docs/playbook/01-tac-progression.md
  - Conditions:
    - When mapping a TAC course concept to where it lives in this toolkit
    - When changing ADW phase behavior that fixed a known course bug (hooks, test parsing, review gating, ZTE, arguments)

- docs/playbook/02-architecture.md
  - Conditions:
    - When adding or changing an ADW phase, module or trigger under `adws/`
    - When you need to know how plan/build/test/review/redteam/document/ship fit together

- docs/playbook/04-zte-readiness.md
  - Conditions:
    - When touching ship/merge logic, gates required for ZTE, or domain ship policies

- docs/playbook/06-advanced-patterns.md
  - Conditions:
    - When working on the model router, budgets, cache, lessons memory, red-team gate or task-board triggers

- docs/playbook/07-operations-runbook.md
  - Conditions:
    - When running, debugging or cleaning up workflows, worktrees or triggers

- app/README.md
  - Conditions:
    - When working on anything under `app/` (dashboard API, WebSocket, client)
    - When changing event ingestion (`/api/events`, `/api/hook-events`) or dashboard security settings

- docs/playbook/03-security-model.md
  - Conditions:
    - When touching `adws/adw_modules/security.py`, `agent.py`, triggers, webhooks, hooks or `.claude/settings.json`
    - When a change handles untrusted input (issues, logs, webhooks, model output) or secrets
    - When changing ship/merge behavior, ZTE, permissions or budgets

- .claude/commands/test_e2e.md
  - Conditions:
    - When a plan includes UI behavior and needs a new E2E spec under `.claude/commands/e2e/`

- .claude/commands/e2e/test_dashboard_loads.md
  - Conditions:
    - When writing a new E2E spec (use as the format reference)
    - When changing dashboard KPI tiles or the runs table

- .claude/commands/e2e/test_live_events.md
  - Conditions:
    - When changing `/api/events`, event streaming, or the live timeline

- .claude/commands/e2e/test_run_detail.md
  - Conditions:
    - When changing the run detail view, run phases, gates or cost display

- core/common.py
  - Conditions:
    - When adding or changing a deterministic domain tool (devops, soc, iam) or its findings
    - When writing prompts that consume `AnalysisReport` findings

- specs/templates/
  - Conditions:
    - When writing a plan by hand, or an infra change, incident triage or access review document

<!-- /document appends entries for docs/features/*.md below this line -->
