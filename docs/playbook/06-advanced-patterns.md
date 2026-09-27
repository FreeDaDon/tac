# 06 — Advanced patterns (beyond the TAC curriculum)

Each pattern below is implemented, tested, and opt-out-able. Where it has limits, this page says so.

## 1. Cost-aware model router + hard budgets
**Files:** `adws/adw_modules/model_router.py`, `budget.py`, `agent.py`

- Every slash command has a task class: `mechanical`, `standard` or `heavy`. The model set `base|heavy` maps each class to haiku, sonnet or opus.
- Cost is read from Claude Code's `result` message (`total_cost_usd`, `usage`) and accumulated into run state.
- At **80%** of `TAC_RUN_BUDGET_USD`, heavy commands are downgraded from opus to sonnet.
- At **100%**, every further agent call returns `BUDGET_EXCEEDED` without running. The workflow fails with state saved, so the run can be resumed after raising the budget.

**Why:** a stuck repair loop on opus is the most common way an autonomous pipeline burns money.

## 2. Adversarial red-team gate
**Files:** `adws/adw_modules/redteam.py`, `.claude/commands/redteam.md`, `adws/adw_redteam_iso.py`

A separate agent with a hostile persona audits the diff. It gets the deterministic scanner results first:

- **Test tampering:** deleted test files, added skip/xfail/noqa/ts-ignore, net assertions removed.
- **ruff `S` rules** on changed Python files.
- **Secret scan.**

Any critical or high finding fails the gate. The agent cannot suppress scanner findings, because they are merged in code.

**Why:** the builder agent's incentive is "make the tests pass", and the cheapest way to do that is to weaken the tests. A second agent with the opposite incentive, plus diff-level checks, catches that.

## 3. Lessons memory (reflective loop)
**Files:** `adws/adw_modules/memory.py`, `.claude/commands/reflect.md`, `adw_document_iso.reflect`

- After any run that needed a repair, failed a gate, or needed more than one review round, `/reflect` extracts 0–3 durable lessons as JSON.
- Code writes one file per lesson under `agent/lessons/`. Files are deduplicated by slug and the index is rebuilt.
- Planning calls `memory.relevant()`, which scores by tag and keyword overlap, and hands the top-k lessons to the planner.

**Deliberately not a vector DB.** Files are diffable, reviewable in PRs, and trivially deletable when wrong. Move to embeddings only when you have more than a few hundred lessons and retrieval quality measurably suffers.

## 4. Read-only prompt cache ("semantic" cache)
**Files:** `adws/adw_modules/cache.py`

- **Key:** SHA-256 of the command, the model, the normalized prompt (volatile tokens such as adw ids and timestamps removed, whitespace collapsed) and the git tree hash including uncommitted diff.
- **Allowlist only:** `/classify_issue`, `/generate_branch_name`, `/review`, `/redteam`. These do not mutate the repo, so replaying their text output is equivalent to re-running them. Mutating commands are **never** cached, because replaying `/implement`'s text would not replay its edits.

**Honest value:** small. It is mostly useful on resumed runs and repeated reviews of an unchanged tree. Disable it with `TAC_CACHE_ENABLED=0`.

## 5. Trust boundaries by construction
- Payloads go to agents **as file paths** (`agent.write_input_file`), never inlined into argv. This fixed the tac-7 argument splitting and keeps untrusted text fenced.
- Paths that come from the model are resolved and checked (`security.resolve_inside`). The planner writes to a path **code chose**, and code verifies that it exists.
- Templates and gate configuration are read from the main checkout only, so an agent cannot rewrite the rules that judge it.

## 6. Deterministic domain analysis + agent interpretation
**Files:** `core/`, `adws/adw_domain_iso.py`

Tools produce `AnalysisReport` findings with stable rule ids and export to SARIF. The agent only ranks the findings, explains them, and proposes changes. Its output is a typed `DomainAssessment`, with `requires_human_approval` on every action. Nothing in a domain pack executes a change.

## 7. Observability as a first-class output
Every phase and agent call emits a `TelemetryEvent` to JSONL first and pushes it to the dashboard second, best-effort. The dashboard can be down without affecting runs. Hook events from interactive Claude Code sessions land in the same stream (`/api/hook-events`).

## Candidates not implemented (and why)
- **Automatic model escalation on repeated failure** (sonnet to opus on attempt 3). This is easy to add in `repair.py`, but it fights the budget. Add it once KPI data shows opus actually resolves what sonnet can't.
- **Parallel speculative implementations** (N agents, keep the one that passes gates). Effective, but it multiplies cost by N. It fits best-of-N for high-value features and is not needed by default.
- **Container sandbox per run.** This is the right next step for untrusted repos; see 03-security-model. It is left to your infrastructure (Docker, Firecracker) rather than baked in.
