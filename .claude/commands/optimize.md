---
description: Profile and optimize a target with before/after measurements (interactive)
argument-hint: <target: file, function, endpoint or command, plus goal>
---
# Optimize

Make the target measurably faster or cheaper without changing behavior. Measure first; no measurement,
no change.

## Target
$ARGUMENTS

## Security Rules
- Never read `.env` files or credential files. Never print secrets.
- Do not disable validation, security checks, caching correctness, or tests to gain speed.

## Instructions
1. **Define the metric.** From the target, pick one primary metric (latency p50/p95, wall time, memory, tokens/cost, bundle size) and the exact command that measures it. If the target is empty or unmeasurable, stop and say what is needed.
2. **Baseline.** Run the measurement at least 3 times; record median and spread. Confirm `uv run pytest -q` passes before changing anything.
3. **Profile.** Find where the time/memory/cost actually goes (`uv run python -m cProfile -s cumtime ...`, `uv run python -X importtime ...`, timing logs, `npm run build` output for bundles). Do not guess.
4. **Change one thing at a time**, targeting the largest measured cost. Prefer algorithmic and I/O fixes (N+1 calls, repeated parsing, missing indexes, unnecessary work) over micro-optimizations.
5. **Re-measure** the same way after each change. Keep a change only if it improves the metric beyond noise; revert it otherwise.
6. **Validate** behavior: `uv run ruff check .`, `uv run mypy adws core`, `uv run pytest -q` (and the client build if touched).

## Report
- Metric, command, baseline vs final (median, spread, percent change).
- Each change kept, with its individual effect; changes tried and reverted.
- Validation results and `git diff --stat`.
