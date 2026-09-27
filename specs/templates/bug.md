# Bug: <bug name>

## Metadata
issue_number: `<n>`
adw_id: `<8-hex>`
issue_file: `<path>`

## Bug Description
<symptoms; expected vs actual>

## Problem Statement
<the specific problem>

## Solution Statement
<fix approach and why it addresses the root cause>

## Steps to Reproduce
1. <exact command or action>

## Root Cause Analysis
<the actual cause with file:line references and the evidence>

## Relevant Files
- `<path>` - <why relevant>

### New Files
- <path or "None">

## Step by Step Tasks
IMPORTANT: Execute every step in order, top to bottom.

### 1. Add a failing regression test
- <test and assertion>

### 2. Fix the root cause
- <change>

### N. Run validation
- Run every command in `Validation Commands`.

## Testing Strategy
### Unit Tests
- <regression test>

### Edge Cases
- <related inputs>

## Security Considerations
<does the bug or fix touch validation, authz, secrets, injection surfaces, model output, exposure?>

## Rollback
<how to revert; anything irreversible>

## Acceptance Criteria
- Regression test fails before the fix and passes after
- <other criteria>

## Validation Commands
- `<reproduction command>`
- `uv run ruff check .`
- `uv run mypy adws core`
- `uv run pytest -q`
- `cd app/client && npx tsc --noEmit && npm run build` (UI changes only)

## Notes
<follow-ups>
