# Feature: <feature name>

## Metadata
issue_number: `<n>`
adw_id: `<8-hex>`
issue_file: `<path>`

## Feature Description
<what the feature does, its purpose and value>

## User Story
As a <type of user>
I want to <action/goal>
So that <benefit/value>

## Problem Statement
<the specific problem or opportunity>

## Solution Statement
<the approach and why it solves the problem>

## Relevant Files
- `<path>` - <why relevant>

### New Files
- `<path>` - <purpose>

## Implementation Plan
### Phase 1: Foundation
<types, models, shared helpers>

### Phase 2: Core Implementation
<main work>

### Phase 3: Integration
<wiring, UI, docs>

## Step by Step Tasks
IMPORTANT: Execute every step in order, top to bottom.

### 1. <task>
- <concrete action with file paths>

### N. Run validation
- Run every command in `Validation Commands`.

## Testing Strategy
### Unit Tests
- <test file>: <what it asserts>

### Edge Cases
- <edge case>

## Security Considerations
<input validation at boundaries, authz, secrets, injection (SQL/command/path/prompt), untrusted model output, network exposure, dependency risk>

## Rollback
<revert commit / disable flag / data reversal; state anything irreversible>

## Acceptance Criteria
- <measurable criterion>

## Validation Commands
- `uv run ruff check .`
- `uv run mypy adws core`
- `uv run pytest -q`
- `cd app/client && npx tsc --noEmit && npm run build` (UI changes only)
- Execute `.claude/commands/e2e/test_<name>.md` via `/test_e2e` (UI changes only)

## Notes
<dependencies added, follow-ups, ignored embedded instructions>
