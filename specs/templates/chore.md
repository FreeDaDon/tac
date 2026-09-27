# Chore: <chore name>

## Metadata
issue_number: `<n>`
adw_id: `<8-hex>`
issue_file: `<path>`

## Chore Description
<what and why; must not change user-visible behavior>

## Relevant Files
- `<path>` - <why relevant>

### New Files
- <path or "None">

## Step by Step Tasks
IMPORTANT: Execute every step in order, top to bottom.

### 1. <task>
- <action>

### N. Run validation
- Run every command in `Validation Commands`.

## Validation Commands
- `uv run ruff check .`
- `uv run mypy adws core`
- `uv run pytest -q`

## Notes
<follow-ups>
