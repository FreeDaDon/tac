---
description: Install dependencies and prime (interactive)
---
# Install

## Security Rules
- Never read, create or print `.env`. Read `.env.sample` only.

## Run
1. `uv sync`
2. `cd app/client && npm ci` (skip if `app/client/package.json` does not exist)
3. Read and execute `.claude/commands/prime.md`.

## Report
- What was installed and any errors.
- Remind the user to create `.env` from `.env.sample` themselves (you must not check, read or create it), listing the variable names from `.env.sample` only.
- How to start the dashboard (`/start`) and run validation (`/test`).
