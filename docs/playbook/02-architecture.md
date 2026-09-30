# 02 — Architecture

## Layers

```
            Triggers (PITER: T)                         Humans
   webhook (HMAC) · cron · Todone tasks.md        CLI · dashboard · PR review
                 │                                        │
                 ▼                                        ▼
┌──────────────────────────── AI Developer Workflows (adws/) ───────────────────────────┐
│ plan ─▶ build ─▶ test ─▶ review ─▶ redteam ─▶ document ─▶ (ship, ZTE only)           │
│  each phase = deterministic Python orchestrating focused, single-purpose agents        │
│                                                                                        │
│ adw_modules: state · agent(runner, router, budget, cache) · security · gates · repair  │
│              redteam · memory · kpis · telemetry · git/github/worktree · domains       │
└────────────┬───────────────────────────┬──────────────────────────┬───────────────────┘
             │ slash-command templates   │ deterministic tools      │ events
             ▼                           ▼                          ▼
      .claude/commands/*.md         core/ (no LLM)           app/ control plane
      (prompt layer, hooks,         security · devops ·      FastAPI + WebSocket
       hardened settings)           soc · iam · mcp_gov ·    + Vite/TS console
                                        gcp_sre · export
```

**Rule of thumb:** code owns state, control flow, validation and verdicts. Agents own
translation and judgment (plan, implement, repair, review, interpret). Every agent output
crosses a typed boundary (`utils.parse_json` + pydantic) before code acts on it.

## One run, end to end

| Step | Deterministic (code) | Non-deterministic (agent) |
|---|---|---|
| Plan | adw_id, state, sanitize and fence the issue, allocate ports, create worktree, compute plan path | classify issue, branch slug, write the spec to the given path |
| Build | validate worktree, commit, push, PR | `/implement <plan>` |
| Test | run gates from main checkout config, parse JUnit, decide pass or fail | one `/resolve_failed_test` per failing check |
| E2E | start app on the run's port, collect results | `/test_e2e` via Playwright MCP, `/resolve_failed_e2e_test` |
| Review | diff to file, loop control, gate verdict | `/review`, `/patch` for each blocker |
| Red team | test-tampering diff scan, ruff `S` rules, secret scan | `/redteam` adversarial audit |
| Document | KPIs, lesson files | `/document`, `/reflect` |
| Ship | five locks, server-side squash merge | none |

## State and artifacts

```
agent/
  runs/<adw_id>/state.json         ADWStateData (atomic write + flock); keeps unknown keys
  runs/<adw_id>/events.jsonl       telemetry, source of truth for the dashboard
  runs/<adw_id>/inputs/            issue (fenced), diffs, failure payloads handed to agents by path
  runs/<adw_id>/<agent_name>/      prompt.md + raw_output.jsonl per agent call (names unique per iteration)
  runs/<adw_id>/test_reports/      junit.xml
  reports/<adw_id>/                domain pack outputs: report.md, findings.json, findings.sarif
  lessons/*.md + INDEX.md          durable lessons (one per file)
  kpis.jsonl → agentic_kpis.md     KPI rows, rendered table
  cache.db                         read-only prompt cache
trees/<adw_id>/                    git worktree + .ports.env (ports, per-run DB path)
```

## Isolation

- **Worktree per run**: `trees/<adw_id>`, branched from `origin/<base>` or the local base branch.
- **Ports**: backend 9100–9149, frontend 9150–9199. The starting slot is `int(adw_id,16) % 50`. The allocator probes with `bind()` and skips slots already recorded in another tree's `.ports.env`. That allows 50 concurrent runs.
- **Database per run**: `TAC_DB_PATH` in `.ports.env`, pointing at `trees/<id>/agent_data/<id>.db`.
- **No secrets in worktrees**: tac-7 copied `.env` into every worktree. This toolkit passes an allowlisted environment to subprocesses instead (`security.safe_subprocess_env`).
- **Trusted config comes from the main checkout**: slash-command templates and gate commands are read from the main checkout. An agent that edits them inside its worktree cannot change its own prompts or weaken its own gates.

## Policy as code (optional)

`infra/terraform/modules/mcp-connector` renders an MCP server manifest in the exact JSON shape
`core/mcp_gov/manifest.py` scans, with variable validations and a `terraform_data.guard`
precondition block mirroring the scanner's own rules (wildcard/admin scopes, plaintext transport,
broad audience, missing review ticket outside `dev`). A bad connector config fails at
`terraform plan` before a human ever runs the scanner — and the scanner still runs as an
independent second gate afterward, so a bypass of one layer doesn't silently pass. It never
registers, enables or talks to a real connector; the only provider is `hashicorp/local`, rendering
JSON files to disk. See [`infra/terraform/README.md`](../../infra/terraform/README.md).

## Extending

- **New workflow phase**: write `run(adw_id) -> bool` in `adws/adw_<name>_iso.py` and wrap the body in `workflow_ops.phase(...)`. Record a `GateResult` and add it to `PHASES` in `adw_sdlc_iso.py`.
- **New agent command**: add `.claude/commands/<name>.md` with an exact output contract, register it in `model_router.COMMAND_CLASS`, and add a `mock_agent` handler.
- **New domain tool**: add `core/<pack>/<tool>.py` returning `AnalysisReport`, register it in `core/registry.py`, add a fixture and tests.
- **New domain**: add a `DomainSpec` in `adw_modules/domains.py` with its ship policy.
