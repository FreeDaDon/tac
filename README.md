# TAC Toolkit — Expert Agentic Engineering Playbook

A production-grade framework for running AI coding agents **out of the loop** safely: turning
an issue into a validated PR, with worktree isolation, typed trust boundaries, self-healing test
loops, an adversarial red-team gate, cost budgets, a live control plane, and runnable domain packs
for **Software Engineering, DevOps/IaC, SOC, IAM, MCP/AI-connector governance and GCP SRE**.

It generalizes the Tactical Agentic Coding course architecture (TAC-2 → TAC-8) and fixes the
places where the course code was educational rather than safe. See
[01-tac-progression](docs/playbook/01-tac-progression.md) for the mapping and the list of fixes.

```
issue ─▶ plan ─▶ build ─▶ test+repair ─▶ e2e+repair ─▶ review+patch ─▶ red team ─▶ document ─▶ ship*
           └── each step: deterministic code orchestrating one focused agent ──┘      *5 locks, ZTE only
```

## Quickstart

```bash
uv sync && (cd app/client && npm ci && npm run build)
scripts/check.sh                                   # every gate, locally

# zero-cost dry run of the whole pipeline (mock agent, real gates, real worktree)
TAC_AGENT_RUNNER=mock uv run adws/adw_sdlc_iso.py --issue-file specs/examples/issue.md

# real run (needs ANTHROPIC_API_KEY or a logged-in `claude` CLI)
uv run adws/adw_sdlc_iso.py --issue 42                  # GitHub issue -> PR
uv run adws/adw_domain_iso.py --pack soc --input core/fixtures/soc/auth.log
uv run adws/adw_domain_iso.py --pack mcp_gov --input core/fixtures/mcp_gov --fail-on high   # AI connector intake
uv run adws/adw_domain_iso.py --pack gcp_sre --input core/fixtures/gcp_sre                   # GCP SRE triage
scripts/start.sh                                         # dashboard at http://127.0.0.1:8000
```

## Layout

| Path | What it is |
|---|---|
| `adws/` | AI Developer Workflows: `adw_{plan,build,test,review,redteam,document,ship}_iso.py`, the composites `adw_sdlc_iso.py` and `adw_sdlc_zte_iso.py`, and `adw_domain_iso.py` |
| `adws/adw_modules/` | state, agent runner, model router, budget, cache, security, gates, repair, redteam, memory, KPIs, telemetry, git, GitHub, worktree, Jev typed decisions |
| `adws/adw_triggers/` | HMAC-verified webhook, cron poller, Todone `tasks.md` queue |
| `.claude/` | slash-command templates (the prompt layer), fail-closed hooks, hardened `settings.json` |
| `core/` | deterministic domain tools, no LLM calls: security, devops, soc, iam, mcp_gov, gcp_sre, export (md/json/SARIF), fixtures |
| `app/` | control plane: FastAPI with a WebSocket event stream, and a Vite/TypeScript operator console |
| `agent/` | runtime: run state and events, KPIs (`agentic_kpis.md`), lessons memory, reports |
| `specs/` | plan templates in `specs/templates/` (feature, bug, chore, patch, infra_change, incident_triage, access_review, ai_connector_review, gcp_sre_incident) and generated plans |
| `docs/playbook/` | the playbook: start at [00-principles](docs/playbook/00-principles.md) |

## Guarantees (enforced in code, covered by tests)

- **Model output is untrusted.** Every agent response is parsed into a pydantic schema. Malformed output is a failed attempt, never a pass. Model-supplied paths must resolve inside the run's worktree.
- **Untrusted input is fenced.** Issue, log and webhook content is sanitized, marked with injection signals, and handed to agents as a file path.
- **Isolation.** Each run gets its own git worktree, its own port pair (backend 9100–9149, frontend 9150–9199), and its own database file. No secrets are copied into worktrees, and subprocesses get an allowlisted environment.
- **`--dangerously-skip-permissions`** is only used inside `trees/<adw_id>` **and** with `TAC_ALLOW_SKIP_PERMISSIONS=1`. Otherwise agents run under `settings.json` with a fail-closed `PreToolUse` hook.
- **Narrow self-healing.** One failing check leads to one focused repair agent. The loop stops when failures stop changing.
- **Gates judge from the main checkout.** Gate commands and templates can't be weakened by the agent being judged.
- **Zero-Touch shipping is locked.** It requires an operator flag, a domain policy that allows it, all eight gates green (E2E not skipped), budget left, and green PR checks. The merge happens server-side, never in your checkout.
- **Budgets.** Cost per run is tracked from Claude Code's own accounting. Heavy commands are downgraded at 80% of the budget, and agent calls stop at 100%.

## Jev typed decisions (advisory only)

Mechanical-class classification calls (`/classify_issue`) try a cheap, schema-validated typed
decision first, via [Jev](https://typesafe.ai) (TypeSafe AI's System One API) — a single
`{model, state, questions}` → `{choice, probabilities, confidence}` round trip instead of a full
agent subprocess. A low-confidence or failed Jev call always falls back to the existing full-agent
command unchanged; Jev never gates a pass/fail decision, a security check, or a ship/merge step.
See [`adws/adw_modules/jev.py`](adws/adw_modules/jev.py) and principle 17 in
[00-principles](docs/playbook/00-principles.md).

```bash
# .env
JEV_BACKEND=mock        # default: offline, deterministic, zero cost, no network
JEV_BACKEND=typesafe    # TypeSafe's own endpoint — needs TYPESAFE_API_KEY (console.typesafe.ai/keys)
JEV_BACKEND=openrouter  # OpenRouter's decision endpoint — needs OPENROUTER_API_KEY
JEV_BACKEND=live        # alias: prefers TYPESAFE_API_KEY, then OPENROUTER_API_KEY, whichever is set
```

If a live provider ever has an outage or a bad key, set `JEV_BACKEND=mock` and every workflow that
uses Jev keeps working unchanged — it was always advisory, never load-bearing.

## Playbook

| Doc | Topic |
|---|---|
| [00-principles](docs/playbook/00-principles.md) | TAC operating rules and this toolkit's additions |
| [01-tac-progression](docs/playbook/01-tac-progression.md) | TAC-2 → TAC-8, mapped to files here, and the course defects that were fixed |
| [02-architecture](docs/playbook/02-architecture.md) | layers, a run end to end, state layout, isolation, extension points |
| [03-security-model](docs/playbook/03-security-model.md) | threat model, controls, residual risks |
| [04-zte-readiness](docs/playbook/04-zte-readiness.md) | the ship locks, the graduation ladder, the pre-flight checklist |
| 05-domain-[swe](docs/playbook/05-domain-swe.md) / [devops](docs/playbook/05-domain-devops.md) / [soc](docs/playbook/05-domain-soc.md) / [iam](docs/playbook/05-domain-iam.md) / [mcp-gov](docs/playbook/05-domain-mcp-gov.md) / [gcp-sre](docs/playbook/05-domain-gcp-sre.md) | domain packs |
| [06-advanced-patterns](docs/playbook/06-advanced-patterns.md) | router and budgets, red team, lessons memory, cache: what each is worth |
| [07-operations-runbook](docs/playbook/07-operations-runbook.md) | daily commands, triage, failure table, maintenance |

## Requirements

Python 3.12 with uv, Node 22 with npm, git, the `claude` CLI, and `gh` for the GitHub flow.
Terraform, SIEMs and cloud CLIs are **not** required: the domain packs analyze exported artifacts
(`terraform show -json`, log files, Splunk exports, scanner JSON, IAM exports, MCP manifests).
