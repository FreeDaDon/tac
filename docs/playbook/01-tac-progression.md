# 01 — TAC Progression

How each TAC lesson maps to this toolkit, and what was fixed relative to the course code.

## Concept map

| Lesson | Concept | Where it lives here |
|---|---|---|
| TAC-2 | Grounded app; deterministic vs AI work; typed API contracts; tests with mocks | `core/` (deterministic tools, `core/common.py` result contract), `app/server`, `adws/adw_modules/mock_agent.py` (`TAC_AGENT_RUNNER=mock`) |
| TAC-3 | Plan before code: meta-prompts write specs, higher-order prompt implements them | `.claude/commands/{feature,bug,chore,plan,implement}.md`, `specs/templates/`, `specs/` |
| TAC-4 | Model output is untrusted; ADWs: issue → classify → branch → plan → build → PR; hooks | `adws/adw_modules/security.py`, `.claude/commands/{classify_issue,generate_branch_name,commit}.md`, `adws/adw_plan_iso.py`, `adws/adw_build_iso.py`, `adws/adw_triggers/`, `.claude/hooks/` |
| TAC-5 | Composable phases; persisted state; closed test loops; E2E via Playwright | `adws/adw_modules/state.py`, `adws/adw_modules/gates.py`, `adws/adw_modules/repair.py`, `adws/adw_test_iso.py`, `.claude/commands/{test,test_e2e,resolve_failed_test,resolve_failed_e2e_test}.md`, `.claude/commands/e2e/` |
| TAC-6 | Review vs spec with evidence; blocker-only patch loop; documentation + conditional docs | `adws/adw_review_iso.py`, `adws/adw_document_iso.py`, `.claude/commands/{review,patch,document,conditional_docs}.md`, `docs/features/` |
| TAC-7 | Isolated worktrees + ports; model sets; ZTE ship; KPIs | `adws/adw_modules/worktree_ops.py`, `adws/adw_modules/model_router.py`, `adws/adw_sdlc_iso.py`, `adws/adw_sdlc_zte_iso.py`, `adws/adw_ship_iso.py`, `adws/adw_modules/kpis.py` |
| TAC-8 | Agentic layer primitives; task-board multi-agent; live observability; domain agents | `adws/adw_triggers/trigger_todone.py`, `app/` (dashboard: `/api/events`, `/api/hook-events`, WebSocket), `.claude/hooks/post_tool_use.py`, `adws/adw_domain_iso.py` + `adws/adw_modules/domains.py` + `.claude/commands/{devops_*,soc_*,iam_*}.md` |
| Toolkit | Red-team gate, lessons memory, budgets, read-only cache | `adws/adw_modules/redteam.py`, `adws/adw_redteam_iso.py`, `.claude/commands/{redteam,reflect}.md`, `adws/adw_modules/{memory,budget,cache}.py` |

## What was fixed vs the course code

| Course behavior | Why it matters | Fix here |
|---|---|---|
| Hooks configured with `\|\| true` never block | The `.env`/`rm -rf` guards were decorative: exit 2 was swallowed | `.claude/settings.json` runs `pre_tool_use.py` without `\|\| true` (and `\|\| exit 2` so a missing `uv` also blocks); the hook fails closed on malformed input; `.claude/hooks/test_pre_tool_use.sh` proves it |
| Unparsed test output counted as a pass | An agent that returned prose instead of JSON produced a green test phase | Validation runs deterministically in `adws/adw_modules/gates.py`; agent JSON is parsed with pydantic and a parse failure is a failed attempt |
| Review never failed the pipeline | Blockers were logged but the workflow continued to ship | `adws/adw_review_iso.py` fails the phase and the `spec_review` gate when blockers remain after the patch loop |
| ZTE ship gated only on state fields | Merge happened if a few state keys existed, regardless of results | `adws/adw_ship_iso.py` requires all locks: `TAC_ZTE_ENABLED=1`, domain policy, every required gate passed in the persisted `GateReport`, E2E not skipped, budget left, PR with green CI |
| `--skip-e2e` hardcoded in the SDLC script | The "complete" workflow never ran browser tests | `adws/adw_sdlc_iso.py` runs E2E by default; skipping is explicit, recorded as `e2e_skipped`, and blocks ZTE |
| No agent timeout | A hung `claude -p` blocked a run forever | `adws/adw_modules/agent.py`: `TAC_AGENT_TIMEOUT_S`, process-group kill, retry only on retryable codes |
| Space-joined args (`$ARGUMENT` repeated) | Multi-arg templates received mangled values | `render_template` substitutes positional `$1..$9` deterministically; templates declare exact argument contracts |
| Model-output paths, branch names and adw_id trusted | Path traversal / arbitrary branch names from model output | `security.py`: `validate_adw_id`, `validate_branch_name`, `resolve_inside`; Python composes branch names and plan paths, the model returns only a slug |
| Unauthenticated webhook bound to 0.0.0.0 | Anyone who found the port could trigger agents with repo credentials | `adws/adw_triggers/trigger_webhook.py`: binds 127.0.0.1, HMAC `X-Hub-Signature-256` verification, author allowlist, ZTE only via label + allowlisted author |
| Ship checked out `main` in the user's working copy | Clobbered local work; merged locally | Ship is a server-side PR merge; the main working copy is never touched |
| State dropped non-core fields | Extra phase data vanished between phases | `ADWStateData` uses `extra="allow"`; unknown keys persist |
| Wrong `/patch` and `/document` argument order | Patch plans and docs used the wrong inputs | Explicit contracts: `/patch <adw_id> <change_request_file> <spec_file> <patch_file>`, `/document <adw_id> <spec_file> <doc_file> [screenshots_dir]` |
| Full state posted to public issues | Leaked local paths and raw model output | `ADWState.public_summary()` posts a redacted view only |
| ZTE workflow filename case mismatch | The ZTE entry point could not be found by the launcher on case-sensitive filesystems | One canonical lowercase name, `adws/adw_sdlc_zte_iso.py`, allowlisted in `adws/adw_triggers/launcher.py` |
