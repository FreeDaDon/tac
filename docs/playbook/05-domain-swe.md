# 05 — Domain pack: SWE (SDLC pipeline, red team, secret gate)

**Ship policy: `zte_allowed`, behind gates.** SWE is the only pack that can auto-merge. It can do
so only when every lock in [04-zte-readiness](04-zte-readiness.md) holds, including the
deterministic `secret_scan` gate below.

## What it automates

The full SDLC: issue, plan, build, test, review, red team, document, ship
(`adw_sdlc_iso`, `adw_sdlc_zte_iso`). This pack's `core/` tools are the deterministic checks that
the pipeline and `/redteam` rely on.

## Deterministic tools (`core/security/`)

| Tool | Input | Detects |
|---|---|---|
| `secret_scan` | A directory or file | AWS access key IDs, GitHub (`ghp_`, `gho_`, `github_pat_`...), Anthropic (`sk-ant-`), OpenAI (`sk-`), Slack (`xox*`) and private-key headers. Also high-entropy values assigned to secret-like names (Shannon entropy 3.5 or more, mixed character classes, placeholders ignored). It skips binary files, `.git`, `node_modules`, `.venv`, `trees/`, `agent/runs`, `dist` and tool caches. |
| `sql_lint` | `.sql`, one query per line | `SQL-DANGEROUS-OP`, `SQL-COMMENT`, `SQL-INJECTION` (tautologies, stacked statements) and `SQL-UNION-INJECTION` (UNION after a closed quote, NULL column probing, catalog reads). A plain `a UNION SELECT b` passes. |
| `unicode_scan` | A file or directory | `SWE-BIDI` (Trojan Source, CVE-2021-42574) and `SWE-ZERO-WIDTH`. |

```bash
uv run python -m core.registry swe . --fail-on high                             # the ZTE gate
uv run python -m core.registry swe . --format sarif --out secrets.sarif         # code scanning
uv run python -m core.registry swe queries.sql
uv run python -m core.registry swe src --tool unicode_scan
```

The library side (`core/security/sql_security.py`) is used by the app at runtime.
`validate_identifier`, `escape_identifier`, `execute_query_safely`, `validate_sql_query`,
`build_safe_in_clause` and `sanitize_value_for_like` guard every query. `sanitize.py`
(`sanitize_untrusted`, `escape_markdown`, `markdown_code`) handles any untrusted text on its way
into a report or prompt.

## Secret findings and the allowlist

- A finding never contains the secret. It carries only the first 4 characters, the length and a 16-hex sha256 `fingerprint`.
- `.secretsallow` at the repo root holds path globs relative to that file, such as `core/fixtures/**`, or `fingerprint:<hex16>` lines. The scanner uses the nearest `.secretsallow` at or above the scan root, so worktrees under `trees/` apply their own copy.
- Allowlist a fingerprint for a known test value. Never allowlist a whole source directory to make a gate pass.

## The agent's role

- The ADW pipeline calls the slash commands `/feature`, `/bug`, `/chore`, `/implement`, `/test`, `/review`, `/document` and `/redteam`.
- `/redteam` reviews the diff adversarially. Its findings, together with the deterministic `secret_scan` gate, decide the `redteam` and `secret_scan` gates.
- The agent may fix code in its worktree. It may not edit `.secretsallow`, weaken a gate, or mark a skipped check as passed.

```bash
uv run adws/adw_sdlc_iso.py --issue 42           # PR for human review
uv run adws/adw_sdlc_zte_iso.py --issue 42       # auto-merge only if all ship locks hold
uv run adws/adw_domain_iso.py --pack swe --input . --no-agent
```

## Safety notes

- The regexes are tuned for low noise, not completeness. Keep push protection or server-side scanning enabled as well.
- A real hit means rotating the credential. Deleting the line does not remove the secret from git history.
- The fixture repo `core/fixtures/swe/sample_repo` contains deliberately fake keys, and they are allowlisted by path.

## Extending

1. New credential format: add a `SecretRule` to `RULES` in `secret_scan.py`. Test it with a value built by string concatenation, so the test file itself stays clean. Add a negative case.
2. New SQL signature: add it to `INJECTION_PATTERNS` or `UNION_INJECTION_PATTERNS` in `sql_security.py`, with legitimate queries that must still pass.
3. New tool: write `analyze_file(path, **opts) -> AnalysisReport` and register it in `PACK_TOOLS["swe"]`. Directories default to `secret_scan`.
