# 05 — Domain pack: SOC (triage, detection tuning, vulnerability priority)

**Ship policy: `report_only` for triage** (`--propose` is ignored). **Rule changes are `pr_only`.**
A tuned Sigma rule reaches the SIEM only through a human-approved PR.

## What it automates

- First-pass triage of authentication logs, identity events and Zeek connection logs.
- Scoring a Sigma rule against labeled events. This gives the precision, recall and false-positive numbers for SIEM tuning.
- Ordering scanner output (Trivy, Grype) by exploitability rather than raw CVSS.

## Deterministic tools (`core/soc/`)

| Tool | Input | Detects |
|---|---|---|
| `auth_log` | `auth.log`, `syslog`, `secure`, `*.log` | `SOC-BRUTEFORCE` (5 or more failures from one IP in 10 minutes). It becomes critical as `SOC-BRUTEFORCE-SUCCESS` when a login from that IP then succeeds. Also `SOC-PASSWORD-SPRAY` (one IP, 5 or more users in 30 minutes) and `SOC-UNUSUAL-SUDO` (sudo to root by a user who is neither a known admin nor a regular sudo user). |
| `json_events` | `*.jsonl` (ECS-style fields: `@timestamp`, `event.action`, `event.outcome`, `user.name`, `source.ip`, `source.geo.location`) | The same detectors, plus `SOC-IMPOSSIBLE-TRAVEL` (haversine speed above 900 km/h, needs lat/lon). |
| `zeek` | `conn.log` (TSV with a `#fields` header) | `SOC-PORTSCAN` (20 or more host:port targets in 60 seconds), `SOC-BEACON` (10 or more connections with inter-arrival coefficient of variation at or below 0.1), `SOC-LARGE-OUTBOUND` (100 MB or more from RFC1918 to external). |
| `sigma` | Sigma YAML plus labeled JSONL (`label: malicious\|benign`) | Lint (`SIGMA-LINT-*`: missing id, level or falsepositives, broad values, unused selections, bad condition). Evaluation gives `tp/fp/fn/tn`, `precision`, `recall`, `false_positive_rate` and `f1`, plus a `SIGMA-FP` finding carrying each offending event. |
| `vuln_triage` | Trivy JSON (`Results`) or Grype JSON (`matches`), plus a KEV list | `VULN-P1` to `VULN-P4`, sorted by priority. P1 means in CISA KEV, or CVSS 9 or more with EPSS 0.5 or more. `evidence.reasons` explains each rating. |

```bash
uv run python -m core.registry soc /var/log/auth.log --opt admin_users=alice,ops
uv run python -m core.registry soc events.jsonl --opt max_speed_kmh=1000
uv run python -m core.registry soc conn.log --opt beacon_min_connections=20
uv run python -m core.registry soc rules/ssh_bruteforce.yml --opt events=labeled_events.jsonl
uv run python -m core.registry soc trivy.json --opt kev=known_exploited_vulnerabilities.json
uv run python -m core.registry soc core/fixtures/soc --format sarif --out soc.sarif   # whole directory
```

By convention, `sigma` finds `labeled_events.jsonl` beside the rule or in its parent directory,
and `vuln_triage` finds `kev.json` beside the report. `--opt` overrides both. The KEV file can be
the CISA catalog (`vulnerabilities[].cveID`) or `{"cveIDs": [...]}`. Every threshold listed above
is an `--opt`. See each `analyze_file` for the option names.

## The agent's role

- `/soc_triage` receives the findings and correlates them. For example, it links a brute-force source IP to a beacon from the same host.
- It assigns an incident priority and drafts containment steps for a human.
- It marks false positives with a reason, for example "10.0.0.66 is the authorized vulnerability scanner".
- `/soc_tune_rule` proposes a filter for each `SIGMA-FP`. It then re-runs `sigma` so the new precision and recall are measured, not claimed, and opens a PR with the rule diff and the before and after metrics.

```bash
uv run adws/adw_domain_iso.py --pack soc --input core/fixtures/soc/auth.log
uv run adws/adw_domain_iso.py --pack soc --input core/fixtures/soc --fail-on critical
```

## Safety notes

- Log content is attacker-controlled. Every string is escaped before it reaches Markdown (`core/security/sanitize.py`). Agents must treat evidence as data, never as instructions.
- Detections are heuristics with tunable thresholds. They are not verdicts. No automated containment, blocking or account action exists in this pack.
- Classic syslog lines have no year. `--opt year=` sets it, and the default is 2024. Timestamps are treated as UTC.
- A rule change that lowers recall is a regression, even if false positives drop. Review both numbers.

## Extending

1. Write a pure detector `detect_x(events, ...) -> list[Finding]` over the parsed records (`AuthEvent`, `Conn`). Call it from `detect_all` or from the module's `analyze_file`.
2. For a new log format, write a parser to the existing record type, so every detector works on it unchanged.
3. Register new tools in `PACK_TOOLS["soc"]` and `_detect_soc`. Add a fixture under `core/fixtures/soc/` and exact-count tests.
