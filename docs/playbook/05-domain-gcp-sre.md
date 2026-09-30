# 05 — Domain pack: GCP SRE (Terraform and IAM audit, Splunk and Kafka triage, Node.js traces)

**Ship policy: `pr_only`.** The pack reads exports and writes reports. It never runs `gcloud`, `terraform`,
`kubectl` or a Kafka CLI, never changes IAM, firewalls or brokers, and never queries Splunk. Every fix is a
proposal for a human, ideally as a Terraform PR.

## What it automates

- **GCP configuration audit.** It reads `terraform show -json` output (state or plan) and flags risky IAM, service identities, firewalls, databases, buckets and GKE settings.
- **Log triage.** It reads Splunk exports, GCP Cloud Logging exports and plain logs (Kafka broker and client, Kubernetes, application) and turns them into counted findings with first and last seen times.
- **Node.js stack-trace extraction.** It groups traces by signature and points to the top application frame, so the on-call engineer sees the file and line and how often it fails.

## Deterministic tools (`core/gcp_sre/`)

| Tool | Input | Detects |
|---|---|---|
| `gcp_tf` | `terraform show -json` of a state file or saved plan. Modules are walked. | **IAM:** `GCP-IAM-PUBLIC` (`allUsers`, `allAuthenticatedUsers`; critical on data services), `GCP-IAM-PRIMITIVE` (owner and editor; critical when bound to a service account), `GCP-IAM-ESCALATION` (token creator, service-account admin, IAM admin roles at project, folder or org level), `GCP-IAM-ADMIN-ROLE`, `GCP-IAM-USER-DIRECT` (privileged role bound to a person, not a group), `GCP-IAM-AUTHORITATIVE` (`_iam_policy` and `_iam_binding` lockout risk). **Service identities:** `GCP-SA-KEY`, `GCP-STATE-SECRET` (private key stored in state), `GCP-SA-DEFAULT` (default compute service account, high with `cloud-platform` scope), `GCP-SA-SCOPE`, `GCP-SA-OVERPRIVILEGED`. **Network:** `GCP-NET-FW-OPEN` (internet to SSH, RDP, databases, Kafka, or all ports), `GCP-NET-FW-PUBLIC`, `GCP-NET-PUBLIC-IP`. **Data:** `GCP-DATA-SQL-PUBLIC`, `GCP-DATA-SQL-PUBLIC-IP`, `GCP-DATA-SQL-BACKUP`, `GCP-DATA-DELETION-PROTECTION`, `GCP-DATA-BUCKET-PAP`, `GCP-DATA-BUCKET-ACL`. **GKE:** `GCP-GKE-ABAC`, `GCP-GKE-PUBLIC-NODES`, `GCP-GKE-MASTER-OPEN`, `GCP-GKE-NO-WI`. Metrics: `identity_matrix` (member to roles), `service_accounts`, `resources_by_type`, `risk_score`. |
| `sre_logs` | Splunk export (JSON, JSONL, CSV with `_raw` and `_time`), Cloud Logging export, or plain text | **Kafka:** `KAFKA-BROKER-UNAVAILABLE`, `KAFKA-REBALANCE` (3 or more), `KAFKA-CONSUMER-EVICTED`, `KAFKA-CONSUMER-LAG` (with group and topic), `KAFKA-OFFSET-RESET`, `KAFKA-ISR`, `KAFKA-AUTH`, `KAFKA-PRODUCE-FAIL`, `KAFKA-DISK`. **Splunk:** `SPLUNK-PIPELINE-BLOCKED` (logs may be missing, so "no errors" means unknown). **Runtime and GCP:** `SRE-OOM`, `SRE-CRASHLOOP`, `SRE-DB-POOL`, `SRE-CAPACITY`, `SRE-QUOTA`, `SRE-PERMISSION`, `SRE-DEADLINE`. **Shape:** `SRE-ERROR-BURST` (busiest error minute against the median), `SRE-ERROR-RATE` (over 5% errors). Each finding carries `count`, `first_seen`, `last_seen`, `hosts` and up to three redacted samples. Metrics: level counts, time range, `top_error_signatures` with ids, IPs and numbers normalized. |
| `node_trace` | Any of the log inputs above | Extracts `Error: message` plus `at fn (file:line:col)` frames, `Caused by:` chains, async frames and `file://` paths, and classifies each frame as `app`, `dependency` (node_modules) or `internal`. Groups by error type, normalized message and top application frame. `NODE-OOM` (critical), `NODE-UNCAUGHT`, `NODE-EMFILE`, `NODE-EADDRINUSE`, `NODE-NET` (with the `host:port` target), `NODE-KAFKAJS`, `NODE-CODE-DEFECT` (TypeError, ReferenceError, RangeError or SyntaxError in application code), `NODE-DEP-ERROR` (with the package), `NODE-LISTENER-LEAK`, `NODE-ERROR`. A signature seen 5 or more times is raised one severity level. Metrics: `top_signatures`, `hot_files`, `dependency_origins`. |

```bash
terraform show -json > state.json                       # you run this, the pack never does
uv run python -m core.registry gcp_sre state.json --fail-on high                 # CI gate: exit 2
uv run python -m core.registry gcp_sre exports/                                  # every state, log and export in a directory
uv run python -m core.registry gcp_sre kafka.log --opt lag_threshold=5000
uv run python -m core.registry gcp_sre app.log --tool node_trace --opt repeat_threshold=3
uv run python -m core.registry gcp_sre exports/ --format sarif --out sre.sarif
```

When no `--tool` is given, a log file is analyzed by `sre_logs`, and by `node_trace` as well when it contains
stack traces. Pass `--tool` to run only one of them. Options: `lag_threshold` (10000), `burst_min` (10),
`burst_factor` (3.0), `repeat_threshold` (5).

## The agent's role

- `/gcp_sre_triage` reads the findings, orders them by `first_seen` and separates probable cause from symptoms. For example, a broker outage that precedes an ISR shrink and a rebalance storm is the cause, and the consumer lag is the symptom.
- It names the file and line from `top_app_frame` for a regression suspect and suggests `git log` or `git blame` on it. It marks log gaps from `SPLUNK-PIPELINE-BLOCKED` as unknown, not healthy.
- For IAM findings it recommends group bindings, workload identity and per-workload service accounts. It never proposes a broader role to make a permission error go away.
- It puts read-only diagnostics first and marks every state-changing step `requires_human_approval: true`.

```bash
uv run adws/adw_domain_iso.py --pack gcp_sre --input exports/                         # analysis + agent triage
uv run adws/adw_domain_iso.py --pack gcp_sre --input state.json --fail-on high        # gate a Terraform review
uv run adws/adw_domain_iso.py --pack gcp_sre --input exports/ --propose               # report PR from an isolated worktree
```

Use `specs/templates/gcp_sre_incident.md` as the incident record.

## Safety notes

- Logs are attacker-controlled: request paths, headers, user input and error messages all end up in them. Samples are redacted (known secret formats), stripped of control characters, capped in length, and escaped in Markdown. Agents get findings as a file path, never inline in a prompt.
- Terraform state can hold secrets. The pack reports the presence of a service-account private key, never its value. Treat exported state as confidential and delete it after the review.
- The signatures are heuristics. A rebalance count is a symptom to explain, not a diagnosis. Thresholds are options, so tune them per service.
- `first_seen` comes from the log timestamps. Plain logs without a year or time zone are read as UTC. Check clock skew between hosts before trusting an order across sources.
- The audit sees the configuration in the export. It cannot see org policies, VPC Service Controls, or IAM granted outside Terraform. For effective permissions use IAM Recommender and Policy Analyzer.
- Splunk exports are limited by the search that produced them. Say which search and window you used in the incident record.

## Extending

1. GCP rule: add a check in `core/gcp_sre/tfgcp.py` (one of the `check_*` functions, or a new one added to `CHECKS`) with the next free `GCP-*` id, and a positive and negative test in `core/tests/test_gcp_tf.py`.
2. Log signature: add a `_sig(...)` to `SIGNATURES` in `core/gcp_sre/logs.py`. Set `min_count` for symptoms that only matter in bulk. Test it in `core/tests/test_sre_logs.py`.
3. Node.js classification: add a branch in `_classify` in `core/gcp_sre/nodetrace.py`, or a marker in `_MARKERS` for process-level messages that have no stack.
4. New log format: add a loader path in `core/gcp_sre/events.py` that yields `Event` records. All analyzers then work on it unchanged.
5. New tool: write `analyze_file(path, **opts) -> AnalysisReport`, register it in `PACK_TOOLS["gcp_sre"]` and `_detect_gcp_sre`. If it should also run on files another tool detects, add it to `COMPANIONS`.
