# GCP SRE Incident: <short title>

## Metadata
incident_id: `<id>`
detected: `<UTC timestamp>`
source: `<alert policy, Splunk alert, on-call page, customer report>`
severity: `<SEV1|SEV2|SEV3|SEV4>`
status: `<triage|mitigated|resolved|monitoring|closed>`
incident commander: `<name>`
services affected: `<Node.js service names, Kafka topics and consumer groups, GCP projects>`
environment: `<prod | staging>`

## Summary
<2-4 sentences: user impact, probable cause, current state, next check.>

## Impact
- Users / requests affected: <numbers and window>
- SLO burned: <SLI, target, remaining error budget>
- Data at risk (lag, loss, duplicates): <yes/no and evidence>

## Timeline (UTC)
| Time | Source | Event |
|---|---|---|
| <ts> | <deploy / Terraform change / Kafka / Node / Splunk> | <what happened> |

Build the order from `first_seen` in the analyzer findings. The earliest failing component is the probable cause. Later ones are usually symptoms.

## Deterministic Analysis
Export the evidence (Splunk search results as JSON/CSV, Kafka broker and consumer logs, Node.js application logs, `terraform show -json` of the state), then run:

```bash
uv run python -m core.registry gcp_sre <export-dir-or-file> --format json --out findings.json
uv run python -m core.registry gcp_sre <state.json> --tool gcp_tf --fail-on high
uv run python -m core.registry gcp_sre <app.log> --tool node_trace --opt repeat_threshold=5
uv run python -m core.registry gcp_sre <kafka.log> --tool sre_logs --opt lag_threshold=10000
uv run adws/adw_domain_iso.py --pack gcp_sre --input <export-dir>            # + agent triage in an isolated run
```

| Tool | Findings | Top signatures / hot spots |
|---|---|---|
| `sre_logs` | <n> | <rule ids with count, first/last seen> |
| `node_trace` | <n> | <error type, top application frame `file:line`, count> |
| `gcp_tf` | <n> | <IAM, firewall, service-account findings> |

## Kafka
- Brokers healthy / ISR complete: <yes/no, evidence>
- Consumer groups: <group, topic, lag, rebalance count>
- Producer errors: <timeouts, auth, size>

## Node.js
| Error | Top app frame | Count | First seen | Regression suspect (deploy)? |
|---|---|---|---|---|
| <TypeError> | <src/orders/build.js:88> | <6> | <ts> | <yes: deploy abc123> |

## GCP Configuration and IAM
| Finding | Resource | Exposure | Fix (as a Terraform PR) |
|---|---|---|---|
| <GCP-NET-FW-OPEN> | <google_compute_firewall.x> | <port 22 from internet> | <restrict source_ranges> |

## Observability Gaps
- Splunk ingestion gaps (`SPLUNK-PIPELINE-BLOCKED`): <window where "no errors" means unknown>
- Missing alerts or dashboards that would have caught this sooner: <list>

## Mitigation and Recovery
| Action | Owner | Approved by | Done (UTC) | Reversible? |
|---|---|---|---|---|
| <restart broker, scale service, roll back deploy, revoke role> | | | | |

Diagnostics first (read-only). Any production change needs approval from the incident commander. The agent proposes and never changes GCP, Kafka or IAM.

## Root Cause and Follow-ups
- Root cause: <...>
- Contributing factors: <...>
- Actions (owner, due date): <list, each tracked in a ticket>

## Evidence
- Raw exports and hashes: <paths>
- Deterministic analysis output: <agent/reports/<adw_id>/report.md, findings.json, findings.sarif>
