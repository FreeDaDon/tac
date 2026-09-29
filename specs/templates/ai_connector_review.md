# AI Connector Review: <connector / server name and version>

## Metadata
request_id: `<ticket or intake id>`
requester: `<name, team>`
reviewer: `<name>`
platform: `<Claude (Anthropic API / claude.ai) | Copilot Studio | Gemini | other>`
connector type: `<MCP server | skill | plugin | agent | script>`
source: `<repository / vendor / internal team, exact version and commit or hash>`
target audience: `<named IdP groups only; never "everyone">`
environment: `<dev | staging | production>`
data classification: `<public | internal | confidential | regulated (GxP / PHI / PII)>`

## Business Purpose
<What problem this solves, who uses it, and why an existing approved connector does not.>

## Intake Checklist
- [ ] Source repository, publisher and license identified; version pinned (no `latest`)
- [ ] Manifest and every tool description read in full by a human
- [ ] Data flows drawn: what data the connector reads, where it sends it, and who can see the result
- [ ] Requester confirmed the minimum capabilities needed (tools and scopes)

## Deterministic Analysis
Run from the repository root, then attach the report under Evidence:

```bash
uv run python -m core.registry mcp_gov <path-to-connector> --fail-on high
uv run python -m core.registry mcp_gov <manifest.json> --opt allowed_scopes=<comma-list-of-approved-scopes>
uv run adws/adw_domain_iso.py --pack mcp_gov --input <path-to-connector> --propose   # isolated worktree + PR
```

| Tool | Result | Release gate | Report |
|---|---|---|---|
| `mcp_manifest` | <n findings, risk score> | <blocked / needs_review / eligible_for_human_review> | <path> |
| `connector_scan` | <n findings> | <...> | <path> |

`release_gate` is advisory. A human authorizes release.

## Risk Assessment
| # | Rule / Finding | Location | Severity | Real risk? | Decision |
|---|---|---|---|---|---|
| 1 | <MCP-SCOPE-BROAD> | <server:auth.scopes> | <high> | <yes / false positive (why)> | <remove scope / accept with exception / reject> |

Categories reviewed:
- [ ] Prompt injection and tool poisoning (tool descriptions, manifests, skill text, hidden characters)
- [ ] Data exfiltration paths (network egress, environment access, credential paths, render-time URLs)
- [ ] Overly broad permissions (OAuth scopes, filesystem roots, admin roles)
- [ ] Unintended tool behavior (execution, destructive tools, wrong annotations, unconstrained inputs)
- [ ] Authentication (IdP-issued OAuth with PKCE, no static or literal secrets, service identities)
- [ ] Supply chain (pinned packages and images, install hooks, remote code download)
- [ ] Trifecta check: private data + untrusted content + external send in one server?

## Access Model
| Item | Requested | Approved |
|---|---|---|
| OAuth scopes | <list> | <list; each mapped to a tool that needs it> |
| Service identity | <name, owner, secret location> | <...> |
| Audience (IdP groups) | <groups> | <groups> |
| Egress destinations | <hosts> | <allowlisted hosts> |

## Release Authorization
Decision: `<reject | fix and resubmit | approve for the named audience>`

Conditions of approval: <pinned version, egress allowlist, per-call human approval on tools X and Y, audit logging enabled>

Rollout plan: dev, then staging, then production, using the same infrastructure-as-code module in each environment. Rollback: <how to disable the connector and revoke its tokens>.

| Role | Name | Date | Ticket |
|---|---|---|---|
| Security reviewer | | | |
| IAM owner (scopes and groups) | | | |
| Platform owner | | | |
| Business owner | | | |

Agents propose. Humans approve, register and distribute every connector.

## Operational Handoff
- Owner and on-call: <team>
- Monitoring and audit logs: <where tool calls and denials are recorded>
- Re-review triggers: version bump, new tool or scope, publisher change, incident
- Documentation: <link to architecture and configuration docs>

## Evidence
- Manifest and source hashes: <paths>
- Deterministic analysis output: <agent/reports/<adw_id>/report.md, findings.json, findings.sarif>
- Approvals and tickets: <links>
