# 05 — Domain pack: IAM (policy lint, access model, access review)

**Ship policy: `pr_only`.** The pack proposes. Humans revoke. Every revocation plan has status
`pending_human_approval` and `executes: false`. No code path calls AWS.

## What it automates

- Linting IAM policies for wildcard and escalation risks before they merge.
- Checking an RBAC/ABAC model for separation-of-duties conflicts, admin sprawl and attribute violations.
- Periodic access reviews: dormant and never-used accounts, stale keys, admins without MFA. Each review ends in a ready-to-approve revocation plan.

## Deterministic tools (`core/iam/`)

| Tool | Input | Detects |
|---|---|---|
| `iam_policy` | Policy JSON (bare, or `get-policy-version` or `get-role` output) | `IAM001` Allow `*` on `*` (critical). `IAM002` `*` or `service:*` actions. `IAM003` write actions on `Resource "*"`. `IAM004` and `IAM005` Allow with NotAction or NotResource. `IAM006` `iam:PassRole` on any role. `IAM007` trust policy with a wildcard principal (critical without a Condition). `IAM008` sensitive actions without an MFA condition. `IAM009` old Version. `IAM010` malformed statement. |
| `rbac` | YAML or JSON `{roles, users, sod_rules, abac_policies}` | `RBAC-SOD` (after inheritance, with glob permissions), `RBAC-ADMIN`, `RBAC-ABAC`, `RBAC-UNUSED-ROLE`, `RBAC-CYCLE`, `RBAC-UNKNOWN-ROLE`. |
| `iam_audit` | Inventory JSON `{as_of?, users:[...]}` | `AUD-DORMANT` (over 90 days idle), `AUD-NEVER-USED` (over 30 days old), `AUD-STALE-KEY` (over 90 days old or unused), `AUD-NO-MFA-ADMIN`, `AUD-ADMIN-SPRAWL` (more than 3 admins). |
| `iam_revoke` | Same inventory | The audit findings, plus `metrics.revocation_plan`. Each step records `account`, `action` (`disable`, `remove_key`, `detach_policy` or `remove_group`), `reason`, `reversible` and an AWS CLI `command_preview`. |

```bash
uv run python -m core.registry iam policy.json --fail-on high
uv run python -m core.registry iam rbac_model.yaml
uv run python -m core.registry iam inventory.json --opt as_of=2025-06-30 --opt dormant_days=60
uv run python -m core.registry iam inventory.json --tool iam_revoke --format json --out plan.json
uv run python -m core.registry iam core/fixtures/iam            # every policy, model and inventory
```

The audit date comes from `--opt as_of`, then the inventory's `as_of`, then today in UTC. Pin
it, and results become reproducible.

## The agent's role

- `/iam_access_review` reads the findings and the plan. It groups steps by owner and orders them. For example, it enforces MFA before touching an admin, and deactivates a key before deleting it.
- It flags accounts that look dormant but are expected, such as break-glass accounts. It writes the review for the approver.
- `/iam_policy_fix` proposes a least-privilege rewrite of a flagged policy as a PR. Lint must come back clean before the PR is opened.
- The agent never removes a step's `reversible: false` marking, and never turns a preview into an executed command.

```bash
uv run adws/adw_domain_iso.py --pack iam --input core/fixtures/iam --propose   # PR for human approval
```

## Safety notes

- `remove_key` is irreversible. The preview deactivates the key first and deletes it after a wait. Keep that order.
- Service accounts get a key action, never a console action. Check their workloads before you disable anything.
- The inventory holds access key IDs. Treat reports as internal.
- Lint catches structural risk. It cannot check effective permissions across SCPs, permission boundaries and resource policies. For that, use IAM Access Analyzer or the policy simulator.

## Extending

1. Policy rule: add a check in `lint_statement` with the next free `IAM0NN` id, plus a positive and a negative test in `core/tests/test_iam_policy.py`.
2. Audit rule: add it to `audit_user` or `audit_inventory`. If it should lead to action, map it in `revoke.steps_for`, and keep previews read-only in spirit and quoted with `shlex.quote`.
3. New input kind: write `analyze_file(path, **opts) -> AnalysisReport`, then register it in `PACK_TOOLS["iam"]` and `_detect_iam`.
