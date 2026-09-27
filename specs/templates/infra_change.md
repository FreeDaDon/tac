# Infra Change: <change name>

## Metadata
change_id: `<ticket or adw_id>`
owner: `<name>`
environment: `<dev|staging|prod>`
tool: `<terraform|opentofu|pulumi|other>`
ship_policy: `pr_only` <!-- infra never ships zero-touch -->

## Purpose
<why this change is needed; link to the request>

## Scope
- In scope: <modules/stacks/resources>
- Out of scope: <explicitly untouched>

## Plan Diff Summary
Output of `terraform plan -out=tf.plan && terraform show -json tf.plan` analyzed by the deterministic `tfplan` tool.

| Action | Count | Resources |
|---|---|---|
| create | <n> | <addresses> |
| update in-place | <n> | <addresses> |
| replace (destroy + create) | <n> | <addresses> |
| delete | <n> | <addresses> |

## Blast Radius
- Stateful resources affected (DBs, buckets, volumes, keys, DNS): <list or "none">
- Identity/network exposure changes (IAM, security groups, public access): <list or "none">
- Services/users impacted and expected downtime: <estimate>
- Dependencies that may break: <list>

## Drift
- Drift detected before this change (`terraform plan -refresh-only`): <none | list>
- Will this apply overwrite manual changes? <yes/no + which>

## Security Considerations
<encryption, logging, least privilege, public exposure, secrets in state/vars>

## Rollback
| Action | Rollback path | Reversible? |
|---|---|---|
| <resource/action> | <re-apply previous commit / restore snapshot <id> / manual steps> | <yes/partial/no> |

Pre-apply safety steps: <snapshots/backups taken, with IDs>

## Validation
- `terraform fmt -check && terraform validate`
- Deterministic analysis: the devops `tfplan` tool via `python -m core.registry` (no blocking findings, or each one accepted below)
- Post-apply checks: <health checks, smoke tests, dashboards>

## Findings Accepted
| Finding (rule_id / resource) | Reason accepted | Accepted by |
|---|---|---|

## Approval
- [ ] Plan reviewed by: <name>, <date>
- [ ] Rollback verified feasible by: <name>
- [ ] Apply window: <date/time>
- [ ] Applied by a human: <name> (agents never run apply)
