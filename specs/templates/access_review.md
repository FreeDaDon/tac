# Access Review: <system / account / period>

## Metadata
review_id: `<id>`
period: `<start> to <end>`
reviewer: `<name>`
systems in scope: `<AWS account ids / IdP / apps>`
data sources: `<credential report, access advisor, IdP export, HR roster>`

## Scope
- Principals reviewed: <users, roles, groups, service accounts, keys>
- Out of scope: <list>

## Findings
| # | Rule / Finding | Principal | Evidence | Risk | Decision |
|---|---|---|---|---|---|
| 1 | <IAM-DORMANT-KEY> | <arn/user> | <last used 214d ago> | <high> | <revoke / reduce / keep (justify)> |

Categories covered:
- [ ] Excess privilege (wildcards, admin policies, PassRole *)
- [ ] Privilege escalation paths
- [ ] Dormant users / keys (>90 days), keys older than 90 days, console without MFA
- [ ] Separation of duties conflicts
- [ ] Cross-account / third-party trust

## Revocation and Reduction Plan
| Principal | Change | Proposed policy / diff | Staged (disable first)? | Owner | Due |
|---|---|---|---|---|---|
| <arn> | <deactivate key, detach policy> | <link to /iam_policy_fix output> | <yes> | | |

Rollback: <how to restore access quickly if a revocation breaks a workload>

## Approvals
| Change | Approver (system owner) | Date | Ticket |
|---|---|---|---|

Agents propose; humans approve and execute every access change.

## Evidence
- Raw exports and hashes: <paths>
- Deterministic analysis output: <agent/runs/<adw_id>/...>
- Screenshots / tickets: <links>

## Sign-off
- Reviewer: <name, date>
- Next review due: <date>
