# Incident Triage: <short title>

## Metadata
incident_id: `<id>`
detected: `<UTC timestamp>`
reporter / source: `<alert rule, tool, person>`
severity: `<SEV1|SEV2|SEV3|SEV4>`
status: `<triage|contained|eradicated|recovered|closed>`
handler: `<name>`

## Summary
<2-4 sentences: what happened, what is affected, current state>

## Timeline (UTC)
| Time | Source | Event |
|---|---|---|
| <ts> | <log/host> | <what happened> |

## Indicators of Compromise
| Type | Value | First seen | Context |
|---|---|---|---|
| ip / domain / hash / user / path | <value> | <ts> | <where observed> |

## MITRE ATT&CK Mapping
| Tactic | Technique (ID) | Evidence |
|---|---|---|
| <e.g. Credential Access> | <Brute Force (T1110)> | <finding / log ref> |

## Scope and Impact
- Affected hosts/accounts/data: <list>
- Confirmed data access or exfiltration: <yes/no/unknown + evidence>

## Containment
| Action | Owner | Approved by | Done (UTC) | Reversible? |
|---|---|---|---|---|
| <disable account / isolate host / block IP> | | | | |

Evidence preserved before containment: <snapshots, log exports, hashes>

## Eradication
- <remove persistence, patch vuln, rotate credentials, rebuild host>

## Recovery
- <restore service, monitoring for recurrence, validation>

## Detection Gaps and Tuning
- <rules that missed / were noisy; link tuned rules produced by /soc_tune_rule>

## Lessons Learned
- What went well: <...>
- What to change: <action, owner, due date>
