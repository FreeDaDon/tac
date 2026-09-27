# 05 — Domain pack: DevOps (IaC risk, drift, rollback)

**Ship policy: `pr_only`.** The pack reads Terraform output and writes reports. It never runs
`terraform apply`, `destroy` or `import`, and never merges its own PR.

## What it automates

- **Plan risk review.** It flags destructive changes and risky configuration in `terraform show -json` output before a human approves the apply.
- **Drift review.** It reports attributes that changed outside Terraform.
- **Rollback planning.** It builds an ordered, dry-run list of the steps needed to undo a plan, and says which steps cannot recover data.

## Deterministic tools (`core/devops/`)

| Tool | Input | Detects |
|---|---|---|
| `tfplan` | `terraform show -json plan.out` | `TF-DESTROY` and `TF-REPLACE` (critical for databases, buckets, KMS, IAM and secrets), `TF-SG-OPEN` (0.0.0.0/0 or ::/0 to sensitive ports), `TF-S3-PUBLIC` (ACLs, anonymous bucket policy, disabled public access block), `TF-UNENCRYPTED`, `TF-IAM-POLICY` (inline policies linted with the IAM rules at high severity or above), `TF-SENSITIVE-UPDATE`. Metrics: counts by action, and `risk_score` from 0 to 100. |
| `drift` | Plan JSON (`resource_drift`), or two state JSONs | `TF-DRIFT` with an attribute diff (secret values masked), `TF-DRIFT-DELETED`, `TF-DRIFT-ADDED`. |
| `rollback` | Plan JSON | `metrics.rollback_plan` holds the steps in reverse order. `TF-ROLLBACK-IRREVERSIBLE` marks stateful deletes and replaces. |

```bash
terraform plan -out plan.out && terraform show -json plan.out > plan.tfplan.json

uv run python -m core.registry devops plan.tfplan.json                        # risk review (md)
uv run python -m core.registry devops plan.tfplan.json --fail-on high         # CI gate: exit 2
uv run python -m core.registry devops plan.tfplan.json --tool drift
uv run python -m core.registry devops before.json --tool drift --opt compare_to=after.json
uv run python -m core.registry devops plan.tfplan.json --tool rollback --format json
uv run python -m core.registry devops plans/ --format sarif --out devops.sarif  # every plan in a dir
```

Files ending in `.tfplan.json`, and any JSON with `resource_changes`, are detected as `tfplan`.
Run `drift` and `rollback` with `--tool`. State files are never auto-detected.

## The agent's role

The ADW runs the tools first. It then hands `findings.json` to `/devops_iac_plan` and
`/devops_drift_review`. The agent only interprets:

- It separates intended changes from dangerous ones.
- It ranks actions and marks likely false positives, such as a planned replace of a stateless resource.
- It writes the reviewer summary.

The agent does not re-derive findings, and it does not edit infrastructure.

```bash
uv run adws/adw_domain_iso.py --pack devops --input plan.tfplan.json            # report only
uv run adws/adw_domain_iso.py --pack devops --input plan.tfplan.json --propose  # report PR
```

## Safety notes

- The rollback `command_preview` strings are examples for a human to adapt. Nothing executes them.
- The plan JSON can contain sensitive values. Drift masks attributes named like `password`, `secret`, `token` or `private_key`. The raw plan is still sensitive, so keep it out of PRs.
- `risk_score` is a triage aid, not an approval. A score of 0 means no rule fired. It does not mean the plan is safe.
- Treat every `critical` destroy or replace as a stop. Snapshot the resource, add `lifecycle { prevent_destroy = true }`, or split the change out.

## Extending

1. Add a pure check `check_x(rc, after) -> list[Finding]` to `tfplan.py`, and add it to the tuple in `analyze_resource_change`.
2. Use a stable `TF-*` rule id, and add positive and negative cases to `core/tests/test_tfplan.py`.
3. For a new input type, write `core/devops/<tool>.py` with `analyze_file(path, **opts) -> AnalysisReport`. Register it in `PACK_TOOLS["devops"]` and teach `_detect_devops` to recognize it.
