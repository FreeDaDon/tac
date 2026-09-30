# mcp-connector Terraform module

Turns an approved AI connector (MCP server) into a version-pinned, group-scoped, per-environment
registration record. It does not talk to any platform. Terraform validates the request and renders
two files, and a CI step registers them with the platform's admin API after a human approves.

```
variables --> validations + guard preconditions --> rendered/<env>/<name>.manifest.json
                                                \-> rendered/<env>/<name>.registration.json
                                                      |
   uv run python -m core.registry mcp_gov rendered/<env> --fail-on high   (exit 2 blocks)
```

## What Terraform refuses

| Rule | Mirrors scanner id |
|---|---|
| HTTPS only, no loopback URL | MCP-TRANSPORT-PLAINTEXT |
| Exact version, never `latest` | MCP-PKG-UNPINNED |
| Wildcard or admin-class scope | MCP-SCOPE-BROAD |
| Scope outside the IAM-approved allowlist | MCP-SCOPE-NOT-ALLOWED |
| Scope that no tool needs, or a tool scope not requested | MCP-SCOPE-UNUSED / MCP-SCOPE-MISSING |
| No audience, or a broad audience | MCP-AUDIENCE-MISSING / MCP-AUDIENCE-BROAD |
| Staging or prod without a review ticket | process control |

Auth is fixed to OAuth authorization code with PKCE. There is no input for a static credential, so
`MCP-AUTH-STATIC` and `MCP-SECRET-LITERAL` cannot be expressed through this module.

## Use

```bash
cd infra/terraform/live
terraform init
terraform plan  -var-file=envs/dev.tfvars      # a human reviews the plan
terraform apply -var-file=envs/dev.tfvars      # separate state per environment
uv run python -m core.registry mcp_gov rendered/dev --fail-on high --opt allowed_scopes=docs.read,docs.list
```

Run `terraform test` in `modules/mcp-connector` for the validation suite.

## Not covered

- Platform registration itself (no provider assumed). The CI step must check that the manifest hash it
  registers equals `manifest_sha256` in the registration record.
- Secrets. A service identity with a client secret belongs in the vault, referenced by path. Add that
  when a connector needs one.
- Runtime behavior. The scanner cannot see it. A new version, tool or scope means a new review.
