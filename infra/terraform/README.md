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
| Anything but HTTPS to a dotted DNS hostname. IP literals of every form (dotted, decimal, hex, octal, IPv6), a `user@` part, `localhost` variants and `metadata.google.internal` are refused, case-insensitively, in every environment | MCP-TRANSPORT-PLAINTEXT |
| Exact version, never `latest` | MCP-PKG-UNPINNED |
| A `*` anywhere in a scope, an admin-class scope, `cloud-platform`, Graph `.default`, full Gmail or full Drive | MCP-SCOPE-BROAD |
| Scope outside the IAM-approved allowlist | MCP-SCOPE-NOT-ALLOWED |
| Scope that no tool needs, or a tool scope not requested | MCP-SCOPE-UNUSED / MCP-SCOPE-MISSING |
| No audience, or a broad audience | MCP-AUDIENCE-MISSING / MCP-AUDIENCE-BROAD |
| Zero tools, more than 25 tools, or two tools with the same name | MCP-TOOL-COUNT |
| A tool `input_schema` that is not a JSON object schema with top-level `additionalProperties: false` | input hardening |
| A `repository` that is not `https://` or carries `user@` credentials | provenance |
| Staging or prod without a review ticket, or any ticket that is not `AICR-<number>` (`AICR-0000` is refused) | process control |

Auth is fixed to OAuth authorization code with PKCE. There is no input for a static credential, so
`MCP-AUTH-STATIC` and `MCP-SECRET-LITERAL` cannot be expressed through this module.

Each tool sets `open_world`, rendered as `openWorldHint`. It defaults to `true`, so a tool nobody
classified counts as egress-capable for the scanner. Set `open_world = false` only after review shows the
tool reaches nothing outside the connector's own data. `input_schema` is a JSON string (pass
`jsonencode({...})`), which lets tools carry differently shaped schemas.

## Use

Each environment is a Terraform workspace with its own state file at `live/state/<env>/terraform.tfstate`.
A guard in `live/main.tf` fails the plan when the selected workspace differs from `environment` in the
tfvars, so a prod plan can never run against dev state.

```bash
cd infra/terraform/live
terraform init
terraform workspace select -or-create dev
terraform plan  -var-file=envs/dev.tfvars -out=dev.tfplan   # a human reviews the plan
terraform apply dev.tfplan
uv run python -m core.registry mcp_gov rendered/dev --fail-on high --opt allowed_scopes=docs.read,docs.list
```

For staging or prod, replace `dev` with the environment name in each command. `envs/staging.tfvars` and
`envs/prod.tfvars` ship with `review_ticket = "SET-REAL-AICR-TICKET"`, which fails validation, so the
plan stops until an operator writes the real `AICR-<number>` ticket. Commit `live/.terraform.lock.hcl`
after the first `init`. State, plan files, `.terraform/` and `rendered/` are git-ignored.

Run the validation suite from `modules/mcp-connector`:

```bash
terraform init -backend=false && terraform validate && terraform test
```

CI runs `terraform fmt -check`, that suite, and `validate` plus `test` on `live/` (which proves the
workspace guard refuses a mismatched plan) against Terraform 1.6.6, the declared floor, and a current
release.

## Not covered

- Platform registration itself (no provider assumed). The CI step must check that the manifest hash it
  registers equals `manifest_sha256` in the registration record.
- Secrets. A service identity with a client secret belongs in the vault, referenced by path. Add that
  when a connector needs one.
- Runtime behavior. The scanner cannot see it. A new version, tool or scope means a new review.
- DNS. A public hostname that resolves to a loopback, private or metadata address (a `*.nip.io` name, for
  example) passes the URL rule. Only egress policy at resolution time can catch that.
- Nested schemas. Only the top level of `input_schema` must set `additionalProperties: false`.
