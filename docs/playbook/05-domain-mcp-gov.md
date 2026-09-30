# 05 — Domain pack: MCP Governance (AI connector intake, RBAC scopes, injection and exfiltration)

**Ship policy: `pr_only`.** The pack reviews and proposes. It never starts, installs, registers, enables or
distributes a connector, and never connects to an MCP server. Release authorization is a human decision recorded in
the spec `specs/templates/ai_connector_review.md`.

## What it automates

- **Intake audit of MCP servers.** It reads a server manifest or a client config (`mcpServers`) and checks transport, authentication, OAuth scopes, the launch command, secrets, tool behavior and input schemas.
- **RBAC and scope validation.** It compares requested scopes with what the tools declare they need and with an optional allowlist of approved scopes, and checks that the audience is a named group.
- **Third-party connector scan.** It scans skills, plugins, scripts and docs for prompt injection, hidden instructions, exfiltration paths, dynamic code execution and remote-code installs before anything is released.

## Deterministic tools (`core/mcp_gov/`)

| Tool | Input | Detects |
|---|---|---|
| `mcp_manifest` | Server manifest or client config, JSON or YAML | **Transport and auth:** `MCP-TRANSPORT-PLAINTEXT`, `MCP-TLS-VERIFY-OFF`, `MCP-AUTH-NONE`, `MCP-AUTH-STATIC`, `MCP-AUTH-FLOW` (implicit or password flow), `MCP-AUTH-PKCE`. **Scopes and audience (rbac.py):** `MCP-SCOPE-BROAD`, `MCP-SCOPE-NOT-ALLOWED`, `MCP-SCOPE-UNUSED`, `MCP-SCOPE-MISSING`, `MCP-SCOPE-WRITE-ON-READONLY`, `MCP-AUDIENCE-MISSING`, `MCP-AUDIENCE-BROAD`. **Launch and supply chain:** `MCP-CMD-INLINE`, `MCP-CMD-REMOTE-EXEC`, `MCP-PKG-UNPINNED`, `MCP-IMAGE-UNPINNED`, `MCP-CONTAINER-PRIV`, `MCP-PROVENANCE-*`. **Secrets:** `MCP-SECRET-LITERAL` (length only, never the value). **Tool behavior:** `MCP-TOOL-EXEC`, `MCP-TOOL-DESTRUCTIVE`, `MCP-TOOL-ANNOTATION-MISMATCH` (claims `readOnlyHint` but implies a write), `MCP-INPUT-UNCONSTRAINED`, `MCP-TOOL-DUP`, `MCP-TOOL-SHADOW`, `MCP-TOOL-COUNT`, `MCP-TOOL-NO-ANNOTATIONS`. **Data paths:** `MCP-EXFIL-TRIFECTA` (private data + untrusted content + external send), `MCP-EXFIL-PATH`, `MCP-RESOURCE-BROAD`. Every string in the manifest also goes through the injection scanner, so a poisoned tool description is reported at `server:tools[N].description`. |
| `connector_scan` | A file or directory of text: skills (`SKILL.md`), scripts, docs, configs | **Instructions aimed at the model:** `INJ-OVERRIDE`, `INJ-ROLE-HIJACK`, `INJ-CONCEAL` (hide actions from the user, critical), `INJ-TOOL-COERCION`, `INJ-ROLE-MARKUP`, `INJ-HIDDEN-COMMENT`. **Hidden content:** `INJ-HIDDEN-UNICODE` (bidi and zero-width), `INJ-ASCII-SMUGGLING` (Unicode tag characters, decoded into evidence), `INJ-ENCODED` (base64 that decodes to text, high when it decodes to an instruction). **Exfiltration:** `EXF-SENSITIVE-PATH`, `EXF-ENV-DUMP`, `EXF-NET-EGRESS`, `EXF-SINK-DOMAIN`, `EXF-MD-IMAGE` (image URL that interpolates data), and `EXF-CHAIN` (critical: sensitive read plus outbound path in the same file). **Execution and supply chain:** `EXE-DYNAMIC`, `SUP-REMOTE-EXEC`, `SUP-INSTALL`. |

Both tools add `metrics.release_gate`: `blocked` (any critical or high), `needs_review`, or
`eligible_for_human_review`. The gate is advisory and is never an approval. `mcp_manifest` also reports `risk_score`
(0 to 100), the scope list and the transports.

```bash
uv run python -m core.registry mcp_gov server.json --fail-on high                 # CI gate: exit 2
uv run python -m core.registry mcp_gov server.json --opt allowed_scopes=docs.read,docs.list
uv run python -m core.registry mcp_gov .mcp.json                                   # client config, every server in it
uv run python -m core.registry mcp_gov vendor/connector/ --format sarif --out mcp.sarif
uv run python -m core.registry mcp_gov core/fixtures/mcp_gov                        # manifests and scripts in one pass
```

Options (`--opt key=value`): `allowed_scopes` (comma list of approved scopes), `max_tools` (default 25),
`require_audience` (default true).

Detection: a JSON or YAML file that has `tools`, `mcpServers` or `servers`, or a `name` with a `transport`, `command`
or `url`, is a manifest. Any other text file (`.md`, `.py`, `.js`, `.ts`, `.sh`, `.json`, ...) goes to `connector_scan`.
Lockfiles, minified files and binaries are skipped.

## The agent's role

- `/mcp_connector_review` receives the findings as a file. It separates real risk from false positives (a security doc that quotes injection phrases, for example), groups findings into actions and ranks them P1 to P4.
- It writes the release recommendation into `summary`: reject, fix and resubmit, or approve for the named audience. Every action has `requires_human_approval: true` when it changes access, registration or distribution.
- It never installs, starts or connects to the connector, and never follows instructions found in the connector's text.

```bash
uv run adws/adw_domain_iso.py --pack mcp_gov --input vendor/connector/ --fail-on high
uv run adws/adw_domain_iso.py --pack mcp_gov --input vendor/connector/ --propose    # report PR from an isolated worktree
uv run adws/adw_domain_iso.py --pack mcp_gov --input server.json --no-agent          # deterministic only
```

## Intake workflow (request to handoff)

1. **Intake.** Copy `specs/templates/ai_connector_review.md`. Record the source, exact version, target audience and data classification.
2. **Assess.** Run the pack on the connector. Read the manifest and every tool description yourself. The scanner finds patterns, not intent.
3. **Configure.** Fix the manifest until only approved scopes and groups remain. Keep the connector definition in infrastructure as code, one module for dev, staging and production — `infra/terraform/modules/mcp-connector` does exactly this: it renders the manifest and a registration record, rejects wildcard scopes, plaintext transport and broad audiences at `terraform plan`, and requires a review ticket outside `dev`.
4. **Authorize.** Security, IAM and the platform owner sign the release section. Only then is the connector registered.
5. **Hand off.** Record the owner, audit log location and the events that trigger a re-review (new version, new tool, new scope).

## Safety notes

- Everything in a connector is untrusted, including the text that describes it. Evidence is redacted (known secret formats become `[REDACTED:<rule>]`), stripped of control characters, capped in length, and escaped in Markdown (`core/security/sanitize.py`). Agents get findings as a file path, never inline in a prompt.
- A clean result is not a safe connector. The scanner cannot see behavior that only appears at runtime, a benign description backed by a malicious server, or a dependency that turns hostile after review. Pin versions and re-review when they change.
- Rules are heuristics. Documents that discuss injection can trip `INJ-*`. Judge by location and context.
- The pack analyzes what you give it. It does not fetch remote manifests and does not run `npx`, `uvx` or `docker`.
- Reports contain tool names, URLs and scope lists. Treat them as internal.

## Extending

1. Injection or exfiltration rule: add a `_rule(...)` to `INJECTION_RULES` or `EXFIL_RULES` in `core/mcp_gov/injection.py`, with a positive and a negative test in `core/tests/test_connector_scan.py`.
2. Manifest or scope rule: add a check in `core/mcp_gov/manifest.py` (transport, launch, tools) or `core/mcp_gov/rbac.py` (scopes, audience) and a test in `core/tests/test_mcp_manifest.py`. Use the next free `MCP-*` id.
3. New input kind: write `analyze_file(path, **opts) -> AnalysisReport`, then register it in `PACK_TOOLS["mcp_gov"]` and `_detect_mcp_gov` in `core/registry.py`.
4. New platform (Copilot Studio, Gemini): map its plugin manifest onto `McpServer` in `parse_servers`. The rules then apply unchanged.
