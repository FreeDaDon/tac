import pytest

from core.mcp_gov import manifest, rbac


def _by_rule(report):
    out: dict[str, list] = {}
    for f in report.findings:
        out.setdefault(f.rule_id, []).append(f)
    return out


def test_risky_server_fixture(fixtures):
    report = manifest.analyze_file(fixtures / "mcp_gov" / "servers" / "risky_server.json")
    rules = _by_rule(report)
    assert {"MCP-TRANSPORT-PLAINTEXT", "MCP-SCOPE-BROAD", "MCP-AUDIENCE-BROAD", "MCP-TOOL-EXEC", "MCP-INPUT-UNCONSTRAINED",
            "MCP-TOOL-ANNOTATION-MISMATCH", "MCP-TOOL-DESTRUCTIVE", "MCP-TOOL-SHADOW", "MCP-EXFIL-TRIFECTA",
            "MCP-RESOURCE-BROAD", "MCP-AUTH-STATIC", "MCP-SCOPE-UNUSED", "INJ-CONCEAL", "INJ-TOOL-COERCION",
            "MCP-PROVENANCE-VERSION"} <= set(rules)
    assert {f.evidence["scope"] for f in rules["MCP-SCOPE-BROAD"]} == {
        "crm:*", "https://www.googleapis.com/auth/cloud-platform"}
    assert rules["MCP-TOOL-ANNOTATION-MISMATCH"][0].evidence["tool"] == "update_note"
    assert report.metrics["release_gate"] == "blocked" and report.metrics["risk_score"] == 100
    poisoned = rules["INJ-CONCEAL"][0]
    assert poisoned.location == "acme-crm-connector:tools[0].description"


def test_clean_server_passes(fixtures):
    report = manifest.analyze_file(fixtures / "mcp_gov" / "servers" / "clean_server.json")
    assert report.findings == []
    assert report.metrics["release_gate"] == "eligible_for_human_review"
    assert report.metrics["scopes"] == ["docs.read"]


def test_client_config_launch_risks(fixtures):
    report = manifest.analyze_file(fixtures / "mcp_gov" / "servers" / "client_config.json")
    got = {(f.rule_id, f.resource) for f in report.findings}
    assert {("MCP-CMD-INLINE", "shell-helper"), ("MCP-CMD-REMOTE-EXEC", "shell-helper"),
            ("MCP-SECRET-LITERAL", "shell-helper"), ("MCP-PKG-UNPINNED", "fs"), ("MCP-RESOURCE-BROAD", "fs"),
            ("MCP-CONTAINER-PRIV", "sandbox"), ("MCP-IMAGE-UNPINNED", "sandbox")} <= got
    assert not any(r == "pinned" for _, r in got)  # pinned version + ${VAR} secret reference are fine
    secret = next(f for f in report.findings if f.rule_id == "MCP-SECRET-LITERAL")
    assert "supersecretvalue1234" not in str(secret.evidence) and secret.evidence["length"] == 20


def test_allowed_scopes_option(fixtures):
    path = fixtures / "mcp_gov" / "servers" / "clean_server.json"
    ok = manifest.analyze_file(path, allowed_scopes="docs.read,docs.list")
    assert ok.findings == []
    denied = manifest.analyze_file(path, allowed_scopes="docs.list")
    [f] = denied.findings
    assert f.rule_id == "MCP-SCOPE-NOT-ALLOWED" and f.evidence["scopes"] == ["docs.read"]


def test_rbac_validator_units():
    policy = rbac.RbacPolicy()
    model = rbac.Rbac(server="s", auth_type="oauth2", flow="implicit", scopes=("files.write",), groups=("all-users",),
                      tools=[rbac.ToolAccess("list_files", ("files.read",), read_only=True)], remote=True)
    rules = {f.rule_id for f in rbac.validate(model, policy)}
    assert {"MCP-AUTH-FLOW", "MCP-AUDIENCE-BROAD", "MCP-SCOPE-WRITE-ON-READONLY", "MCP-SCOPE-UNUSED",
            "MCP-SCOPE-MISSING"} <= rules
    assert "MCP-AUTH-NONE" in {f.rule_id for f in rbac.validate(rbac.Rbac(server="s", remote=True, groups=("g",)), policy)}
    assert rbac.validate(rbac.Rbac(server="s", auth_type="oauth2", scopes=("docs.read",), groups=("g",)), policy) == []


def test_parse_servers_shapes():
    parsed = manifest.parse_servers({"mcpServers": {"a": {"command": "x"}, "b": {"url": "https://h/mcp"}}})
    assert [s.name for s in parsed] == ["a", "b"]
    [s] = manifest.parse_servers({"name": "m", "url": "http://localhost:8080/mcp", "tools": []})
    assert s.transport == "http" and not s.remote
    with pytest.raises(ValueError):
        manifest.parse_servers({"hello": "world"})
    with pytest.raises(ValueError):
        manifest.parse_servers(["not", "an", "object"])


def test_tool_classification():
    assert manifest.classify_tool({"name": "runShellCommand"})["exec"]
    c = manifest.classify_tool({"name": "read_customer_records", "description": "Read customer data"})
    assert c["private_data"] and not c["egress"]
    assert manifest.classify_tool({"name": "lookup", "annotations": {"openWorldHint": True}})["egress"]


def test_unpinned_runner_variants():
    def rules(cmd, args):
        [s] = manifest.parse_servers({"mcpServers": {"x": {"command": cmd, "args": args}}})
        return {f.rule_id for f in manifest.check_launch(s)}

    assert "MCP-PKG-UNPINNED" in rules("npx", ["-y", "some-mcp"])
    assert "MCP-PKG-UNPINNED" in rules("npx", ["-y", "some-mcp@latest"])
    assert "MCP-PKG-UNPINNED" not in rules("npx", ["-y", "@corp/some-mcp@1.2.3"])
    assert "MCP-PKG-UNPINNED" not in rules("uvx", ["some-mcp==1.2.3"])
    assert "MCP-CMD-INLINE" in rules("python3", ["-c", "import os"])
