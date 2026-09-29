"""MCP server manifest / client-config parser and auditor.

Accepts (JSON or YAML):
  * a server manifest: `{name, version, transport|url|command, auth, tools:[...], resources:[...], governance}`
  * a client config: `{"mcpServers": {"<name>": {...}}}` (Claude Desktop / `.mcp.json` / VS Code `servers` style)
Audits transport, authentication, OAuth scopes (via rbac.py), launch command supply chain, secrets, tool behavior,
input schemas, exfiltration paths and hidden instructions in every string. Never connects to the server.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.common import SEVERITY_ORDER, AnalysisReport, Finding, FindingSeverity
from core.loaders import load_structured
from core.mcp_gov import injection, rbac
from core.security.sanitize import sanitize_untrusted
from core.security.secret_scan import RULES as SECRET_RULES

TOOL = "mcp_manifest"
SEVERITY_WEIGHTS = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "cmd", "cmd.exe", "powershell", "pwsh", "powershell.exe"})
INLINE_FLAGS = {"python": ("-c",), "python3": ("-c",), "node": ("-e", "--eval"), "deno": ("eval",), "ruby": ("-e",),
                "perl": ("-e",), "sh": ("-c",), "bash": ("-c",), "zsh": ("-c",), "cmd": ("/c", "/k"),
                "powershell": ("-command", "-c", "-encodedcommand", "-enc"), "pwsh": ("-command", "-c", "-enc")}
PACKAGE_RUNNERS = frozenset({"npx", "bunx", "uvx", "pipx", "pnpm", "dlx"})
SECRET_KEY_HINT = re.compile(r"(?i)(secret|token|passw(?:or)?d|api[_-]?key|access[_-]?key|private[_-]?key|credential|authorization)")
SECRET_REFERENCE = re.compile(r"^\s*(?:\$\{?[A-Za-z_]|\{\{|secret://|vault:|op://|env:|gcp-sm://|aws-sm://|keychain:)")
BUILTIN_TOOL_NAMES = frozenset({"bash", "read", "write", "edit", "glob", "grep", "webfetch", "websearch", "task"})
SENSITIVE_URI = re.compile(r"(?i)(?:^|/)\.(?:ssh|aws|gnupg|kube|env)\b|id_rsa|/etc/(?:shadow|passwd)")
BROAD_ROOT = re.compile(r"^(?:file://)?(?:/|~|\$HOME|/\*|/home|/root|/Users|[A-Za-z]:[\\/]?)$|^file:///?\*?$")
DANGEROUS_PARAMS_HIGH = frozenset({"command", "cmd", "script", "code", "sql", "expression"})
DANGEROUS_PARAMS = DANGEROUS_PARAMS_HIGH | {"path", "file_path", "filepath", "filename", "url", "uri", "endpoint",
                                            "host", "template"}
WORD = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")

EXEC_WORDS = re.compile(r"\b(exec|execute|shell|bash|eval|spawn|terminal|subprocess|run[ ](?:command|script|code|shell))\b")
DESTRUCTIVE_WORDS = re.compile(r"\b(delete|remove|drop|truncate|destroy|purge|wipe|revoke|terminate|kill|overwrite|reset)\b")
WRITE_WORDS = re.compile(r"\b(write|create|update|edit|modify|put|post|send|upload|insert|patch|commit|push|deploy|apply|"
                         r"grant|invite|publish)\b")
EGRESS_WORDS = re.compile(r"\b(send|post|upload|email|mail|webhook|publish|notify|forward|share|tweet|sms|http request|"
                          r"fetch url|make request)\b")
READ_WORDS = re.compile(r"\b(read|get|list|search|query|fetch|download|export|retrieve|open)\b")
PRIVATE_NOUNS = re.compile(r"\b(file|files|document|documents|email|emails|mail|inbox|database|db|sql|secret|secrets|"
                           r"credential|credentials|customer|patient|drive|calendar|contact|contacts|record|records|"
                           r"memory|source|repository)\b")
UNTRUSTED_NOUNS = re.compile(r"\b(web|url|page|browse|scrape|email|emails|inbox|message|messages|issue|issues|ticket|"
                             r"comment|comments|pull request|rss|feed|search|website)\b")


@dataclass
class McpServer:
    name: str
    raw: dict[str, Any]
    transport: str = ""
    url: str = ""
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, Any] = field(default_factory=dict)
    auth: dict[str, Any] = field(default_factory=dict)
    scopes: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    tools: list[dict[str, Any]] = field(default_factory=list)
    resources: list[Any] = field(default_factory=list)

    @property
    def host(self) -> str:
        return (urlparse(self.url).hostname or "").lower() if self.url else ""

    @property
    def remote(self) -> bool:
        return bool(self.url) and self.host not in LOCAL_HOSTS


def _str_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [p for p in re.split(r"[,\s]+", value) if p]
    return [str(v) for v in value] if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _server(name: str, raw: dict[str, Any]) -> McpServer:
    auth = raw.get("auth") or raw.get("authentication") or raw.get("oauth") or {}
    auth = {"type": auth} if isinstance(auth, str) else _dict(auth)
    gov = _dict(raw.get("governance"))
    scopes = _str_list(auth.get("scopes") or raw.get("scopes") or _dict(raw.get("permissions")).get("scopes"))
    groups = _str_list(gov.get("approved_groups") or raw.get("allowed_groups") or raw.get("audience")
                       or raw.get("groups"))
    url = str(raw.get("url") or raw.get("endpoint") or raw.get("serverUrl") or "")
    command = str(raw.get("command") or "")
    transport = str(raw.get("transport") or raw.get("type") or ("stdio" if command else "http" if url else "")).lower()
    return McpServer(name=str(raw.get("name") or name), raw=raw, transport=transport, url=url, command=command,
                     args=[str(a) for a in raw.get("args") or []], env=_dict(raw.get("env")),
                     headers=_dict(raw.get("headers")), auth=auth, scopes=scopes, groups=groups,
                     tools=[t for t in raw.get("tools") or [] if isinstance(t, dict)],
                     resources=raw.get("resources") or raw.get("roots") or [])


def parse_servers(data: Any) -> list[McpServer]:
    """Normalize a manifest or client config into servers; ValueError when it is neither."""
    if not isinstance(data, dict):
        raise ValueError("not an MCP manifest (expected an object)")
    for key in ("mcpServers", "servers"):
        if isinstance(data.get(key), dict):
            return [_server(n, v) for n, v in data[key].items() if isinstance(v, dict)]
    if "tools" in data or ("name" in data and any(k in data for k in ("transport", "command", "url", "endpoint"))):
        return [_server(str(data.get("name", "server")), data)]
    raise ValueError("not an MCP manifest (no tools, mcpServers or transport)")


def looks_like_manifest(data: Any) -> bool:
    try:
        parse_servers(data)
    except ValueError:
        return False
    return True


def _words(name: str) -> str:
    return " ".join(w.lower() for w in WORD.findall(name.replace("_", " ").replace("-", " ")))


def _annotations(tool: dict[str, Any]) -> dict[str, Any]:
    return _dict(tool.get("annotations"))


def classify_tool(tool: dict[str, Any]) -> dict[str, bool]:
    """Behavior classes inferred from the tool's name and description (deterministic keyword rules)."""
    name = _words(str(tool.get("name", "")))
    text = f"{name} {_words(str(tool.get('description', '')))}"
    read_name = bool(READ_WORDS.search(name))
    return {
        "exec": bool(EXEC_WORDS.search(name)),
        "destructive": bool(DESTRUCTIVE_WORDS.search(name)),
        "write": bool(WRITE_WORDS.search(name)),
        "egress": bool(EGRESS_WORDS.search(name)) or _annotations(tool).get("openWorldHint") is True,
        "private_data": (read_name and bool(PRIVATE_NOUNS.search(text))),
        "untrusted_content": (read_name and bool(UNTRUSTED_NOUNS.search(text))),
    }


def _f(rule_id: str, severity: FindingSeverity, category: str, title: str, server: McpServer, rec: str,
       location: str = "", **evidence: Any) -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=severity, category=category, resource=server.name,
                   location=location or server.name, evidence=evidence, recommendation=rec)


def _is_secret_literal(key: str, value: Any) -> bool:
    if not isinstance(value, str) or not value or SECRET_REFERENCE.match(value):
        return False
    if any(rule.pattern.search(value) for rule in SECRET_RULES):
        return True
    return bool(SECRET_KEY_HINT.search(key)) and len(value) >= 8 and not value.lower().startswith(("bearer ${", "${"))


def check_transport(s: McpServer) -> list[Finding]:
    out: list[Finding] = []
    if s.url.lower().startswith("http://") and s.host not in LOCAL_HOSTS:
        out.append(_f("MCP-TRANSPORT-PLAINTEXT", "high", "transport", "Remote MCP endpoint over plaintext HTTP", s,
                      "Require TLS (https) for every non-loopback endpoint.", url=sanitize_untrusted(s.url, 200)))
    for key in ("verify_tls", "tls_verify", "verifyTls", "rejectUnauthorized", "verify_ssl"):
        if s.raw.get(key) is False:
            out.append(_f("MCP-TLS-VERIFY-OFF", "high", "transport", "TLS certificate verification disabled", s,
                          "Never disable certificate verification; fix the trust chain instead.", setting=key))
    if s.raw.get("insecure") is True:
        out.append(_f("MCP-TLS-VERIFY-OFF", "high", "transport", "Manifest sets insecure: true", s,
                      "Remove the insecure flag."))
    return out


def check_launch(s: McpServer) -> list[Finding]:
    """stdio launch command: inline code, unpinned packages, privileged containers."""
    if not s.command:
        return []
    out: list[Finding] = []
    exe = Path(s.command).name.lower()
    args = s.args
    joined = " ".join([s.command, *args])
    flags = INLINE_FLAGS.get(exe.removesuffix(".exe"), ())
    if exe in SHELLS or any(a.lower() in flags for a in args):
        out.append(_f("MCP-CMD-INLINE", "high", "execution", "Server is launched through a shell or inline code", s,
                      "Launch a reviewed, pinned executable with a fixed argument list.",
                      command=sanitize_untrusted(joined, 200)))
    if re.search(r"(curl|wget)\s[^|]*\|\s*(ba)?sh", joined):
        out.append(_f("MCP-CMD-REMOTE-EXEC", "critical", "supply-chain", "Launch command pipes a download into a shell", s,
                      "Block. Vendor and pin the server.", command=sanitize_untrusted(joined, 200)))
    if exe in PACKAGE_RUNNERS:
        pkg = next((a for a in args if not a.startswith("-") and a not in ("dlx", "exec", "run")), "")
        pinned = bool(re.search(r"(?<=.)@\d[\w.\-+]*$|==\d|@sha256:", pkg)) and not pkg.endswith("@latest")
        if pkg and not pinned:
            out.append(_f("MCP-PKG-UNPINNED", "medium", "supply-chain",
                          f"Package {sanitize_untrusted(pkg, 80)!r} runs unpinned (latest at launch)", s,
                          "Pin an exact version (and lockfile/hash) from the approved internal registry.",
                          package=sanitize_untrusted(pkg, 80)))
    for i, arg in enumerate(args):
        if BROAD_ROOT.match(arg.strip()):
            out.append(_f("MCP-RESOURCE-BROAD", "high", "rbac", "Launch argument grants the whole filesystem root", s,
                          "Pass a dedicated working directory, never / or $HOME.", location=f"{s.name}:args[{i}]",
                          argument=sanitize_untrusted(arg, 80)))
    if exe == "docker" and "run" in args:
        risky = [a for a in args if a in ("--privileged", "--network=host", "--pid=host", "--cap-add=ALL")
                 or "docker.sock" in a or a.startswith(("-v/:", "--volume=/:"))]
        if risky or any(a in ("-v", "--volume") and i + 1 < len(args) and args[i + 1].startswith("/:")
                        for i, a in enumerate(args)):
            out.append(_f("MCP-CONTAINER-PRIV", "high", "execution", "Container launched with host-level privileges", s,
                          "Remove privileged flags and host mounts; grant only the specific mounts required.",
                          flags=sanitize_untrusted(" ".join(risky), 200)))
        image = next((a for a in reversed(args) if not a.startswith("-") and ("/" in a or ":" in a or a.isalnum())), "")
        if image and "@sha256:" not in image and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")):
            out.append(_f("MCP-IMAGE-UNPINNED", "medium", "supply-chain", "Container image is not pinned by digest", s,
                          "Pin the image by @sha256 digest from the approved registry.", image=sanitize_untrusted(image, 120)))
    return out


def check_secrets(s: McpServer) -> list[Finding]:
    out: list[Finding] = []
    sources = [("env", s.env), ("headers", s.headers)]
    for where, mapping in sources:
        for key, value in mapping.items():
            if _is_secret_literal(str(key), value):
                out.append(_f("MCP-SECRET-LITERAL", "high", "secrets", f"Literal credential in {where}.{key}", s,
                              "Reference a secret from the vault (e.g. ${VAR} injected at runtime); rotate the exposed value.",
                              location=f"{s.name}:{where}.{key}", field=f"{where}.{key}", length=len(str(value))))
    for i, arg in enumerate(s.args):
        prev = s.args[i - 1] if i else ""
        if _is_secret_literal(prev.lstrip("-"), arg) or any(r.pattern.search(arg) for r in SECRET_RULES):
            out.append(_f("MCP-SECRET-LITERAL", "high", "secrets", "Literal credential in launch arguments", s,
                          "Pass secrets through the environment from the vault, not argv (visible in process lists).",
                          location=f"{s.name}:args[{i}]", field=f"args[{i}]", length=len(arg)))
    return out


def check_tools(s: McpServer, max_tools: int) -> list[Finding]:
    out: list[Finding] = []
    names = [str(t.get("name", "")) for t in s.tools]
    for name, n in Counter(names).items():
        if n > 1:
            out.append(_f("MCP-TOOL-DUP", "medium", "tool-behavior", f"Duplicate tool name {name!r}", s,
                          "Tool names must be unique; duplicates enable shadowing.", location=f"{s.name}:tools.{name}"))
    for name in names:
        if name.lower() in BUILTIN_TOOL_NAMES:
            out.append(_f("MCP-TOOL-SHADOW", "medium", "tool-behavior", f"Tool name {name!r} collides with a built-in tool",
                          s, "Rename it; a colliding name can hijack calls meant for the built-in.",
                          location=f"{s.name}:tools.{name}"))
    if len(s.tools) > max_tools:
        out.append(_f("MCP-TOOL-COUNT", "low", "tool-behavior", f"{len(s.tools)} tools exposed (limit {max_tools})", s,
                      "Expose only the tools the use case needs; every tool widens the attack surface."))
    if s.tools and not any(_annotations(t) for t in s.tools):
        out.append(_f("MCP-TOOL-NO-ANNOTATIONS", "low", "tool-behavior",
                      "No tool declares behavior annotations (readOnlyHint, destructiveHint, openWorldHint)", s,
                      "Declare annotations so clients can gate destructive or open-world calls."))
    legs: dict[str, list[str]] = {"private_data": [], "untrusted_content": [], "egress": []}
    for t in s.tools:
        name, ann, cls = str(t.get("name", "")), _annotations(t), classify_tool(t)
        loc = f"{s.name}:tools.{name}"
        for leg in legs:
            if cls[leg]:
                legs[leg].append(name)
        if cls["exec"]:
            out.append(_f("MCP-TOOL-EXEC", "high", "tool-behavior", f"Tool {name!r} executes commands or code", s,
                          "Remove, or run in a sandbox with a fixed command allowlist and per-call human approval.",
                          location=loc, tool=name))
        if cls["destructive"] and ann.get("destructiveHint") is not True:
            out.append(_f("MCP-TOOL-DESTRUCTIVE", "medium", "tool-behavior",
                          f"Tool {name!r} looks destructive but is not annotated destructiveHint", s,
                          "Annotate destructiveHint: true so clients require confirmation.", location=loc, tool=name))
        if ann.get("readOnlyHint") is True and (cls["exec"] or cls["destructive"] or cls["write"]):
            out.append(_f("MCP-TOOL-ANNOTATION-MISMATCH", "high", "tool-behavior",
                          f"Tool {name!r} claims readOnlyHint but its name implies it changes state", s,
                          "Correct the annotation or the tool; a false read-only claim bypasses client safeguards.",
                          location=loc, tool=name))
        props = _dict(_dict(t.get("inputSchema") or t.get("input_schema")).get("properties"))
        loose = sorted(p for p, spec in props.items() if p.lower() in DANGEROUS_PARAMS and isinstance(spec, dict)
                       and spec.get("type", "string") == "string"
                       and not any(k in spec for k in ("enum", "pattern", "maxLength", "format", "const")))
        if loose:
            worst: FindingSeverity = "high" if any(p.lower() in DANGEROUS_PARAMS_HIGH for p in loose) else "medium"
            out.append(_f("MCP-INPUT-UNCONSTRAINED", worst, "tool-behavior",
                          f"Tool {name!r} takes unconstrained string input for sensitive parameter(s)", s,
                          "Add enum/pattern/maxLength constraints and validate server-side.", location=loc,
                          tool=name, parameters=loose))
    if all(legs.values()):
        out.append(_f("MCP-EXFIL-TRIFECTA", "high", "exfiltration",
                      "Server combines private-data access, untrusted content and an external send path", s,
                      "Split the capabilities across servers, or require human approval on the egress tools.",
                      legs={k: sorted(set(v)) for k, v in legs.items()}))
    elif legs["private_data"] and legs["egress"]:
        out.append(_f("MCP-EXFIL-PATH", "medium", "exfiltration", "Server can read private data and send it externally", s,
                      "Restrict egress destinations and require approval on the sending tools.",
                      legs={k: sorted(set(v)) for k, v in legs.items() if k != "untrusted_content"}))
    return out


def check_resources(s: McpServer) -> list[Finding]:
    out: list[Finding] = []
    for res in s.resources:
        uri = str(res.get("uri") or res.get("path") or "") if isinstance(res, dict) else str(res)
        if BROAD_ROOT.match(uri.strip()) or SENSITIVE_URI.search(uri):
            out.append(_f("MCP-RESOURCE-BROAD", "high", "rbac", "Resource root exposes the whole filesystem or credential paths",
                          s, "Scope resources to a dedicated working directory; never expose $HOME or credential stores.",
                          uri=sanitize_untrusted(uri, 200)))
    return out


def check_provenance(s: McpServer) -> list[Finding]:
    if not (s.tools or s.url):  # a bare client-config launch entry has no manifest to hold provenance
        return []
    version = str(s.raw.get("version") or "")
    out: list[Finding] = []
    if not version or version.lower() in ("latest", "*", "main", "master"):
        out.append(_f("MCP-PROVENANCE-VERSION", "low", "supply-chain", "Server version missing or floating", s,
                      "Record an exact released version so approval applies to what is deployed."))
    if not any(s.raw.get(k) for k in ("repository", "homepage", "publisher", "author")):
        out.append(_f("MCP-PROVENANCE-SOURCE", "low", "supply-chain", "No repository, homepage or publisher declared", s,
                      "Require a traceable source before intake review."))
    return out


def scan_strings(s: McpServer) -> list[Finding]:
    """Run the prompt-injection scanner over every string in the server definition (tool poisoning lives here)."""
    out: list[Finding] = []

    def walk(node: Any, path: str) -> None:
        if isinstance(node, str):
            if len(node) > 1500 and path.endswith("description"):
                out.append(_f("MCP-DESCRIPTION-LONG", "low", "prompt-injection",
                              f"Unusually long description ({len(node)} chars) can hide instructions", s,
                              "Keep descriptions short and review them in full.", location=f"{s.name}:{path}"))
            out.extend(injection.scan_text(node, f"{s.name}", location_prefix=f"{s.name}:{path}"))
        elif isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}.{k}" if path else str(k))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")

    walk({k: v for k, v in s.raw.items() if k not in ("env", "headers")}, "")
    return out


def to_rbac(s: McpServer) -> rbac.Rbac:
    tools = []
    for t in s.tools:
        cls, ann = classify_tool(t), _annotations(t)
        tools.append(rbac.ToolAccess(
            name=str(t.get("name", "")), required_scopes=tuple(_str_list(t.get("requiredScopes") or t.get("scopes"))),
            read_only=ann.get("readOnlyHint") is True,
            mutating=cls["exec"] or cls["destructive"] or cls["write"] or ann.get("destructiveHint") is True))
    a = s.auth
    return rbac.Rbac(server=s.name, auth_type=str(a.get("type", "")).lower(), flow=str(a.get("flow", "")),
                     pkce=a.get("pkce"), scopes=tuple(s.scopes), groups=tuple(s.groups), tools=tools,
                     remote=s.remote)


def audit_server(s: McpServer, policy: rbac.RbacPolicy, max_tools: int = 25) -> list[Finding]:
    return [*check_transport(s), *rbac.validate(to_rbac(s), policy), *check_launch(s), *check_secrets(s),
            *check_tools(s, max_tools), *check_resources(s), *check_provenance(s), *scan_strings(s)]


def risk_score(findings: list[Finding]) -> int:
    return min(100, sum(SEVERITY_WEIGHTS[f.severity] for f in findings))


def analyze_file(path: Path, **opts: Any) -> AnalysisReport:
    """Options: `allowed_scopes` (comma list), `max_tools` (int, default 25), `require_audience` (bool, default true)."""
    path = Path(path)
    servers = parse_servers(load_structured(path))
    policy = rbac.RbacPolicy(allowed_scopes=frozenset(_str_list(opts.get("allowed_scopes", ""))),
                             require_audience=bool(opts.get("require_audience", True)))
    max_tools = int(opts.get("max_tools", 25))
    findings: list[Finding] = []
    for s in servers:
        findings.extend(audit_server(s, policy, max_tools))
    findings.sort(key=lambda f: -SEVERITY_ORDER[f.severity])
    worst = max((SEVERITY_ORDER[f.severity] for f in findings), default=0)
    gate = "blocked" if worst >= SEVERITY_ORDER["high"] else "needs_review" if findings else "eligible_for_human_review"
    return AnalysisReport(
        pack="mcp_gov", tool=TOOL, input=str(path), findings=findings,
        metrics={"servers": [s.name for s in servers], "tools": sum(len(s.tools) for s in servers),
                 "scopes": sorted({sc for s in servers for sc in s.scopes}),
                 "transports": sorted({s.transport for s in servers if s.transport}),
                 "risk_score": risk_score(findings), "release_gate": gate},
        summary=f"{len(findings)} finding(s) across {len(servers)} MCP server(s); release gate: {gate} "
                "(a human still authorizes release)")
