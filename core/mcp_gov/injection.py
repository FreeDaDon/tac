"""Prompt-injection and data-exfiltration scanner for third-party AI connectors, scripts and skills.

Deterministic, regex-based, no LLM. Every snippet placed in evidence is redacted (known secret formats)
and sanitized (control/bidi characters stripped, length capped) because the scanned text is attacker-controlled.
Rule ids: INJ-* (instructions aimed at the model), EXF-* (data leaving), EXE-* (code execution), SUP-* (supply chain).
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.common import AnalysisReport, Finding, FindingSeverity
from core.security.sanitize import find_suspicious_unicode, snippet
from core.security.secret_scan import iter_files, read_text_file

TOOL = "connector_scan"
MAX_FINDINGS_PER_FILE = 200
SKIP_SUFFIXES = (".lock", ".min.js", ".map", ".svg", ".png", ".jpg", ".gif", ".ico", ".woff", ".woff2", ".pdf")
SKIP_NAMES = frozenset({"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "uv.lock", "poetry.lock"})
TAG_CHAR_RANGE = range(0xE0000, 0xE0080)  # Unicode "tag" block: invisible ASCII smuggling


@dataclass(frozen=True)
class LineRule:
    rule_id: str
    severity: FindingSeverity
    category: str
    title: str
    pattern: re.Pattern[str]
    recommendation: str


def _rule(rule_id: str, severity: FindingSeverity, category: str, title: str, pattern: str, rec: str,
          flags: int = re.IGNORECASE) -> LineRule:
    return LineRule(rule_id, severity, category, title, re.compile(pattern, flags), rec)


INJECTION_RULES: tuple[LineRule, ...] = (
    _rule("INJ-OVERRIDE", "high", "prompt-injection", "Instruction-override phrase",
          r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|system|all|any|your)\b"
          r"[^.\n]{0,30}\b(instructions?|prompts?|rules?|guidelines?|polic(?:y|ies)|safety)\b",
          "Reject the connector or remove the text; tool metadata must describe behavior, not command the model."),
    _rule("INJ-ROLE-HIJACK", "high", "prompt-injection", "Role or system-prompt hijack phrase",
          r"\byou are (now|no longer)\b|\bnew (system )?(prompt|instructions?)\s*:|\bact as (an? )?(unrestricted|jailbroken)\b"
          r"|\bdeveloper mode\b",
          "Reject the connector or remove the text."),
    _rule("INJ-CONCEAL", "critical", "prompt-injection", "Instruction to conceal actions from the user",
          r"\b(do not|don't|never|without)\b[^.\n]{0,25}\b(tell|inform|notify|mention|reveal|show|disclose|alert)\b"
          r"[^.\n]{0,20}\b(the )?(user|human|operator|anyone)\b"
          r"|\b(silently|secretly|covertly|quietly)\b[^.\n]{0,30}\b(send|forward|upload|post|copy|call|read|include)\b",
          "Treat as a malicious tool-poisoning attempt: block the connector and report it to security."),
    _rule("INJ-TOOL-COERCION", "high", "prompt-injection", "Tool-poisoning pattern (coerces other tool use)",
          r"<\s*important\s*>|\b(before|prior to)\b[^.\n]{0,40}\b(you must|always|first)\b[^.\n]{0,40}"
          r"\b(read|call|use|send|fetch|include)\b|\balways (call|use|invoke) this tool (first|before)\b"
          r"|\b(instead of|rather than)\b[^.\n]{0,20}\b(what|the)\b[^.\n]{0,30}\b(user|requested|asked)\b",
          "Reject the connector; a tool description must not direct how the model uses other tools or data."),
    _rule("INJ-ROLE-MARKUP", "medium", "prompt-injection", "Chat-template or role-delimiter markup in content",
          r"<\|(?:im_start|im_end|system|endoftext)\|>|\[/?INST\]|<</?SYS>>|^\s*(?:system|assistant)\s*:"
          r"|</?\s*(?:system|untrusted[\w_-]*)\s*>",
          "Strip role-delimiter markup; it can spoof a system message inside tool output."),
    _rule("INJ-HIDDEN-COMMENT", "medium", "prompt-injection", "Instruction-like text hidden in an HTML comment",
          r"<!--[^\n]*\b(instruction|ignore|you must|always|never tell|system prompt|assistant)\b[^\n]*-->",
          "Remove hidden comments from connector docs and tool metadata."),
)

SENSITIVE_PATH = (r"(?:~|\$HOME|/home/\w+|/root)?/?\.(?:ssh|aws|gnupg|kube|docker)/|\bid_(?:rsa|ed25519|ecdsa)\b"
                  r"|\.config/(?:gcloud|gh)\b|\bapplication_default_credentials\.json\b"
                  r"|(?:^|[\s/'\"])\.(?:env|npmrc|netrc|pgpass)\b|/etc/(?:shadow|passwd)\b|\bkubeconfig\b"
                  r"|\bLogin Data\b|\bcookies\.sqlite\b")
ENV_DUMP = (r"\bdict\(os\.environ\)|\bos\.environ\.(?:copy|items|keys|values)\(\)|\bjson\.dumps\(\s*os\.environ"
            r"|\bprintenv\b|\benv\s*\||JSON\.stringify\(\s*process\.env\s*\)|Object\.\w+\(process\.env\)|\.\.\.process\.env")
NET_EGRESS = (r"\brequests\.(?:post|put|patch)\(|\bhttpx\.(?:post|put)\(|\burllib\.request\.urlopen\(|\bhttp\.client\b"
              r"|\bfetch\(|\baxios\.(?:post|put)|\bcurl\s+[^|\n]*(?:-d\b|--data|-F\b|-T\b|--upload-file)"
              r"|\bwget\s+[^\n]*--post|\b(?:nc|ncat|socat)\s+\S+\s+\d+|\bsocket\.(?:connect|create_connection)\b"
              r"|\bXMLHttpRequest\b|navigator\.sendBeacon")
EXFIL_SINK = (r"webhook\.site|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|burpcollaborator|oast\.(?:fun|live|site|me)"
              r"|interact\.sh|pastebin\.com|transfer\.sh|discord(?:app)?\.com/api/webhooks|hooks\.slack\.com/services")
RAW_IP_URL = re.compile(r"https?://((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?/")
PRIVATE_IP = re.compile(r"^(?:127\.|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.)")

EXFIL_RULES: tuple[LineRule, ...] = (
    _rule("EXF-SENSITIVE-PATH", "high", "exfiltration", "Reads credential or key material paths", SENSITIVE_PATH,
          "Connectors must not touch credential stores; scope filesystem access to a declared working directory."),
    _rule("EXF-ENV-DUMP", "high", "exfiltration", "Dumps the whole process environment", ENV_DUMP,
          "Read only the named variables the connector needs; never serialize the environment."),
    _rule("EXF-NET-EGRESS", "medium", "exfiltration", "Outbound network write", NET_EGRESS,
          "Allowlist destination hosts in the platform egress policy and document the data sent."),
    _rule("EXF-SINK-DOMAIN", "high", "exfiltration", "Known data-capture / tunnel / paste domain", EXFIL_SINK,
          "Block the destination; no enterprise connector needs a public capture endpoint."),
    _rule("EXF-MD-IMAGE", "high", "exfiltration", "Markdown or HTML image URL that interpolates data (render-time exfiltration)",
          r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*(?:\{\{|\$\{|\{[a-z_]+\}|%7B)"
          r"|<img[^>]+src=[\"']https?://[^\"']*[?&][^\"']*(?:\{\{|\$\{|\{[a-z_]+\})",
          "Strip remote images from tool output or proxy them through an allowlist; URLs must not carry model data."),
    _rule("EXE-DYNAMIC", "high", "execution", "Dynamic code execution or unsafe deserialization",
          r"\beval\(|\bexec\(|\bos\.system\(|subprocess\.\w+\([^)]*shell\s*=\s*True|\bchild_process\b.*\bexec(?:Sync)?\("
          r"|\bnew Function\(|\bpickle\.loads?\(|\byaml\.load\((?!.*SafeLoader)",
          "Replace with a fixed argument list; never build code or shell strings from model-supplied input."),
    _rule("SUP-REMOTE-EXEC", "critical", "supply-chain", "Downloads and executes remote code",
          r"(?:curl|wget)\s[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|base64\s+(?:-d|--decode)[^|\n]*\|\s*(?:ba)?sh"
          r"|\bpowershell\b.*-enc(?:odedcommand)?\b|\biex\s*\(.*(?:downloadstring|iwr)",
          "Block: vendor the code, pin it by hash and review it instead of piping it into a shell."),
    _rule("SUP-INSTALL", "medium", "supply-chain", "Install hook or install from a URL/custom index",
          r"\"(?:pre|post)?install\"\s*:|pip3?\s+install\s+[^\n]*(?:git\+|https?://|--index-url|--extra-index-url)"
          r"|npm\s+(?:i|install)\s+[^\n]*(?:https?://|git\+)",
          "Pin dependencies by version and hash from the approved registry; review install scripts."),
)
ALL_RULES = INJECTION_RULES + EXFIL_RULES
_BY_ID = {r.rule_id: r for r in ALL_RULES}
SENSITIVE_RULES = ("EXF-SENSITIVE-PATH", "EXF-ENV-DUMP")
EGRESS_RULES = ("EXF-NET-EGRESS", "EXF-SINK-DOMAIN")
_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])")


def _finding(rule_id: str, severity: FindingSeverity, category: str, title: str, source: str, location: str,
             evidence: dict[str, Any], recommendation: str) -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=severity, category=category, resource=source,
                   location=location, evidence=evidence, recommendation=recommendation)


def _decode_b64(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    printable = sum(c.isprintable() or c in "\n\t" for c in text)
    return text if text and printable / len(text) >= 0.95 else None


def _line_matches(rule: LineRule, line: str) -> bool:
    if rule.rule_id == "EXF-SINK-DOMAIN":
        return bool(rule.pattern.search(line)) or any(
            not PRIVATE_IP.match(m.group(1)) for m in RAW_IP_URL.finditer(line))
    return bool(rule.pattern.search(line))


def scan_text(text: str, source: str, line_offset: int = 0, location_prefix: str | None = None) -> list[Finding]:
    """Scan text; `location_prefix` replaces `source:line` (used for JSON paths inside manifests)."""
    findings: list[Finding] = []
    first_hit: dict[str, tuple[int, str]] = {}

    def loc(line_no: int) -> str:
        return location_prefix if location_prefix is not None else f"{source}:{line_no + line_offset}"

    for line_no, line in enumerate(text.removeprefix("﻿").splitlines(), start=1):
        for rule in ALL_RULES:
            if _line_matches(rule, line):
                first_hit.setdefault(rule.rule_id, (line_no, snippet(line)))
                findings.append(_finding(rule.rule_id, rule.severity, rule.category, rule.title, source, loc(line_no),
                                         {"line_preview": snippet(line)}, rule.recommendation))
        tags = [c for c in line if ord(c) in TAG_CHAR_RANGE]
        if tags:
            hidden = "".join(chr(ord(c) - 0xE0000) for c in tags)
            findings.append(_finding("INJ-ASCII-SMUGGLING", "critical", "prompt-injection",
                                     "Invisible Unicode tag characters encode a hidden message", source, loc(line_no),
                                     {"hidden_text": snippet(hidden), "characters": len(tags)},
                                     "Reject: invisible tag characters have no legitimate use in connector content."))
        if (hits := find_suspicious_unicode(line)):
            findings.append(_finding("INJ-HIDDEN-UNICODE", "high", "prompt-injection",
                                     "Bidirectional or zero-width characters hide content from reviewers", source,
                                     loc(line_no), {"characters": sorted({n for _, n in hits}), "line_preview": snippet(line)},
                                     "Remove the characters; review the raw bytes of the line."))
        for blob in _B64.findall(line):
            decoded = _decode_b64(blob)
            if decoded is None:
                continue
            hidden_injection = any(r.pattern.search(decoded) for r in INJECTION_RULES)
            findings.append(_finding(
                "INJ-ENCODED", "high" if hidden_injection else "medium", "prompt-injection",
                "Base64 blob decodes to instruction-like text" if hidden_injection else "Opaque base64-encoded text payload",
                source, loc(line_no), {"decoded_preview": snippet(decoded), "encoded_chars": len(blob)},
                "Replace encoded text with plain, reviewable content."))
    if any(r in first_hit for r in SENSITIVE_RULES):
        sensitive = next(first_hit[r] for r in SENSITIVE_RULES if r in first_hit)
        egress = next((first_hit[r] for r in EGRESS_RULES if r in first_hit), None)
        if egress:
            findings.append(_finding(
                "EXF-CHAIN", "critical", "exfiltration", "Reads sensitive data and has an outbound network path in the same file",
                source, loc(sensitive[0]),
                {"sensitive_access": {"line": sensitive[0], "preview": sensitive[1]},
                 "egress": {"line": egress[0], "preview": egress[1]}},
                "Block: this is the shape of a credential-stealing connector. Require a security review with the author."))
    return findings


def _skip(path: Path) -> bool:
    name = path.name.lower()
    return name in SKIP_NAMES or name.endswith(SKIP_SUFFIXES)


def analyze_file(path: Path, **opts: Any) -> AnalysisReport:
    """Scan one text file, or every text file under a directory, for injection/exfiltration/execution risks."""
    path = Path(path)
    findings: list[Finding] = []
    scanned = 0
    for file in iter_files(path):
        if _skip(file):
            continue
        text = read_text_file(file)
        if text is None:
            continue
        scanned += 1
        rel = file.relative_to(path).as_posix() if path.is_dir() else str(file)
        findings.extend(scan_text(text, rel)[:MAX_FINDINGS_PER_FILE])
    by_category: dict[str, int] = {}
    for f in findings:
        by_category[f.category] = by_category.get(f.category, 0) + 1
    blocked = any(f.severity in ("critical", "high") for f in findings)
    return AnalysisReport(
        pack="mcp_gov", tool=TOOL, input=str(path), findings=findings,
        metrics={"files_scanned": scanned, "by_category": by_category,
                 "release_gate": "blocked" if blocked else ("needs_review" if findings else "eligible_for_human_review")},
        summary=f"{len(findings)} injection/exfiltration finding(s) in {scanned} file(s)")
