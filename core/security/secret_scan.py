"""Regex + entropy secret scanner. Findings never contain the secret itself: only a redacted prefix,
its length and a sha256 fingerprint (which is what `.secretsallow` matches on)."""

from __future__ import annotations

import fnmatch
import hashlib
import math
import os
import re
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.common import AnalysisReport, Finding, FindingSeverity

TOOL = "secret_scan"
ALLOWLIST_FILENAME = ".secretsallow"
SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "trees", "dist", "__pycache__", ".mypy_cache",
                       ".ruff_cache", ".pytest_cache"})
SKIP_PATH_PARTS: tuple[tuple[str, ...], ...] = (("agent", "runs"), ("agent", "reports"))
DEFAULT_MAX_BYTES = 1_000_000
DEFAULT_ENTROPY_THRESHOLD = 3.5


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    title: str
    severity: FindingSeverity
    pattern: re.Pattern[str]
    group: int = 0  # regex group holding the secret value


RULES: tuple[SecretRule, ...] = (
    SecretRule("SECRET-AWS-ACCESS-KEY", "AWS access key id", "critical",
               re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"), 1),
    SecretRule("SECRET-GITHUB-TOKEN", "GitHub token", "high",
               re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"), 1),
    SecretRule("SECRET-ANTHROPIC-KEY", "Anthropic API key", "high",
               re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})"), 1),
    SecretRule("SECRET-OPENAI-KEY", "OpenAI API key", "high",
               re.compile(r"\b(sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,})"), 1),
    SecretRule("SECRET-SLACK-TOKEN", "Slack token", "high",
               re.compile(r"\b(xox[abposr]-[A-Za-z0-9\-]{10,})"), 1),
    SecretRule("SECRET-PRIVATE-KEY", "Private key block", "critical",
               re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"), 1),
)
GENERIC_RULE_ID = "SECRET-GENERIC-HIGH-ENTROPY"
_GENERIC_ASSIGNMENT = re.compile(
    r"(?i)\b([A-Za-z0-9_.\-]*(?:secret|token|passwd|password|api[_\-]?key|access[_\-]?key|private[_\-]?key|credential)"
    r"[A-Za-z0-9_.\-]*)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9+/=_\-.~]{16,})[\"']"
)
_PLACEHOLDER = re.compile(r"(?i)(example|placeholder|changeme|your[_\-]|xxxx|dummy|\$\{|<)")


@dataclass(frozen=True)
class SecretMatch:
    rule_id: str
    title: str
    severity: FindingSeverity
    path: str
    line: int
    secret: str = field(repr=False)
    entropy: float

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.secret)


@dataclass(frozen=True)
class Allowlist:
    path_globs: tuple[str, ...] = ()
    fingerprints: frozenset[str] = frozenset()

    def allows(self, rel_path: str, fp: str) -> bool:
        return fp in self.fingerprints or any(fnmatch.fnmatch(rel_path, g) for g in self.path_globs)


def shannon_entropy(value: str) -> float:
    """Bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


def redact(secret: str) -> str:
    return f"{secret[:4]}…({len(secret)} chars)"


def redact_secrets(text: str) -> str:
    """Replace every known-format secret in `text` with a `[REDACTED:<rule>]` marker (for evidence and samples)."""
    for rule in RULES:
        def repl(m: re.Match[str], rule: SecretRule = rule) -> str:
            return m.group(0).replace(m.group(rule.group), f"[REDACTED:{rule.rule_id}]")

        text = rule.pattern.sub(repl, text)

    def redact_generic(m: re.Match[str]) -> str:
        return m.group(0) if _PLACEHOLDER.search(m.group(2)) else m.group(0).replace(m.group(2), "[REDACTED:GENERIC]")

    return _GENERIC_ASSIGNMENT.sub(redact_generic, text)


def parse_allowlist(text: str) -> Allowlist:
    """Lines are path globs (relative to the allowlist's directory) or `fingerprint:<hex16>`; `#` comments."""
    globs: list[str] = []
    fps: set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("fingerprint:"):
            fps.add(line.removeprefix("fingerprint:").strip().lower())
        else:
            globs.append(line.rstrip("/"))
    return Allowlist(tuple(globs), frozenset(fps))


def find_allowlist(start: Path) -> Path | None:
    """Nearest `.secretsallow` in `start` or any ancestor."""
    for directory in (start, *start.parents):
        candidate = directory / ALLOWLIST_FILENAME
        if candidate.is_file():
            return candidate
    return None


def scan_text(text: str, path: str = "", entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD) -> list[SecretMatch]:
    matches: list[SecretMatch] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        matched_spans: list[tuple[int, int]] = []
        for rule in RULES:
            for m in rule.pattern.finditer(line):
                secret = m.group(rule.group)
                matched_spans.append(m.span(rule.group))
                matches.append(SecretMatch(rule.rule_id, rule.title, rule.severity, path, line_no, secret,
                                           round(shannon_entropy(secret), 3)))
        for m in _GENERIC_ASSIGNMENT.finditer(line):
            secret = m.group(2)
            start, end = m.span(2)
            if any(s < end and start < e for s, e in matched_spans) or _PLACEHOLDER.search(secret):
                continue
            entropy = shannon_entropy(secret)
            if entropy >= entropy_threshold and _mixed_charset(secret):
                matches.append(SecretMatch(GENERIC_RULE_ID, f"High-entropy value assigned to `{m.group(1)}`",
                                           "medium", path, line_no, secret, round(entropy, 3)))
    return matches


def _mixed_charset(value: str) -> bool:
    """Generated secrets mix character classes; identifiers like `my-app-token-key` do not."""
    classes = (str.islower, str.isupper, str.isdigit)
    return sum(any(test(c) for c in value) for test in classes) >= 2


def _is_skipped_dir(rel_parts: tuple[str, ...]) -> bool:
    if rel_parts and rel_parts[-1] in SKIP_DIRS:
        return True
    return any(rel_parts[i : i + len(seq)] == seq for seq in SKIP_PATH_PARTS for i in range(len(rel_parts)))


def iter_files(root: Path) -> Iterator[Path]:
    """Deterministically walk `root`, pruning vendored/ephemeral directories."""
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        rel = base.relative_to(root).parts
        dirnames[:] = sorted(d for d in dirnames if not _is_skipped_dir((*rel, d)))
        for name in sorted(filenames):
            yield base / name


def read_text_file(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> str | None:
    """File contents, or None for binary / oversized / unreadable files."""
    try:
        if path.stat().st_size > max_bytes:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def _to_finding(match: SecretMatch, location_path: str) -> Finding:
    return Finding(
        rule_id=match.rule_id,
        title=match.title,
        severity=match.severity,
        category="secret",
        resource=location_path,
        location=f"{location_path}:{match.line}",
        evidence={"redacted": redact(match.secret), "length": len(match.secret),
                  "fingerprint": match.fingerprint, "entropy": match.entropy},
        recommendation="Revoke and rotate the credential, remove it from history, load it from the environment. "
        f"If it is a known test value, add `fingerprint:{match.fingerprint}` to {ALLOWLIST_FILENAME}.",
    )


def scan_paths(
    paths: Iterable[Path],
    allowlist: Allowlist | None = None,
    allowlist_root: Path | None = None,
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> tuple[list[Finding], dict[str, int]]:
    """Scan files/directories. Allowlist globs are matched against paths relative to `allowlist_root`."""
    findings: list[Finding] = []
    stats = {"files_scanned": 0, "files_skipped": 0, "suppressed": 0}
    for top in paths:
        for file in iter_files(top):
            text = read_text_file(file, max_bytes)
            if text is None:
                stats["files_skipped"] += 1
                continue
            stats["files_scanned"] += 1
            rel_to_allow = _relative(file, allowlist_root)
            display = _relative(file, top if top.is_dir() else top.parent)
            for match in scan_text(text, display, entropy_threshold):
                if allowlist and allowlist.allows(rel_to_allow, match.fingerprint):
                    stats["suppressed"] += 1
                    continue
                findings.append(_to_finding(match, display))
    return findings, stats


def _relative(path: Path, root: Path | None) -> str:
    if root is None:
        return path.as_posix()
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def analyze_file(
    path: Path,
    allowlist: Path | str | None = None,
    use_allowlist: bool = True,
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    **opts: Any,
) -> AnalysisReport:
    """Scan a file or directory. By default the nearest `.secretsallow` (searching upward) is applied."""
    path = Path(path)
    allow_file = Path(allowlist) if allowlist else find_allowlist((path if path.is_dir() else path.parent).resolve())
    allow = parse_allowlist(allow_file.read_text(encoding="utf-8")) if (use_allowlist and allow_file) else None
    findings, stats = scan_paths(
        [path], allow, allow_file.parent if allow_file else None, float(entropy_threshold),
        int(opts.get("max_bytes", DEFAULT_MAX_BYTES)),
    )
    return AnalysisReport(
        pack="swe",
        tool=TOOL,
        input=str(path),
        findings=findings,
        metrics={**stats, "findings": len(findings),
                 "allowlist": str(allow_file) if allow is not None and allow_file else None},
        summary=f"{len(findings)} potential secret(s) in {stats['files_scanned']} file(s); "
        f"{stats['suppressed']} suppressed by allowlist",
    )
