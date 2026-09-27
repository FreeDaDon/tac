"""Helpers for handling untrusted text (logs, tool output, model output) before it reaches a report or prompt."""

from __future__ import annotations

import html
import re
import unicodedata
from pathlib import Path
from typing import Any

from core.common import AnalysisReport, Finding
from core.security.secret_scan import iter_files, read_text_file

TOOL = "unicode_scan"
DEFAULT_MAX_LEN = 10_000
TRUNCATION_MARKER = "…[truncated]"

# Bidirectional overrides/isolates (Trojan Source, CVE-2021-42574) and invisible zero-width characters.
BIDI_CHARS = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c")
ZERO_WIDTH_CHARS = frozenset("\u200b\u200c\u200d\u2060\ufeff")
_KEEP_WHITESPACE = frozenset("\n\t")
_MD_SPECIAL = re.compile(r"([\\`*_\[\]|~])")
_MD_LINE_START = re.compile(r"^(\s*)([#>+\-=])")


def is_unsafe_char(char: str) -> bool:
    """True for control (C0/C1/DEL), bidi and zero-width characters, except newline and tab."""
    if char in _KEEP_WHITESPACE:
        return False
    return char in BIDI_CHARS or char in ZERO_WIDTH_CHARS or unicodedata.category(char) == "Cc"


def strip_control_chars(text: str, keep_newlines: bool = True) -> str:
    cleaned = "".join(c for c in text if not is_unsafe_char(c))
    return cleaned if keep_newlines else re.sub(r"[\n\t]+", " ", cleaned)


def cap_length(text: str, max_len: int = DEFAULT_MAX_LEN, marker: str = TRUNCATION_MARKER) -> str:
    if len(text) <= max_len:
        return text
    return text[: max(0, max_len - len(marker))] + marker


def sanitize_untrusted(text: str, max_len: int = DEFAULT_MAX_LEN, keep_newlines: bool = True) -> str:
    """Strip control/bidi/zero-width characters, then cap length."""
    return cap_length(strip_control_chars(text, keep_newlines=keep_newlines), max_len)


def escape_html(text: str) -> str:
    return html.escape(text, quote=True)


def escape_markdown(text: str, max_len: int = 2_000) -> str:
    """Make untrusted text inert inside Markdown prose or a table cell (single line, no HTML, no markup)."""
    safe = sanitize_untrusted(text, max_len=max_len, keep_newlines=False)
    escaped = _MD_SPECIAL.sub(r"\\\1", html.escape(safe, quote=False))
    return _MD_LINE_START.sub(r"\1\\\2", escaped)


def markdown_code(text: str, max_len: int = 2_000) -> str:
    """Render untrusted text as inline code, choosing a backtick fence longer than any run inside it."""
    safe = sanitize_untrusted(text, max_len=max_len, keep_newlines=False)
    longest = max((len(run) for run in re.findall(r"`+", safe)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if safe.startswith("`") or safe.endswith("`") else ""
    return f"{fence}{pad}{safe}{pad}{fence}"


def find_suspicious_unicode(text: str) -> list[tuple[int, str]]:
    """Return (offset, codepoint name) for every bidi or zero-width character."""
    return [
        (i, unicodedata.name(c, f"U+{ord(c):04X}"))
        for i, c in enumerate(text)
        if c in BIDI_CHARS or c in ZERO_WIDTH_CHARS
    ]


def scan_text(text: str, source: str = "") -> list[Finding]:
    """One finding per line that hides bidi/zero-width characters (a leading BOM is ignored)."""
    findings: list[Finding] = []
    for line_no, line in enumerate(text.removeprefix("\ufeff").splitlines(), start=1):
        hits = find_suspicious_unicode(line)
        if not hits:
            continue
        bidi = any(line[i] in BIDI_CHARS for i, _ in hits)
        findings.append(
            Finding(
                rule_id="SWE-BIDI" if bidi else "SWE-ZERO-WIDTH",
                title="Bidirectional control character (Trojan Source)" if bidi else "Invisible zero-width character",
                severity="high" if bidi else "medium",
                category="supply-chain",
                resource=source,
                location=f"{source}:{line_no}",
                evidence={"characters": sorted({name for _, name in hits}), "columns": [i + 1 for i, _ in hits],
                          "line_preview": escape_markdown(line, max_len=200)},
                recommendation="Remove the character or justify it; review the line in a hex-aware viewer.",
            )
        )
    return findings


def analyze_file(path: Path, **opts: Any) -> AnalysisReport:
    """Scan a text file, or every text file under a directory, for hidden bidi/zero-width characters."""
    path = Path(path)
    findings: list[Finding] = []
    scanned = 0
    for file in iter_files(path):
        text = read_text_file(file)
        if text is None:
            continue
        scanned += 1
        findings.extend(scan_text(text, file.relative_to(path).as_posix() if path.is_dir() else str(file)))
    return AnalysisReport(
        pack="swe",
        tool=TOOL,
        input=str(path),
        findings=findings,
        metrics={"files_scanned": scanned, "lines_flagged": len(findings)},
        summary=f"{len(findings)} line(s) with hidden unicode control characters in {scanned} file(s)",
    )
