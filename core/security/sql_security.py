"""SQL injection defenses: identifier validation/escaping, safe execution, and query validation.

Ported from tac-7 app/server/core/sql_security.py with types, a non-raising `find_sql_issues`,
a UNION-based injection check, and `analyze_file` for linting a file of queries.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from core.common import AnalysisReport, Finding, FindingSeverity

TOOL = "sql_lint"


class SQLSecurityError(Exception):
    """Raised when SQL security validation fails."""


_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_\s]*$")
_RESERVED_IDENTIFIERS = frozenset(
    {
        "SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TABLE",
        "DATABASE", "UNION", "AND", "OR", "EXEC", "EXECUTE", "SCRIPT", "GRANT", "REVOKE",
    }
)
_DDL_PREFIXES = ("DROP", "CREATE", "ALTER", "TRUNCATE")

DANGEROUS_PATTERNS: tuple[str, ...] = (
    r"\bDROP\s+(?:TABLE|DATABASE|INDEX|VIEW)\b",
    r"\bDELETE\s+FROM\b",
    r"\bTRUNCATE\s+TABLE\b",
    r"\bEXEC(?:UTE)?\s*\(",
    r"\bCREATE\s+(?:TABLE|DATABASE|INDEX|VIEW)\b",
    r"\bALTER\s+TABLE\b",
    r"\bGRANT\b",
    r"\bREVOKE\b",
    r"\bINSERT\s+INTO\b.*\bSELECT\b",
    r"\bUPDATE\b.*\bSET\b",
    r";\s*(?:SELECT|DROP|DELETE|UPDATE|INSERT)",
)

_STMT = r"(?:SELECT|DROP|DELETE|UPDATE|INSERT|CREATE|ALTER|EXEC)"
INJECTION_PATTERNS: tuple[str, ...] = (
    r"'\s*OR\s*'?1'?\s*=\s*'?1",
    r'"\s*OR\s*"?1"?\s*=\s*"?1',
    r"'[^']*\s*;\s*" + _STMT,
    r'"[^"]*\s*;\s*' + _STMT,
)

# A plain `a UNION SELECT b` between two tables is legitimate, so UNION is only flagged when it carries a
# classic injection signature: it follows a closed string literal, probes column counts with NULL padding,
# or reads schema catalogs.
UNION_INJECTION_PATTERNS: tuple[str, ...] = (
    r"['\"]\s*\)*\s*UNION\s+(?:ALL\s+)?SELECT\b",
    r"\bUNION\s+(?:ALL\s+)?SELECT\s+(?:NULL\s*,\s*)+NULL\b",
    r"\bUNION\s+(?:ALL\s+)?SELECT\b.*\b(?:SQLITE_MASTER|SQLITE_SCHEMA|INFORMATION_SCHEMA|PG_CATALOG|MYSQL\.USER)\b",
)


def validate_identifier(identifier: str, identifier_type: str = "identifier") -> bool:
    """Return True for a safe table/column name; raise SQLSecurityError otherwise."""
    if not identifier:
        raise SQLSecurityError(f"Empty {identifier_type} name is not allowed")
    if not _IDENTIFIER_RE.match(identifier):
        raise SQLSecurityError(
            f"Invalid {identifier_type} name: '{identifier}'. "
            "Only alphanumeric characters, underscores, and spaces are allowed."
        )
    if identifier.upper() in _RESERVED_IDENTIFIERS:
        raise SQLSecurityError(f"SQL keyword '{identifier}' cannot be used as {identifier_type} name")
    return True


def escape_identifier(identifier: str) -> str:
    """Validate then quote an identifier with SQLite square brackets."""
    validate_identifier(identifier)
    return "[" + identifier.replace("]", "]]") + "]"


def execute_query_safely(
    conn: sqlite3.Connection,
    query: str,
    params: Sequence[Any] | None = None,
    identifier_params: dict[str, str] | None = None,
    allow_ddl: bool = False,
) -> sqlite3.Cursor:
    """Execute `query` with `?` value params and `{name}` identifier params escaped safely."""
    for key, value in (identifier_params or {}).items():
        validate_identifier(value, identifier_type=key)
        query = query.replace(f"{{{key}}}", escape_identifier(value))

    if not allow_ddl and query.upper().strip().startswith(_DDL_PREFIXES):
        raise SQLSecurityError(
            "DDL operations are not allowed without explicit permission. "
            "Use allow_ddl=True if this is intentional."
        )

    cursor = conn.cursor()
    if params:
        cursor.execute(query, tuple(params))
    else:
        cursor.execute(query)
    return cursor


def find_sql_issues(query: str) -> list[tuple[str, str]]:
    """Return every (rule_id, message) problem in `query`, in the order validate_sql_query checks them."""
    normalized = query.upper().strip()
    issues: list[tuple[str, str]] = [
        ("SQL-DANGEROUS-OP", f"Query contains potentially dangerous operation: {pattern}")
        for pattern in DANGEROUS_PATTERNS
        if re.search(pattern, normalized)
    ]
    if "--" in query or "/*" in query or "*/" in query:
        issues.append(("SQL-COMMENT", "Query contains SQL comments which are not allowed"))
    if any(re.search(p, normalized, re.IGNORECASE) for p in INJECTION_PATTERNS):
        issues.append(("SQL-INJECTION", "Query contains potential SQL injection pattern"))
    if any(re.search(p, normalized, re.IGNORECASE | re.DOTALL) for p in UNION_INJECTION_PATTERNS):
        issues.append(("SQL-UNION-INJECTION", "Query contains potential UNION-based SQL injection pattern"))
    return issues


def validate_sql_query(query: str) -> bool:
    """Return True if `query` is safe; raise SQLSecurityError with the first problem otherwise."""
    issues = find_sql_issues(query)
    if issues:
        raise SQLSecurityError(issues[0][1])
    return True


def sanitize_value_for_like(value: str) -> str:
    """Escape LIKE wildcards (use with `ESCAPE '\\'`)."""
    for char in ("\\", "%", "_", "["):
        value = value.replace(char, "\\" + char)
    return value


def build_safe_in_clause(column: str, values: list[Any]) -> tuple[str, list[Any]]:
    """Return (`[column] IN (?, ?, ...)`, values)."""
    if not values:
        raise SQLSecurityError("IN clause requires at least one value")
    validate_identifier(column, "column")
    placeholders = ", ".join("?" for _ in values)
    return f"{escape_identifier(column)} IN ({placeholders})", values


def get_safe_table_list(conn: sqlite3.Connection) -> list[str]:
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    return [row[0] for row in cursor.fetchall()]


def check_table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    try:
        validate_identifier(table_name, "table")
    except SQLSecurityError:
        return False
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    return bool(cursor.fetchone()[0] > 0)


_SEVERITY: dict[str, FindingSeverity] = {"SQL-DANGEROUS-OP": "high", "SQL-COMMENT": "medium", "SQL-INJECTION": "critical",
             "SQL-UNION-INJECTION": "critical"}


def lint_queries(queries: list[tuple[int, str]], source: str = "") -> list[Finding]:
    """Lint (line_number, query) pairs, one finding per issue."""
    findings: list[Finding] = []
    for line_no, query in queries:
        for rule_id, message in find_sql_issues(query):
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=message,
                    severity=_SEVERITY[rule_id],
                    category="injection",
                    resource=source,
                    location=f"{source}:{line_no}",
                    evidence={"query": query[:500]},
                    recommendation="Use parameterized queries (`?` placeholders) and escape_identifier().",
                )
            )
    return findings


def analyze_file(path: Path, **opts: Any) -> AnalysisReport:
    """Lint a file with one SQL query per non-empty, non-`#` line."""
    queries = [
        (i, line.strip())
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if line.strip() and not line.lstrip().startswith("#")
    ]
    findings = lint_queries(queries, str(path))
    flagged = len({f.location for f in findings})
    return AnalysisReport(
        pack="swe",
        tool=TOOL,
        input=str(path),
        findings=findings,
        metrics={"queries": len(queries), "flagged_queries": flagged},
        summary=f"{flagged}/{len(queries)} queries flagged",
    )
