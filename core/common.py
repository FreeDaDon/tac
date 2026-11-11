"""Shared result contract for every deterministic domain tool (no LLM calls anywhere in core/)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Hashable, Iterable, Sequence
from typing import Any, Literal

from pydantic import BaseModel, Field

PackName = Literal["swe", "devops", "soc", "iam", "mcp_gov", "gcp_sre"]
FindingSeverity = Literal["critical", "high", "medium", "low", "info"]
SEVERITIES: tuple[FindingSeverity, ...] = ("info", "low", "medium", "high", "critical")
SEVERITY_ORDER: dict[str, int] = {s: i for i, s in enumerate(SEVERITIES)}
SEVERITY_WEIGHTS: dict[str, int] = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}

PUBLIC_CIDRS = frozenset({"0.0.0.0/0", "::/0"})
SENSITIVE_PORTS = {21: "ftp", 22: "ssh", 23: "telnet", 445: "smb", 1433: "mssql", 1521: "oracle", 2181: "zookeeper",
                   2375: "docker", 3306: "mysql", 3389: "rdp", 5432: "postgres", 5601: "kibana", 5900: "vnc",
                   6379: "redis", 9092: "kafka", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb"}
ADMIN_PORTS = frozenset({22, 3389})
DATABASE_PORTS = frozenset({1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017})


class Finding(BaseModel):
    rule_id: str                      # stable id, e.g. "IAM001", "TF-DESTROY", "SOC-BRUTEFORCE"
    title: str
    severity: FindingSeverity
    category: str                     # e.g. "privilege", "drift", "detection", "secret"
    resource: str = ""                # file, ARN, host, user, resource address
    location: str = ""                # "path:line" when applicable
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommendation: str = ""


class AnalysisReport(BaseModel):
    pack: PackName
    tool: str                         # e.g. "tfplan", "auth_log", "iam_policy"
    input: str                        # input path or description
    findings: list[Finding] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    summary: str = ""

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    def blocking(self, threshold: str = "high") -> list[Finding]:
        return [f for f in self.findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[threshold]]


def as_list(value: Any) -> list[Any]:
    """YAML/JSON fields that may hold one item or a list of them; a scalar string is one item, not its characters."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "yes", "y", "on", "1"}:
        return True
    if text in {"false", "no", "n", "off", "0"}:
        return False
    raise ValueError(f"expected a boolean, got {value!r}")


def bump_severity(severity: FindingSeverity, steps: int = 1) -> FindingSeverity:
    return SEVERITIES[min(len(SEVERITIES) - 1, SEVERITY_ORDER[severity] + steps)]


def risk_score(findings: Iterable[Finding]) -> int:
    return min(100, sum(SEVERITY_WEIGHTS[f.severity] for f in findings))


def exposure_severity(ports: Iterable[int], all_ports: bool = False) -> FindingSeverity:
    """Internet ingress: every port, remote-admin or datastore ports are critical; other sensitive services high."""
    exposed = set(ports)
    return "critical" if all_ports or exposed & (ADMIN_PORTS | DATABASE_PORTS) else "high"


def max_distinct_in_window[T](items: Sequence[T], at: Callable[[T], Any], key: Callable[[T], Hashable],
                              window: Any) -> tuple[int, int, int]:
    """(most distinct keys inside any `window`-wide span of time-sorted items, that span's start, its end index)."""
    counts: Counter[Hashable] = Counter()
    best, best_start, best_end, start = 0, 0, 0, 0
    for end, item in enumerate(items):
        counts[key(item)] += 1
        while at(item) - at(items[start]) > window:
            old = key(items[start])
            counts[old] -= 1
            if not counts[old]:
                del counts[old]
            start += 1
        if len(counts) > best:
            best, best_start, best_end = len(counts), start, end
    return best, best_start, best_end
