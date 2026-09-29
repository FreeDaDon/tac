"""Splunk / Kafka / GCP runtime log analyzer for SRE triage.

Input: Splunk export (JSON, JSONL, CSV with `_raw`/`_time`), GCP Cloud Logging export, or plain text logs
(Kafka broker/client, Kubernetes, application). Aggregates known failure signatures into one finding each,
with count, first/last seen, affected hosts and redacted samples. Deterministic: same input, same output.
"""

from __future__ import annotations

import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from core.common import AnalysisReport, Finding, FindingSeverity
from core.gcp_sre import events as ev
from core.security.sanitize import snippet

TOOL = "sre_logs"
DEFAULT_LAG_THRESHOLD = 10_000
DEFAULT_BURST_MIN = 10
DEFAULT_BURST_FACTOR = 3.0
ERROR_RATE_THRESHOLD = 0.05
MAX_SAMPLES = 3
MAX_HOSTS = 5
_SEV_ORDER: tuple[FindingSeverity, ...] = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class Signature:
    rule_id: str
    severity: FindingSeverity
    category: str
    title: str
    pattern: re.Pattern[str]
    recommendation: str
    min_count: int = 1


def _sig(rule_id: str, severity: FindingSeverity, category: str, title: str, pattern: str, rec: str,
         min_count: int = 1) -> Signature:
    return Signature(rule_id, severity, category, title, re.compile(pattern, re.IGNORECASE), rec, min_count)


SIGNATURES: tuple[Signature, ...] = (
    _sig("KAFKA-BROKER-UNAVAILABLE", "high", "kafka", "Kafka brokers unreachable or leaderless",
         r"Broker may not be available|LEADER_NOT_AVAILABLE|BrokerNotAvailable|Connection to node -?\d+ [^\n]*could not be "
         r"established|NotLeaderForPartition|NOT_LEADER_(?:OR_FOLLOWER|FOR_PARTITION)|KafkaJSConnectionError|"
         r"KafkaJSBrokerNotFound|ECONNREFUSED[^\n]*:9092|no brokers available",
         "Check broker health and controller election, then network paths/firewalls from clients to :9092/:9093."),
    _sig("KAFKA-REBALANCE", "high", "kafka", "Consumer group rebalance storm",
         r"rebalanc(?:e|ing)|Revoking previously assigned partitions|REBALANCE_IN_PROGRESS|group is rebalancing",
         "Look for flapping consumers (OOM/crashloop), long processing vs max.poll.interval.ms, or missing static membership.",
         min_count=3),
    _sig("KAFKA-CONSUMER-EVICTED", "high", "kafka", "Consumer evicted from its group (session/poll timeout)",
         r"session timeout|max\.poll\.interval\.ms|CommitFailedException|UNKNOWN_MEMBER_ID|Member \S+ (?:has left|sending LeaveGroup)",
         "Reduce batch size or raise max.poll.interval.ms; check for GC pauses or blocked handlers."),
    _sig("KAFKA-OFFSET-RESET", "medium", "kafka", "Offset out of range / offset reset (possible data loss or replay)",
         r"OffsetOutOfRange|OFFSET_OUT_OF_RANGE|Resetting offset for partition|Fetch position [^\n]* is out of range",
         "Confirm retention vs consumer downtime; decide between earliest (replay) and latest (skip) deliberately."),
    _sig("KAFKA-ISR", "high", "kafka", "Under-replicated partitions / ISR below minimum",
         r"Shrinking ISR|UnderReplicatedPartitions|NOT_ENOUGH_REPLICAS|NotEnoughReplicas|min\.insync\.replicas",
         "Find the lagging or down replica; do not lower min.insync.replicas to hide it."),
    _sig("KAFKA-AUTH", "high", "kafka", "Kafka authentication/authorization failures",
         r"SaslAuthenticationException|TopicAuthorizationException|GroupAuthorizationException|"
         r"ClusterAuthorizationException|SSL handshake failed|SASL authentication failed|TOPIC_AUTHORIZATION_FAILED",
         "Check ACLs, credentials rotation and certificate expiry for the client's service identity."),
    _sig("KAFKA-PRODUCE-FAIL", "medium", "kafka", "Producer delivery failures",
         r"Expiring \d+ record\(s\)|RecordTooLargeException|MESSAGE_TOO_LARGE|delivery (?:failed|timeout)|"
         r"ProducerFenced|Failed to send",
         "Check broker availability, message.max.bytes vs payload size, and delivery.timeout.ms."),
    _sig("KAFKA-DISK", "critical", "kafka", "Broker storage failure",
         r"KafkaStorageException|No space left on device|Log directory [^\n]* has failed",
         "Free or extend the broker disk immediately; a full log dir takes the broker offline."),
    _sig("SPLUNK-PIPELINE-BLOCKED", "high", "observability", "Splunk ingestion is blocked or dropping events (logs may be missing)",
         r"blocked=true|queue is full|Forwarder [^\n]*dropp|TcpOutputProc[^\n]*blocked|Dropping \d+ events|"
         r"license[^\n]*(?:violation|exceeded)",
         "Restore ingestion first; treat gaps in this data as unknown, not as healthy."),
    _sig("SRE-OOM", "high", "runtime", "Out-of-memory kills",
         r"OOMKilled|Out of memory: Kill(?:ed)? process|Container terminated on signal 9|Memory limit of \d+ MiB exceeded|"
         r"exit code 137|OutOfMemoryError|JavaScript heap out of memory",
         "Compare memory limit with working set; look for a leak or unbounded batch before raising the limit."),
    _sig("SRE-CRASHLOOP", "high", "runtime", "Crash loop or failing health probes",
         r"CrashLoopBackOff|Back-off restarting failed container|Container failed to start|Liveness probe failed|"
         r"Readiness probe failed|startup probe failed",
         "Inspect the previous container's logs and the most recent config/secret/image change."),
    _sig("SRE-DB-POOL", "high", "runtime", "Database connection pool exhaustion",
         r"connection pool[^\n]*(?:exhausted|timeout)|too many connections|remaining connection slots are reserved|"
         r"Timeout acquiring (?:a )?connection|Cannot acquire connection",
         "Check pool size x replicas against the database max_connections; look for leaked connections."),
    _sig("SRE-CAPACITY", "high", "runtime", "No capacity to serve requests",
         r"no available instance|aborted because there was no available instance|max instances|scaled to zero",
         "Raise max instances or concurrency, or find the traffic spike."),
    _sig("SRE-QUOTA", "medium", "gcp", "API or resource quota exhausted",
         r"RESOURCE_EXHAUSTED|quota exceeded|rateLimitExceeded|429 Too Many Requests",
         "Check the quota in the console; add backoff or request an increase."),
    _sig("SRE-PERMISSION", "medium", "gcp", "Permission denied calling a GCP API",
         r"PERMISSION_DENIED|403 Forbidden|Caller does not have|does not have [^\n]* permission|"
         r"insufficient authentication scopes",
         "Identify the calling service identity and the missing role; grant the narrowest role, never owner/editor."),
    _sig("SRE-DEADLINE", "medium", "runtime", "Timeouts / deadline exceeded",
         r"DEADLINE_EXCEEDED|context deadline exceeded|upstream request timeout|504 Gateway Timeout",
         "Find the slow dependency; check retries amplifying load."),
)
_LAG = re.compile(r"\b(?:consumer[ _-]?)?lag(?:[ _-]max)?\s*[=:]\s*(\d+)", re.IGNORECASE)
_GROUP = re.compile(r"\bgroup(?:[ _-]?id)?\s*[=:]\s*['\"]?([\w.\-]+)", re.IGNORECASE)
_TOPIC = re.compile(r"\btopic\s*[=:]\s*['\"]?([\w.\-]+)", re.IGNORECASE)
_NORMALIZERS = ((re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
                (re.compile(r"\b0x[0-9a-f]+\b", re.I), "<hex>"),
                (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<ip>"),
                (re.compile(r"\d+"), "<n>"))


def normalize(message: str) -> str:
    text = message.splitlines()[0] if message else ""
    for pattern, repl in _NORMALIZERS:
        text = pattern.sub(repl, text)
    return snippet(text)[:160]


def looks_like_log(path: Path) -> bool:
    head = ev.sniff(path)
    if path.suffix.lower() in {".json", ".jsonl", ".ndjson", ".csv"}:
        if any(k in head for k in ev.SNIFF_KEYS) or ("severity" in head and "timestamp" in head):
            return True
        return '"level"' in head and ('"message"' in head or '"msg"' in head)
    return bool(ev._TS_RE.search(head) or ev._LEVEL_RE.search(head))


def _bump(severity: FindingSeverity, steps: int) -> FindingSeverity:
    return _SEV_ORDER[min(len(_SEV_ORDER) - 1, _SEV_ORDER.index(severity) + steps)]


@dataclass
class _Agg:
    count: int = 0
    first: datetime | None = None
    last: datetime | None = None
    first_line: int = 0
    hosts: Counter[str] = field(default_factory=Counter)
    samples: list[str] = field(default_factory=list)

    def add(self, e: ev.Event) -> None:
        self.count += 1
        self.first_line = self.first_line or e.line
        if e.ts:
            self.first = min(self.first, e.ts) if self.first else e.ts
            self.last = max(self.last, e.ts) if self.last else e.ts
        if e.host:
            self.hosts[e.host] += 1
        if len(self.samples) < MAX_SAMPLES:
            self.samples.append(snippet(e.message.splitlines()[0]))


def _iso(ts: datetime | None) -> str | None:
    return ts.isoformat() if ts else None


def _finding(sig: Signature, agg: _Agg, source: str, total: int) -> Finding:
    steps = 1 if agg.count >= max(20, sig.min_count * 10) and sig.severity in ("medium", "low") else 0
    hosts = [h for h, _ in agg.hosts.most_common(MAX_HOSTS)]
    return Finding(rule_id=sig.rule_id, title=sig.title, severity=_bump(sig.severity, steps), category=sig.category,
                   resource=source, location=f"{source}:{agg.first_line}",
                   evidence={"count": agg.count, "share_of_events": round(agg.count / total, 4) if total else 0,
                             "first_seen": _iso(agg.first), "last_seen": _iso(agg.last), "hosts": hosts,
                             "samples": agg.samples},
                   recommendation=sig.recommendation)


def _lag_finding(events: list[ev.Event], source: str, threshold: int) -> Finding | None:
    worst: tuple[int, ev.Event] | None = None
    for e in events:
        for m in _LAG.finditer(e.message):
            if worst is None or int(m.group(1)) > worst[0]:
                worst = (int(m.group(1)), e)
    if worst is None or worst[0] < threshold:
        return None
    lag, e = worst
    group, topic = _GROUP.search(e.message), _TOPIC.search(e.message)
    return Finding(rule_id="KAFKA-CONSUMER-LAG", title=f"Consumer lag {lag} exceeds threshold {threshold}", severity="high",
                   category="kafka", resource=source, location=f"{source}:{e.line}",
                   evidence={"max_lag": lag, "threshold": threshold, "group": group.group(1) if group else None,
                             "topic": topic.group(1) if topic else None, "seen": _iso(e.ts), "sample": snippet(e.message)},
                   recommendation="Scale consumers or fix the slow handler; check for a stalled partition or rebalance loop.")


def _burst_findings(events: list[ev.Event], source: str, burst_min: int, factor: float) -> list[Finding]:
    """Compare the busiest error minute with the median error count over every minute that has any event."""
    errors: Counter[str] = Counter()
    minutes: set[str] = set()
    for e in events:
        if e.ts:
            minute = e.ts.strftime("%Y-%m-%dT%H:%MZ")
            minutes.add(minute)
            if e.level in ev.ERROR_LEVELS:
                errors[minute] += 1
    if len(minutes) < 3 or not errors:
        return []
    median = statistics.median(errors.get(m, 0) for m in sorted(minutes))
    peak_minute, peak = max(sorted(errors.items()), key=lambda kv: kv[1])
    if peak < max(burst_min, factor * median):
        return []
    return [Finding(
        rule_id="SRE-ERROR-BURST", title=f"Error burst: {peak} errors in one minute (median {median:g})",
        severity="high" if peak >= 5 * max(median, 1) else "medium", category="runtime", resource=source, location=source,
        evidence={"minute": peak_minute, "errors": peak, "median_per_minute": median, "minutes_observed": len(minutes),
                  "top_minutes": dict(errors.most_common(5))},
        recommendation="Align the burst start with deploys, config changes and upstream incidents.")]


def analyze_events(events: list[ev.Event], source: str, **opts: Any) -> tuple[list[Finding], dict[str, Any]]:
    lag_threshold = int(opts.get("lag_threshold", DEFAULT_LAG_THRESHOLD))
    total = len(events)
    aggs: dict[str, _Agg] = defaultdict(_Agg)
    levels: Counter[str] = Counter()
    hosts: Counter[str] = Counter()
    error_sigs: Counter[str] = Counter()
    for e in events:
        levels[e.level or "UNKNOWN"] += 1
        if e.host:
            hosts[e.host] += 1
        if e.level in ev.ERROR_LEVELS:
            error_sigs[normalize(e.message)] += 1
        for sig in SIGNATURES:
            if sig.pattern.search(e.message):
                aggs[sig.rule_id].add(e)
    findings = [_finding(sig, aggs[sig.rule_id], source, total)
                for sig in SIGNATURES if sig.rule_id in aggs and aggs[sig.rule_id].count >= sig.min_count]
    if (lag := _lag_finding(events, source, lag_threshold)):
        findings.append(lag)
    findings += _burst_findings(events, source, int(opts.get("burst_min", DEFAULT_BURST_MIN)),
                                float(opts.get("burst_factor", DEFAULT_BURST_FACTOR)))
    errors = sum(n for lvl, n in levels.items() if lvl in ev.ERROR_LEVELS)
    if total >= 20 and errors / total > ERROR_RATE_THRESHOLD:
        findings.append(Finding(rule_id="SRE-ERROR-RATE", title=f"{errors / total:.1%} of events are errors",
                                severity="medium", category="runtime", resource=source, location=source,
                                evidence={"errors": errors, "events": total},
                                recommendation="Start with the top error signatures in metrics.top_error_signatures."))
    stamps = [e.ts for e in events if e.ts]
    metrics = {"events": total, "levels": dict(levels), "time_range": [_iso(min(stamps)), _iso(max(stamps))] if stamps else None,
               "top_hosts": dict(hosts.most_common(5)),
               "top_error_signatures": [{"signature": s, "count": n} for s, n in error_sigs.most_common(10)]}
    return findings, metrics


def analyze_file(path: Path, **opts: Any) -> AnalysisReport:
    """Options: `lag_threshold` (default 10000), `burst_min` (10), `burst_factor` (3.0)."""
    path = Path(path)
    events = ev.load_events(path)
    findings, metrics = analyze_events(events, path.name, **opts)
    return AnalysisReport(pack="gcp_sre", tool=TOOL, input=str(path), findings=findings, metrics=metrics,
                          summary=f"{len(findings)} finding(s) from {len(events)} log event(s)")
