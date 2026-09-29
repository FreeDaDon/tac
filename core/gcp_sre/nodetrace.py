"""Node.js stack-trace extractor and triage classifier.

Parses `Error: msg` + `    at fn (file:line:col)` blocks (also `Caused by:` / `[cause]:` chains, async frames, ES-module
`file://` paths) out of plain logs or Splunk/Cloud Logging exports, groups them by signature (type + normalized message +
top application frame) and classifies each group. Deterministic; never executes or fetches anything.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from core.common import AnalysisReport, Finding, FindingSeverity
from core.gcp_sre import events as ev
from core.gcp_sre.logs import normalize
from core.security.sanitize import snippet

TOOL = "node_trace"
DEFAULT_REPEAT_THRESHOLD = 5
MAX_FRAMES_IN_EVIDENCE = 6
MAX_GROUPS = 500

_HEADER = re.compile(r"(?:^|[\s\]:>])(?P<type>KafkaJS\w+|(?:[A-Za-z_$][\w$]*)?(?:Error|Exception))"
                     r"(?:\s*\[(?P<code>[A-Z][A-Z0-9_]+)\])?:\s*(?P<msg>.*)$")
_CAUSE = re.compile(r"^\s*(?:Caused by:|\[cause\]:)\s*(?P<rest>.*)$")
_FRAME_FN = re.compile(r"^\s*at (?:async )?(?P<fn>.+?) \((?P<loc>.+)\)\s*$")
_FRAME_BARE = re.compile(r"^\s*at (?:async )?(?P<loc>\S+)\s*$")
_LOC = re.compile(r"^(?P<file>.+?):(?P<line>\d+)(?::(?P<col>\d+))?$")
_NODE_MODULES = re.compile(r"node_modules[\\/](?P<pkg>@[^\\/]+[\\/][^\\/]+|[^\\/]+)")
_TARGET = re.compile(r"(?P<host>\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9][\w.\-]*[A-Za-z0-9]):(?P<port>\d{2,5})\b")
_MARKERS: tuple[tuple[str, FindingSeverity, str, re.Pattern[str], str], ...] = (
    ("NODE-OOM", "critical", "V8 heap exhausted (process aborted)",
     re.compile(r"JavaScript heap out of memory|Allocation failed - JavaScript heap|ERR_WORKER_OUT_OF_MEMORY", re.I),
     "Capture a heap snapshot, look for unbounded caches/queues; only then adjust --max-old-space-size and container memory."),
    ("NODE-UNCAUGHT", "high", "Uncaught exception or unhandled promise rejection",
     re.compile(r"uncaughtException|Uncaught Exception|unhandledRejection|UnhandledPromiseRejection|"
                r"Unhandled 'error' event", re.I),
     "Add error handling at the failing await/emitter; make the process exit and restart cleanly rather than limp on."),
    ("NODE-LISTENER-LEAK", "medium", "EventEmitter listener leak warning",
     re.compile(r"MaxListenersExceededWarning"), "Find the code adding listeners in a loop and remove them."),
)
_NET_CODES = re.compile(r"\b(ECONNREFUSED|ECONNRESET|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|EPIPE|EHOSTUNREACH|ENETUNREACH)\b")
_CODE_DEFECTS = frozenset({"TypeError", "ReferenceError", "RangeError", "SyntaxError"})
_SEV_ORDER: tuple[FindingSeverity, ...] = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class Frame:
    fn: str
    file: str
    line: int
    col: int
    kind: str  # app | dependency | internal

    def render(self) -> str:
        return snippet(f"{self.fn} ({self.file}:{self.line}:{self.col})" if self.fn else f"{self.file}:{self.line}:{self.col}", 160)


@dataclass
class Trace:
    type: str
    message: str
    code: str = ""
    frames: list[Frame] = field(default_factory=list)
    causes: list[str] = field(default_factory=list)
    ts: datetime | None = None
    host: str = ""

    @property
    def top_app_frame(self) -> Frame | None:
        return next((f for f in self.frames if f.kind == "app"), None)

    @property
    def top_frame(self) -> Frame | None:
        return self.frames[0] if self.frames else None

    @property
    def signature(self) -> str:
        top = self.top_app_frame or self.top_frame
        where = f"{top.file}:{top.line}" if top else "no-frame"
        return f"{self.type}|{normalize(self.message)}|{where}"


def looks_like_node_trace(path: Path) -> bool:
    head = ev.sniff(path, 200_000)
    return bool(re.search(r"^\s+at (?:async )?.+:\d+(?::\d+)?\)?\s*$", head, re.MULTILINE)
                or re.search(r"\\n\s*at (?:async )?[^\\]+:\d+(?::\d+)?\)?", head))  # frames inside JSON strings


def classify_frame(file: str) -> str:
    normalized = file.replace("\\", "/")
    if normalized.startswith(("node:", "internal/")) or normalized in ("native", "<anonymous>"):
        return "internal"
    return "dependency" if "node_modules/" in normalized else "app"


def parse_frame(line: str) -> Frame | None:
    m = _FRAME_FN.match(line)
    fn, loc = (m.group("fn"), m.group("loc")) if m else ("", "")
    if not m:
        b = _FRAME_BARE.match(line)
        if not b:
            return None
        loc = b.group("loc")
    lm = _LOC.match(loc)
    if not lm:
        return Frame(fn=fn, file=loc, line=0, col=0, kind=classify_frame(loc))
    file = lm.group("file").removeprefix("file://")
    return Frame(fn=fn, file=file, line=int(lm.group("line")), col=int(lm.group("col") or 0), kind=classify_frame(file))


def extract_traces(text: str, ts: datetime | None = None, host: str = "") -> list[Trace]:
    """All stack traces in `text`. A trace is a header line followed by `at ...` frames; headerless frame runs are kept."""
    traces: list[Trace] = []
    current: Trace | None = None
    for line in text.splitlines():
        cause = _CAUSE.match(line)
        if cause and current is not None:
            current.causes.append(snippet(cause.group("rest"), 200))
            continue
        frame = parse_frame(line) if line.lstrip().startswith("at ") else None
        if frame:
            if current is None:
                current = Trace(type="UnknownError", message="", ts=ts, host=host)
                traces.append(current)
            current.frames.append(frame)
            continue
        header = _HEADER.search(line)
        if header:
            current = Trace(type=header.group("type"), message=header.group("msg").strip(), code=header.group("code") or "",
                            ts=ts, host=host)
            traces.append(current)
        elif not line.startswith((" ", "\t")):
            current = None
    return [t for t in traces if t.frames]


@dataclass
class _Group:
    trace: Trace
    count: int = 0
    first: datetime | None = None
    last: datetime | None = None
    hosts: Counter[str] = field(default_factory=Counter)

    def add(self, t: Trace) -> None:
        self.count += 1
        if t.ts:
            self.first = min(self.first, t.ts) if self.first else t.ts
            self.last = max(self.last, t.ts) if self.last else t.ts
        if t.host:
            self.hosts[t.host] += 1


def _iso(ts: datetime | None) -> str | None:
    return ts.isoformat() if ts else None


def _bump(severity: FindingSeverity, count: int, threshold: int) -> FindingSeverity:
    return _SEV_ORDER[min(3, _SEV_ORDER.index(severity) + 1)] if count >= threshold and severity in ("low", "medium") else severity


def _classify(g: _Group, source: str, threshold: int) -> Finding:
    t = g.trace
    top = t.top_app_frame or t.top_frame
    message = t.message
    evidence: dict[str, Any] = {
        "error_type": t.type, "code": t.code, "message": snippet(message, 240), "count": g.count,
        "first_seen": _iso(g.first), "last_seen": _iso(g.last), "hosts": [h for h, _ in g.hosts.most_common(5)],
        "top_app_frame": t.top_app_frame.render() if t.top_app_frame else None,
        "frames": [f.render() for f in t.frames[:MAX_FRAMES_IN_EVIDENCE]],
        "causes": t.causes[:3],
    }
    location = f"{top.file}:{top.line}" if top and top.line else source
    net = _NET_CODES.search(f"{t.code} {message}")
    dep = _NODE_MODULES.search(t.top_frame.file) if t.top_frame and not t.top_app_frame else None
    sev: FindingSeverity
    if re.search(r"\b(EMFILE|ENFILE)\b", f"{t.code} {message}"):
        rule, sev, title, rec = ("NODE-EMFILE", "high", "File-descriptor exhaustion (too many open files)",
                                 "Find unclosed streams/sockets; raise ulimit -n only after fixing the leak.")
    elif "EADDRINUSE" in f"{t.code} {message}":
        rule, sev, title, rec = ("NODE-EADDRINUSE", "medium", "Port already in use at startup",
                                 "Check for a duplicate process or a slow shutdown during rolling restarts.")
    elif t.type.startswith("KafkaJS"):
        rule, sev, title, rec = ("NODE-KAFKAJS", "medium", f"KafkaJS client error {t.type}",
                                 "Correlate with the broker/consumer-group findings from the log analyzer.")
    elif net:
        target = _TARGET.search(message)
        if target:
            evidence["target"] = f"{target.group('host')}:{target.group('port')}"
        rule, sev, title, rec = ("NODE-NET", "medium", f"Network failure {net.group(1)}" + (f" to {evidence['target']}" if target else ""),
                                 "Verify the dependency is up, DNS resolves, and firewall/VPC rules allow the path; "
                                 "add timeouts and bounded retries.")
    elif t.type in _CODE_DEFECTS and t.top_app_frame:
        rule, sev, title, rec = ("NODE-CODE-DEFECT", "medium", f"{t.type} thrown in application code",
                                 "Likely a code defect: inspect the top application frame and the last deploy touching it.")
    elif dep:
        evidence["package"] = dep.group("pkg")
        rule, sev, title, rec = ("NODE-DEP-ERROR", "low", f"Error originates inside dependency {dep.group('pkg')}",
                                 "Check the dependency version and how the application calls it.")
    else:
        rule, sev, title, rec = ("NODE-ERROR", "low", f"{t.type} stack trace", "Triage by top frame and frequency.")
    return Finding(rule_id=rule, title=title, severity=_bump(sev, g.count, threshold), category="node", resource=source,
                   location=location, evidence=evidence, recommendation=rec)


def analyze_events(events: list[ev.Event], source: str, **opts: Any) -> tuple[list[Finding], dict[str, Any]]:
    threshold = int(opts.get("repeat_threshold", DEFAULT_REPEAT_THRESHOLD))
    groups: dict[str, _Group] = {}
    total = 0
    marker_hits: dict[str, tuple[int, ev.Event]] = {}
    for e in events:
        for rule_id, _, _, pattern, _ in _MARKERS:
            if pattern.search(e.message):
                count, first = marker_hits.get(rule_id, (0, e))
                marker_hits[rule_id] = (count + 1, first)
        for trace in extract_traces(e.message, e.ts, e.host):
            total += 1
            key = trace.signature
            if key not in groups and len(groups) >= MAX_GROUPS:
                continue
            groups.setdefault(key, _Group(trace)).add(trace)
    findings = [_classify(g, source, threshold) for g in groups.values()]
    for rule_id, sev, title, _, rec in _MARKERS:
        if rule_id in marker_hits:
            count, first = marker_hits[rule_id]
            findings.append(Finding(rule_id=rule_id, title=title, severity=sev, category="node", resource=source,
                                    location=f"{source}:{first.line}",
                                    evidence={"count": count, "first_seen": _iso(first.ts), "sample": snippet(first.message.splitlines()[0])},
                                    recommendation=rec))
    ranked = sorted(groups.values(), key=lambda g: -g.count)
    hot_files = Counter(g.trace.top_app_frame.file for g in groups.values() if g.trace.top_app_frame)
    packages = Counter(m.group("pkg") for g in groups.values() if g.trace.top_frame and not g.trace.top_app_frame
                       and (m := _NODE_MODULES.search(g.trace.top_frame.file)))
    metrics = {"traces": total, "unique_signatures": len(groups),
               "top_signatures": [{"error_type": g.trace.type, "message": snippet(g.trace.message, 160), "count": g.count,
                                   "top_app_frame": g.trace.top_app_frame.render() if g.trace.top_app_frame else None,
                                   "first_seen": _iso(g.first), "last_seen": _iso(g.last)} for g in ranked[:10]],
               "hot_files": dict(hot_files.most_common(5)), "dependency_origins": dict(packages.most_common(5))}
    return findings, metrics


def analyze_file(path: Path, **opts: Any) -> AnalysisReport:
    """Options: `repeat_threshold` (default 5): a signature seen this often is escalated one severity level."""
    path = Path(path)
    events = ev.load_events(path)
    findings, metrics = analyze_events(events, path.name, **opts)
    return AnalysisReport(pack="gcp_sre", tool=TOOL, input=str(path), findings=findings, metrics=metrics,
                          summary=f"{metrics['traces']} stack trace(s), {metrics['unique_signatures']} unique signature(s)")
