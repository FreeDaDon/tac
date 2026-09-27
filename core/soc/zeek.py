"""Zeek conn.log parsing and network detections (port scan, beaconing, large outbound transfers)."""

from __future__ import annotations

import ipaddress
import statistics
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.common import AnalysisReport, Finding

TOOL = "zeek"
DEFAULT_FIELDS = ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration",
                  "orig_bytes", "resp_bytes", "conn_state")


@dataclass(frozen=True)
class Conn:
    ts: float
    src: str
    sport: int
    dst: str
    dport: int
    proto: str
    duration: float
    orig_bytes: int
    resp_bytes: int
    conn_state: str
    line: int = 0


def _num(value: str, cast: type[int] | type[float]) -> Any:
    return cast(0) if value in {"-", "", "(empty)"} else cast(value)


def parse_conn_log(lines: list[str]) -> list[Conn]:
    """Parse Zeek TSV (`#separator`/`#fields` headers honoured)."""
    sep, fields = "\t", list(DEFAULT_FIELDS)
    conns: list[Conn] = []
    for line_no, line in enumerate(lines, start=1):
        if line.startswith("#separator"):
            sep = line.split(" ", 1)[1].strip().encode().decode("unicode_escape")
            continue
        if line.startswith("#fields"):
            fields = line.split(sep)[1:]
            continue
        if not line.strip() or line.startswith("#"):
            continue
        row = dict(zip(fields, line.split(sep), strict=False))
        conns.append(Conn(
            ts=float(row["ts"]), src=row["id.orig_h"], sport=_num(row.get("id.orig_p", "-"), int),
            dst=row["id.resp_h"], dport=_num(row.get("id.resp_p", "-"), int), proto=row.get("proto", ""),
            duration=_num(row.get("duration", "-"), float), orig_bytes=_num(row.get("orig_bytes", "-"), int),
            resp_bytes=_num(row.get("resp_bytes", "-"), int), conn_state=row.get("conn_state", ""), line=line_no,
        ))
    return sorted(conns, key=lambda c: c.ts)


def detect_port_scan(conns: list[Conn], min_targets: int = 20, window_seconds: float = 60.0,
                     source: str = "") -> list[Finding]:
    """One source touching >= min_targets distinct (host, port) pairs inside window_seconds."""
    by_src: dict[str, list[Conn]] = defaultdict(list)
    for c in conns:
        by_src[c.src].append(c)
    findings = []
    for src, items in sorted(by_src.items()):
        start, best = 0, (0, 0, 0)
        for end in range(len(items)):
            while items[end].ts - items[start].ts > window_seconds:
                start += 1
            targets = {(c.dst, c.dport) for c in items[start : end + 1]}
            if len(targets) > best[0]:
                best = (len(targets), start, end)
        count, s, e = best
        if count < min_targets:
            continue
        window = items[s : e + 1]
        hosts, ports = sorted({c.dst for c in window}), sorted({c.dport for c in window})
        kind = "vertical" if len(hosts) == 1 else ("horizontal" if len(ports) == 1 else "mixed")
        findings.append(Finding(
            rule_id="SOC-PORTSCAN", title=f"Port scan ({kind}) from {src}: {count} targets in {window_seconds:.0f}s",
            severity="high", category="detection", resource=src, location=f"{source}:{window[0].line}",
            evidence={"source": src, "targets": count, "hosts": hosts[:20], "ports": ports[:50],
                      "scan_type": kind, "rejected": sum(1 for c in window if c.conn_state in {"REJ", "S0", "RSTR"})},
            recommendation=f"Identify {src}; if not an authorized scanner, contain it and review what responded."))
    return findings


def detect_beaconing(conns: list[Conn], min_connections: int = 10, max_cv: float = 0.1,
                     min_interval_seconds: float = 5.0, source: str = "") -> list[Finding]:
    """src->dst:port pairs with >= min_connections whose inter-arrival coefficient of variation <= max_cv."""
    pairs: dict[tuple[str, str, int], list[Conn]] = defaultdict(list)
    for c in conns:
        pairs[(c.src, c.dst, c.dport)].append(c)
    findings = []
    for (src, dst, dport), items in sorted(pairs.items()):
        if len(items) < min_connections:
            continue
        gaps = [b.ts - a.ts for a, b in zip(items, items[1:], strict=False)]
        mean = statistics.fmean(gaps)
        if mean < min_interval_seconds:
            continue
        cv = statistics.pstdev(gaps) / mean
        if cv > max_cv:
            continue
        findings.append(Finding(
            rule_id="SOC-BEACON", title=f"Beaconing {src} -> {dst}:{dport} every ~{mean:.0f}s",
            severity="high", category="detection", resource=f"{src}->{dst}:{dport}",
            location=f"{source}:{items[0].line}",
            evidence={"source": src, "destination": dst, "port": dport, "connections": len(items),
                      "mean_interval_s": round(mean, 2), "cv": round(cv, 4),
                      "bytes_out": sum(c.orig_bytes for c in items)},
            recommendation=f"Inspect the process on {src} talking to {dst}; check threat intel; block if C2."))
    return findings


# RFC1918, loopback, link-local and IPv6 ULA. (ipaddress.is_private also covers documentation ranges.)
INTERNAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "fc00::/7", "fe80::/10", "::1/128",
))


def _is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in INTERNAL_NETWORKS)


def detect_large_outbound(conns: list[Conn], threshold_bytes: int = 100_000_000, source: str = "") -> list[Finding]:
    """Internal -> external byte totals per (src, dst) at or above threshold_bytes."""
    totals: dict[tuple[str, str], list[Conn]] = defaultdict(list)
    for c in conns:
        if _is_internal(c.src) and not _is_internal(c.dst):
            totals[(c.src, c.dst)].append(c)
    findings = []
    for (src, dst), items in sorted(totals.items()):
        sent = sum(c.orig_bytes for c in items)
        if sent < threshold_bytes:
            continue
        findings.append(Finding(
            rule_id="SOC-LARGE-OUTBOUND", title=f"Large outbound transfer {src} -> {dst} ({sent / 1e6:.1f} MB)",
            severity="high" if sent >= 10 * threshold_bytes else "medium", category="detection",
            resource=f"{src}->{dst}", location=f"{source}:{items[0].line}",
            evidence={"source": src, "destination": dst, "bytes_out": sent, "connections": len(items),
                      "ports": sorted({c.dport for c in items})},
            recommendation="Confirm the destination is a sanctioned service (backup, CDN); otherwise treat as exfil."))
    return findings


def analyze_file(path: Path, **opts: Any) -> AnalysisReport:
    conns = parse_conn_log(Path(path).read_text(encoding="utf-8", errors="replace").splitlines())
    src = str(path)
    findings = [
        *detect_port_scan(conns, int(opts.get("scan_min_targets", 20)), float(opts.get("scan_window_seconds", 60)),
                          src),
        *detect_beaconing(conns, int(opts.get("beacon_min_connections", 10)), float(opts.get("beacon_max_cv", 0.1)),
                          float(opts.get("beacon_min_interval_seconds", 5)), src),
        *detect_large_outbound(conns, int(opts.get("outbound_threshold_bytes", 100_000_000)), src),
    ]
    return AnalysisReport(
        pack="soc", tool=TOOL, input=src, findings=findings,
        metrics={"connections": len(conns), "unique_sources": len({c.src for c in conns}),
                 "unique_destinations": len({c.dst for c in conns})},
        summary=f"{len(findings)} detection(s) from {len(conns)} connection(s)",
    )
