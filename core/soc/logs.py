"""Authentication log parsing (Linux auth.log/syslog, ECS-style JSON lines) and detectors."""

from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from core.common import AnalysisReport, Finding
from core.loaders import get_field

Kind = Literal["auth", "sudo"]
Outcome = Literal["success", "failure", "unknown"]
DEFAULT_SYSLOG_YEAR = 2024  # classic syslog lines carry no year; pass `year=` for real data
SHELLS = frozenset({"bash", "sh", "zsh", "dash", "fish", "su", "ksh", "tcsh"})
EARTH_RADIUS_KM = 6371.0088


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    kind: Kind
    outcome: Outcome
    user: str
    source_ip: str = ""
    host: str = ""
    method: str = ""
    invalid_user: bool = False
    target_user: str = ""
    command: str = ""
    lat: float | None = None
    lon: float | None = None
    country: str = ""
    line: int = 0


_SYSLOG_TS = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$")
_ISO_TS = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s+(?P<rest>.*)$")
_SSHD_FAILED = re.compile(r"sshd\[\d+\]: Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) "
                          r"from (?P<ip>\S+)")
_SSHD_ACCEPTED = re.compile(r"sshd\[\d+\]: Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)")
_SSHD_INVALID = re.compile(r"sshd\[\d+\]: Invalid user (?P<user>\S*) from (?P<ip>\S+)")
_SUDO = re.compile(r"sudo(?:\[\d+\])?:\s+(?P<user>\S+) : .*?USER=(?P<target>\S+) ; COMMAND=(?P<command>.*)$")


def _parse_ts(match: re.Match[str], year: int) -> datetime:
    raw = match.group("ts")
    if "T" in raw:
        ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return ts if ts.tzinfo else ts.replace(tzinfo=UTC)
    return datetime.strptime(f"{year} {' '.join(raw.split())}", "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)


def parse_auth_line(line: str, line_no: int = 0, year: int = DEFAULT_SYSLOG_YEAR) -> AuthEvent | None:
    """Parse one auth.log/syslog line; unrelated lines return None. Syslog times are assumed UTC."""
    m = _SYSLOG_TS.match(line) or _ISO_TS.match(line)
    if not m:
        return None
    ts, host, rest = _parse_ts(m, year), m.group("host"), m.group("rest")
    if f := _SSHD_FAILED.search(rest):
        return AuthEvent(ts, "auth", "failure", f.group("user"), f.group("ip"), host, f.group("method"),
                         invalid_user=bool(f.group("invalid")), line=line_no)
    if a := _SSHD_ACCEPTED.search(rest):
        return AuthEvent(ts, "auth", "success", a.group("user"), a.group("ip"), host, a.group("method"), line=line_no)
    if i := _SSHD_INVALID.search(rest):
        return AuthEvent(ts, "auth", "failure", i.group("user"), i.group("ip"), host, "invalid_user",
                         invalid_user=True, line=line_no)
    if s := _SUDO.search(rest):
        return AuthEvent(ts, "sudo", "success", s.group("user"), host=host, target_user=s.group("target"),
                         command=s.group("command").strip(), line=line_no)
    return None


def parse_auth_log(lines: list[str], year: int = DEFAULT_SYSLOG_YEAR) -> list[AuthEvent]:
    return [e for i, line in enumerate(lines, start=1) if (e := parse_auth_line(line, i, year))]


def _outcome(value: Any) -> Outcome:
    v = str(value or "").lower()
    if v in {"success", "succeeded", "ok", "true"}:
        return "success"
    if v in {"failure", "failed", "fail", "false", "denied"}:
        return "failure"
    return "unknown"


def _geo(record: dict[str, Any]) -> tuple[float | None, float | None, str]:
    for prefix in ("source.geo", "geo", "client.geo"):
        loc = get_field(record, f"{prefix}.location")
        lat = get_field(record, f"{prefix}.location.lat") if isinstance(loc, dict) else None
        lon = get_field(record, f"{prefix}.location.lon") if isinstance(loc, dict) else None
        if lat is None:
            lat, lon = get_field(record, f"{prefix}.lat"), get_field(record, f"{prefix}.lon")
        if lat is not None and lon is not None:
            country = get_field(record, f"{prefix}.country_iso_code") or get_field(record, f"{prefix}.country_name")
            return float(lat), float(lon), str(country or "")
    return None, None, ""


def parse_json_event(record: dict[str, Any], line_no: int = 0) -> AuthEvent | None:
    """Map an ECS-ish event to AuthEvent. Needs @timestamp, event.action and user.name."""
    raw_ts, action, user = get_field(record, "@timestamp"), get_field(record, "event.action"), \
        get_field(record, "user.name")
    if not (raw_ts and action and user):
        return None
    ts = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
    ts = ts if ts.tzinfo else ts.replace(tzinfo=UTC)
    lat, lon, country = _geo(record)
    action_l = str(action).lower()
    kind: Kind = "sudo" if "sudo" in action_l else "auth"
    if kind == "auth" and not any(k in action_l for k in ("login", "logon", "auth", "ssh", "sign")):
        return None
    return AuthEvent(
        timestamp=ts, kind=kind, outcome=_outcome(get_field(record, "event.outcome")), user=str(user),
        source_ip=str(get_field(record, "source.ip") or ""), host=str(get_field(record, "host.name") or ""),
        method=str(action), target_user=str(get_field(record, "user.target.name") or ("root" if kind == "sudo" else "")),
        command=str(get_field(record, "process.command_line") or ""), lat=lat, lon=lon, country=country, line=line_no,
    )


def parse_json_events(lines: list[str]) -> list[AuthEvent]:
    events = []
    for i, line in enumerate(lines, start=1):
        if line.strip():
            record = json.loads(line)
            if isinstance(record, dict) and (e := parse_json_event(record, i)):
                events.append(e)
    return events


def _max_in_window(times: list[datetime], window: timedelta) -> tuple[int, int]:
    """(max events inside any window, index of the window's last event)."""
    best, best_end, start = 0, 0, 0
    for end in range(len(times)):
        while times[end] - times[start] > window:
            start += 1
        if end - start + 1 > best:
            best, best_end = end - start + 1, end
    return best, best_end


def _failures_by_ip(events: list[AuthEvent]) -> dict[str, list[AuthEvent]]:
    grouped: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in sorted(events, key=lambda e: e.timestamp):
        if e.kind == "auth" and e.outcome == "failure" and e.source_ip:
            grouped[e.source_ip].append(e)
    return grouped


def detect_bruteforce(events: list[AuthEvent], threshold: int = 5, window: timedelta = timedelta(minutes=10),
                      spray_min_users: int = 5, source: str = "") -> list[Finding]:
    """>= threshold failures from one IP within window. IPs spread over >= spray_min_users users are left to
    detect_spraying. A later success from the same IP escalates to critical."""
    findings = []
    successes = [e for e in sorted(events, key=lambda e: e.timestamp) if e.kind == "auth" and e.outcome == "success"]
    for ip, fails in sorted(_failures_by_ip(events).items()):
        count, end = _max_in_window([e.timestamp for e in fails], window)
        users = sorted({e.user for e in fails})
        if count < threshold or len(users) >= spray_min_users:
            continue
        burst_end = fails[end].timestamp
        success = next((e for e in successes if e.source_ip == ip and e.timestamp >= burst_end), None)
        evidence: dict[str, Any] = {"source_ip": ip, "failures_in_window": count, "total_failures": len(fails),
                                    "users": users, "first_seen": fails[0].timestamp.isoformat(),
                                    "window_minutes": window.total_seconds() / 60}
        if success:
            evidence |= {"success_user": success.user, "success_at": success.timestamp.isoformat(),
                         "success_line": success.line}
            findings.append(Finding(
                rule_id="SOC-BRUTEFORCE-SUCCESS", title=f"SSH brute force from {ip} followed by successful login "
                f"as {success.user}: compromise likely", severity="critical", category="detection", resource=ip,
                location=f"{source}:{success.line}", evidence=evidence,
                recommendation=f"Isolate the host, kill sessions of {success.user}, rotate its credentials, block {ip}, "
                "and review commands run after login."))
        else:
            findings.append(Finding(
                rule_id="SOC-BRUTEFORCE", title=f"SSH brute force from {ip} ({count} failures)", severity="high",
                category="detection", resource=ip, location=f"{source}:{fails[end].line}", evidence=evidence,
                recommendation=f"Block {ip} (fail2ban/NACL); enforce key-only SSH and disable root login."))
    return findings


def detect_spraying(events: list[AuthEvent], min_users: int = 5, window: timedelta = timedelta(minutes=30),
                    source: str = "") -> list[Finding]:
    """One IP failing against >= min_users distinct accounts within window."""
    findings = []
    for ip, fails in sorted(_failures_by_ip(events).items()):
        start, best_users, best_end = 0, set[str](), 0
        for end in range(len(fails)):
            while fails[end].timestamp - fails[start].timestamp > window:
                start += 1
            users = {e.user for e in fails[start : end + 1]}
            if len(users) > len(best_users):
                best_users, best_end = users, end
        if len(best_users) >= min_users:
            findings.append(Finding(
                rule_id="SOC-PASSWORD-SPRAY", title=f"Password spraying from {ip} against {len(best_users)} accounts",
                severity="high", category="detection", resource=ip, location=f"{source}:{fails[best_end].line}",
                evidence={"source_ip": ip, "users": sorted(best_users), "window_minutes": window.total_seconds() / 60},
                recommendation=f"Block {ip}; check targeted accounts for any later successful login; enforce MFA."))
    return findings


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def detect_impossible_travel(events: list[AuthEvent], max_speed_kmh: float = 900.0, min_distance_km: float = 100.0,
                             source: str = "") -> list[Finding]:
    """Consecutive non-failed logins of one user whose implied speed exceeds max_speed_kmh."""
    by_user: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in sorted(events, key=lambda e: e.timestamp):
        if e.kind == "auth" and e.outcome != "failure" and e.lat is not None and e.lon is not None:
            by_user[e.user].append(e)
    findings = []
    for user, logins in sorted(by_user.items()):
        for prev, cur in zip(logins, logins[1:], strict=False):
            assert prev.lat is not None and prev.lon is not None and cur.lat is not None and cur.lon is not None
            distance = haversine_km(prev.lat, prev.lon, cur.lat, cur.lon)
            hours = (cur.timestamp - prev.timestamp).total_seconds() / 3600
            speed = math.inf if hours == 0 else distance / hours
            if distance < min_distance_km or speed <= max_speed_kmh:
                continue
            findings.append(Finding(
                rule_id="SOC-IMPOSSIBLE-TRAVEL",
                title=f"Impossible travel for {user}: {prev.country or '?'} -> {cur.country or '?'} "
                f"({distance:.0f} km in {hours * 60:.0f} min)", severity="high", category="detection", resource=user,
                location=f"{source}:{cur.line}",
                evidence={"user": user, "from": {"ip": prev.source_ip, "country": prev.country,
                                                 "at": prev.timestamp.isoformat()},
                          "to": {"ip": cur.source_ip, "country": cur.country, "at": cur.timestamp.isoformat()},
                          "distance_km": round(distance, 1),
                          "speed_kmh": None if math.isinf(speed) else round(speed, 1)},
                recommendation=f"Confirm with {user}; if not them, revoke sessions and reset credentials + MFA."))
    return findings


def detect_unusual_sudo(events: list[AuthEvent], admin_users: frozenset[str] = frozenset(), baseline_min: int = 3,
                        source: str = "") -> list[Finding]:
    """sudo to root by a user who is neither a known admin nor a regular (>= baseline_min) sudo user here."""
    sudo = [e for e in events if e.kind == "sudo" and e.target_user == "root" and e.user != "root"]
    counts: dict[str, int] = defaultdict(int)
    for e in sudo:
        counts[e.user] += 1
    findings = []
    for e in sorted(sudo, key=lambda e: e.timestamp):
        if e.user in admin_users or counts[e.user] >= baseline_min:
            continue
        binary = e.command.split()[0].rsplit("/", 1)[-1] if e.command else ""
        shell = binary in SHELLS
        findings.append(Finding(
            rule_id="SOC-UNUSUAL-SUDO", title=f"Unusual sudo to root by {e.user}" + (" (interactive shell)" if shell else ""),
            severity="high" if shell else "medium", category="detection", resource=e.user,
            location=f"{source}:{e.line}",
            evidence={"user": e.user, "command": e.command[:300], "host": e.host, "at": e.timestamp.isoformat(),
                      "sudo_count": counts[e.user]},
            recommendation="Verify the change was authorized; restrict sudoers to specific commands."))
    return findings


def detect_all(events: list[AuthEvent], source: str = "", **opts: Any) -> list[Finding]:
    raw_admins = opts.get("admin_users") or ()
    admin_users = frozenset(raw_admins.split(",") if isinstance(raw_admins, str) else raw_admins)
    return [
        *detect_bruteforce(events, int(opts.get("bruteforce_threshold", 5)),
                           timedelta(minutes=float(opts.get("bruteforce_window_minutes", 10))),
                           int(opts.get("spray_min_users", 5)), source),
        *detect_spraying(events, int(opts.get("spray_min_users", 5)),
                         timedelta(minutes=float(opts.get("spray_window_minutes", 30))), source),
        *detect_impossible_travel(events, float(opts.get("max_speed_kmh", 900)), source=source),
        *detect_unusual_sudo(events, admin_users, int(opts.get("sudo_baseline_min", 3)), source),
    ]


def is_json_lines(path: Path, lines: list[str]) -> bool:
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        return True
    first = next((line for line in lines if line.strip()), "")
    return first.lstrip().startswith("{")


def analyze_file(path: Path, **opts: Any) -> AnalysisReport:
    """auth.log/syslog (tool `auth_log`) or JSON-lines events (tool `json_events`), chosen by content."""
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    as_json = is_json_lines(Path(path), lines)
    events = parse_json_events(lines) if as_json else parse_auth_log(lines, int(opts.get("year", DEFAULT_SYSLOG_YEAR)))
    findings = detect_all(events, str(path), **opts)
    failures = sum(1 for e in events if e.kind == "auth" and e.outcome == "failure")
    return AnalysisReport(
        pack="soc", tool="json_events" if as_json else "auth_log", input=str(path), findings=findings,
        metrics={"lines": len(lines), "events": len(events), "auth_failures": failures,
                 "auth_successes": sum(1 for e in events if e.kind == "auth" and e.outcome == "success"),
                 "sudo_events": sum(1 for e in events if e.kind == "sudo"),
                 "unique_source_ips": len({e.source_ip for e in events if e.source_ip})},
        summary=f"{len(findings)} detection(s) from {len(events)} auth event(s)",
    )
