"""Vulnerability triage for Trivy and Grype JSON: normalize, enrich with CISA KEV / EPSS, prioritize P1..P4."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.common import AnalysisReport, Finding, FindingSeverity

TOOL = "vuln_triage"
KEV_FILENAME = "kev.json"
SEVERITY_DEFAULT_CVSS = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5}
PRIORITY_SEVERITY: dict[str, FindingSeverity] = {"P1": "critical", "P2": "high", "P3": "medium", "P4": "low"}


@dataclass(frozen=True)
class Vuln:
    vuln_id: str
    package: str
    installed: str
    fixed_version: str
    severity: str            # critical|high|medium|low|unknown
    cvss: float | None
    epss: float | None
    target: str
    title: str
    source: str
    aliases: tuple[str, ...] = ()

    @property
    def fix_available(self) -> bool:
        return bool(self.fixed_version)

    @property
    def cve_ids(self) -> set[str]:
        return {i for i in (self.vuln_id, *self.aliases) if i.upper().startswith("CVE-")}


def _severity(raw: Any) -> str:
    value = str(raw or "").lower()
    return value if value in SEVERITY_DEFAULT_CVSS else "unknown"


def _max_score(scores: list[Any]) -> float | None:
    numbers = [float(s) for s in scores if isinstance(s, int | float)]
    return max(numbers) if numbers else None


def parse_trivy(data: dict[str, Any]) -> list[Vuln]:
    vulns = []
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            cvss = _max_score([src.get("V3Score") or src.get("V2Score") for src in (v.get("CVSS") or {}).values()])
            epss = v.get("EPSS")
            vulns.append(Vuln(
                vuln_id=v.get("VulnerabilityID", ""), package=v.get("PkgName", ""),
                installed=v.get("InstalledVersion", ""), fixed_version=v.get("FixedVersion") or "",
                severity=_severity(v.get("Severity")), cvss=cvss,
                epss=float(epss) if isinstance(epss, int | float) else None,
                target=result.get("Target", ""), title=v.get("Title", ""), source="trivy"))
    return vulns


def parse_grype(data: dict[str, Any]) -> list[Vuln]:
    vulns = []
    for m in data.get("matches") or []:
        v, art = m.get("vulnerability") or {}, m.get("artifact") or {}
        cvss = _max_score([(c.get("metrics") or {}).get("baseScore") for c in v.get("cvss") or []])
        epss = _max_score([e.get("epss") for e in v.get("epss") or []])
        fix = v.get("fix") or {}
        fixed = ", ".join(fix.get("versions") or []) if fix.get("state") == "fixed" else ""
        locations = art.get("locations") or [{}]
        vulns.append(Vuln(
            vuln_id=v.get("id", ""), package=art.get("name", ""), installed=art.get("version", ""),
            fixed_version=fixed, severity=_severity(v.get("severity")), cvss=cvss, epss=epss,
            target=locations[0].get("path", ""), title=v.get("description", "")[:200], source="grype",
            aliases=tuple(r.get("id", "") for r in m.get("relatedVulnerabilities") or [])))
    return vulns


def parse_scan(data: dict[str, Any]) -> list[Vuln]:
    if "Results" in data:
        return parse_trivy(data)
    if "matches" in data:
        return parse_grype(data)
    raise ValueError("not a Trivy (Results) or Grype (matches) report")


def parse_kev(data: Any) -> frozenset[str]:
    """CISA KEV catalog ({"vulnerabilities":[{"cveID"}]}) or a simple {"cveIDs": [...]} / list."""
    if isinstance(data, list):
        return frozenset(str(c).upper() for c in data)
    ids = [str(c) for c in data.get("cveIDs", [])]
    ids += [str(v.get("cveID")) for v in data.get("vulnerabilities", []) if v.get("cveID")]
    return frozenset(i.upper() for i in ids)


def base_score(v: Vuln) -> float:
    return v.cvss if v.cvss is not None else SEVERITY_DEFAULT_CVSS.get(v.severity, 0.0)


def prioritize(v: Vuln, kev: frozenset[str]) -> tuple[str, float, bool, list[str]]:
    """(priority P1..P4, score 0-100 for ordering within a tier, in KEV, reasons)."""
    score = base_score(v)
    in_kev = bool({c.upper() for c in v.cve_ids} & kev)
    epss = v.epss or 0.0
    reasons = [f"base {score:.1f}"]
    if in_kev:
        reasons.append("in CISA KEV (known exploited)")
    if v.epss is not None:
        reasons.append(f"EPSS {epss:.2f}")
    reasons.append("fix available" if v.fix_available else "no fix yet")

    if in_kev or (score >= 9.0 and epss >= 0.5):
        priority = "P1"
    elif score >= 9.0 or (score >= 7.0 and epss >= 0.1):
        priority = "P2"
    elif score >= 7.0 or (score >= 4.0 and v.fix_available):
        priority = "P3"
    else:
        priority = "P4"
    numeric = min(100.0, score * 6 + (25 if in_kev else 0) + epss * 10 + (5 if v.fix_available else 0))
    return priority, round(numeric, 2), in_kev, reasons


def dedupe(vulns: list[Vuln]) -> list[Vuln]:
    seen: dict[tuple[str, str, str, str], Vuln] = {}
    for v in vulns:
        seen.setdefault((v.vuln_id, v.package, v.installed, v.target), v)
    return list(seen.values())


def triage(vulns: list[Vuln], kev: frozenset[str] = frozenset(), source: str = "") -> list[Finding]:
    ranked = []
    for v in dedupe(vulns):
        priority, score, in_kev, reasons = prioritize(v, kev)
        ranked.append((priority, -score, v.vuln_id, v.package, v, score, in_kev, reasons))
    ranked.sort(key=lambda r: r[:4])
    return [
        Finding(
            rule_id=f"VULN-{priority}", title=f"{v.vuln_id} in {v.package} {v.installed}", severity=PRIORITY_SEVERITY[priority],
            category="vulnerability", resource=f"{v.target}:{v.package}" if v.target else v.package, location=source,
            evidence={"priority": priority, "priority_score": score, "vuln_id": v.vuln_id, "aliases": list(v.aliases),
                      "package": v.package, "installed": v.installed, "fixed_version": v.fixed_version,
                      "severity": v.severity, "cvss": v.cvss, "epss": v.epss,
                      "kev": in_kev, "scanner": v.source, "reasons": reasons},
            recommendation=(f"Upgrade {v.package} to {v.fixed_version}." if v.fix_available
                            else "No fix available: mitigate (config, WAF, isolation) and track upstream."),
        )
        for priority, _, _, _, v, score, in_kev, reasons in ranked
    ]


def find_kev(scan_path: Path) -> Path | None:
    candidate = scan_path.parent / KEV_FILENAME
    return candidate if candidate.is_file() else None


def analyze_file(path: Path, kev: Path | str | None = None, **opts: Any) -> AnalysisReport:
    """Triage a Trivy/Grype report; KEV comes from `kev=` or a kev.json beside the report."""
    path = Path(path)
    vulns = parse_scan(json.loads(path.read_text(encoding="utf-8")))
    kev_path = Path(kev) if kev else find_kev(path)
    kev_ids = parse_kev(json.loads(kev_path.read_text(encoding="utf-8"))) if kev_path else frozenset()
    findings = triage(vulns, kev_ids, str(path))
    counts = {p: sum(1 for f in findings if f.evidence["priority"] == p) for p in PRIORITY_SEVERITY}
    return AnalysisReport(
        pack="soc", tool=TOOL, input=str(path), findings=findings,
        metrics={"vulnerabilities": len(findings), "by_priority": counts,
                 "kev_matches": sum(1 for f in findings if f.evidence["kev"]),
                 "fixable": sum(1 for f in findings if f.evidence["fixed_version"]),
                 "kev_source": str(kev_path) if kev_path else None},
        summary=f"{len(findings)} vulnerabilities: " + ", ".join(f"{p} {n}" for p, n in counts.items()),
    )
