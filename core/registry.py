"""Pack/tool registry, input auto-detection, and the `python -m core.registry` CLI."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Protocol

import yaml

from core.common import SEVERITY_ORDER, AnalysisReport, Finding
from core.devops import drift, rollback, tfplan
from core.export.jsonout import to_json
from core.export.markdown import render_reports
from core.export.sarif import to_sarif
from core.iam import audit, policy, rbac, revoke
from core.security import sanitize, secret_scan, sql_security
from core.security.secret_scan import SKIP_DIRS
from core.soc import logs, sigma, vuln_triage, zeek


class Analyzer(Protocol):
    def __call__(self, path: Path, **opts: Any) -> AnalysisReport: ...


class UnknownInputError(ValueError):
    pass


PACK_TOOLS: dict[str, dict[str, Analyzer]] = {
    "swe": {"secret_scan": secret_scan.analyze_file, "sql_lint": sql_security.analyze_file,
            "unicode_scan": sanitize.analyze_file},
    "devops": {"tfplan": tfplan.analyze_file, "drift": drift.analyze_file, "rollback": rollback.analyze_file},
    "soc": {"auth_log": logs.analyze_file, "json_events": logs.analyze_file, "zeek": zeek.analyze_file,
            "sigma": sigma.analyze_file, "vuln_triage": vuln_triage.analyze_file},
    "iam": {"iam_policy": policy.analyze_file, "rbac": rbac.analyze_file, "iam_audit": audit.analyze_file,
            "iam_revoke": revoke.analyze_file},
}
# Tools that consume the same input kind as another (auto-detected) tool.
INPUT_KIND = {"drift": "tfplan", "rollback": "tfplan", "iam_revoke": "iam_audit"}
AUTH_LOG_NAMES = frozenset({"auth.log", "syslog", "secure", "messages"})
MAX_SNIFF_BYTES = 50_000_000


def _load(path: Path) -> Any:
    """Parsed JSON/YAML content, or None when unparseable/too large."""
    try:
        if path.stat().st_size > MAX_SNIFF_BYTES:
            return None
        text = path.read_text(encoding="utf-8")
        return yaml.safe_load(text) if path.suffix.lower() in {".yml", ".yaml"} else json.loads(text)
    except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError):
        return None


def _head(path: Path, lines: int = 5) -> str:
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            return "".join(fh.readline() for _ in range(lines))
    except OSError:
        return ""


def _detect_devops(path: Path) -> str | None:
    if path.name.lower().endswith(".tfplan.json"):
        return "tfplan"
    data = _load(path) if path.suffix.lower() == ".json" else None
    if isinstance(data, dict):
        if "resource_changes" in data:
            return "tfplan"
        if "resource_drift" in data:
            return "drift"
    return None


def _detect_soc(path: Path) -> str | None:
    name, suffix = path.name.lower(), path.suffix.lower()
    if "#separator" in _head(path) or (name.startswith("conn") and suffix == ".log"):
        return "zeek"
    if suffix in {".yml", ".yaml"}:
        data = _load(path)
        return "sigma" if isinstance(data, dict) and "detection" in data else None
    if suffix == ".json":
        data = _load(path)
        return "vuln_triage" if isinstance(data, dict) and ("Results" in data or "matches" in data) else None
    if suffix in {".jsonl", ".ndjson"}:
        return "json_events"
    if name in AUTH_LOG_NAMES or suffix == ".log":
        return "auth_log"
    return None


def _detect_iam(path: Path) -> str | None:
    if path.suffix.lower() not in {".json", ".yml", ".yaml"}:
        return None
    data = _load(path)
    if not isinstance(data, dict):
        return None
    if "Statement" in data or "PolicyVersion" in data:
        return "iam_policy"
    if "roles" in data:
        return "rbac"
    if isinstance(data.get("users"), list):
        return "iam_audit"
    return None


def detect_tool(pack: str, path: Path) -> str:
    """Pick the tool for an input by filename and content; raise UnknownInputError if nothing fits."""
    path = Path(path)
    if pack not in PACK_TOOLS:
        raise ValueError(f"unknown pack {pack!r}; expected one of {sorted(PACK_TOOLS)}")
    if pack == "swe":
        return "sql_lint" if path.suffix.lower() == ".sql" else "secret_scan"
    if path.is_dir():
        raise UnknownInputError(f"{path} is a directory; use run_pack to analyze every file in it")
    detectors = {"devops": _detect_devops, "soc": _detect_soc, "iam": _detect_iam}
    tool = detectors[pack](path)
    if tool is None:
        raise UnknownInputError(f"cannot detect a {pack} tool for {path}")
    return tool


def iter_input_files(root: Path) -> Iterator[Path]:
    for file in sorted(root.rglob("*")):
        rel = file.relative_to(root).parts
        if file.is_file() and not any(p in SKIP_DIRS or p.startswith(".") for p in rel):
            yield file


def _input_error(pack: str, tool: str, path: Path, exc: Exception) -> AnalysisReport:
    return AnalysisReport(
        pack=pack, tool=tool, input=str(path), summary="input could not be analyzed",  # type: ignore[arg-type]
        findings=[Finding(rule_id="INPUT-ERROR", title=f"Could not analyze input: {type(exc).__name__}",
                          severity="low", category="input", resource=str(path), location=str(path),
                          evidence={"error": str(exc)[:500]}, recommendation="Check the file format.")],
    )


def run_pack(pack: str, input_path: Path, tool: str | None = None, **opts: Any) -> list[AnalysisReport]:
    """Run one tool (given or detected) on a file, or every recognizable file of a devops/soc/iam directory."""
    input_path = Path(input_path)
    if pack not in PACK_TOOLS:
        raise ValueError(f"unknown pack {pack!r}; expected one of {sorted(PACK_TOOLS)}")
    if tool is not None and tool not in PACK_TOOLS[pack]:
        raise ValueError(f"unknown tool {tool!r} for pack {pack}; expected one of {sorted(PACK_TOOLS[pack])}")
    if not input_path.exists():
        raise FileNotFoundError(input_path)

    if not input_path.is_dir() or pack == "swe":
        chosen = tool or detect_tool(pack, input_path)
        return [PACK_TOOLS[pack][chosen](input_path, **opts)]

    reports = []
    for file in iter_input_files(input_path):
        try:
            detected = detect_tool(pack, file)
        except UnknownInputError:
            continue
        if tool is not None and INPUT_KIND.get(tool, tool) != detected:
            continue
        chosen = tool or detected
        try:
            reports.append(PACK_TOOLS[pack][chosen](file, **opts))
        except (ValueError, KeyError, TypeError) as exc:
            reports.append(_input_error(pack, chosen, file, exc))
    return reports


def worst_severity(reports: list[AnalysisReport]) -> str:
    return max((r.max_severity for r in reports), key=lambda s: SEVERITY_ORDER[s], default="info")


def _coerce(value: str) -> Any:
    for cast in (int, float):
        try:
            return cast(value)
        except ValueError:
            pass
    return {"true": True, "false": False}.get(value.lower(), value)


def parse_opts(pairs: list[str]) -> dict[str, Any]:
    opts: dict[str, Any] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise argparse.ArgumentTypeError(f"--opt expects key=value, got {pair!r}")
        opts[key.replace("-", "_")] = _coerce(value)
    return opts


def render(reports: list[AnalysisReport], fmt: str) -> str:
    if fmt == "json":
        return to_json(reports)
    if fmt == "sarif":
        return json.dumps(to_sarif(reports), indent=2, ensure_ascii=False, default=str)
    return render_reports(reports)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m core.registry", description="Run deterministic domain tools.")
    parser.add_argument("pack", choices=sorted(PACK_TOOLS))
    parser.add_argument("path", type=Path)
    parser.add_argument("--tool", help="tool name (default: auto-detect)")
    parser.add_argument("--format", choices=["md", "json", "sarif"], default="md")
    parser.add_argument("--out", type=Path, help="write output to FILE instead of stdout")
    parser.add_argument("--fail-on", choices=sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.__getitem__),
                        help="exit 2 if any finding is at or above this severity")
    parser.add_argument("--opt", action="append", default=[], metavar="KEY=VALUE",
                        help="tool option, e.g. --opt events=labeled.jsonl --opt as_of=2025-06-30")
    args = parser.parse_args(argv)

    try:
        reports = run_pack(args.pack, args.path, args.tool, **parse_opts(args.opt))
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    output = render(reports, args.format)
    if args.out:
        args.out.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output if output.endswith("\n") else output + "\n")
    if args.fail_on and any(r.blocking(args.fail_on) for r in reports):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
