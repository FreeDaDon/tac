"""Minimal Sigma support: load, lint, match, and score a rule against labeled events (SIEM rule tuning)."""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from core.common import AnalysisReport, Finding, FindingSeverity
from core.loaders import get_field, load_jsonl

TOOL = "sigma"
SUPPORTED_MODIFIERS = frozenset({"contains", "startswith", "endswith", "re", "all"})
MIN_CONTAINS_LEN = 4
LABELED_EVENTS_FILENAME = "labeled_events.jsonl"
Matcher = Callable[[dict[str, Any]], bool]


class SigmaError(ValueError):
    pass


def load_rule(path: Path) -> dict[str, Any]:
    rule = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(rule, dict) or not isinstance(rule.get("detection"), dict):
        raise SigmaError(f"{path}: not a Sigma rule (no detection map)")
    return rule


# ---------------------------------------------------------------- matching

def _value_matches(actual: Any, expected: Any, modifier: str) -> bool:
    if expected is None:
        return actual is None
    if actual is None:
        return False
    a, e = str(actual), str(expected)
    if modifier == "re":
        return re.search(e, a) is not None
    a, e = a.lower(), e.lower()
    if modifier == "contains":
        return e in a
    if modifier == "startswith":
        return a.startswith(e)
    if modifier == "endswith":
        return a.endswith(e)
    if "*" in e or "?" in e:
        return fnmatch.fnmatchcase(a, e)
    return a == e


def _field_matches(event: dict[str, Any], key: str, expected: Any) -> bool:
    field, *mods = key.split("|")
    unknown = set(mods) - SUPPORTED_MODIFIERS
    if unknown:
        raise SigmaError(f"unsupported modifier(s): {sorted(unknown)}")
    modifier = next((m for m in mods if m != "all"), "")
    values = expected if isinstance(expected, list) else [expected]
    actual = get_field(event, field)
    combine = all if "all" in mods else any
    return combine(_value_matches(actual, v, modifier) for v in values)


def selection_matches(selection: Any, event: dict[str, Any]) -> bool:
    """Map = AND of fields; list of maps = OR; list of strings = keyword search over all values."""
    if isinstance(selection, dict):
        return all(_field_matches(event, k, v) for k, v in selection.items())
    if isinstance(selection, list):
        if all(isinstance(s, dict) for s in selection):
            return any(selection_matches(s, event) for s in selection)
        haystack = " ".join(str(v) for v in _flatten(event)).lower()
        return any(str(s).lower() in haystack for s in selection)
    raise SigmaError(f"unsupported selection type: {type(selection).__name__}")


def _flatten(value: Any) -> list[Any]:
    if isinstance(value, dict):
        return [x for v in value.values() for x in _flatten(v)]
    if isinstance(value, list):
        return [x for v in value for x in _flatten(v)]
    return [value]


# ---------------------------------------------------------------- condition parser

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def _tokenize(condition: str) -> list[str]:
    if "|" in condition:
        raise SigmaError("aggregation conditions (`|`) are not supported")
    tokens, pos = [], 0
    while pos < len(condition.rstrip()):
        m = _TOKEN.match(condition, pos)
        if not m:
            raise SigmaError(f"cannot parse condition near: {condition[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


class _Parser:
    """expr := term (or term)* ; term := factor (and factor)* ;
    factor := not factor | ( expr ) | (1|any|all) of (pattern|them) | identifier"""

    def __init__(self, tokens: list[str], identifiers: list[str]) -> None:
        self.tokens, self.pos, self.identifiers = tokens, 0, identifiers
        self.referenced: set[str] = set()

    def _peek(self) -> str | None:
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        if self.pos >= len(self.tokens):
            raise SigmaError("unexpected end of condition")
        self.pos += 1
        return self.tokens[self.pos - 1]

    def parse(self) -> Callable[[dict[str, bool]], bool]:
        node = self._expr()
        if self.pos != len(self.tokens):
            raise SigmaError(f"unexpected token {self.tokens[self.pos]!r}")
        return node

    def _expr(self) -> Callable[[dict[str, bool]], bool]:
        parts = [self._term()]
        while self._peek() == "or":
            self._next()
            parts.append(self._term())
        return parts[0] if len(parts) == 1 else (lambda r: any(p(r) for p in parts))

    def _term(self) -> Callable[[dict[str, bool]], bool]:
        parts = [self._factor()]
        while self._peek() == "and":
            self._next()
            parts.append(self._factor())
        return parts[0] if len(parts) == 1 else (lambda r: all(p(r) for p in parts))

    def _factor(self) -> Callable[[dict[str, bool]], bool]:
        tok = self._next()
        low = tok.lower()
        if low == "not":
            inner = self._factor()
            return lambda r: not inner(r)
        if tok == "(":
            node = self._expr()
            if self._next() != ")":
                raise SigmaError("missing `)`")
            return node
        if low in {"1", "any", "all"} and self._peek() == "of":
            self._next()
            target = self._next()
            names = self.identifiers if target.lower() == "them" else \
                [i for i in self.identifiers if fnmatch.fnmatchcase(i, target)]
            if not names:
                raise SigmaError(f"`{target}` matches no search identifier")
            self.referenced.update(names)
            combine = all if low == "all" else any
            return lambda r: combine(r[n] for n in names)
        if tok not in self.identifiers:
            raise SigmaError(f"unknown search identifier `{tok}`")
        self.referenced.add(tok)
        return lambda r: r[tok]


def compile_rule(rule: dict[str, Any]) -> tuple[Matcher, set[str]]:
    """Return (event matcher, referenced search identifiers)."""
    detection = dict(rule["detection"])
    condition = detection.pop("condition", None)
    if isinstance(condition, list):
        condition = " or ".join(f"({c})" for c in condition)
    if not isinstance(condition, str):
        raise SigmaError("detection.condition is missing")
    identifiers = sorted(detection)
    parser = _Parser(_tokenize(condition), identifiers)
    evaluate = parser.parse()

    def matcher(event: dict[str, Any]) -> bool:
        return evaluate({name: selection_matches(detection[name], event) for name in identifiers})

    return matcher, parser.referenced


# ---------------------------------------------------------------- lint

def _lint(rule_id: str, severity: FindingSeverity, title: str, resource: str, recommendation: str, **evidence: Any) -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=severity,
                   category="detection-quality", resource=resource, location=resource, evidence=evidence,
                   recommendation=recommendation)


def _broad_values(detection: dict[str, Any]) -> list[str]:
    broad = []
    for name, selection in detection.items():
        if name == "condition":
            continue
        maps = selection if isinstance(selection, list) else [selection]
        for sel in maps:
            if not isinstance(sel, dict):
                continue
            for key, value in sel.items():
                mods = key.split("|")[1:]
                for v in value if isinstance(value, list) else [value]:
                    text = "" if v is None else str(v)
                    if text.strip("*?") == "" and v is not None:
                        broad.append(f"{name}.{key}={text!r}")
                    elif "contains" in mods and len(text) < MIN_CONTAINS_LEN:
                        broad.append(f"{name}.{key}={text!r}")
    return broad


def lint_rule(rule: dict[str, Any], source: str = "") -> list[Finding]:
    findings: list[Finding] = []
    required: tuple[tuple[str, str, FindingSeverity], ...] = (("id", "SIGMA-LINT-ID", "medium"), ("level", "SIGMA-LINT-LEVEL", "low"),
                ("falsepositives", "SIGMA-LINT-FALSEPOSITIVES", "low"), ("logsource", "SIGMA-LINT-LOGSOURCE", "medium"),
                ("description", "SIGMA-LINT-DESCRIPTION", "info"))
    for field, rule_id, severity in required:
        if not rule.get(field):
            findings.append(_lint(rule_id, severity, f"Rule is missing `{field}`", source,
                                  f"Add `{field}` so the rule can be tracked, routed and tuned."))
    broad = _broad_values(rule.get("detection", {}))
    if broad:
        findings.append(_lint("SIGMA-LINT-BROAD", "medium", "Overly broad selection values", source,
                              "Use longer, more specific values or add a field constraint.", values=broad))
    try:
        _, referenced = compile_rule(rule)
    except SigmaError as exc:
        findings.append(_lint("SIGMA-LINT-CONDITION", "high", f"Invalid detection: {exc}", source,
                              "Fix the condition/selection so the rule compiles."))
        return findings
    unused = sorted(set(rule["detection"]) - {"condition"} - referenced)
    if unused:
        findings.append(_lint("SIGMA-LINT-UNUSED", "low", f"Search identifier(s) not used in condition: {unused}",
                              source, "Reference or remove unused selections.", unused=unused))
    return findings


# ---------------------------------------------------------------- evaluation

def _ratio(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


def evaluate_rule(rule: dict[str, Any], events: list[dict[str, Any]], source: str = "") -> tuple[dict[str, Any],
                                                                                                  list[Finding]]:
    """Score against events carrying `label: malicious|benign`. Returns (metrics, FP/FN findings)."""
    matcher, _ = compile_rule(rule)
    tp = fp = fn = tn = 0
    findings: list[Finding] = []
    title = rule.get("title", source)
    for index, event in enumerate(events, start=1):
        label = str(event.get("label", "")).lower()
        if label not in {"malicious", "benign"}:
            raise SigmaError(f"event {index} has no malicious|benign label")
        body = {k: v for k, v in event.items() if k != "label"}
        hit = matcher(body)
        if hit and label == "malicious":
            tp += 1
        elif hit:
            fp += 1
            findings.append(Finding(
                rule_id="SIGMA-FP", title=f"False positive: `{title}` matched benign event #{index}", severity="medium",
                category="detection-quality", resource=source, location=f"{source}#event{index}",
                evidence={"event_index": index, "event": body},
                recommendation="Add a `filter` selection excluding this benign pattern (`selection and not filter`)."))
        elif label == "malicious":
            fn += 1
            findings.append(Finding(
                rule_id="SIGMA-FN", title=f"Missed malicious event #{index}", severity="low",
                category="detection-quality", resource=source, location=f"{source}#event{index}",
                evidence={"event_index": index, "event": body},
                recommendation="Broaden the selection carefully or add a second selection for this variant."))
        else:
            tn += 1
    metrics = {"events": len(events), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
               "precision": _ratio(tp, tp + fp), "recall": _ratio(tp, tp + fn),
               "false_positive_rate": _ratio(fp, fp + tn), "f1": _ratio(2 * tp, 2 * tp + fp + fn)}
    return metrics, findings


def find_labeled_events(rule_path: Path) -> Path | None:
    """Conventional companion file: labeled_events.jsonl beside the rule or in its parent directory."""
    for directory in (rule_path.parent, rule_path.parent.parent):
        candidate = directory / LABELED_EVENTS_FILENAME
        if candidate.is_file():
            return candidate
    return None


def analyze_file(path: Path, events: Path | str | None = None, **opts: Any) -> AnalysisReport:
    """Lint the rule; if labeled events are given (or found beside it), also score it."""
    path = Path(path)
    rule = load_rule(path)
    findings = lint_rule(rule, str(path))
    metrics: dict[str, Any] = {"rule_id": rule.get("id"), "title": rule.get("title"), "level": rule.get("level")}
    events_path = Path(events) if events else find_labeled_events(path)
    compiles = not any(f.rule_id == "SIGMA-LINT-CONDITION" for f in findings)
    if events_path and compiles:
        scores, eval_findings = evaluate_rule(rule, load_jsonl(events_path), str(path))
        metrics |= scores | {"events_file": str(events_path)}
        findings.extend(eval_findings)
        summary = (f"precision {scores['precision']}, recall {scores['recall']}, "
                   f"FPR {scores['false_positive_rate']} (TP {scores['tp']} / FP {scores['fp']} / FN {scores['fn']})")
    else:
        summary = f"lint only: {len(findings)} issue(s)"
    return AnalysisReport(pack="soc", tool=TOOL, input=str(path), findings=findings, metrics=metrics, summary=summary)
