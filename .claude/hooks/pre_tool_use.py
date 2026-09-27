#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""PreToolUse guard for Claude Code. FAILS CLOSED.

Contract (Claude Code hooks): JSON on stdin {session_id, tool_name, tool_input, cwd, ...}.
  exit 0 -> allow
  exit 2 -> block; stderr is shown to the agent as the reason
Malformed input or an internal error also exits 2: a guard that crashes open is not a guard.

This is a regex/token guard. It stops accidents and naive prompt-injection payloads; it is
NOT a sandbox (see docs/playbook/03-security-model.md). Run untrusted work in a disposable
container with no cloud credentials.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

ALLOWED_ENV_FILES = {".env.sample", ".env.example", ".env.template"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
PATH_TOOLS = WRITE_TOOLS | {"Read", "Grep", "Glob", "LS"}
SENSITIVE_HOME_PATHS = [".ssh", ".aws/credentials", ".aws/config", ".config/gh", ".netrc", ".docker/config.json",
                        ".kube/config", ".config/gcloud", ".azure", ".gnupg"]
LOG_MAX_CHARS = 500


class Blocked(Exception):
    pass


# ----------------------------------------------------------------------------- helpers
def project_dir(payload: dict) -> Path:
    root = os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or os.getcwd()
    return Path(root).resolve()


def normalize(command: str) -> str:
    """Lowercase, drop quotes/backslash escapes, collapse whitespace."""
    text = command.lower()
    text = re.sub(r"[\"'\\]", "", text)
    return " ".join(text.split())


def segments(normalized: str) -> list[str]:
    """Split a normalized command on chaining/substitution operators."""
    parts = re.split(r"&&|\|\||;|\||\n|\$\(|`|\(|\)|&", normalized)
    return [p.strip() for p in parts if p.strip()]


def words(segment: str) -> list[str]:
    return re.findall(r"[^\s<>]+", segment)


def is_env_file(token: str) -> bool:
    name = token.rstrip("/").rsplit("/", 1)[-1]
    if name in ALLOWED_ENV_FILES:
        return False
    return name == ".env" or name.startswith(".env.")


def home_dir() -> Path:
    return Path(os.path.expanduser("~")).resolve()


def is_sensitive_path(raw: str) -> bool:
    text = raw.strip().lower()
    if not text:
        return False
    # textual forms (~, $home) as they appear in shell commands
    for p in SENSITIVE_HOME_PATHS:
        for prefix in ("~/", "$home/", "${home}/"):
            if text.startswith(prefix + p) or f" {prefix}{p}" in f" {text}":
                return True
    try:
        resolved = str(Path(os.path.expanduser(raw)).resolve()).lower()
    except (OSError, RuntimeError):
        return True
    home = str(home_dir()).lower()
    return any(resolved == f"{home}/{p}" or resolved.startswith(f"{home}/{p}/") for p in SENSITIVE_HOME_PATHS)


# ----------------------------------------------------------------------------- bash rules
DESTRUCTIVE_PATTERNS: list[tuple[str, str]] = [
    (r"(^|\s)(sudo|doas)(\s|$)", "privilege escalation (sudo) is not allowed"),
    (r"(^|\s)chmod\s+(-[a-z]+\s+)*(0?777|a\+rwx|ugo\+rwx)(\s|$)", "chmod 777 is not allowed"),
    (r"(^|\s)git\s+(.*\s)?reset\s+(.*\s)?--hard(\s|$)", "git reset --hard is not allowed"),
    (r"(^|\s)(terraform|tofu)\s+(.*\s)?(apply|destroy)(\s|$)", "terraform apply/destroy must be run by a human"),
    (r"(^|\s)pulumi\s+(.*\s)?(up|destroy|update)(\s|$)", "pulumi up/destroy must be run by a human"),
    (r"(^|\s)aws\s+(.*\s)?iam\s+(delete|detach|remove)[a-z-]*", "destructive aws iam call"),
    (r"(^|\s)aws\s+(.*\s)?iam\s+put-[a-z-]*policy", "aws iam put-*-policy must be run by a human"),
    (r"(^|\s)aws\s+(.*\s)?s3\s+rb(\s|$)", "aws s3 rb is not allowed"),
    (r"(^|\s)aws\s+(.*\s)?s3\s+rm\s+.*--recursive", "recursive aws s3 rm is not allowed"),
    (r"(^|\s)gcloud\s+(.*\s)?delete(\s|$)", "gcloud delete is not allowed"),
    (r"(^|\s)az\s+(.*\s)?delete(\s|$)", "az delete is not allowed"),
    (r"(^|\s)kubectl\s+(.*\s)?delete(\s|$)", "kubectl delete is not allowed"),
    (r"(^|\s)dd\s+(.*\s)?of=/dev/", "dd to a device is not allowed"),
    (r"(^|\s)mkfs(\.[a-z0-9]+)?(\s|$)", "mkfs is not allowed"),
    (r"(^|\s)(shred|wipefs)(\s|$)", "disk wiping tools are not allowed"),
    (r">\s*/dev/(sd|nvme|hd|xvd|vd)", "writing to a block device is not allowed"),
]

# checked against the whole normalized command (pipes must survive)
PIPE_TO_SHELL = [
    r"(curl|wget)\b[^|]*\|\s*((sudo|env)\s+)?(ba|z|da|k|fi)?sh\b",
    r"(curl|wget)\b[^|]*\|\s*(python[0-9.]*|perl|ruby|node)(\s+-)?\s*($|[;&|)])",
    r"(ba|z|da|k)?sh\s+(-[a-z]+\s+)*<\(\s*(curl|wget)",
    r"(ba|z|da|k)?sh\s+-c\s+.*\$\(\s*(curl|wget)",
    r"(^|\s)(source|\.)\s+<\(\s*(curl|wget)",
]


def check_rm(seg: str) -> None:
    toks = words(seg)
    for i, tok in enumerate(toks):
        if tok.rsplit("/", 1)[-1] != "rm":
            continue
        recursive = force = False
        targets: list[str] = []
        for arg in toks[i + 1:]:
            if arg == "--":
                continue
            if arg.startswith("--"):
                recursive |= arg == "--recursive"
                force |= arg == "--force"
            elif arg.startswith("-"):
                recursive |= "r" in arg[1:]
                force |= "f" in arg[1:]
            else:
                targets.append(arg)
        if recursive and force:
            raise Blocked("rm with recursive+force flags is not allowed; delete specific files instead")
        if recursive and any(t in ("/", "/*", "~", "~/", "$home", "${home}", "*", ".", "./", "..", "../") for t in targets):
            raise Blocked("recursive rm on a root/home/cwd/wildcard path is not allowed")


def check_find(seg: str) -> None:
    toks = words(seg)
    if not toks or toks[0].rsplit("/", 1)[-1] != "find":
        return
    destructive = "-delete" in toks or ("-exec" in toks and any(t.rsplit("/", 1)[-1] == "rm" for t in toks))
    if not destructive:
        return
    roots = [t for t in toks[1:] if not t.startswith("-")][:1]
    if not roots or roots[0] in ("/", "/*", "~", "~/", "$home", "${home}") or roots[0].startswith(("/", "~")):
        raise Blocked("find -delete/-exec rm outside the project is not allowed")


def check_git(seg: str) -> None:
    toks = words(seg)
    if "git" not in toks:
        return
    after_git = toks[toks.index("git") + 1:]
    if "push" in after_git:
        args = after_git[after_git.index("push") + 1:]
        for a in args:
            if a in ("-f", "--force", "--mirror", "--delete", "-d") or a.startswith("--force") or (
                a.startswith("-") and not a.startswith("--") and "f" in a[1:]
            ):
                raise Blocked("force/mirror/delete pushes are not allowed")
            if a.startswith("+"):
                raise Blocked("force-push refspecs (+ref) are not allowed")
            ref = a.split(":")[-1]
            if ref in ("main", "master", "refs/heads/main", "refs/heads/master"):
                raise Blocked("pushing directly to main/master is not allowed; open a PR")
    if "clean" in after_git:
        flags = "".join(a[1:] for a in after_git[after_git.index("clean") + 1:] if a.startswith("-") and not a.startswith("--"))
        long_force = "--force" in after_git
        if ("f" in flags or long_force) and ("d" in flags or "x" in flags):
            raise Blocked("git clean -fd/-fx is not allowed")


def check_bash(command: str) -> None:
    if not isinstance(command, str):
        raise Blocked("malformed Bash tool_input.command")
    norm = normalize(command)
    for pat in PIPE_TO_SHELL:
        if re.search(pat, norm):
            raise Blocked("piping downloaded content into an interpreter is not allowed")
    for tok in words(re.sub(r"[|;&()`=]", " ", norm)):
        if is_env_file(tok):
            raise Blocked(f"access to secret env file {tok!r} is not allowed (use .env.sample)")
        if is_sensitive_path(tok):
            raise Blocked(f"access to credential path {tok!r} is not allowed")
    for seg in segments(norm):
        check_rm(seg)
        check_find(seg)
        check_git(seg)
        for pat, reason in DESTRUCTIVE_PATTERNS:
            if re.search(pat, seg):
                raise Blocked(reason)


# ----------------------------------------------------------------------------- file-tool rules
def tool_paths(tool_input: dict) -> list[str]:
    out = []
    for key in ("file_path", "notebook_path", "path"):
        val = tool_input.get(key)
        if val is not None:
            if not isinstance(val, str):
                raise Blocked(f"malformed tool_input.{key}")
            out.append(val)
    return out


def check_file_tool(tool_name: str, tool_input: dict, root: Path, cwd: Path) -> None:
    paths = tool_paths(tool_input)
    if tool_name in WRITE_TOOLS and not paths:
        raise Blocked(f"{tool_name} without a file path")
    glob_pat = tool_input.get("pattern") if tool_name == "Glob" else tool_input.get("glob")
    if isinstance(glob_pat, str) and is_env_file(glob_pat.split("*")[-1] or "x"):
        raise Blocked("globbing for .env files is not allowed")
    for raw in paths:
        if is_env_file(raw):
            raise Blocked(f"access to secret env file {raw!r} is not allowed (use .env.sample)")
        if is_sensitive_path(raw):
            raise Blocked(f"access to credential path {raw!r} is not allowed")
        if tool_name in WRITE_TOOLS:
            p = Path(os.path.expanduser(raw))
            full = Path(os.path.realpath(p if p.is_absolute() else cwd / p))
            if full != root and root not in full.parents:
                raise Blocked(f"write outside the project directory is not allowed: {full}")


# ----------------------------------------------------------------------------- logging + main
def log_decision(payload: dict | None, decision: str, reason: str) -> None:
    try:
        root = Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
        log_dir = root / "agent" / "hook_logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        tool_input = (payload or {}).get("tool_input") if isinstance(payload, dict) else None
        summary = ""
        if isinstance(tool_input, dict):
            summary = str(tool_input.get("command") or tool_input.get("file_path") or tool_input.get("path") or "")
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "session_id": (payload or {}).get("session_id", "") if isinstance(payload, dict) else "",
            "tool_name": (payload or {}).get("tool_name", "") if isinstance(payload, dict) else "",
            "decision": decision,
            "reason": reason,
            "input": summary[:LOG_MAX_CHARS],
        }
        with open(log_dir / "pre_tool_use.jsonl", "a") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception:  # noqa: BLE001, S110 - logging is best effort, the decision is not
        pass


def decide(payload: object) -> None:
    if not isinstance(payload, dict):
        raise Blocked("malformed hook payload (expected JSON object)")
    tool_name = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_name, str) or not tool_name or not isinstance(tool_input, dict):
        raise Blocked("malformed hook payload (tool_name/tool_input)")
    root = project_dir(payload)
    raw_cwd = payload.get("cwd")
    cwd = Path(raw_cwd).resolve() if isinstance(raw_cwd, str) and raw_cwd else root
    if tool_name == "Bash":
        check_bash(tool_input.get("command"))
    elif tool_name in PATH_TOOLS:
        check_file_tool(tool_name, tool_input, root, cwd)


def main() -> int:
    payload = None
    try:
        payload = json.loads(sys.stdin.read())
        decide(payload)
    except Blocked as exc:
        log_decision(payload, "block", str(exc))
        print(f"BLOCKED by pre_tool_use hook: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - fail closed on anything unexpected
        log_decision(payload, "block", f"hook error: {type(exc).__name__}")
        print(f"BLOCKED by pre_tool_use hook: malformed input or hook error ({type(exc).__name__})", file=sys.stderr)
        return 2
    log_decision(payload, "allow", "")
    return 0


if __name__ == "__main__":
    sys.exit(main())
