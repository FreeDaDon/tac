"""GitHub via the gh CLI. Issue content is returned sanitized; it is still untrusted."""

from __future__ import annotations

import json
import os
import re
import subprocess

from .data_types import IssuePayload
from .security import sanitize_untrusted, validate_branch_name, validate_issue_number
from .utils import base_branch

BOT_MARKER = "[TAC-ADW]"
_REMOTE_RE = re.compile(r"github\.com[:/](?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$")


class GitHubError(RuntimeError):
    pass


def extract_repo_path(url: str) -> str:
    """owner/repo from https or ssh remotes."""
    m = _REMOTE_RE.search(url.strip())
    if not m:
        raise GitHubError(f"cannot parse GitHub repo from {url!r}")
    return f"{m['owner']}/{m['repo']}"


def repo_path() -> str:
    url = os.getenv("GITHUB_REPO_URL")
    if not url:
        from .git_ops import git

        url = git("remote", "get-url", "origin", check=False)
    if not url:
        raise GitHubError("no GITHUB_REPO_URL and no origin remote")
    return extract_repo_path(url)


def _env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in {"PATH", "HOME", "USER", "LANG"}}
    if os.getenv("GITHUB_PAT"):
        env["GH_TOKEN"] = os.environ["GITHUB_PAT"]
    return env


def gh(*args: str, timeout: int = 60) -> str:
    proc = subprocess.run(["gh", *args], capture_output=True, text=True, env=_env(), timeout=timeout)
    if proc.returncode != 0:
        raise GitHubError(f"gh {args[0]} failed: {proc.stderr.strip()}")
    return proc.stdout


def fetch_issue(number: str) -> IssuePayload:
    num = validate_issue_number(number)
    data = json.loads(gh("issue", "view", num, "-R", repo_path(), "--json", "number,title,body,author,labels"))
    return IssuePayload(
        number=str(data["number"]),
        title=sanitize_untrusted(data.get("title", ""), 300),
        body=sanitize_untrusted(data.get("body") or ""),
        author=(data.get("author") or {}).get("login", ""),
        labels=[lbl["name"] for lbl in data.get("labels", [])],
    )


def comment(number: str, adw_id: str, body: str) -> None:
    """Post a bot comment. Failures are swallowed: comments are a courtesy, not a gate."""
    try:
        gh("issue", "comment", validate_issue_number(number), "-R", repo_path(),
           "--body", f"{BOT_MARKER} `{adw_id}` {body}")
    except (GitHubError, subprocess.SubprocessError, OSError):
        pass


def find_pr(branch: str) -> str | None:
    validate_branch_name(branch)
    out = gh("pr", "list", "-R", repo_path(), "--head", branch, "--json", "number,url", "--limit", "1")
    items = json.loads(out or "[]")
    return items[0]["url"] if items else None


def create_pr(branch: str, title: str, body: str) -> str:
    validate_branch_name(branch)
    existing = find_pr(branch)
    if existing:
        return existing
    out = gh("pr", "create", "-R", repo_path(), "--head", branch, "--base", base_branch(),
             "--title", sanitize_untrusted(title, 200), "--body", body)
    return out.strip().splitlines()[-1]


def merge_pr(branch: str) -> str:
    """Squash-merge via GitHub (server side). Never touches the local main checkout."""
    validate_branch_name(branch)
    return gh("pr", "merge", branch, "-R", repo_path(), "--squash", "--delete-branch", timeout=120)


def pr_checks_green(branch: str) -> bool:
    try:
        out = gh("pr", "checks", branch, "-R", repo_path(), "--json", "state")
    except GitHubError:
        return False
    checks = json.loads(out or "[]")
    return all(c.get("state") in ("SUCCESS", "SKIPPED", "NEUTRAL") for c in checks)
