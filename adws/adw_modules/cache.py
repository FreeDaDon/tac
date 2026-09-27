"""Prompt-result cache for read-only agent calls.

Only commands in CACHEABLE_COMMANDS are ever cached: they do not mutate the repo, so a
hit is equivalent to re-running them. The key includes the git tree hash of the working
directory, so any code change invalidates the entry. Mutating commands (plan, implement,
repair, patch, commit) are never cached: replaying their text would not replay their effects.

"Semantic" normalization: whitespace collapse, case-fold of the command, and removal of
volatile tokens (adw ids, timestamps) so equivalent prompts share an entry.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
import subprocess
import time
from pathlib import Path

from .data_types import AgentResponse
from .utils import agent_dir, env_flag

CACHEABLE_COMMANDS = {"/classify_issue", "/generate_branch_name", "/review", "/redteam"}
DEFAULT_TTL_S = 7 * 24 * 3600

_VOLATILE = [
    re.compile(r"\b[a-f0-9]{8}\b"),  # adw ids
    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"),
]


def normalize_prompt(prompt: str) -> str:
    text = prompt.strip()
    for pattern in _VOLATILE:
        text = pattern.sub("<v>", text)
    return re.sub(r"\s+", " ", text)


def tree_hash(working_dir: str | None) -> str:
    """Hash of the committed tree plus uncommitted diff; '' when not a git repo."""
    if not working_dir:
        return ""
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=working_dir, capture_output=True, text=True, timeout=10
        ).stdout.strip()
        diff = subprocess.run(
            ["git", "diff", "HEAD"], cwd=working_dir, capture_output=True, text=True, timeout=30
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    return hashlib.sha256((head + diff).encode()).hexdigest()


class PromptCache:
    def __init__(self, path: Path | None = None, ttl_s: int = DEFAULT_TTL_S) -> None:
        self.path = path or agent_dir() / "cache.db"
        self.ttl_s = ttl_s
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, command TEXT, response TEXT,"
                " created REAL, hits INTEGER DEFAULT 0)"
            )

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=10)

    @staticmethod
    def enabled_for(slash_command: str) -> bool:
        return env_flag("TAC_CACHE_ENABLED", True) and slash_command in CACHEABLE_COMMANDS

    @staticmethod
    def key(slash_command: str, prompt: str, model: str, working_dir: str | None) -> str:
        material = "\x1f".join([slash_command.lower(), model, normalize_prompt(prompt), tree_hash(working_dir)])
        return hashlib.sha256(material.encode()).hexdigest()

    def get(self, key: str) -> AgentResponse | None:
        with self._conn() as c:
            row = c.execute("SELECT response, created FROM cache WHERE key = ?", (key,)).fetchone()
            if not row:
                return None
            if time.time() - row[1] > self.ttl_s:
                c.execute("DELETE FROM cache WHERE key = ?", (key,))
                return None
            c.execute("UPDATE cache SET hits = hits + 1 WHERE key = ?", (key,))
        resp = AgentResponse.model_validate_json(row[0])
        resp.cached = True
        resp.usage = type(resp.usage)()  # a hit costs nothing
        return resp

    def put(self, key: str, slash_command: str, response: AgentResponse) -> None:
        if not response.success:
            return
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO cache (key, command, response, created, hits) VALUES (?, ?, ?, ?, 0)",
                (key, slash_command, response.model_dump_json(), time.time()),
            )

    def stats(self) -> dict[str, int]:
        with self._conn() as c:
            entries, hits = c.execute("SELECT COUNT(*), COALESCE(SUM(hits), 0) FROM cache").fetchone()
        return {"entries": entries, "hits": hits}
