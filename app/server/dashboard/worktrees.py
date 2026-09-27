"""List isolated worktrees (trees/<adw_id>/.ports.env) and whether their ports are live."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

from .runs import is_valid_adw_id, runs_dir


def port_listening(port: int, host: str = "127.0.0.1", timeout: float = 0.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _parse_ports_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() in {"BACKEND_PORT", "FRONTEND_PORT"}:
            out[key.strip()] = value.strip()
    return out


def _port(value: str | None) -> int | None:
    try:
        port = int(value or "")
    except ValueError:
        return None
    return port if 1 <= port <= 65535 else None


def list_worktrees(root: Path) -> list[dict[str, Any]]:
    trees = root / "trees"
    if not trees.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for tree in sorted(trees.iterdir()):
        if not tree.is_dir() or not is_valid_adw_id(tree.name):
            continue
        env = _parse_ports_env(tree / ".ports.env")
        be, fe = _port(env.get("BACKEND_PORT")), _port(env.get("FRONTEND_PORT"))
        out.append(
            {
                "adw_id": tree.name,
                "backend_port": be,
                "frontend_port": fe,
                "backend_live": port_listening(be) if be else False,
                "frontend_live": port_listening(fe) if fe else False,
                "has_ports_env": bool(env),
                "has_run": (runs_dir(root) / tree.name).is_dir(),
            }
        )
    return out
