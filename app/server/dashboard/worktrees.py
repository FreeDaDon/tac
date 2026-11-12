"""List isolated worktrees (trees/<adw_id>/.ports.env) and whether their ports are live."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
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
    found: list[tuple[str, int | None, int | None, bool]] = []
    for tree in sorted(trees.iterdir()):
        if not tree.is_dir() or not is_valid_adw_id(tree.name):
            continue
        env = _parse_ports_env(tree / ".ports.env")
        found.append((tree.name, _port(env.get("BACKEND_PORT")), _port(env.get("FRONTEND_PORT")), bool(env)))
    ports = sorted({p for _, be, fe, _ in found for p in (be, fe) if p})
    with ThreadPoolExecutor(max_workers=max(1, min(32, len(ports)))) as pool:
        live = dict(zip(ports, pool.map(port_listening, ports), strict=True))
    return [
        {
            "adw_id": adw_id,
            "backend_port": be,
            "frontend_port": fe,
            "backend_live": live.get(be, False) if be else False,
            "frontend_live": live.get(fe, False) if fe else False,
            "has_ports_env": has_env,
            "has_run": (runs_dir(root) / adw_id).is_dir(),
        }
        for adw_id, be, fe, has_env in found
    ]
