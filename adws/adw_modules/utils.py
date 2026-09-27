"""Shared paths, IDs, logging and JSON parsing helpers for ADWs."""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from pydantic import BaseModel, TypeAdapter


def project_root() -> Path:
    """Repository root. Overridable for tests via TAC_PROJECT_ROOT."""
    override = os.getenv("TAC_PROJECT_ROOT")
    if override:
        return Path(override).resolve()
    return Path(__file__).resolve().parents[2]


load_dotenv(project_root() / ".env")


def agent_dir() -> Path:
    return project_root() / "agent"


def runs_dir() -> Path:
    return agent_dir() / "runs"


def run_dir(adw_id: str) -> Path:
    from .security import validate_adw_id

    return runs_dir() / validate_adw_id(adw_id)


def trees_dir() -> Path:
    return project_root() / "trees"


def base_branch() -> str:
    return os.getenv("TAC_BASE_BRANCH", "main")


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def make_adw_id() -> str:
    """8 lowercase hex chars; validated everywhere it is used as a path component."""
    return secrets.token_hex(4)


def setup_logger(adw_id: str, workflow: str) -> logging.Logger:
    logger = logging.getLogger(f"adw.{adw_id}.{workflow}")
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    log_dir = run_dir(adw_id) / workflow
    log_dir.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(log_dir / "execution.log")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(f"[{adw_id}:{workflow}] %(message)s"))
    logger.addHandler(fh)
    logger.addHandler(ch)
    logger.propagate = False
    return logger


_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)```", re.DOTALL)


def extract_json_text(text: str) -> str:
    """Pull the JSON payload out of model output (handles code fences and prose around it)."""
    fenced = _FENCE_RE.search(text)
    if fenced:
        text = fenced.group(1)
    text = text.strip()
    starts = [i for i in (text.find("["), text.find("{")) if i != -1]
    if not starts:
        raise ValueError("no JSON object or array found in model output")
    start = min(starts)
    closer = "]" if text[start] == "[" else "}"
    end = text.rfind(closer)
    if end < start:
        raise ValueError("unterminated JSON in model output")
    return text[start : end + 1]


def parse_json(text: str, target_type: Any = None) -> Any:
    """Strictly parse model output. Raises ValueError on anything malformed.

    Model output is untrusted: callers must treat a ValueError as a failed attempt,
    never as an empty/passing result.
    """
    raw = extract_json_text(text)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON from model: {exc}") from exc
    if target_type is None:
        return data
    try:
        if isinstance(target_type, type) and issubclass(target_type, BaseModel):
            return target_type.model_validate(data)
        return TypeAdapter(target_type).validate_python(data)
    except Exception as exc:  # pydantic ValidationError
        raise ValueError(f"model output failed schema validation: {exc}") from exc
