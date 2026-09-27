"""Launcher: `uv run python app/server/run.py` (from the repo root) or `python run.py` in app/server."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dashboard.__main__ import main  # noqa: E402

if __name__ == "__main__":
    main()
