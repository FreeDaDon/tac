"""`python -m dashboard` (run from app/server): serve on TAC_DASHBOARD_HOST:TAC_DASHBOARD_PORT."""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.getenv("TAC_DASHBOARD_HOST", "127.0.0.1")
    port = int(os.getenv("TAC_DASHBOARD_PORT", "8000"))
    uvicorn.run("dashboard.main:app", host=host, port=port, proxy_headers=False, log_level="info")


if __name__ == "__main__":
    main()
