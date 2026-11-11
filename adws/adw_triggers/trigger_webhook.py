#!/usr/bin/env -S uv run
"""GitHub webhook trigger (PITER: the T). Hardened vs tac-7:

- X-Hub-Signature-256 HMAC verification (GITHUB_WEBHOOK_SECRET required; fails closed)
- binds 127.0.0.1 by default (expose via a tunnel you control)
- only users in TAC_TRIGGER_ALLOWED_USERS can trigger runs; the check is on whoever performed the
  action (the event `sender`), so a non-allowlisted triager labeling an allowlisted user's issue
  triggers nothing
- `labeled` events trigger only when the label just added is a tac:* trigger label
- each X-GitHub-Delivery id is processed once, and the launcher allows one active run per issue
- workflow chosen deterministically from a comment command or labels, never by an LLM
- Zero-Touch only via the `tac:zte` label AND an allowlisted author

Comment commands:  /adw sdlc [heavy]   /adw plan   /adw zte
Labels:            tac:sdlc  tac:plan  tac:zte  tac:heavy

Usage: uv run adws/adw_triggers/trigger_webhook.py   (env PORT, default 8001)
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re

import uvicorn
from fastapi import FastAPI, HTTPException, Request

from adws.adw_modules.github import BOT_MARKER
from adws.adw_modules.utils import runs_dir
from adws.adw_triggers.launcher import launch

MAX_BODY = 1_000_000
COMMAND_RE = re.compile(r"^/adw\s+(sdlc|plan|zte)(\s+heavy)?\s*$", re.MULTILINE)
WORKFLOW_FOR = {"sdlc": "adw_sdlc_iso", "plan": "adw_plan_iso", "zte": "adw_sdlc_zte_iso"}
TRIGGER_LABELS = {"tac:sdlc", "tac:plan", "tac:zte"}
DELIVERY_RE = re.compile(r"^[0-9a-fA-F-]{8,64}$")
MAX_REMEMBERED_DELIVERIES = 2000


def verify_signature(secret: str, body: bytes, header: str | None) -> bool:
    if not secret or not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)


def allowed_users() -> set[str]:
    return {u.strip().lower() for u in os.getenv("TAC_TRIGGER_ALLOWED_USERS", "").split(",") if u.strip()}


def decide(event: str, payload: dict) -> tuple[str, str] | None:
    """Return (workflow, model_set) or None. Pure function: easy to test."""
    issue = payload.get("issue") or {}
    labels = {lbl.get("name", "") for lbl in issue.get("labels", [])}
    heavy = "tac:heavy" in labels
    if event == "issue_comment" and payload.get("action") == "created":
        comment = payload.get("comment") or {}
        body = comment.get("body") or ""
        author = (comment.get("user") or {}).get("login", "").lower()
        if BOT_MARKER in body or author not in allowed_users():
            return None
        m = COMMAND_RE.search(body)
        if not m:
            return None
        kind = m.group(1)
        if kind == "zte" and "tac:zte" not in labels:
            return None
        return WORKFLOW_FOR[kind], "heavy" if (m.group(2) or heavy) else "base"
    if event == "issues" and payload.get("action") in ("opened", "labeled"):
        actor = (payload.get("sender") or issue.get("user") or {}).get("login", "").lower()
        if actor not in allowed_users():
            return None
        if payload.get("action") == "labeled" and (payload.get("label") or {}).get("name") not in TRIGGER_LABELS:
            return None
        if "tac:zte" in labels:
            return "adw_sdlc_zte_iso", "heavy" if heavy else "base"
        if "tac:sdlc" in labels:
            return "adw_sdlc_iso", "heavy" if heavy else "base"
        if "tac:plan" in labels:
            return "adw_plan_iso", "heavy" if heavy else "base"
    return None


def first_delivery(delivery_id: str) -> bool:
    """Record a webhook delivery id; False when it was already processed (GitHub redelivery, replay)."""
    if not DELIVERY_RE.match(delivery_id):
        return False
    path = runs_dir() / "_triggers" / "deliveries.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        fh.seek(0)
        try:
            seen: list[str] = json.loads(fh.read() or "[]")
        except json.JSONDecodeError:
            seen = []
        if delivery_id in seen:
            return False
        seen = [*seen, delivery_id][-MAX_REMEMBERED_DELIVERIES:]
        fh.seek(0)
        fh.truncate()
        fh.write(json.dumps(seen))
    return True


def create_app() -> FastAPI:
    app = FastAPI(title="TAC webhook trigger", docs_url=None, redoc_url=None)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "signature_required": True, "allowed_users": len(allowed_users())}

    @app.post("/gh-webhook")
    async def webhook(request: Request) -> dict:
        body = await request.body()
        if len(body) > MAX_BODY:
            raise HTTPException(413, "payload too large")
        secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")
        if not verify_signature(secret, body, request.headers.get("X-Hub-Signature-256")):
            raise HTTPException(401, "invalid signature")
        event = request.headers.get("X-GitHub-Event", "")
        payload = json.loads(body or b"{}")
        decision = decide(event, payload)
        if not decision:
            return {"status": "ignored"}
        if not first_delivery(request.headers.get("X-GitHub-Delivery", "")):
            return {"status": "ignored", "reason": "missing or duplicate delivery id"}
        workflow, model_set = decision
        number = str((payload.get("issue") or {}).get("number", ""))
        try:
            proc = launch(workflow, issue=number, model_set=model_set)
        except (ValueError, RuntimeError) as exc:
            return {"status": "rejected", "reason": str(exc)}
        return {"status": "launched", "workflow": workflow, "pid": proc.pid}

    return app


def main() -> None:
    if not os.getenv("GITHUB_WEBHOOK_SECRET"):
        raise SystemExit("GITHUB_WEBHOOK_SECRET is required")
    uvicorn.run(create_app(), host=os.getenv("TAC_WEBHOOK_HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8001")))


if __name__ == "__main__":
    main()
