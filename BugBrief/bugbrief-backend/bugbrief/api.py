"""HTTP API (FastAPI): thin wrapper over Service with API-key auth, rate limits and safe error mapping.
Run: uvicorn bugbrief.api:app --host 0.0.0.0 --port 8000"""
from __future__ import annotations

import hmac
import os
import time
from collections import defaultdict, deque
from typing import Dict, List

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from . import llm, logparse, redact as rd
from .service import Service
from .store import Store

app = FastAPI(title="BugBrief", version="0.1.0")
_KEYS = [k for k in os.environ.get("BUGBRIEF_API_KEYS", "").split(",") if k]
_DEV = os.environ.get("BUGBRIEF_DEV") == "1"
_svc = Service(Store(os.environ.get("DB_PATH", "bugbrief.db")), llm.anthropic_caller() if os.environ.get("ANTHROPIC_API_KEY") else None, strict=os.environ.get("STRICT_PRIVACY") == "1")
_hits: Dict[str, deque] = defaultdict(deque)
LIMIT = int(os.environ.get("RATE_LIMIT", "30"))


def auth(x_api_key: str = Header(default="")) -> str:
    if _DEV and not _KEYS:
        return "dev"
    if not any(hmac.compare_digest(x_api_key.encode(), k.encode()) for k in _KEYS):
        raise HTTPException(401, "Missing or invalid X-API-Key.")
    q, now = _hits[x_api_key], time.time()
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= LIMIT:
        raise HTTPException(429, "Rate limit exceeded. Try again in a minute.")
    q.append(now)
    return x_api_key


class ReportReq(BaseModel):
    description: str = Field(default="", max_length=20000)
    logs: str = Field(default="", max_length=1_000_000)
    environment: Dict[str, str] = Field(default_factory=dict)
    images_base64: List[str] = Field(default_factory=list, max_length=4)


class TextReq(BaseModel):
    text: str = Field(max_length=1_000_000)
    strict: bool = False


@app.get("/healthz")
def health():
    return {"ok": True, "model": bool(_svc.caller)}


@app.post("/v1/reports")
def create(req: ReportReq, _: str = Depends(auth)):
    try:
        return _svc.create_from_b64(req.description, req.logs, req.environment, req.images_base64)
    except llm.LLMError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/v1/reports")
def list_reports(q: str = "", severity: str = "", _: str = Depends(auth)):
    return _svc.store.list(q, severity)


@app.get("/v1/reports/{rid}")
def get_report(rid: str, style: str = "", _: str = Depends(auth)):
    try:
        return PlainTextResponse(_svc.render(rid, style)) if style in ("github", "jira", "plain", "json") else _svc.store.get(rid)
    except KeyError:
        raise HTTPException(404, "Report not found.")


@app.delete("/v1/reports/{rid}")
def delete(rid: str, _: str = Depends(auth)):
    _svc.store.delete(rid)
    return {"deleted": rid}


@app.get("/v1/stats")
def stats(_: str = Depends(auth)):
    return _svc.store.stats()


@app.post("/v1/redact")
def redact_text(req: TextReq, _: str = Depends(auth)):
    r = rd.redact(req.text, req.strict)
    return {"text": r.text, "counts": r.counts, "total": r.total}


@app.post("/v1/parse")
def parse(req: TextReq, _: str = Depends(auth)):
    r = logparse.parse_logs(req.text)
    r.pop("errors")
    return r
