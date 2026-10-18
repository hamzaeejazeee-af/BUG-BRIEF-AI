"""Application layer shared by the CLI and the HTTP API."""
from __future__ import annotations

import base64
import binascii
from typing import Callable, List, Optional

from . import evalx, llm, report as rp
from .store import Store


class Service:
    def __init__(self, store: Store, caller: Optional[Callable] = None, strict: bool = False):
        self.store, self.caller, self.strict = store, caller, strict

    def create(self, description: str = "", logs: str = "", env: Optional[dict] = None, images: Optional[List[bytes]] = None) -> dict:
        res = llm.generate_report(description, logs, env, images, self.caller, self.strict, self.store.history_for_dupes())
        res["id"] = self.store.add(res)
        return res

    def create_from_b64(self, description: str, logs: str, env: Optional[dict], images_b64: List[str]) -> dict:
        try:
            images = [base64.b64decode(x, validate=True) for x in images_b64]
        except (binascii.Error, ValueError) as exc:
            raise llm.LLMError("An image was not valid base64.") from exc
        return self.create(description, logs, env, images)

    def render(self, rid: str, style: str = "github") -> str:
        return rp.render(self.store.get(rid)["report"], style)

    def run_eval(self, live: bool = False) -> dict:
        out = {"offline": evalx.eval_all()}
        if live:
            if not self.caller:
                raise llm.LLMError("Set ANTHROPIC_API_KEY to run the live check.")
            out["live"] = evalx.eval_live(self.caller)
        return out
