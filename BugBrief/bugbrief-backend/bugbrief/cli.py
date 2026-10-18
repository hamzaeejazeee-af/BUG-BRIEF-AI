"""Command line: python -m bugbrief report|parse|redact|eval|history|stats|export"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List

from . import llm, logparse, redact as rd, report as rp
from .service import Service
from .store import Store


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def main(argv: List[str] | None = None, out=None) -> int:
    out = out or sys.stdout
    p = argparse.ArgumentParser(prog="bugbrief")
    p.add_argument("--db", default="bugbrief.db")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("report"); a.add_argument("--desc", default=""); a.add_argument("--desc-file"); a.add_argument("--logs"); a.add_argument("--image", action="append", default=[])
    a.add_argument("--style", default="github", choices=["github", "jira", "plain", "json"]); a.add_argument("--strict", action="store_true"); a.add_argument("--env", action="append", default=[], help="key=value")
    a = sub.add_parser("parse"); a.add_argument("logfile")
    a = sub.add_parser("redact"); a.add_argument("file"); a.add_argument("--strict", action="store_true")
    a = sub.add_parser("eval"); a.add_argument("--live", action="store_true")
    sub.add_parser("history"); sub.add_parser("stats")
    a = sub.add_parser("export"); a.add_argument("format", choices=["csv", "json"])
    args = p.parse_args(argv)
    try:
        if args.cmd == "parse":
            r = logparse.parse_logs(_read(args.logfile)); r.pop("errors"); print(json.dumps(r, indent=2, default=str), file=out); return 0
        if args.cmd == "redact":
            r = rd.redact(_read(args.file), args.strict); print(r.text, file=out); print(f"[{r.total} item(s) hidden: {r.counts}]", file=sys.stderr); return 0
        caller = llm.anthropic_caller() if os.environ.get("ANTHROPIC_API_KEY") else None
        svc = Service(Store(args.db), caller, strict=getattr(args, "strict", False))
        if args.cmd == "report":
            desc = _read(args.desc_file) if args.desc_file else args.desc
            env = dict(kv.split("=", 1) for kv in args.env if "=" in kv)
            images = [open(path, "rb").read() for path in args.image]
            res = svc.create(desc, _read(args.logs) if args.logs else "", env, images)
            print(rp.render(res["report"], args.style), file=out)
            print(f"\nrepro score {res['score']}/100 | id {res['id']}" + (" | OFFLINE DRAFT: " + res["notice"] if res["offline"] else ""), file=sys.stderr)
        elif args.cmd == "eval":
            print(json.dumps(svc.run_eval(args.live), indent=2), file=out)
        elif args.cmd == "history":
            for r in svc.store.list():
                print(f"{r['id']}  {r['severity']:<8} {r['score']:>3}  {r['title']}", file=out)
        elif args.cmd == "stats":
            print(json.dumps(svc.store.stats(), indent=2), file=out)
        elif args.cmd == "export":
            print(svc.store.export_csv() if args.format == "csv" else json.dumps([svc.store.get(r["id"]) for r in svc.store.list(limit=500)], indent=2), file=out)
        return 0
    except (llm.LLMError, OSError, KeyError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
