"""Evaluation over the golden dataset (shared with the browser app) plus an optional live model check."""
from __future__ import annotations

import json
import os
from typing import Callable, Optional

from . import logparse, redact as rd, report as rp
from .llm import generate_report

GOLDEN = json.load(open(os.path.join(os.path.dirname(__file__), "golden.json")))


def _wrap(rows, n):
    p = sum(1 for r in rows if r["ok"])
    return {"n": n, "passed": p, "accuracy": p / n if n else 1.0, "rows": rows}


def eval_parser(g=GOLDEN):
    rows = []
    for c in g["logs"]:
        p, e, fails = logparse.parse_logs(c["text"]), c["expect"], []
        if e.get("no_error") and p["error_count"]:
            fails.append("found errors in clean log")
        for s in e.get("signature_has", []):
            if not p["signature"] or s not in p["signature"]:
                fails.append(f'signature lacks "{s}"')
        if e.get("kind") and p["kind"] != e["kind"]:
            fails.append(f"kind {p['kind']}")
        if e.get("errors_min") and p["error_count"] < e["errors_min"]:
            fails.append("too few errors")
        if "status" in e and p["status_codes"] != e["status"]:
            fails.append(f"status {p['status_codes']}")
        if e.get("repeated_min") and len(p["repeated"]) < e["repeated_min"]:
            fails.append("repeats not collapsed")
        if e.get("time_first") and (p["time_first"] or "")[:19] != e["time_first"]:
            fails.append("time range")
        for k, v in (e.get("env") or {}).items():
            if k == "os_has":
                if "Windows" not in p["env"].get("os", ""):
                    fails.append("os")
            elif p["env"].get(k) != v:
                fails.append(f"env.{k}={p['env'].get(k)}")
        rows.append({"id": c["id"], "ok": not fails, "detail": "; ".join(fails)})
    return _wrap(rows, len(g["logs"]))


def eval_redaction(g=GOLDEN):
    rows = []
    for i, c in enumerate(g["redaction"], 1):
        t = rd.redact(c["text"], strict=bool(c.get("strict"))).text
        fails = [f"leaked {s[:18]}" for s in c.get("must_not", []) if s in t] + [f"lost {s[:18]}" for s in c.get("must", []) if s not in t]
        rows.append({"id": f"redaction-{i}", "ok": not fails, "detail": "; ".join(fails)})
    return _wrap(rows, len(g["redaction"]))


def eval_severity(g=GOLDEN):
    rows, within = [], 0
    for i, (text, exp) in enumerate(g["severity"], 1):
        got = rp.rule_severity(text)["level"]
        within += abs(rp.SEV.index(got) - rp.SEV.index(exp)) <= 1
        rows.append({"id": f"severity-{i}", "ok": got == exp, "detail": "" if got == exp else f"got {got}, expected {exp}"})
    out = _wrap(rows, len(g["severity"]))
    out["within_one"] = within / len(g["severity"])
    return out


def eval_dedupe(g=GOLDEN):
    rows, tp, fp, fn = [], 0, 0, 0
    for i, c in enumerate(g["dedupe"], 1):
        s = rp.similarity(c["a"], c["b"])
        pred = s["score"] >= rp.DUP_THRESHOLD
        tp += pred and c["duplicate"]; fp += pred and not c["duplicate"]; fn += (not pred) and c["duplicate"]
        rows.append({"id": f"dedupe-{i}", "ok": pred == c["duplicate"], "detail": "" if pred == c["duplicate"] else f"score {s['score']:.2f}"})
    out = _wrap(rows, len(g["dedupe"]))
    out["precision"] = tp / (tp + fp) if tp + fp else 1.0
    out["recall"] = tp / (tp + fn) if tp + fn else 1.0
    return out


def sample_report() -> dict:
    return rp.normalize_report({"title": "Checkout page freezes when tapping Pay", "summary": "Tapping Pay throws a TypeError.", "component": "checkout", "severity": "high", "severity_reason": "Blocks purchases",
        "environment": {"app": "Shop web", "version": "2.4.1", "os": "iOS 17.2", "browser": "Safari"}, "preconditions": ["Signed in"],
        "steps": [{"text": "Open the cart with three items", "source": "description"}, {"text": "Tap the Pay button", "source": "description"}],
        "expected": "The payment sheet opens.", "actual": "Nothing happens.", "frequency": "always",
        "evidence": {"log_excerpts": [{"text": "Uncaught TypeError: Cannot read properties of undefined (reading 'price')", "note": "Console"}]}, "labels": ["regression"], "missing_info": [{"question": "Android too?"}], "confidence": 0.8})


def eval_templates():
    r, rows = sample_report(), []
    checks = {"github": ["## ", "### Steps to reproduce", "1. Open the cart", "```", "**Labels:**"], "jira": ["h2. ", "h3. Steps to reproduce", "# Open the cart", "{code}", "*Labels:*"],
              "plain": ["CHECKOUT PAGE", "Steps to reproduce", "  1. Open the cart", "Expected:", "Actual:"], "json": ['"title"', '"steps"', '"severity": "high"']}
    for style, need in checks.items():
        out = rp.render(r, style)
        miss = [x for x in need if x not in out]
        rows.append({"id": f"template-{style}", "ok": not miss, "detail": "missing " + ", ".join(miss) if miss else ""})
    return _wrap(rows, len(checks))


def eval_all(g=GOLDEN):
    parts = {"parser": eval_parser(g), "redaction": eval_redaction(g), "severity": eval_severity(g), "dedupe": eval_dedupe(g), "templates": eval_templates()}
    n, p = sum(x["n"] for x in parts.values()), sum(x["passed"] for x in parts.values())
    return {"parts": parts, "n": n, "passed": p, "accuracy": p / n}


def eval_live(caller: Callable, g=GOLDEN) -> dict:
    rows, fab, kw, exact = [], 0, 0.0, 0
    for c in g["reports"]:
        res = generate_report(c["inputs"]["description"], c["inputs"]["logs"], caller=caller)
        if res["offline"]:
            raise RuntimeError("Model unavailable: " + res["notice"])
        r = res["report"]
        hay = " ".join([r["title"], r["summary"], " ".join(s["text"] for s in r["steps"]), r["expected"], r["actual"], r["component"]]).lower()
        found = sum(1 for k in c["expected"]["keywords"] if k in hay) / len(c["expected"]["keywords"])
        rows.append({"id": c["id"], "severity": r["severity"], "expected": c["expected"]["severity"], "keywords": found, "score": res["score"]})
        fab += res["grounding"]["fabricated_quotes"]; kw += found; exact += r["severity"] == c["expected"]["severity"]
    n = len(rows)
    return {"n": n, "severity_exact": exact / n, "keyword_recall": kw / n, "fabricated_quotes": fab, "rows": rows}
