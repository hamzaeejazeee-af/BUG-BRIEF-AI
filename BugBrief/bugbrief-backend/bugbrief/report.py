"""Report logic: severity rules, schema normalisation, grounding, scoring, duplicates, templates."""
from __future__ import annotations

import csv
import io
import json
import math
import re
from typing import Dict, List

SEV = ["low", "medium", "high", "critical"]
FREQ = ["always", "often", "sometimes", "once", "unknown"]
SRC = ["description", "log", "screenshot", "assumed"]
STOP = set("the a an of to in is it and or for on with as by at from this that be are was how what where does do did which when why can i me my we our "
           "you your there if then else not no yes any all use about into out up per also after before just very really page app but has have had will "
           "would should could than so such get got gets".split())


def stem(w: str) -> str:
    if len(w) <= 4:
        return w
    if w.endswith("s") and not w.endswith("ss"):
        w = w[:-1]
    for suf in ("ations", "ation", "ing", "ers", "er", "ed", "es", "ly"):
        if len(w) - len(suf) >= 3 and w.endswith(suf):
            return w[: -len(suf)]
    return w


def tokens(s: str) -> List[str]:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(s or "")).lower()
    return [stem(w.replace("'", "")) for w in re.findall(r"[a-z][a-z0-9']*|\d+", s) if len(w.replace("'", "")) >= 2 and w.replace("'", "") not in STOP]


def _s(x, n=2000) -> str:
    return ("" if x is None else x if isinstance(x, str) else str(x)).strip()[:n]


# ---- severity rules ----
_CRIT = re.compile(r"data (was |got |is )?(deleted|lost|wiped)|data loss|lost (all )?(my |the )?data|charged (me )?twice|double[- ]charge|security|vulnerab|unauthori[sz]ed|(view|see|access|read) (other|another) users?|leak|breach|production (is )?down|outage|cannot log ?in at all", re.I)
_LOW = re.compile(r"typo|misspell|misalign|spacing|colou?r|cosmetic|alignment|pixel|\bfont\b|icon|padding|spelling|says\s+['\"\u2018\u201c][^'\"\u2019\u201d]+['\"\u2019\u201d]\s+instead of", re.I)
_BLOCK = re.compile(r"crash|fatal|\b5\d\d\b|cannot|can't|unable", re.I)
_HIGH = re.compile(r"crash|fatal|\b5\d\d\b|server error|freez|hang|blank screen|exception|cannot|can't|unable to|broken", re.I)


def rule_severity(text: str, parsed: dict | None = None) -> dict:
    t, reasons, level = str(text or ""), [], "medium"
    if _CRIT.search(t):
        level = "critical"; reasons.append("mentions data loss, double charging or a security or outage problem")
    elif _LOW.search(t) and not _BLOCK.search(t):
        level = "low"; reasons.append("looks cosmetic")
    elif _HIGH.search(t):
        level = "high"; reasons.append("describes a crash, server error or blocked feature")
    p = parsed and parsed.get("primary")
    if p and SEV.index(level) < 2 and (p["kind"] in ("crash", "exception") or p.get("status", 0) >= 500):
        level = "high"; reasons.append("logs show " + p["type"])
    return {"level": level, "reasons": reasons}


# ---- schema ----
def normalize_report(o) -> dict:
    o = o if isinstance(o, dict) else {}
    env = o.get("environment") if isinstance(o.get("environment"), dict) else {}
    try:
        conf = float(o.get("confidence"))
        conf = 0.5 if math.isnan(conf) else min(1.0, max(0.0, conf))
    except (TypeError, ValueError):
        conf = 0.5
    sev = str(o.get("severity", "")).lower()
    r = {"title": _s(o.get("title"), 140), "summary": _s(o.get("summary"), 600), "component": _s(o.get("component"), 60),
         "severity": sev if sev in SEV else "medium", "severity_reason": _s(o.get("severity_reason"), 300),
         "environment": {k: _s(env.get(k), n) for k, n in (("app", 80), ("version", 40), ("os", 60), ("device", 60), ("browser", 60), ("other", 120))},
         "preconditions": [x for x in (_s(p, 200) for p in (o.get("preconditions") or []) if p is not None) if x][:6], "steps": [],
         "expected": _s(o.get("expected"), 500), "actual": _s(o.get("actual"), 500),
         "frequency": str(o.get("frequency", "")).lower() if str(o.get("frequency", "")).lower() in FREQ else "unknown",
         "evidence": {"log_excerpts": [], "screenshot_observations": [], "user_quotes": []}, "suspected_cause": _s(o.get("suspected_cause"), 400),
         "workaround": _s(o.get("workaround"), 300), "labels": [], "missing_info": [], "confidence": conf}
    for s in (o.get("steps") or []):
        text = s if isinstance(s, str) else _s((s or {}).get("text"), 300)
        src = str(s.get("source", "")).lower() if isinstance(s, dict) else ""
        if text.strip():
            r["steps"].append({"text": re.sub(r"^\s*\d+[.)]\s*", "", text)[:300], "source": src if src in SRC else "assumed"})
    r["steps"] = r["steps"][:15]
    ev = o.get("evidence") if isinstance(o.get("evidence"), dict) else {}
    for x in (ev.get("log_excerpts") or [])[:4]:
        t = x if isinstance(x, str) else _s((x or {}).get("text"), 600)
        if t.strip():
            r["evidence"]["log_excerpts"].append({"text": t[:600], "note": _s(x.get("note"), 160) if isinstance(x, dict) else ""})
    r["evidence"]["screenshot_observations"] = [y for y in (_s(x, 200) for x in (ev.get("screenshot_observations") or [])) if y][:5]
    r["evidence"]["user_quotes"] = [y for y in (_s(x, 200) for x in (ev.get("user_quotes") or [])) if y][:4]
    r["labels"] = [re.sub(r"\s+", "-", _s(x, 30).lower()) for x in (o.get("labels") or []) if _s(x, 30)][:6]
    for x in (o.get("missing_info") or [])[:5]:
        q = x if isinstance(x, str) else _s((x or {}).get("question"), 200)
        if q.strip():
            r["missing_info"].append({"question": q[:200], "why": _s(x.get("why"), 160) if isinstance(x, dict) else ""})
    return r


# ---- grounding and scoring ----
def _ws(s) -> str:
    return re.sub(r"\s+", " ", str(s or "")).strip().lower()


def _overlap(a: str, b: set) -> float:
    ta = tokens(a)
    return sum(1 for t in ta if t in b) / len(ta) if ta else 0.0


def ground_check(report: dict, description: str = "", logs: str = "", screenshots: int = 0) -> dict:
    desc, lg, logs_ws = set(tokens(description)), set(tokens(logs)), _ws(logs)
    statuses = []
    for s in report["steps"]:
        if s["source"] == "description":
            statuses.append("verified" if _overlap(s["text"], desc) >= 0.34 else "weak")
        elif s["source"] == "log":
            statuses.append("verified" if logs and _overlap(s["text"], lg) >= 0.3 else "weak")
        elif s["source"] == "screenshot":
            statuses.append("unverifiable" if screenshots > 0 else "weak")
        else:
            statuses.append("assumed")
    credit = {"verified": 1, "unverifiable": 0.6, "weak": 0.15, "assumed": 0}
    step_score = sum(credit[s] for s in statuses) / len(statuses) if statuses else 0.0
    quotes = [bool(logs_ws and _ws(q["text"]) and _ws(q["text"]) in logs_ws) for q in report["evidence"]["log_excerpts"]]
    qscore = sum(quotes) / len(quotes) if quotes else None
    g = step_score if qscore is None else 0.6 * step_score + 0.4 * qscore
    return {"grounding": g if statuses else 0.0, "steps": statuses, "quotes": quotes, "assumed": statuses.count("assumed"), "fabricated_quotes": quotes.count(False)}


def completeness(report: dict, screenshots: int = 0) -> dict:
    env_known = sum(1 for k, v in report["environment"].items() if v and k != "other")
    long_steps = sum(1 for s in report["steps"] if len(s["text"].split()) >= 3)
    ev = report["evidence"]
    items = [("title", "Clear title", 10, 12 <= len(report["title"]) <= 120, "Write a short title that names the symptom and where it happens."),
             ("env", "Environment known", 15, env_known >= 2, "Which device, OS, browser and app version?"),
             ("steps", "Reproducible steps", 25, long_steps >= 2, "List the exact steps, starting from a known state."),
             ("results", "Expected and actual", 20, bool(report["expected"] and report["actual"] and _ws(report["expected"]) != _ws(report["actual"])), "What should happen, and what happens instead?"),
             ("evidence", "Evidence attached", 15, bool(ev["log_excerpts"] or ev["screenshot_observations"] or screenshots > 0), "Add a log, error text or a screenshot."),
             ("severity", "Severity explained", 5, bool(report["severity_reason"]), "Say who is affected and how badly."),
             ("frequency", "Frequency stated", 5, report["frequency"] != "unknown", "Does it happen every time or only sometimes?"),
             ("version", "Version or build", 5, bool(report["environment"]["version"]), "Which app version or build number?")]
    return {"score": sum(w for _, _, w, ok, _ in items if ok) / 100, "items": [{"key": k, "label": l, "w": w, "ok": ok, "hint": h} for k, l, w, ok, h in items]}


def repro_score(comp: float, grounding: float, conf: float) -> int:
    c = lambda x: max(0.0, min(1.0, x))
    return round(100 * c(0.55 * comp + 0.30 * grounding + 0.15 * conf))


# ---- duplicates ----
DUP_THRESHOLD = 0.5


def _vec(r: dict) -> Dict[str, int]:
    v: Dict[str, int] = {}
    for t in tokens(" ".join([r.get("title", ""), r.get("signature", ""), r.get("actual", "")])):
        v[t] = v.get(t, 0) + 1
    return v


def similarity(a: dict, b: dict) -> dict:
    sa, sb = _ws(a.get("signature")), _ws(b.get("signature"))
    if sa and sa == sb:
        return {"score": 1.0, "reason": "same error signature"}
    va, vb = _vec(a), _vec(b)
    dot = sum(v * vb.get(k, 0) for k, v in va.items())
    na, nb = math.sqrt(sum(v * v for v in va.values())), math.sqrt(sum(v * v for v in vb.values()))
    return {"score": dot / (na * nb) if na and nb else 0.0, "reason": "similar wording"}


def find_duplicates(item: dict, history: List[dict], limit: int = 3) -> List[dict]:
    out = []
    for h in history:
        s = similarity(item, h)
        if s["score"] >= DUP_THRESHOLD:
            out.append({"id": h["id"], "title": h["title"], **s})
    return sorted(out, key=lambda d: -d["score"])[:limit]


# ---- templates ----
def _env_rows(r):
    e = r["environment"]
    return [(n, e[k]) for n, k in (("App", "app"), ("Version", "version"), ("OS", "os"), ("Device", "device"), ("Browser", "browser"), ("Other", "other")) if e[k]]


def to_github(r: dict) -> str:
    o = f"## {r['title']}\n\n" + (r["summary"] + "\n\n" if r["summary"] else "") + f"**Severity:** {r['severity']}" + (f" - {r['severity_reason']}" if r["severity_reason"] else "") + f"  \n**Component:** {r['component'] or 'unknown'}  \n**Frequency:** {r['frequency']}\n\n"
    env = _env_rows(r)
    if env:
        o += "### Environment\n| Field | Value |\n| --- | --- |\n" + "\n".join(f"| {k} | {v.replace('|', chr(92) + '|')} |" for k, v in env) + "\n\n"
    if r["preconditions"]:
        o += "### Preconditions\n" + "\n".join("- " + p for p in r["preconditions"]) + "\n\n"
    o += "### Steps to reproduce\n" + ("\n".join(f"{i + 1}. {s['text']}" + (" _(assumed)_" if s["source"] == "assumed" else "") for i, s in enumerate(r["steps"])) if r["steps"] else "_No steps provided._") + "\n\n"
    o += f"### Expected result\n{r['expected'] or '_Not stated._'}\n\n### Actual result\n{r['actual'] or '_Not stated._'}\n\n"
    ev = r["evidence"]
    if ev["log_excerpts"] or ev["screenshot_observations"] or ev["user_quotes"]:
        o += "### Evidence\n"
        for l in ev["log_excerpts"]:
            o += (l["note"] + "\n" if l["note"] else "") + "```\n" + l["text"] + "\n```\n"
        o += "".join(f"- Screenshot: {s}\n" for s in ev["screenshot_observations"]) + "".join(f'- Reporter: "{s}"\n' for s in ev["user_quotes"]) + "\n"
    if r["suspected_cause"]:
        o += "### Suspected cause (unverified)\n" + r["suspected_cause"] + "\n\n"
    if r["workaround"]:
        o += "### Workaround\n" + r["workaround"] + "\n\n"
    if r["missing_info"]:
        o += "### Open questions\n" + "\n".join("- " + q["question"] for q in r["missing_info"]) + "\n\n"
    labels = ["bug", "severity:" + r["severity"]] + (["component:" + r["component"]] if r["component"] else []) + r["labels"]
    return re.sub(r"\n{3,}", "\n\n", o + "**Labels:** " + ", ".join(labels) + "\n")


def to_jira(r: dict) -> str:
    o = f"h2. {r['title']}\n\n" + (r["summary"] + "\n\n" if r["summary"] else "") + f"*Severity:* {r['severity']}" + (f" - {r['severity_reason']}" if r["severity_reason"] else "") + f"\n*Component:* {r['component'] or 'unknown'}\n*Frequency:* {r['frequency']}\n\n"
    env = _env_rows(r)
    if env:
        o += "h3. Environment\n" + "\n".join(f"|*{k}*|{v}|" for k, v in env) + "\n\n"
    o += "h3. Steps to reproduce\n" + ("\n".join("# " + s["text"] + (" _(assumed)_" if s["source"] == "assumed" else "") for s in r["steps"]) if r["steps"] else "_No steps provided._") + "\n\n"
    o += f"h3. Expected result\n{r['expected'] or '_Not stated._'}\n\nh3. Actual result\n{r['actual'] or '_Not stated._'}\n\n"
    for l in r["evidence"]["log_excerpts"]:
        o += "{code}\n" + l["text"] + "\n{code}\n"
    if r["suspected_cause"]:
        o += "\nh3. Suspected cause (unverified)\n" + r["suspected_cause"] + "\n"
    labels = ["bug", "severity-" + r["severity"]] + ([r["component"]] if r["component"] else []) + r["labels"]
    return o + "\n*Labels:* " + ", ".join(labels) + "\n"


def to_plain(r: dict) -> str:
    o = r["title"].upper() + "\n" + "=" * min(len(r["title"]), 60) + "\n\n" + (r["summary"] + "\n\n" if r["summary"] else "") + f"Severity: {r['severity']}" + (f" ({r['severity_reason']})" if r["severity_reason"] else "") + f"\nComponent: {r['component'] or 'unknown'}\nFrequency: {r['frequency']}\n"
    env = _env_rows(r)
    if env:
        o += "\nEnvironment\n" + "\n".join(f"  {k}: {v}" for k, v in env) + "\n"
    o += "\nSteps to reproduce\n" + ("\n".join(f"  {i + 1}. {s['text']}" + (" (assumed)" if s["source"] == "assumed" else "") for i, s in enumerate(r["steps"])) if r["steps"] else "  (none provided)") + "\n"
    o += f"\nExpected: {r['expected'] or 'not stated'}\nActual:   {r['actual'] or 'not stated'}\n"
    if r["evidence"]["log_excerpts"]:
        o += "\nLog excerpt\n" + "\n".join("\n".join("  | " + x for x in l["text"].split("\n")) for l in r["evidence"]["log_excerpts"]) + "\n"
    if r["missing_info"]:
        o += "\nQuestions for the reporter\n" + "\n".join("  - " + q["question"] for q in r["missing_info"]) + "\n"
    return o


def render(r: dict, style: str = "github") -> str:
    return {"jira": to_jira, "plain": to_plain}.get(style, to_github)(r) if style != "json" else json.dumps(r, indent=2)


CSV_HEAD = ["id", "created", "title", "severity", "component", "frequency", "repro_score", "signature", "steps", "expected", "actual"]


def to_csv(rows: List[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_HEAD)
    for h in rows:
        r = h["report"]
        w.writerow([h["id"], h["created"], r["title"], r["severity"], r["component"], r["frequency"], h["score"], h.get("signature", ""), " > ".join(s["text"] for s in r["steps"]), r["expected"], r["actual"]])
    return buf.getvalue().rstrip("\n")
