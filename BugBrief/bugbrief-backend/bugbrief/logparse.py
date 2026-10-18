"""Find the error that matters in a pile of logs: stack traces, crashes, HTTP failures, environment hints."""
from __future__ import annotations

import re
from typing import Dict, List, Optional

_LEVEL = re.compile(r"\b(FATAL|CRITICAL|ERROR|WARN(?:ING)?|INFO|DEBUG|TRACE)\b")
_RANK = {"crash": 4, "exception": 3, "http": 2, "network": 2, "log": 1}
_JAVA_EX = re.compile(r"^\s*((?:[a-z_]\w*\.)+[A-Z]\w*(?:Exception|Error))(?::\s*(.*))?$")
_JAVA_FRAME = re.compile(r"^\s*at\s+([\w.$<>]+)\(([\w.]+):(\d+)\)")
_JS_FRAME = re.compile(r"^\s*at\s+(?:([^\s(]+)\s+\()?([^)\s]+?):(\d+):(\d+)\)?")
_TS = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")


def base_name(p: str) -> str:
    p = re.split(r"[?#]", str(p or ""))[0]
    return re.split(r"[/\\]", p)[-1]


def normalize_msg(m: str) -> str:
    m = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<uuid>", str(m or ""), flags=re.I)
    m = re.sub(r"\b0x[0-9a-f]{6,}\b", "<hex>", m, flags=re.I)
    m = re.sub(r"\b\d{4,}\b", "<n>", m)
    return re.sub(r"\s+", " ", m).strip()[:200]


def env_hints(t: str) -> Dict[str, str]:
    e: Dict[str, str] = {}
    if m := re.search(r"Edg/(\d+)", t):
        e["browser"] = "Edge " + m.group(1)
    elif m := re.search(r"Chrome/(\d+)", t):
        e["browser"] = "Chrome " + m.group(1)
    elif m := re.search(r"Firefox/(\d+)", t):
        e["browser"] = "Firefox " + m.group(1)
    elif m := re.search(r"Version/(\d+(?:\.\d+)*).*Safari/", t):
        e["browser"] = "Safari " + m.group(1)
    if m := re.search(r"Windows NT (\d+\.\d+)", t):
        e["os"] = "Windows " + ("10/11" if m.group(1) == "10.0" else m.group(1))
    elif m := re.search(r"Android (\d+(?:\.\d+)?)", t):
        e["os"] = "Android " + m.group(1)
    elif m := re.search(r"(?:iOS|iPhone OS|CPU OS)[: _]+(\d+[._]\d+(?:[._]\d+)?)", t):
        e["os"] = "iOS " + m.group(1).replace("_", ".")
    elif m := re.search(r"Mac OS X (\d+[._]\d+)", t):
        e["os"] = "macOS " + m.group(1).replace("_", ".")
    elif re.search(r"\bLinux\b", t):
        e["os"] = "Linux"
    if m := re.search(r"Node(?:\.js)?\s+v?(\d+\.\d+\.\d+)", t):
        e["node"] = m.group(1)
    if m := re.search(r"Python\s+(\d+\.\d+(?:\.\d+)?)", t):
        e["python"] = m.group(1)
    if m := re.search(r"\b(iPhone\d+,\d+|Pixel \d+(?: Pro)?|SM-[A-Z]\d+\w*)", t):
        e["device"] = m.group(1)
    if m := re.search(r"Process:\s*([\w.]+)", t):
        e["package"] = m.group(1)
    if m := re.search(r"\b(?:app\s*)?(?:version|build)\s*[:=]?\s*v?(\d+\.\d+(?:\.\d+)*)", t, re.I):
        e["version"] = m.group(1)
    return e


def _frames(lines: List[str], start: int, rx: re.Pattern) -> List[re.Match]:
    out: List[re.Match] = []
    for j in range(start, len(lines)):
        if len(out) >= 8:
            break
        f = rx.match(lines[j])
        if f:
            out.append(f)
        elif out or (lines[j].strip() and not re.match(r"\s", lines[j])):
            break
    return out


def parse_logs(text: str) -> dict:
    lines = str(text or "").split("\n")
    errors: List[dict] = []
    levels: Dict[str, int] = {}
    for ln in lines:
        if m := _LEVEL.search(ln):
            k = m.group(1).replace("WARNING", "WARN")
            levels[k] = levels.get(k, 0) + 1
    i = 0
    while i < len(lines):
        ln = re.sub(r"^[A-Z]/[\w.]+:\s*", "", lines[i])
        if ln.startswith("Traceback (most recent call last):"):
            fr, j = [], i + 1
            while j < len(lines) and re.match(r"\s", lines[j]):
                if pf := re.search(r'File "([^"]+)", line (\d+), in (\S+)', lines[j]):
                    fr.append({"file": pf.group(1), "line": int(pf.group(2)), "fn": pf.group(3)})
                j += 1
            ex = re.match(r"^([\w.]+(?:Error|Exception|Exit|Interrupt)):\s*(.*)$", lines[j]) if j < len(lines) else None
            if ex:
                errors.append({"kind": "exception", "lang": "python", "type": ex.group(1), "message": ex.group(2), "frames": fr[::-1], "line": i + 1})
                i = j
            i += 1
            continue
        if m := re.search(r"Terminating app due to uncaught exception '(\w+)', reason: '(.*)'", ln):
            errors.append({"kind": "crash", "lang": "ios", "type": m.group(1), "message": m.group(2), "frames": [], "line": i + 1})
            i += 1
            continue
        if "FATAL EXCEPTION" in ln:
            for q in range(i + 1, min(i + 5, len(lines))):
                jn = _JAVA_EX.match(lines[q])
                if jn:
                    jf = _frames(lines, q + 1, _JAVA_FRAME)
                    errors.append({"kind": "crash", "lang": "java", "type": jn.group(1), "message": jn.group(2) or "",
                                   "frames": [{"fn": f.group(1), "file": f.group(2), "line": int(f.group(3))} for f in jf], "line": q + 1})
                    i = q
                    break
            i += 1
            continue
        if m := re.match(r"^(?:Exception in thread \"[^\"]*\"\s+|Caused by:\s*)?((?:[a-z_]\w*\.)+[A-Z]\w*(?:Exception|Error))(?::\s*(.*))?$", ln.strip()):
            jf = _frames(lines, i + 1, _JAVA_FRAME)
            errors.append({"kind": "exception", "lang": "java", "type": m.group(1), "message": m.group(2) or "",
                           "frames": [{"fn": f.group(1), "file": f.group(2), "line": int(f.group(3))} for f in jf], "line": i + 1})
            i += 1
            continue
        m = re.search(r"\b((?:[A-Z][A-Za-z]*)?(?:Error|Exception)):\s*(.*)$", ln)
        if m and not re.match(r"\s*at\s", ln):
            jf = _frames(lines, i + 1, _JS_FRAME)
            errors.append({"kind": "exception", "lang": "js", "type": m.group(1), "message": re.sub(r"\s+at\s.*$", "", m.group(2)),
                           "frames": [{"fn": f.group(1) or "(anonymous)", "file": f.group(2), "line": int(f.group(3))} for f in jf], "line": i + 1})
            i += 1
            continue
        m = re.search(r'"(GET|POST|PUT|PATCH|DELETE)\s+(\S+)\s+HTTP/[\d.]+"\s+(\d{3})', ln)
        if m and int(m.group(3)) >= 400:
            errors.append({"kind": "http", "lang": "http", "type": "HTTP " + m.group(3), "message": m.group(1) + " " + m.group(2), "frames": [], "line": i + 1, "status": int(m.group(3))})
        elif m := re.search(r"net::(ERR_[A-Z_]+)", ln):
            errors.append({"kind": "network", "lang": "browser", "type": m.group(1), "message": ln.strip()[:160], "frames": [], "line": i + 1})
        elif (m := re.search(r"responded with a status of (\d{3})", ln)) and int(m.group(1)) >= 400:
            errors.append({"kind": "http", "lang": "browser", "type": "HTTP " + m.group(1), "message": ln.strip()[:160], "frames": [], "line": i + 1, "status": int(m.group(1))})
        elif re.search(r"\b(FATAL|CRITICAL|ERROR)\b", ln):
            errors.append({"kind": "log", "lang": "generic", "type": "ERROR", "message": re.sub(r"^.*?\b(?:FATAL|CRITICAL|ERROR)\b[:\s-]*", "", ln).strip()[:200], "frames": [], "line": i + 1})
        i += 1
    primary: Optional[dict] = None
    best = -1.0
    for e in errors:
        e["key"] = e["type"] + ": " + normalize_msg(e["message"])
        r = _RANK[e["kind"]] + (0.5 if e.get("status", 0) >= 500 else 0)
        if r > best:
            primary, best = e, r
    signature = None
    if primary:
        f0 = primary["frames"][0] if primary["frames"] else None
        signature = primary["type"] + ": " + normalize_msg(primary["message"]) + (f" @ {base_name(f0['file'])}:{f0['fn']}" if f0 else "")
    rep: Dict[str, dict] = {}
    for l in lines:
        if not l.strip():
            continue
        k = re.sub(r"\d+", "#", re.sub(r"\[[^\]]*\]", "", re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "", re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?Z?", "", l)))).strip()
        if len(k) > 6:
            rep.setdefault(k, {"text": l.strip()[:140], "count": 0})["count"] += 1
    repeated = sorted([r for r in rep.values() if r["count"] >= 3], key=lambda r: -r["count"])[:5]
    status: List[int] = []
    for e in errors:
        if e.get("status") and e["status"] not in status:
            status.append(e["status"])
    ts = _TS.findall(str(text or ""))
    return {"line_count": len(lines), "levels": levels, "errors": errors, "error_count": len(errors), "primary": primary, "signature": signature,
            "status_codes": status, "kind": primary["kind"] if primary else None, "repeated": repeated, "time_first": ts[0] if ts else None,
            "time_last": ts[-1] if ts else None, "env": env_hints(str(text or ""))}


def trim_logs(text: str, max_chars: int = 12000) -> str:
    text = str(text or "")
    if len(text) <= max_chars:
        return text
    lines = text.split("\n")
    keep = set()
    for e in parse_logs(text)["errors"][:12]:
        keep.update(range(max(0, e["line"] - 4), min(len(lines), e["line"] + 8)))
    for h in range(15):
        keep.add(h)
        keep.add(len(lines) - 1 - h)
    out, last = [], -2
    for k in sorted(x for x in keep if 0 <= x < len(lines)):
        if k != last + 1:
            out.append("... [lines skipped] ...")
        out.append(lines[k])
        last = k
    joined = "\n".join(out)
    return joined[:max_chars] + "\n... [truncated]" if len(joined) > max_chars else joined
