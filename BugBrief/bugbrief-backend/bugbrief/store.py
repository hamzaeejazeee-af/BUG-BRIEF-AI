"""SQLite history of generated reports, with dashboard statistics and exports."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from . import report as rp

SCHEMA = """CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, created REAL, title TEXT, severity TEXT, component TEXT, score INTEGER,
signature TEXT, redactions INTEGER, data TEXT)"""


class Store:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute(SCHEMA)

    def add(self, result: dict, rid: Optional[str] = None) -> str:
        rid = rid or uuid.uuid4().hex[:12]
        r = result["report"]
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO reports VALUES (?,?,?,?,?,?,?,?,?)", (rid, time.time(), r["title"], r["severity"], r["component"], result["score"],
                            result["signature"], result["redactions"]["total"], json.dumps(result)))
        return rid

    def get(self, rid: str) -> dict:
        row = self.db.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
        if not row:
            raise KeyError(rid)
        return {"id": row["id"], "created": row["created"], **json.loads(row["data"])}

    def delete(self, rid: str) -> None:
        with self.db:
            self.db.execute("DELETE FROM reports WHERE id=?", (rid,))

    def list(self, q: str = "", severity: str = "", limit: int = 100) -> List[dict]:
        sql, args = "SELECT id, created, title, severity, component, score, signature FROM reports WHERE 1=1", []
        if severity:
            sql += " AND severity=?"; args.append(severity)
        if q:
            sql += " AND (title LIKE ? OR component LIKE ? OR signature LIKE ?)"; args += [f"%{q}%"] * 3
        return [dict(r) for r in self.db.execute(sql + " ORDER BY created DESC LIMIT ?", args + [max(1, min(limit, 500))])]

    def history_for_dupes(self, limit: int = 200) -> List[dict]:
        out = []
        for r in self.db.execute("SELECT id, title, signature, data FROM reports ORDER BY created DESC LIMIT ?", (limit,)):
            out.append({"id": r["id"], "title": r["title"], "signature": r["signature"], "actual": json.loads(r["data"])["report"]["actual"]})
        return out

    def stats(self) -> dict:
        rows = self.db.execute("SELECT severity, component, score, signature, redactions FROM reports").fetchall()
        sev = {s: 0 for s in reversed(rp.SEV)}
        comp, sigs = {}, {}
        for r in rows:
            sev[r["severity"]] += 1
            if r["component"]:
                comp[r["component"]] = comp.get(r["component"], 0) + 1
            if r["signature"]:
                sigs[r["signature"]] = sigs.get(r["signature"], 0) + 1
        n = len(rows)
        return {"reports": n, "avg_score": round(sum(r["score"] for r in rows) / n, 1) if n else 0, "by_severity": sev, "secrets_hidden": sum(r["redactions"] for r in rows),
                "top_components": sorted(comp.items(), key=lambda x: -x[1])[:5], "recurring_errors": [(k, v) for k, v in sorted(sigs.items(), key=lambda x: -x[1]) if v > 1][:5]}

    def export_csv(self) -> str:
        rows = []
        for r in self.list(limit=500):
            full = self.get(r["id"])
            rows.append({"id": r["id"], "created": datetime.fromtimestamp(r["created"], timezone.utc).isoformat(), "report": full["report"], "score": full["score"], "signature": full["signature"]})
        return rp.to_csv(rows)
