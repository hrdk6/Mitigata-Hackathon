"""The Blackboard — the shared knowledge base every agent reads and writes.

Backed by SQLite (a file, or in-memory for tests). All access is serialised by
a single lock so parallel agent threads can write safely. Tasks are deduplicated
by a `dedupe_key`, which is what stops the same host being scanned twice.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any

from nighttrace.models import Status, TaskStatus, now_iso

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL, port INTEGER, service TEXT, product TEXT,
    surface TEXT NOT NULL, data TEXT, created TEXT,
    UNIQUE(host, port, surface)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT, type TEXT, surface TEXT, ptes TEXT,
    status TEXT, severity TEXT, score REAL DEFAULT 0,
    description TEXT, fix TEXT,
    asset_host TEXT, asset_port INTEGER, check_id TEXT,
    data TEXT, created TEXT, updated TEXT,
    UNIQUE(check_id, asset_host, asset_port, title)
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER, kind TEXT, content TEXT, created TEXT
);
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT, ptes TEXT, target TEXT, check_id TEXT,
    dedupe_key TEXT UNIQUE, status TEXT, attempts INTEGER DEFAULT 0,
    data TEXT, created TEXT, updated TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent TEXT, action TEXT, ptes TEXT, level TEXT,
    message TEXT, data TEXT, created TEXT
);
CREATE TABLE IF NOT EXISTS attack_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src TEXT, dst TEXT, finding_id INTEGER, label TEXT, created TEXT,
    UNIQUE(src, dst, label)
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


def _dumps(obj: Any) -> str:
    return json.dumps(obj, default=str)


def _row(r: sqlite3.Row) -> dict:
    d = dict(r)
    if "data" in d and d["data"]:
        try:
            d["data"] = json.loads(d["data"])
        except (ValueError, TypeError):
            pass
    return d


class Blackboard:
    def __init__(self, path: str = ":memory:"):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._lock = threading.RLock()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- events (audit trail + live feed) -----------------------------------
    def add_event(self, agent: str, action: str, ptes: str, message: str,
                  level: str = "info", data: dict | None = None) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO events(agent,action,ptes,level,message,data,created) "
                "VALUES(?,?,?,?,?,?,?)",
                (agent, action, ptes, level, message, _dumps(data or {}), now_iso()),
            )
            self._conn.commit()
            return cur.lastrowid

    def list_events(self, since_id: int = 0, limit: int = 500) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
                (since_id, limit),
            ).fetchall()
            return [_row(r) for r in rows]

    # -- assets --------------------------------------------------------------
    def upsert_asset(self, host: str, port: int | None, service: str | None,
                     product: str | None, surface: str, data: dict | None = None) -> tuple[int, bool]:
        with self._lock:
            existing = self._conn.execute(
                "SELECT id FROM assets WHERE host=? AND port IS ? AND surface=?",
                (host, port, surface),
            ).fetchone()
            if existing:
                self._conn.execute(
                    "UPDATE assets SET service=COALESCE(?,service), product=COALESCE(?,product), data=? WHERE id=?",
                    (service, product, _dumps(data or {}), existing["id"]),
                )
                self._conn.commit()
                return existing["id"], False
            cur = self._conn.execute(
                "INSERT INTO assets(host,port,service,product,surface,data,created) VALUES(?,?,?,?,?,?,?)",
                (host, port, service, product, surface, _dumps(data or {}), now_iso()),
            )
            self._conn.commit()
            return cur.lastrowid, True

    def list_assets(self, surface: str | None = None) -> list[dict]:
        with self._lock:
            if surface:
                rows = self._conn.execute("SELECT * FROM assets WHERE surface=? ORDER BY id", (surface,)).fetchall()
            else:
                rows = self._conn.execute("SELECT * FROM assets ORDER BY id").fetchall()
            return [_row(r) for r in rows]

    # -- findings ------------------------------------------------------------
    def add_finding(self, *, title: str, type: str, surface: str, ptes: str,
                    severity: str, status: str = Status.SUSPECTED.value,
                    description: str = "", fix: str = "", asset_host: str | None = None,
                    asset_port: int | None = None, check_id: str | None = None,
                    data: dict | None = None) -> tuple[int, bool]:
        with self._lock:
            ts = now_iso()
            try:
                cur = self._conn.execute(
                    "INSERT INTO findings(title,type,surface,ptes,status,severity,description,fix,"
                    "asset_host,asset_port,check_id,data,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (title, type, surface, ptes, status, severity, description, fix,
                     asset_host, asset_port, check_id, _dumps(data or {}), ts, ts),
                )
                self._conn.commit()
                return cur.lastrowid, True
            except sqlite3.IntegrityError:
                row = self._conn.execute(
                    "SELECT id FROM findings WHERE check_id IS ? AND asset_host IS ? AND asset_port IS ? AND title=?",
                    (check_id, asset_host, asset_port, title),
                ).fetchone()
                return (row["id"] if row else -1), False

    def update_finding(self, finding_id: int, *, status: str | None = None,
                       score: float | None = None, data: dict | None = None) -> None:
        with self._lock:
            if status is not None:
                self._conn.execute("UPDATE findings SET status=?,updated=? WHERE id=?",
                                   (status, now_iso(), finding_id))
            if score is not None:
                self._conn.execute("UPDATE findings SET score=?,updated=? WHERE id=?",
                                   (score, now_iso(), finding_id))
            if data is not None:
                self._conn.execute("UPDATE findings SET data=?,updated=? WHERE id=?",
                                   (_dumps(data), now_iso(), finding_id))
            self._conn.commit()

    def get_finding(self, finding_id: int) -> dict | None:
        with self._lock:
            r = self._conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
            if not r:
                return None
            d = _row(r)
            d["evidence"] = [_row(e) for e in self._conn.execute(
                "SELECT * FROM evidence WHERE finding_id=? ORDER BY id", (finding_id,)).fetchall()]
            return d

    def list_findings(self, status: str | None = None, asset_host: str | None = None) -> list[dict]:
        with self._lock:
            q = "SELECT * FROM findings"
            conds, args = [], []
            if status:
                conds.append("status=?"); args.append(status)
            if asset_host:
                conds.append("asset_host=?"); args.append(asset_host)
            if conds:
                q += " WHERE " + " AND ".join(conds)
            q += " ORDER BY score DESC, id ASC"
            rows = self._conn.execute(q, args).fetchall()
            out = []
            for r in rows:
                d = _row(r)
                d["evidence"] = [_row(e) for e in self._conn.execute(
                    "SELECT * FROM evidence WHERE finding_id=? ORDER BY id", (d["id"],)).fetchall()]
                out.append(d)
            return out

    def add_evidence(self, finding_id: int, kind: str, content: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO evidence(finding_id,kind,content,created) VALUES(?,?,?,?)",
                (finding_id, kind, content[:8000], now_iso()),
            )
            self._conn.commit()
            return cur.lastrowid

    # -- tasks (with dedupe) -------------------------------------------------
    def enqueue_task(self, *, type: str, ptes: str, target: dict, dedupe_key: str,
                     check_id: str | None = None, data: dict | None = None) -> tuple[int, bool]:
        with self._lock:
            ts = now_iso()
            try:
                cur = self._conn.execute(
                    "INSERT INTO tasks(type,ptes,target,check_id,dedupe_key,status,attempts,data,created,updated) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (type, ptes, _dumps(target), check_id, dedupe_key,
                     TaskStatus.PENDING.value, 0, _dumps(data or {}), ts, ts),
                )
                self._conn.commit()
                return cur.lastrowid, True
            except sqlite3.IntegrityError:
                return -1, False  # duplicate work, already queued/done

    def claim_pending(self, limit: int) -> list[dict]:
        """Atomically take up to `limit` pending tasks and mark them RUNNING."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM tasks WHERE status=? ORDER BY id ASC LIMIT ?",
                (TaskStatus.PENDING.value, limit),
            ).fetchall()
            claimed = []
            for r in rows:
                self._conn.execute("UPDATE tasks SET status=?,updated=? WHERE id=?",
                                   (TaskStatus.RUNNING.value, now_iso(), r["id"]))
                d = _row(r)
                d["target"] = json.loads(r["target"]) if r["target"] else {}
                claimed.append(d)
            self._conn.commit()
            return claimed

    def finish_task(self, task_id: int, status: str, attempts: int | None = None) -> None:
        with self._lock:
            if attempts is None:
                self._conn.execute("UPDATE tasks SET status=?,updated=? WHERE id=?",
                                   (status, now_iso(), task_id))
            else:
                self._conn.execute("UPDATE tasks SET status=?,attempts=?,updated=? WHERE id=?",
                                   (status, attempts, now_iso(), task_id))
            self._conn.commit()

    def requeue_task(self, task_id: int) -> None:
        with self._lock:
            self._conn.execute("UPDATE tasks SET status=?,updated=? WHERE id=?",
                               (TaskStatus.PENDING.value, now_iso(), task_id))
            self._conn.commit()

    def pending_count(self) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) c FROM tasks WHERE status IN (?,?)",
                (TaskStatus.PENDING.value, TaskStatus.RUNNING.value),
            ).fetchone()["c"]

    # -- attack graph --------------------------------------------------------
    def add_attack_edge(self, src: str, dst: str, label: str, finding_id: int | None = None) -> None:
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO attack_edges(src,dst,finding_id,label,created) VALUES(?,?,?,?,?)",
                    (src, dst, finding_id, label, now_iso()),
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                pass

    def list_attack_edges(self) -> list[dict]:
        with self._lock:
            return [_row(r) for r in self._conn.execute(
                "SELECT * FROM attack_edges ORDER BY id").fetchall()]

    # -- meta ----------------------------------------------------------------
    def set_meta(self, key: str, value: Any) -> None:
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", (key, _dumps(value)))
            self._conn.commit()

    def get_meta(self, key: str, default: Any = None) -> Any:
        with self._lock:
            r = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            if not r:
                return default
            try:
                return json.loads(r["value"])
            except (ValueError, TypeError):
                return r["value"]

    def stats(self) -> dict:
        with self._lock:
            def c(q, a=()):
                return self._conn.execute(q, a).fetchone()["c"]
            return {
                "assets": c("SELECT COUNT(*) c FROM assets"),
                "findings": c("SELECT COUNT(*) c FROM findings"),
                "confirmed": c("SELECT COUNT(*) c FROM findings WHERE status=?", (Status.CONFIRMED.value,)),
                "suspected": c("SELECT COUNT(*) c FROM findings WHERE status=?", (Status.SUSPECTED.value,)),
                "refuted": c("SELECT COUNT(*) c FROM findings WHERE status=?", (Status.REFUTED.value,)),
                "tasks": c("SELECT COUNT(*) c FROM tasks"),
                "events": c("SELECT COUNT(*) c FROM events"),
                "edges": c("SELECT COUNT(*) c FROM attack_edges"),
            }
