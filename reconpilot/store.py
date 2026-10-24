"""Evidence store and entity graph. One SQLite file per engagement keeps client data isolated."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .scope import Scope

SCHEMA = """
CREATE TABLE IF NOT EXISTS project (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY, module TEXT NOT NULL, query TEXT NOT NULL,
    fetched_at TEXT NOT NULL, raw TEXT NOT NULL, sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY, type TEXT NOT NULL, value TEXT NOT NULL,
    in_scope INTEGER NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    UNIQUE(type, value));
CREATE TABLE IF NOT EXISTS entity_evidence (
    entity_id INTEGER NOT NULL, evidence_id INTEGER NOT NULL,
    PRIMARY KEY (entity_id, evidence_id));
CREATE TABLE IF NOT EXISTS relationships (
    id INTEGER PRIMARY KEY, src_id INTEGER NOT NULL, dst_id INTEGER NOT NULL,
    type TEXT NOT NULL, evidence_id INTEGER NOT NULL, UNIQUE(src_id, dst_id, type));
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY, module TEXT NOT NULL, target TEXT NOT NULL, tier TEXT NOT NULL,
    requested_by TEXT NOT NULL, reason TEXT, status TEXT NOT NULL, approved_by TEXT,
    created_at TEXT NOT NULL, finished_at TEXT, error TEXT);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL, description TEXT,
    evidence_ids TEXT NOT NULL, status TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
    target TEXT, detail TEXT);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
"""

SEVERITIES = ("info", "low", "medium", "high", "critical")
_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_ref(ref: str | int, prefix: str) -> int:
    """Accept 'E12', 'e12' or 12 and return 12."""
    text = str(ref).strip().upper()
    if text.startswith(prefix):
        text = text[len(prefix):]
    if not text.isdigit():
        raise ValueError(f"invalid {prefix} reference: {ref!r}")
    return int(text)


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    # ---------- project ----------
    @classmethod
    def create_project(cls, data_dir: str | Path, name: str, *, client: str, auth_ref: str,
                       scope: Scope, allow_cloud: bool = False, allow_low_touch: bool = True) -> "Store":
        if not _NAME_RE.match(name):
            raise ValueError("project name may only contain letters, digits, '-' and '_'")
        if not auth_ref.strip():
            raise ValueError("an authorization reference (SoW, RoE or bug bounty URL) is required")
        if not scope.domains and not scope.networks:
            raise ValueError("scope needs at least one domain or network")
        path = Path(data_dir) / f"{name}.db"
        if path.exists():
            raise FileExistsError(f"project {name!r} already exists at {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        store = cls(path)
        meta = {"name": name, "client": client, "auth_ref": auth_ref, "allow_cloud": allow_cloud,
                "allow_low_touch": allow_low_touch, "created_at": now(), "scope": scope.to_dict()}
        for key, value in meta.items():
            store.db.execute("INSERT INTO project VALUES (?, ?)", (key, json.dumps(value)))
        store.db.commit()
        store.audit("user", "project.create", name, json.dumps(meta))
        return store

    @classmethod
    def open_project(cls, data_dir: str | Path, name: str) -> "Store":
        path = Path(data_dir) / f"{name}.db"
        if not path.exists():
            raise FileNotFoundError(f"no project named {name!r} in {data_dir}")
        return cls(path)

    @staticmethod
    def list_projects(data_dir: str | Path) -> list[str]:
        return sorted(p.stem for p in Path(data_dir).glob("*.db"))

    def meta(self) -> dict[str, Any]:
        return {r["key"]: json.loads(r["value"]) for r in self.db.execute("SELECT * FROM project")}

    def set_meta(self, key: str, value: Any) -> None:
        self.db.execute("INSERT OR REPLACE INTO project VALUES (?, ?)", (key, json.dumps(value)))
        self.db.commit()
        self.audit("user", "project.update", key, json.dumps(value))

    @property
    def scope(self) -> Scope:
        return Scope.from_dict(self.meta()["scope"])

    # ---------- audit ----------
    def audit(self, actor: str, action: str, target: str | None = None, detail: str | None = None) -> None:
        self.db.execute("INSERT INTO audit_log (ts, actor, action, target, detail) VALUES (?,?,?,?,?)",
                        (now(), actor, action, target, detail))
        self.db.commit()

    def audit_entries(self, limit: int = 100) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)))

    # ---------- evidence ----------
    def add_evidence(self, module: str, query: str, raw: Any) -> int:
        text = raw if isinstance(raw, str) else json.dumps(raw, sort_keys=True, default=str)
        digest = hashlib.sha256(text.encode()).hexdigest()
        cur = self.db.execute(
            "INSERT INTO evidence (module, query, fetched_at, raw, sha256) VALUES (?,?,?,?,?)",
            (module, query, now(), text, digest))
        self.db.commit()
        return cur.lastrowid

    def get_evidence(self, evidence_id: int) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()

    def evidence_exists(self, ids: Iterable[int]) -> bool:
        ids = list(ids)
        if not ids:
            return False
        marks = ",".join("?" * len(ids))
        count = self.db.execute(f"SELECT COUNT(*) FROM evidence WHERE id IN ({marks})", ids).fetchone()[0]
        return count == len(set(ids))

    # ---------- entities ----------
    def upsert_entity(self, etype: str, value: str, evidence_id: int) -> int:
        value = value.strip().lower() if etype not in ("url", "technology", "txt") else value.strip()
        in_scope = int(etype in ("technology", "registrar", "txt") or self.scope.contains(value))
        ts = now()
        row = self.db.execute("SELECT id FROM entities WHERE type = ? AND value = ?", (etype, value)).fetchone()
        if row:
            entity_id = row["id"]
            self.db.execute("UPDATE entities SET last_seen = ? WHERE id = ?", (ts, entity_id))
        else:
            entity_id = self.db.execute(
                "INSERT INTO entities (type, value, in_scope, first_seen, last_seen) VALUES (?,?,?,?,?)",
                (etype, value, in_scope, ts, ts)).lastrowid
        self.db.execute("INSERT OR IGNORE INTO entity_evidence VALUES (?, ?)", (entity_id, evidence_id))
        self.db.commit()
        return entity_id

    def add_relationship(self, src_id: int, dst_id: int, rtype: str, evidence_id: int) -> None:
        self.db.execute("INSERT OR IGNORE INTO relationships (src_id, dst_id, type, evidence_id) VALUES (?,?,?,?)",
                        (src_id, dst_id, rtype, evidence_id))
        self.db.commit()

    def get_entity(self, entity_id: int) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()

    def find_entity(self, etype: str, value: str) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM entities WHERE type = ? AND value = ?",
                               (etype, value.strip().lower())).fetchone()

    def entities(self, etype: str | None = None, in_scope: bool | None = None,
                 query: str | None = None, limit: int = 1000) -> list[sqlite3.Row]:
        sql, args = "SELECT * FROM entities WHERE 1=1", []
        if etype:
            sql += " AND type = ?"
            args.append(etype)
        if in_scope is not None:
            sql += " AND in_scope = ?"
            args.append(int(in_scope))
        if query:
            sql += " AND value LIKE ?"
            args.append(f"%{query}%")
        sql += " ORDER BY type, value LIMIT ?"
        args.append(limit)
        return list(self.db.execute(sql, args))

    def entity_evidence_ids(self, entity_id: int) -> list[int]:
        return [r[0] for r in self.db.execute(
            "SELECT evidence_id FROM entity_evidence WHERE entity_id = ? ORDER BY evidence_id", (entity_id,))]

    def neighbors(self, entity_id: int) -> list[dict]:
        rows = self.db.execute(
            """SELECT r.type AS rel, r.evidence_id, 'out' AS dir, e.* FROM relationships r
                   JOIN entities e ON e.id = r.dst_id WHERE r.src_id = ?
               UNION ALL
               SELECT r.type AS rel, r.evidence_id, 'in' AS dir, e.* FROM relationships r
                   JOIN entities e ON e.id = r.src_id WHERE r.dst_id = ?""",
            (entity_id, entity_id))
        return [dict(r) for r in rows]

    def stats(self) -> dict[str, Any]:
        by_type = {r["type"]: r["n"] for r in self.db.execute(
            "SELECT type, COUNT(*) AS n FROM entities WHERE in_scope = 1 GROUP BY type")}
        out_of_scope = self.db.execute("SELECT COUNT(*) FROM entities WHERE in_scope = 0").fetchone()[0]
        evidence = self.db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
        return {"in_scope_entities": by_type, "out_of_scope_entities": out_of_scope, "evidence_records": evidence}

    # ---------- jobs ----------
    def create_job(self, module: str, target: str, tier: str, requested_by: str,
                   reason: str | None, status: str) -> int:
        cur = self.db.execute(
            "INSERT INTO jobs (module, target, tier, requested_by, reason, status, created_at) VALUES (?,?,?,?,?,?,?)",
            (module, target, tier, requested_by, reason, status, now()))
        self.db.commit()
        return cur.lastrowid

    def update_job(self, job_id: int, **fields: Any) -> None:
        if fields.get("status") in ("done", "failed", "denied"):
            fields.setdefault("finished_at", now())
        cols = ", ".join(f"{k} = ?" for k in fields)
        self.db.execute(f"UPDATE jobs SET {cols} WHERE id = ?", (*fields.values(), job_id))
        self.db.commit()

    def get_job(self, job_id: int) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()

    def jobs(self, status: str | None = None) -> list[sqlite3.Row]:
        if status:
            return list(self.db.execute("SELECT * FROM jobs WHERE status = ? ORDER BY id", (status,)))
        return list(self.db.execute("SELECT * FROM jobs ORDER BY id"))

    def last_successful_job(self, module: str, target: str) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM jobs WHERE module = ? AND target = ? AND status = 'done' ORDER BY id DESC LIMIT 1",
            (module, target)).fetchone()

    # ---------- findings ----------
    def create_finding(self, title: str, severity: str, description: str,
                       evidence_ids: list[int], created_by: str) -> int:
        severity = severity.lower()
        if severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")
        if not self.evidence_exists(evidence_ids):
            raise ValueError("every finding must cite existing evidence IDs")
        cur = self.db.execute(
            "INSERT INTO findings (title, severity, description, evidence_ids, status, created_by, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (title, severity, description, json.dumps(sorted(set(evidence_ids))), "draft", created_by, now()))
        self.db.commit()
        self.audit(created_by, "finding.create", f"F{cur.lastrowid}", title)
        return cur.lastrowid

    def set_finding_status(self, finding_id: int, status: str, actor: str = "user") -> None:
        if status not in ("draft", "validated", "rejected"):
            raise ValueError("status must be draft, validated or rejected")
        self.db.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
        self.db.commit()
        self.audit(actor, f"finding.{status}", f"F{finding_id}")

    def findings(self, status: str | None = None) -> list[sqlite3.Row]:
        order = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 " \
                "WHEN 'low' THEN 3 ELSE 4 END, id"
        if status:
            return list(self.db.execute(f"SELECT * FROM findings WHERE status = ? ORDER BY {order}", (status,)))
        return list(self.db.execute(f"SELECT * FROM findings ORDER BY {order}"))

    def close(self) -> None:
        self.db.close()
