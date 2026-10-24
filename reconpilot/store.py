"""Evidence store and entity graph. One SQLite file per engagement keeps client data isolated."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .scope import DERIVED_TYPES, Scope, normalize_phone

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

# Each entry upgrades the schema by one version (PRAGMA user_version). Never edit a shipped entry: append.
MIGRATIONS: list[str] = [
    # 1: indexes for evidence dedupe and graph lookups
    """CREATE INDEX IF NOT EXISTS idx_evidence_dedupe ON evidence (sha256, module, query);
       CREATE INDEX IF NOT EXISTS idx_entity_evidence_ev ON entity_evidence (evidence_id);
       CREATE INDEX IF NOT EXISTS idx_relationships_dst ON relationships (dst_id);
       CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs (status);""",
]
SCHEMA_VERSION = len(MIGRATIONS)

SEVERITIES = ("info", "low", "medium", "high", "critical")
TIERS = ("passive", "low_touch", "active", "unknown")
HOST_TYPES = ("domain", "subdomain", "ip", "url")
IDENTITY_TYPES = ("person", "username", "account", "email", "phone", "organization", "breach")
ENTITY_TYPES = HOST_TYPES + ("technology",) + IDENTITY_TYPES
# Values compared case-insensitively. Usernames keep their case: some sites treat them as distinct.
_LOWERCASE_TYPES = ("domain", "subdomain", "ip", "email")
_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def parse_ref(ref: str | int, prefix: str) -> int:
    """Accept 'E12', 'e12' or 12 and return 12."""
    text = str(ref).strip().upper()
    if text.startswith(prefix):
        text = text[len(prefix):]
    if not text.isdigit():
        raise ValueError(f"invalid {prefix} reference: {ref!r}")
    return int(text)


def normalize_value(etype: str, value: str) -> str:
    value = value.strip()
    if etype in _LOWERCASE_TYPES:
        return value.lower().rstrip(".")
    if etype == "phone":
        return normalize_phone(value)
    return value


def _rowid(cur: sqlite3.Cursor) -> int:
    assert cur.lastrowid is not None
    return cur.lastrowid


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        # Autocommit mode: single writes commit at once; bulk work runs inside transaction().
        self.db = sqlite3.connect(self.path, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self._migrate()
        self._scope: Scope | None = None
        self._tx_depth = 0

    def _migrate(self) -> None:
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        for number, script in enumerate(MIGRATIONS[version:], start=version + 1):
            self.db.executescript(script)
            self.db.execute(f"PRAGMA user_version = {number}")

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Group many writes into one commit (much faster for imports). Nests safely."""
        if self._tx_depth:
            self._tx_depth += 1
            try:
                yield
            finally:
                self._tx_depth -= 1
            return
        self.db.execute("BEGIN")
        self._tx_depth = 1
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        else:
            self.db.execute("COMMIT")
        finally:
            self._tx_depth = 0

    @contextmanager
    def savepoint(self) -> Iterator[None]:
        """Undo everything written inside the block if it raises."""
        self.db.execute("SAVEPOINT rp_sp")
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK TO rp_sp")
            self.db.execute("RELEASE rp_sp")
            raise
        self.db.execute("RELEASE rp_sp")

    # ---------- project ----------
    @classmethod
    def create_project(cls, data_dir: str | Path, name: str, *, client: str, auth_ref: str,
                       scope: Scope, allow_cloud: bool = False, allow_low_touch: bool = True,
                       allow_active: bool = False) -> "Store":
        if not _NAME_RE.match(name):
            raise ValueError("project name may only contain letters, digits, '-' and '_'")
        if not auth_ref.strip():
            raise ValueError("an authorization reference (SoW, RoE or bug bounty URL) is required")
        if scope.is_empty:
            raise ValueError("scope needs at least one domain, network or subject")
        path = Path(data_dir) / f"{name}.db"
        if path.exists():
            raise FileExistsError(f"project {name!r} already exists at {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        store = cls(path)
        meta = {"name": name, "client": client, "auth_ref": auth_ref, "allow_cloud": allow_cloud,
                "allow_low_touch": allow_low_touch, "allow_active": allow_active,
                "created_at": now(), "scope": scope.to_dict()}
        with store.transaction():
            for key, value in meta.items():
                store.db.execute("INSERT INTO project VALUES (?, ?)", (key, json.dumps(value)))
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

    @property
    def runs_dir(self) -> Path:
        return self.path.parent / "runs" / self.path.stem

    def meta(self) -> dict[str, Any]:
        return {r["key"]: json.loads(r["value"]) for r in self.db.execute("SELECT * FROM project")}

    def set_meta(self, key: str, value: Any) -> None:
        self.db.execute("INSERT OR REPLACE INTO project VALUES (?, ?)", (key, json.dumps(value)))
        if key == "scope":
            self._scope = None
        self.audit("user", "project.update", key, json.dumps(value))

    @property
    def scope(self) -> Scope:
        if self._scope is None:
            self._scope = Scope.from_dict(self.meta()["scope"])
        return self._scope

    def save_scope(self, scope: Scope) -> int:
        """Persist a changed scope and re-flag every entity. Returns how many flags changed."""
        if scope.is_empty:
            raise ValueError("scope needs at least one domain, network or subject")
        with self.transaction():
            self.set_meta("scope", scope.to_dict())
            return self.rescope()

    def rescope(self) -> int:
        """Recompute in_scope for every entity from the current scope."""
        scope, changed = self.scope, 0
        with self.transaction():
            rows = list(self.db.execute("SELECT id, type, value, in_scope FROM entities"))
            for r in rows:
                decision = scope.contains_entity(r["type"], r["value"])
                if decision is None:
                    continue
                if int(decision) != r["in_scope"]:
                    self.db.execute("UPDATE entities SET in_scope = ? WHERE id = ?", (int(decision), r["id"]))
                    changed += 1
            # Derived entities (accounts) follow the entity they were found from.
            for r in self.db.execute(f"SELECT id, in_scope FROM entities WHERE type IN "
                                     f"({','.join('?' * len(DERIVED_TYPES))})", DERIVED_TYPES).fetchall():
                parent_in = self.db.execute(
                    "SELECT MAX(e.in_scope) FROM relationships rel JOIN entities e ON e.id = rel.src_id "
                    "WHERE rel.dst_id = ?", (r["id"],)).fetchone()[0]
                flag = int(bool(parent_in))
                if flag != r["in_scope"]:
                    self.db.execute("UPDATE entities SET in_scope = ? WHERE id = ?", (flag, r["id"]))
                    changed += 1
        if changed:
            self.audit("user", "scope.rescope", None, f"{changed} entities re-flagged")
        return changed

    # ---------- audit ----------
    def audit(self, actor: str, action: str, target: str | None = None, detail: str | None = None) -> None:
        self.db.execute("INSERT INTO audit_log (ts, actor, action, target, detail) VALUES (?,?,?,?,?)",
                        (now(), actor, action, target, detail))

    def audit_entries(self, limit: int = 100) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)))

    # ---------- evidence ----------
    def insert_evidence(self, module: str, query: str, raw: Any) -> tuple[int, bool]:
        """Store a raw record. Returns (evidence id, created); an identical record is reused, not duplicated."""
        text = raw if isinstance(raw, str) else json.dumps(raw, sort_keys=True, default=str)
        digest = hashlib.sha256(text.encode()).hexdigest()
        row = self.db.execute("SELECT id FROM evidence WHERE sha256 = ? AND module = ? AND query = ? LIMIT 1",
                              (digest, module, query)).fetchone()
        if row:
            return row["id"], False
        cur = self.db.execute(
            "INSERT INTO evidence (module, query, fetched_at, raw, sha256) VALUES (?,?,?,?,?)",
            (module, query, now(), text, digest))
        return _rowid(cur), True

    def add_evidence(self, module: str, query: str, raw: Any) -> int:
        return self.insert_evidence(module, query, raw)[0]

    def get_evidence(self, evidence_id: int) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()

    def evidence_exists(self, ids: Iterable[int]) -> bool:
        ids = sorted(set(ids))
        if not ids:
            return False
        marks = ",".join("?" * len(ids))
        count = self.db.execute(f"SELECT COUNT(*) FROM evidence WHERE id IN ({marks})", ids).fetchone()[0]
        return count == len(ids)

    # ---------- entities ----------
    def upsert_entity(self, etype: str, value: str, evidence_id: int, in_scope: bool | None = None) -> int:
        """Create or refresh an entity. in_scope overrides the scope decision for derived entities."""
        value = normalize_value(etype, value)
        decision = self.scope.contains_entity(etype, value)
        flag = int(bool(decision if decision is not None else in_scope))
        ts = now()
        row = self.db.execute("SELECT id, in_scope FROM entities WHERE type = ? AND value = ?",
                              (etype, value)).fetchone()
        if row:
            entity_id = row["id"]
            # A derived entity becomes in scope once any in-scope parent reaches it.
            new_flag = max(row["in_scope"], flag) if decision is None else flag
            self.db.execute("UPDATE entities SET last_seen = ?, in_scope = ? WHERE id = ?", (ts, new_flag, entity_id))
        else:
            entity_id = _rowid(self.db.execute(
                "INSERT INTO entities (type, value, in_scope, first_seen, last_seen) VALUES (?,?,?,?,?)",
                (etype, value, flag, ts, ts)))
        self.db.execute("INSERT OR IGNORE INTO entity_evidence VALUES (?, ?)", (entity_id, evidence_id))
        return entity_id

    def add_relationship(self, src_id: int, dst_id: int, rtype: str, evidence_id: int) -> None:
        self.db.execute("INSERT OR IGNORE INTO relationships (src_id, dst_id, type, evidence_id) VALUES (?,?,?,?)",
                        (src_id, dst_id, rtype, evidence_id))

    def get_entity(self, entity_id: int) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()

    def find_entity(self, etype: str, value: str) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM entities WHERE type = ? AND value = ?",
                               (etype, normalize_value(etype, value))).fetchone()

    def entities(self, etype: str | None = None, in_scope: bool | None = None,
                 query: str | None = None, limit: int = 1000) -> list[sqlite3.Row]:
        sql, args = "SELECT * FROM entities WHERE 1=1", list[Any]()
        if etype:
            sql += " AND type = ?"
            args.append(etype)
        if in_scope is not None:
            sql += " AND in_scope = ?"
            args.append(int(in_scope))
        if query:
            sql += " AND value LIKE ? ESCAPE '\\'"
            args.append(_like(query))
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

    def relationships(self) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT * FROM relationships ORDER BY id"))

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
        return _rowid(cur)

    def find_open_job(self, module: str, target: str) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM jobs WHERE module = ? AND target = ? AND status IN ('suggested', 'approved', 'running') "
            "ORDER BY id LIMIT 1", (module, target)).fetchone()

    _JOB_COLUMNS = {"status", "approved_by", "finished_at", "error", "tier"}

    def update_job(self, job_id: int, **fields: Any) -> None:
        unknown = set(fields) - self._JOB_COLUMNS
        if unknown:
            raise ValueError(f"cannot update job columns {sorted(unknown)}")
        if fields.get("status") in ("done", "failed", "denied"):
            fields.setdefault("finished_at", now())
        cols = ", ".join(f"{k} = ?" for k in fields)
        self.db.execute(f"UPDATE jobs SET {cols} WHERE id = ?", (*fields.values(), job_id))

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
        self.audit(created_by, "finding.create", f"F{cur.lastrowid}", title)
        return _rowid(cur)

    def find_finding_by_title(self, title: str) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM findings WHERE lower(title) = lower(?) AND status != 'rejected'",
                               (title.strip(),)).fetchone()

    def set_finding_status(self, finding_id: int, status: str, actor: str = "user") -> None:
        if status not in ("draft", "validated", "rejected"):
            raise ValueError("status must be draft, validated or rejected")
        self.db.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
        self.audit(actor, f"finding.{status}", f"F{finding_id}")

    def findings(self, status: str | None = None) -> list[sqlite3.Row]:
        order = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 " \
                "WHEN 'low' THEN 3 ELSE 4 END, id"
        if status:
            return list(self.db.execute(f"SELECT * FROM findings WHERE status = ? ORDER BY {order}", (status,)))
        return list(self.db.execute(f"SELECT * FROM findings ORDER BY {order}"))

    def close(self) -> None:
        self.db.close()
