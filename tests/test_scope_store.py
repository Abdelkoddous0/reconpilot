import sqlite3
from datetime import date

import pytest

from reconpilot.scope import Scope, ScopeError
from reconpilot.store import Store


@pytest.mark.parametrize("value,expected", [
    ("example.com", True),
    ("www.example.com", True),
    ("https://api.example.com/login", True),
    ("admin@example.com", True),
    ("dev.example.com", False),
    ("x.dev.example.com", False),
    ("notexample.com", False),
    ("10.0.0.5", True),
    ("10.0.1.5", False),
])
def test_scope_contains(value, expected):
    scope = Scope.from_entries(["example.com", "10.0.0.0/24"], exclude=["dev.example.com"])
    assert scope.contains(value) is expected


def test_scope_window():
    scope = Scope.from_entries(["example.com"], start=date(2026, 1, 1), end=date(2026, 1, 31))
    scope.require("example.com", today=date(2026, 1, 15))
    with pytest.raises(ScopeError):
        scope.require("example.com", today=date(2026, 2, 1))


def test_project_requires_authorization(tmp_path):
    with pytest.raises(ValueError):
        Store.create_project(tmp_path, "x", client="c", auth_ref=" ", scope=Scope.from_entries(["a.com"]))
    with pytest.raises(ValueError):
        Store.create_project(tmp_path, "x", client="c", auth_ref="ref", scope=Scope())


def test_entities_flag_out_of_scope(store):
    ev = store.add_evidence("test", "q", "raw")
    inside = store.upsert_entity("subdomain", "www.example.com", ev)
    outside = store.upsert_entity("subdomain", "cdn.other.net", ev)
    assert store.get_entity(inside)["in_scope"] == 1
    assert store.get_entity(outside)["in_scope"] == 0


def test_findings_need_real_evidence(store):
    with pytest.raises(ValueError):
        store.create_finding("t", "high", "d", [999], "user")
    ev = store.add_evidence("test", "q", "raw")
    fid = store.create_finding("t", "high", "d", [ev], "user")
    assert store.findings()[0]["id"] == fid


def test_audit_log_is_append_only(store):
    store.audit("user", "x")
    with pytest.raises(sqlite3.IntegrityError):
        store.db.execute("DELETE FROM audit_log")
    with pytest.raises(sqlite3.IntegrityError):
        store.db.execute("UPDATE audit_log SET actor = 'someone'")


def test_schema_is_migrated(store):
    from reconpilot.store import SCHEMA_VERSION
    assert store.db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    names = {r[0] for r in store.db.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    assert "idx_evidence_dedupe" in names


def test_search_escapes_like_wildcards(store):
    ev = store.add_evidence("test", "q", "raw")
    store.upsert_entity("subdomain", "a_b.example.com", ev)
    store.upsert_entity("subdomain", "axb.example.com", ev)
    assert [r["value"] for r in store.entities(query="a_b")] == ["a_b.example.com"]


def test_identical_evidence_is_reused(store):
    assert store.add_evidence("m", "q", {"a": 1}) == store.add_evidence("m", "q", {"a": 1})
    assert store.add_evidence("m", "q", {"a": 1}) != store.add_evidence("m", "other", {"a": 1})


def test_scope_change_reflags_entities(store):
    ev = store.add_evidence("test", "q", "raw")
    store.upsert_entity("subdomain", "dev.example.com", ev)
    assert store.find_entity("subdomain", "dev.example.com")["in_scope"] == 0
    scope = store.scope
    scope.remove("dev.example.com")
    assert store.save_scope(scope) == 1
    assert store.find_entity("subdomain", "dev.example.com")["in_scope"] == 1


def test_failed_parse_leaves_no_evidence(store, tmp_path):
    from reconpilot.importers import Importer
    f = tmp_path / "subs.json"
    f.write_text('{"host": "www.example.com", "source": "x"}\n{"source": "x", "input": "example.com", "host": null}\n')
    summary = Importer(store).import_file(f, "subfinder")
    assert summary.evidence == 1 and summary.skipped == 1
    assert store.stats()["evidence_records"] == 1


def test_import_refused_outside_window(tmp_path):
    from reconpilot.importers import Importer
    from reconpilot.scope import ScopeError
    s = Store.create_project(tmp_path, "old", client="c", auth_ref="r",
                             scope=Scope.from_entries(["example.com"], end=date(2020, 1, 1)))
    f = tmp_path / "hosts.txt"
    f.write_text("www.example.com\n")
    with pytest.raises(ScopeError, match="ignore-window"):
        Importer(s).import_file(f)
    assert Importer(s, ignore_window=True).import_file(f).evidence == 1
