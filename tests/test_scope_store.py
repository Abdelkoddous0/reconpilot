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
