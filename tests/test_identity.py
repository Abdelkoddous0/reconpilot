import shutil
from pathlib import Path

import pytest

from reconpilot.importers import Importer
from reconpilot.scope import Scope, guess_type
from reconpilot.store import Store
from reconpilot.tools import detect_adapter

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def people(tmp_path):
    scope = Scope.from_entries(["example.com"])
    scope.add_subject("username", "jdoe_test")
    scope.add_subject("email", "jane@example.com")
    s = Store.create_project(tmp_path, "people", client="Lab", auth_ref="consent-form-7", scope=scope)
    yield s
    s.close()


@pytest.mark.parametrize("value,expected", [
    ("jdoe", "username"), ("jane@example.com", "email"), ("+33 6 12 34 56 78", "phone"),
    ("10.0.0.1", "ip"), ("https://a.example.com/x", "url"), ("example.com", "domain"), ("Jane Doe", "person"),
])
def test_guess_type(value, expected):
    assert guess_type(value) == expected


def test_subjects_scope():
    scope = Scope.from_entries(["example.com"])
    scope.add_subject("username", "JDoe")
    assert scope.contains_entity("username", "jdoe") is True
    assert scope.contains_entity("username", "someone") is False
    assert scope.contains_entity("email", "anyone@example.com") is True  # domain in scope
    assert scope.contains_entity("email", "x@gmail.com") is False
    assert scope.contains_entity("account", "https://github.com/jdoe") is None  # inherits
    with pytest.raises(ValueError):
        scope.add_subject("passport", "123")


def test_project_with_only_subjects(tmp_path):
    scope = Scope()
    scope.add_subject("username", "jdoe")
    Store.create_project(tmp_path, "p", client="c", auth_ref="r", scope=scope).close()


@pytest.mark.parametrize("path,name", [
    ("sherlock/jdoe_test.csv", "sherlock"),
    ("maigret/report_jdoe_test_ndjson.json", "maigret"),
    ("holehe/holehe_1792800000_jane@example.com_results.csv", "holehe"),
    ("theharvester/harvest.json", "theharvester"),
])
def test_detection(path, name):
    assert detect_adapter(FIXTURES / path).name == name


def test_sherlock_accounts_inherit_scope(people):
    s = Importer(people).import_file(FIXTURES / "sherlock/jdoe_test.csv")
    assert s.evidence == 2 and s.skipped == 1  # the "Available" row is not stored
    user = people.find_entity("username", "jdoe_test")
    accounts = [n for n in people.neighbors(user["id"]) if n["type"] == "account"]
    assert {a["value"] for a in accounts} == {"https://www.github.com/jdoe_test", "https://www.reddit.com/user/jdoe_test"}
    assert all(a["in_scope"] for a in accounts)


def test_maigret_extracts_profile_data(people):
    Importer(people).import_file(FIXTURES / "maigret/report_jdoe_test_ndjson.json")
    acc = people.find_entity("account", "https://github.com/jdoe_test")
    related = {(n["type"], n["value"]): n for n in people.neighbors(acc["id"])}
    assert ("person", "Jane Doe") in related
    assert related[("email", "jane@example.com")]["in_scope"] == 1   # seeded subject
    assert related[("username", "janedoe")]["in_scope"] == 0         # a lead, not authorized yet
    assert ("url", "https://janedoe.dev") in related


def test_holehe_reads_email_from_file_name(people, tmp_path):
    src = FIXTURES / "holehe/holehe_1792800000_jane@example.com_results.csv"
    s = Importer(people).import_file(src)
    assert s.evidence == 2  # spotify and twitter; not-registered and rate-limited rows are skipped
    email = people.find_entity("email", "jane@example.com")
    accounts = {n["value"] for n in people.neighbors(email["id"]) if n["type"] == "account"}
    assert accounts == {"spotify.com:jane@example.com", "twitter.com:jane@example.com"}


def test_theharvester(people):
    s = Importer(people).import_file(FIXTURES / "theharvester/harvest.json")
    assert s.skipped == 1  # "not-an-email"
    mail = people.find_entity("subdomain", "mail.example.com")
    assert "10.0.0.25" in {n["value"] for n in people.neighbors(mail["id"])}
    assert people.find_entity("email", "info@example.com")["in_scope"] == 1


def test_seeding_later_rescopes_leads(people):
    Importer(people).import_file(FIXTURES / "maigret/report_jdoe_test_ndjson.json")
    assert people.find_entity("username", "janedoe")["in_scope"] == 0
    scope = people.scope
    scope.add_subject("username", "janedoe")
    assert people.save_scope(scope) >= 1
    assert people.find_entity("username", "janedoe")["in_scope"] == 1


def test_reimport_does_not_duplicate(people, tmp_path):
    copy = tmp_path / "jdoe_test.csv"
    shutil.copy(FIXTURES / "sherlock/jdoe_test.csv", copy)
    Importer(people).import_file(copy)
    again = Importer(people).import_file(copy)
    assert again.evidence == 0 and again.duplicates == 2
    assert people.stats()["evidence_records"] == 2
