import json
from pathlib import Path

import pytest

from reconpilot.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture
def rp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def run(*argv):
        main(["--data-dir", str(tmp_path / "data"), *argv])
    return run


def test_full_flow(rp, tmp_path, capsys):
    rp("new", "lab", "--client", "Example Corp", "--auth-ref", "RoE-1",
       "--scope", "example.com", "--scope", "10.0.0.0/24", "--exclude", "dev.example.com")
    assert (tmp_path / "data" / ".active").read_text() == "lab"
    rp("import", str(EXAMPLES / "subfinder.json"), str(EXAMPLES / "httpx.json"))
    rp("status")
    rp("search", "admin")
    rp("search", "--out")
    rp("show", "E7")
    rp("show", "N1")
    rp("findings")
    rp("steps")
    rp("models")
    rp("log")
    rp("report")
    out = capsys.readouterr().out
    assert "admin.example.com" in out
    assert "dev.example.com" in out
    assert (tmp_path / "lab-report.md").exists()


def test_cloud_blocked_by_default(rp, capsys):
    rp("new", "lab", "--client", "c", "--auth-ref", "r", "--scope", "example.com")
    with pytest.raises(SystemExit):
        rp("ask", "-m", "anthropic:claude-opus-5-5", "hello")
    assert "allow_cloud=false" in capsys.readouterr().out


def test_helpful_error_without_projects(rp, capsys):
    with pytest.raises(SystemExit):
        rp("status")
    assert "rp new" in capsys.readouterr().out


def test_use_switches_project(rp, tmp_path):
    rp("new", "a", "--client", "c", "--auth-ref", "r", "--scope", "a.com")
    rp("new", "b", "--client", "c", "--auth-ref", "r", "--scope", "b.com")
    rp("use", "a")
    assert (tmp_path / "data" / ".active").read_text() == "a"


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_identity_flow_and_exports(rp, tmp_path, capsys):
    rp("new", "osint", "--client", "Lab", "--auth-ref", "consent-7", "--seed", "username:jdoe_test")
    rp("import", str(FIXTURES / "sherlock/jdoe_test.csv"), str(FIXTURES / "maigret/report_jdoe_test_ndjson.json"))
    capsys.readouterr()
    rp("search", "-t", "account", "--json")
    accounts = json.loads(capsys.readouterr().out)
    assert {"https://www.github.com/jdoe_test", "https://github.com/jdoe_test"} <= {a["value"] for a in accounts}
    rp("seed", "email", "jane@example.com", "--note", "same consent form")
    capsys.readouterr()
    rp("scope", "show", "--json")
    assert {"type": "email", "value": "jane@example.com", "note": "same consent form"} in \
        json.loads(capsys.readouterr().out)["subjects"]
    rp("export", "--format", "graphml", "-o", str(tmp_path / "g.graphml"))
    assert "<graphml" in (tmp_path / "g.graphml").read_text()
    rp("export", "--format", "csv", "-o", str(tmp_path / "e.csv"))
    rp("report", "--format", "html", "--drafts", "-o", str(tmp_path / "r.html"))
    html = (tmp_path / "r.html").read_text()
    assert "<h2>Accounts</h2>" in html and "jdoe_test" in html


def test_scope_edit_and_policy(rp, capsys):
    rp("new", "lab", "--client", "c", "--auth-ref", "r", "--scope", "example.com")
    rp("scope", "add", "10.0.0.0/24")
    rp("scope", "add", "--exclude", "vpn.example.com")
    rp("scope", "remove", "10.0.0.0/24")
    rp("policy", "low-touch", "off")
    capsys.readouterr()
    rp("scope", "show", "--json")
    scope = json.loads(capsys.readouterr().out)
    assert scope["networks"] == [] and scope["exclude_domains"] == ["vpn.example.com"]
    with pytest.raises(SystemExit):
        rp("run", "httpx", "www.example.com")


def test_tools_playbooks_doctor(rp, capsys):
    rp("tools", "--json")
    names = {t["name"] for t in json.loads(capsys.readouterr().out)}
    assert {"sherlock", "maigret", "holehe", "theharvester", "subfinder"} <= names
    rp("playbooks")
    rp("doctor")
    assert "Tools" in capsys.readouterr().out


def test_unknown_run_target(rp, capsys):
    rp("new", "lab", "--client", "c", "--auth-ref", "r", "--scope", "example.com")
    with pytest.raises(SystemExit):
        rp("run", "nope", "example.com")
    assert "unknown tool or playbook" in capsys.readouterr().out


def test_report_says_when_it_truncates(tmp_path):
    from reconpilot.report import MAX_ROWS, build_report
    from reconpilot.scope import Scope
    from reconpilot.store import Store
    s = Store.create_project(tmp_path, "big", client="c", auth_ref="r", scope=Scope.from_entries(["example.com"]))
    ev = s.add_evidence("t", "q", "raw")
    with s.transaction():
        for i in range(MAX_ROWS + 5):
            s.upsert_entity("subdomain", f"h{i}.example.com", ev)
    assert f"Showing {MAX_ROWS:,} of {MAX_ROWS + 5:,}" in build_report(s)
