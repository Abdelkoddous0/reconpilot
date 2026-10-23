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
