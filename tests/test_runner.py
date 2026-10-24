import json
import sys
from datetime import date

import pytest

import reconpilot.tools as tools
from reconpilot.playbook import Playbook, run_playbook
from reconpilot.scope import Scope
from reconpilot.store import Store
from reconpilot.tools.base import ToolAdapter
from reconpilot.tools.runner import RunError, Runner


class FakeSubdomains(ToolAdapter):
    """Pretends to be subfinder: a Python one-liner writes JSON lines into the run directory."""
    name = "fakesubs"
    binary = sys.executable
    accepts = ("domain",)
    output_glob = "out.json"

    def command(self, target, outdir, options):
        lines = [{"host": f"{p}.{target}", "source": "fake"} for p in ("www", "api")]
        script = f"import json; open('out.json','w').write('\\n'.join(json.dumps(x) for x in {lines!r}))"
        return [sys.executable, "-c", script]

    def handle(self, ctx, rec, ev):
        ctx.host(rec["host"], ev)


class FakeEmails(FakeSubdomains):
    name = "fakeemails"
    accepts = ("domain",)

    def command(self, target, outdir, options):
        lines = [{"email": f"info@{target}"}, {"email": "x@other.org"}]
        script = f"import json; open('out.json','w').write('\\n'.join(json.dumps(x) for x in {lines!r}))"
        return [sys.executable, "-c", script]

    def handle(self, ctx, rec, ev):
        ctx.entity("email", rec["email"], ev)


class FakeEmailCheck(FakeSubdomains):
    name = "fakecheck"
    accepts = ("email",)
    tier = "low_touch"

    def command(self, target, outdir, options):
        return [sys.executable, "-c", f"open('out.json','w').write('{{\"email\": \"{target}\"}}')"]

    def handle(self, ctx, rec, ev):
        ctx.link(ctx.entity("email", rec["email"], ev), "registered_on", "account", "site:" + rec["email"], ev)


class Broken(FakeSubdomains):
    name = "broken"

    def command(self, target, outdir, options):
        return [sys.executable, "-c", "import sys; sys.exit(3)"]


@pytest.fixture(autouse=True)
def fake_tools(monkeypatch):
    reg = dict(tools.registry())
    for cls in (FakeSubdomains, FakeEmails, FakeEmailCheck, Broken):
        reg[cls.name] = cls()
    monkeypatch.setattr(tools, "_registry", reg)


def test_run_imports_output(store, config):
    result = Runner(store, config).run("fakesubs", "example.com")
    assert result.evidence == 2
    job = store.get_job(result.job_id)
    assert job["status"] == "done" and job["tier"] == "passive"
    assert store.find_entity("subdomain", "api.example.com")["in_scope"] == 1
    assert (result.outdir / "stdout.txt").exists()
    assert json.loads((result.outdir / "command.json").read_text())[0] == sys.executable


def test_run_refuses_out_of_scope(store, config):
    with pytest.raises(RunError, match="out of scope"):
        Runner(store, config).run("fakesubs", "evil.com")
    assert store.jobs() == []


def test_run_refuses_wrong_target_type(store, config):
    with pytest.raises(RunError, match="takes email"):
        Runner(store, config).run("fakecheck", "example.com", ttype="domain")


def test_run_respects_engagement_window(tmp_path, config):
    scope = Scope.from_entries(["example.com"], start=date(2020, 1, 1), end=date(2020, 1, 31))
    s = Store.create_project(tmp_path, "old", client="c", auth_ref="r", scope=scope)
    with pytest.raises(RunError, match="window"):
        Runner(s, config).run("fakesubs", "example.com")


def test_low_touch_blocked_when_passive_only(store, config):
    store.set_meta("allow_low_touch", False)
    with pytest.raises(RunError, match="passive-only"):
        Runner(store, config).run("fakecheck", "admin@example.com")


def test_failed_tool_marks_job_failed(store, config):
    with pytest.raises(RunError, match="exited with 3"):
        Runner(store, config).run("broken", "example.com")
    assert store.jobs()[0]["status"] == "failed"


def test_run_job_needs_approval(store, config):
    jid = store.create_job("fakesubs", "example.com", "passive", "ai", "why", "suggested")
    with pytest.raises(RunError, match="not approved"):
        Runner(store, config).run_job(jid)
    store.update_job(jid, status="approved")
    assert Runner(store, config).run_job(jid).job_id == jid
    assert store.get_job(jid)["status"] == "done"


def test_playbook_feeds_found_entities_forward(store, config):
    pb = Playbook(name="t", input="domain", steps=[
        {"tool": "fakeemails"},
        {"tool": "fakecheck", "for_each": "email", "requires_approval": True},
    ])
    asked, events = [], []
    report = run_playbook(pb, "example.com", store, Runner(store, config),
                          confirm=lambda q: asked.append(q) or True,
                          on_event=lambda k, t: events.append(k), ask=lambda q: None)
    assert len(report.runs) == 2
    assert asked == ["Run fakecheck info@example.com? (low_touch)"]
    assert report.skipped == ["fakecheck x@other.org: out of scope"]
    assert store.find_entity("account", "site:info@example.com")["in_scope"] == 1


def test_builtin_playbooks_load(config):
    from reconpilot.playbook import load_playbooks
    names = set(load_playbooks(config))
    assert {"username-sweep", "email-footprint", "domain-surface"} <= names


def test_httpx_name_clash_is_detected():
    from reconpilot.tools.infra import Httpx
    assert Httpx().verify("Usage: httpx [OPTIONS] URL") is not None
    assert Httpx().verify("[INF] Current Version: v1.12.0") is None
