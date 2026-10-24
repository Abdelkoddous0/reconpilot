"""ReconPilot command-line interface. Run `rp` with no arguments for the interactive menu."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import date
from pathlib import Path

from . import ui
from .ai.analyst import IDENTITY_TRIAGE_PROMPT, TRIAGE_PROMPT, Analyst, AnalystError
from .ai.providers import ProviderError, check_provider, get_provider, resolve_spec
from .config import load_config
from .export import EXPORT_FORMATS, entity_dict, export
from .importers import Importer, formats
from .playbook import load_playbooks, run_playbook
from .report import REPORT_FORMATS, build_html_report, build_report
from .scope import SUBJECT_TYPES, Scope, ScopeError
from .store import ENTITY_TYPES, Store, parse_ref
from .tools import registry
from .tools.runner import RunError, Runner

console = ui.console


class CLIError(Exception):
    def __init__(self, message: str, hint: str | None = None):
        super().__init__(message)
        self.hint = hint


class App:
    """Shared state for every command: config, active project and the open store."""

    def __init__(self, cfg: dict, project: str | None = None):
        self.cfg = cfg
        self.data_dir = Path(cfg["data_dir"])
        self._project = project
        self._store: Store | None = None

    # ---------- active project ----------
    @property
    def active_file(self) -> Path:
        return self.data_dir / ".active"

    def active(self) -> str | None:
        try:
            name = self.active_file.read_text().strip()
        except OSError:
            return None
        return name if name in Store.list_projects(self.data_dir) else None

    def set_active(self, name: str) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.active_file.write_text(name)
        self._project, self._store = name, None

    def project_name(self) -> str:
        if self._project:
            return self._project
        if name := self.active():
            return name
        projects = Store.list_projects(self.data_dir)
        if len(projects) == 1:
            return projects[0]
        if not projects:
            raise CLIError("no projects yet", "create one with: rp new")
        raise CLIError("no active project", f"pick one with: rp use <name>   ({', '.join(projects)})")

    @property
    def store(self) -> Store:
        if self._store is None:
            name = self.project_name()
            try:
                self._store = Store.open_project(self.data_dir, name)
            except FileNotFoundError:
                raise CLIError(f"project '{name}' not found", "list projects with: rp ls") from None
        return self._store

    def model_spec(self, override: str | None, profile: str) -> str:
        return resolve_spec(self.cfg, override, profile)


def emit_json(data) -> None:
    """Machine-readable output on stdout, without rich markup."""
    print(json.dumps(data, indent=2, default=str))


def _parse_seed(text: str) -> tuple[str, str]:
    stype, sep, value = text.partition(":")
    if not sep or stype not in SUBJECT_TYPES or not value.strip():
        raise CLIError(f"bad --seed {text!r}", f"use TYPE:VALUE with TYPE one of {', '.join(SUBJECT_TYPES)}, "
                                               "e.g. --seed username:jdoe")
    return stype, value.strip()


# ======================= projects =======================

def cmd_new(app: App, args) -> None:
    name, client, auth_ref, scope_in = args.name, args.client, args.auth_ref, args.scope or []
    exclude, allow_cloud, seeds = args.exclude or [], args.allow_cloud, [_parse_seed(s) for s in args.seed or []]
    if not (name and client and auth_ref and (scope_in or seeds)):
        if not sys.stdin.isatty():
            raise CLIError("missing details", "rp new NAME --client C --auth-ref REF --scope example.com "
                                              "(or --seed username:jdoe)")
        import questionary
        ui.console.print(ui.BANNER + "\n")
        name = name or questionary.text("Project name (letters, digits, - _):").unsafe_ask()
        client = client or questionary.text("Client name:").unsafe_ask()
        auth_ref = auth_ref or questionary.text(
            "Authorization reference (SoW / RoE ID or bug bounty URL):").unsafe_ask()
        if not scope_in and not seeds:
            scope_in = [s.strip() for s in questionary.text(
                "In-scope domains / CIDRs (comma separated, optional):").unsafe_ask().split(",") if s.strip()]
            raw = questionary.text("People to investigate, as type:value (comma separated, optional; "
                                   "types: username, email, phone, person):").unsafe_ask()
            seeds = [_parse_seed(s.strip()) for s in raw.split(",") if s.strip()]
        if not args.exclude:
            exclude = [s.strip() for s in questionary.text(
                "Out-of-scope domains / CIDRs (comma separated, optional):").unsafe_ask().split(",") if s.strip()]
        if not args.allow_cloud:
            allow_cloud = questionary.confirm("Allow cloud AI models for this client's data?",
                                              default=False).unsafe_ask()
    scope = Scope.from_entries(scope_in, exclude,
                               start=date.fromisoformat(args.start) if args.start else None,
                               end=date.fromisoformat(args.end) if args.end else None)
    for stype, value in seeds:
        scope.add_subject(stype, value)
    Store.create_project(app.data_dir, name, client=client, auth_ref=auth_ref, scope=scope,
                         allow_cloud=bool(allow_cloud), allow_low_touch=not args.passive_only)
    app.set_active(name)
    ui.ok(f"created project [bold]{name}[/] and made it active")
    ui.hint("cloud AI " + ("allowed" if allow_cloud else "blocked: local models only (change with: rp cloud on)"))
    ui.hint("next: rp run <tool> <target>, or rp import <file>  (see tools with: rp tools)")


def cmd_use(app: App, args) -> None:
    if args.name not in Store.list_projects(app.data_dir):
        raise CLIError(f"project '{args.name}' not found", "list projects with: rp ls")
    app.set_active(args.name)
    ui.ok(f"active project: [bold]{args.name}[/]")


def cmd_ls(app: App, args) -> None:
    names = Store.list_projects(app.data_dir)
    if not names:
        raise CLIError("no projects yet", "create one with: rp new")
    console.print(ui.projects_table(names, app.active()))


def cmd_status(app: App, args) -> None:
    if getattr(args, "json", False):
        meta = app.store.meta()
        emit_json({"project": meta, "stats": app.store.stats(),
                   "draft_findings": len(app.store.findings("draft")),
                   "pending_steps": len(app.store.jobs("suggested"))})
        return
    console.print(ui.dashboard(app.store, app.model_spec(None, "analyst")))


# ======================= scope and policy =======================

def cmd_scope(app: App, args) -> None:
    store = app.store
    scope = store.scope
    if args.action == "show":
        if args.json:
            emit_json(scope.to_dict())
            return
        console.print(ui.scope_table(scope))
        return
    if args.action == "add":
        for value in args.values:
            scope.add(value, exclude=args.exclude)
    elif args.action == "remove":
        missing = [v for v in args.values if not scope.remove(v)]
        for value in missing:
            ui.warn(f"{value} was not in scope")
    elif args.action == "window":
        scope.start = date.fromisoformat(args.start) if args.start else None
        scope.end = date.fromisoformat(args.end) if args.end else None
    changed = store.save_scope(scope)
    ui.ok("scope saved" + (f", {changed} entities re-flagged" if changed else ""))


def cmd_seed(app: App, args) -> None:
    scope = app.store.scope
    for value in args.values:
        scope.add_subject(args.type, value, args.note or "")
    changed = app.store.save_scope(scope)
    ui.ok(f"added {len(args.values)} {args.type} subject(s)" + (f", {changed} entities re-flagged" if changed else ""))
    ui.hint(f"next: rp run {'sherlock' if args.type == 'username' else 'holehe'} {args.values[0]}"
            if args.type in ("username", "email") else "next: rp tools")


def cmd_policy(app: App, args) -> None:
    key = {"low-touch": "allow_low_touch", "active": "allow_active"}[args.what]
    allow = args.state == "on"
    app.store.set_meta(key, allow)
    (ui.warn if allow and args.what == "active" else ui.ok)(
        f"{args.what} tools {'allowed' if allow else 'blocked'} for [bold]{app.project_name()}[/]")


def cmd_cloud(app: App, args) -> None:
    allow = args.state == "on"
    app.store.set_meta("allow_cloud", allow)
    if allow:
        ui.warn(f"cloud AI models allowed for [bold]{app.project_name()}[/]: data will leave this machine")
    else:
        ui.ok(f"cloud AI models blocked for [bold]{app.project_name()}[/]")


# ======================= data in =======================

def cmd_import(app: App, args) -> None:
    importer = Importer(app.store, ignore_window=args.ignore_window)
    for file in args.files:
        if not Path(file).is_file():
            ui.fail(f"{file}: file not found")
            continue
        try:
            s = importer.import_file(file, args.format)
        except ScopeError as exc:
            raise CLIError(str(exc)) from None
        except ValueError as exc:
            ui.fail(f"{file}: {exc}", "set the format explicitly with --format (see rp tools)")
            continue
        ui.ok(f"{file} [muted]({s.format})[/]: {s.evidence} new evidence records, {len(s.entities)} entities"
              + (f", [muted]{s.duplicates} already imported[/]" if s.duplicates else "")
              + (f", [warn]{s.skipped} skipped[/]" if s.skipped else ""))


def _runner(app: App) -> Runner:
    return Runner(app.store, app.cfg)


def cmd_run(app: App, args) -> None:
    what = args.what
    runner = _runner(app)
    if what.upper().startswith("J") and what[1:].isdigit():
        with console.status(f"[brand]running {what.upper()}[/]"):
            result = runner.run_job(parse_ref(what, "J"))
        _print_run(result)
        return
    if not args.target:
        raise CLIError("missing target", f"rp run {what} <target>")
    playbooks = load_playbooks(app.cfg)
    if what in playbooks:
        _run_playbook(app, runner, playbooks[what], args)
        return
    if what not in registry():
        names = ", ".join(n for n, a in registry().items() if a.runnable)
        raise CLIError(f"unknown tool or playbook {what!r}", f"tools: {names} · playbooks: {', '.join(playbooks)}")
    with console.status(f"[brand]running {what}[/] [muted]on {args.target}[/]"):
        result = runner.run(what, args.target, ttype=args.type)
    _print_run(result)


def _print_run(result) -> None:
    lines = sum(s.lines for s in result.summaries)
    skipped = sum(s.skipped for s in result.summaries)
    ui.ok(f"J{result.job_id} {result.adapter} on {result.target}: {result.evidence} new evidence records, "
          f"{len(result.entities)} entities" + (f" [muted]({lines} output records, {skipped} not matches "
                                               f"or unreadable)[/]" if skipped else ""))
    if not result.summaries:
        ui.warn("no results: the tool's output was empty (stdout.txt and stderr.txt are in the run folder)")
    ui.hint(f"raw output: {result.outdir} · explore: rp search · triage: rp triage")


def _run_playbook(app: App, runner: Runner, pb, args) -> None:
    import questionary

    def confirm(question: str) -> bool:
        if args.yes:
            return True
        if not sys.stdin.isatty():
            return False
        return bool(questionary.confirm(question, default=False).ask())

    def on_event(kind: str, text: str) -> None:
        {"step": lambda t: console.print(f"[brand]▸ {t}[/]"), "ok": ui.ok,
         "fail": lambda t: ui.fail(t)}[kind](text)

    def ask(question: str) -> None:
        try:
            run_question(app, question, args.model, "analyst")
        except CLIError as exc:
            ui.fail(f"analyst step: {exc}", exc.hint)

    console.print(f"[bold]playbook {pb.name}[/] [muted]on {args.target}[/]")
    report = run_playbook(pb, args.target, app.store, runner, confirm=confirm, on_event=on_event, ask=ask)
    for item in report.skipped:
        ui.warn(f"skipped {item}")
    ui.hint(f"{len(report.runs)} runs · {len(report.skipped)} skipped · {len(report.failed)} failed")


# ======================= explore =======================

def cmd_search(app: App, args) -> None:
    in_scope = None if args.all else (False if args.out else True)
    rows = app.store.entities(etype=args.type, query=args.text, in_scope=in_scope)
    if args.json:
        emit_json([entity_dict(app.store, r) for r in rows])
        return
    if not rows:
        ui.warn("nothing matched")
        return
    console.print(ui.entities_table(app.store, rows))
    ui.hint(f"{len(rows)} results · details: rp show N<id>")


def cmd_show(app: App, args) -> None:
    ref = args.ref.strip().upper()
    store = app.store
    if ref.startswith("E"):
        row = store.get_evidence(parse_ref(ref, "E"))
        if not row:
            raise CLIError(f"no evidence {ref}")
        if args.json:
            emit_json(dict(row))
            return
        console.print(f"[id]E{row['id']}[/]  [muted]{row['module']} · {row['query']} · {row['fetched_at']}[/]")
        console.print(f"[muted]sha256 {row['sha256']}[/]")
        try:
            console.print_json(row["raw"])
        except json.JSONDecodeError:
            console.print(row["raw"], markup=False, highlight=False)
    elif ref.startswith("N"):
        row = store.get_entity(parse_ref(ref, "N"))
        if not row:
            raise CLIError(f"no entity {ref}")
        if args.json:
            emit_json({**entity_dict(store, row), "relationships": [
                {"direction": n["dir"], "relation": n["rel"], "entity": f"N{n['id']}", "type": n["type"],
                 "value": n["value"], "evidence": f"E{n['evidence_id']}"} for n in store.neighbors(row["id"])]})
            return
        scope = "[ok]in scope[/]" if row["in_scope"] else "[warn]out of scope[/]"
        console.print(f"[id]N{row['id']}[/] [bold]{row['value']}[/] [muted]({row['type']})[/] · {scope}")
        console.print(f"[muted]first seen {row['first_seen']} · evidence "
                      f"{', '.join(f'E{i}' for i in store.entity_evidence_ids(row['id']))}[/]")
        t = ui.table("", "Relation", "Entity", "Type", "Evidence")
        for n in store.neighbors(row["id"]):
            t.add_row("→" if n["dir"] == "out" else "←", n["rel"], f"[id]N{n['id']}[/] {n['value']}",
                      n["type"], f"[muted]E{n['evidence_id']}[/]")
        console.print(t)
    elif ref.startswith("F"):
        f = next((x for x in store.findings() if x["id"] == parse_ref(ref, "F")), None)
        if not f:
            raise CLIError(f"no finding {ref}")
        if args.json:
            emit_json({**dict(f), "evidence_ids": json.loads(f["evidence_ids"])})
            return
        console.print(ui.findings_table([f]))
        ui.markdown(f["description"] or "_no description_")
    else:
        raise CLIError(f"unknown reference {args.ref!r}", "use N12 (entity), E12 (evidence) or F3 (finding)")


# ======================= AI =======================

def _analyst(app: App, model: str | None, profile: str) -> Analyst:
    spec = app.model_spec(model, profile)
    try:
        provider = get_provider(spec, app.cfg, allow_cloud=app.store.meta()["allow_cloud"])
    except ProviderError as exc:
        raise CLIError(str(exc), "see available models with: rp models") from None
    return Analyst(app.store, provider, app.cfg)


def run_question(app: App, question: str, model: str | None, profile: str) -> None:
    analyst = _analyst(app, model, profile)
    try:
        with console.status(f"[brand]analyst thinking[/] [muted]({analyst.provider.spec})[/]"):
            result = analyst.ask(question)
    except (ProviderError, AnalystError) as exc:
        raise CLIError(str(exc), "check the model with: rp models") from None
    console.print()
    ui.markdown(result.answer)
    badge = "[ok]✔ citations verified[/]" if result.validated else "[bad]✖ failed citation check: unverified[/]"
    console.print(f"\n{badge}  [muted]{result.model} · {result.steps} steps · "
                  f"{len(result.tool_calls)} tool calls · {len(result.claims)} cited claims[/]")


def cmd_ask(app: App, args) -> None:
    run_question(app, " ".join(args.question), args.model, "analyst")


def cmd_triage(app: App, args) -> None:
    before_f, before_j = len(app.store.findings()), len(app.store.jobs())
    prompt = IDENTITY_TRIAGE_PROMPT if getattr(args, "identity", False) else TRIAGE_PROMPT
    run_question(app, prompt, args.model, "triage")
    new_f, new_j = len(app.store.findings()) - before_f, len(app.store.jobs()) - before_j
    if new_f or new_j:
        ui.hint(f"{new_f} draft findings (rp findings) · {new_j} suggested steps (rp steps)")


def cmd_chat(app: App, args) -> None:
    import questionary
    analyst = _analyst(app, args.model, "analyst")
    console.print(ui.BANNER)
    console.print(f"[muted]chatting about [bold]{app.project_name()}[/] with {analyst.provider.spec} · "
                  "type /exit to leave, /status for the dashboard[/]\n")
    while True:
        question = questionary.text("you ›", qmark="").ask()
        if question is None or question.strip() in ("/exit", "/quit", "exit", "quit"):
            break
        if question.strip() == "/status":
            cmd_status(app, argparse.Namespace(json=False))
            continue
        if question.strip():
            try:
                run_question(app, question, args.model, "analyst")
            except CLIError as exc:
                ui.fail(str(exc), exc.hint)
            console.print()


# ======================= review =======================

def cmd_findings(app: App, args) -> None:
    rows = app.store.findings() if args.all else [f for f in app.store.findings() if f["status"] != "rejected"]
    if getattr(args, "json", False):
        emit_json([{**dict(f), "evidence_ids": json.loads(f["evidence_ids"])} for f in rows])
        return
    if not rows:
        ui.warn("no findings yet")
        ui.hint("run: rp triage")
        return
    console.print(ui.findings_table(rows))
    ui.hint("details: rp show F<id> · rp accept F<id> · rp reject F<id>")


def _finding_status(status: str):
    def handler(app: App, args) -> None:
        for ref in args.ids:
            fid = parse_ref(ref, "F")
            if not any(f["id"] == fid for f in app.store.findings()):
                ui.fail(f"no finding F{fid}")
                continue
            app.store.set_finding_status(fid, status)
            ui.ok(f"F{fid} {'accepted' if status == 'validated' else status}")
    return handler


def cmd_steps(app: App, args) -> None:
    rows = app.store.jobs(None if args.all else "suggested")
    if getattr(args, "json", False):
        emit_json([dict(j) for j in rows])
        return
    if not rows:
        ui.warn("no pending suggestions" + ("" if args.all else " (see all with --all)"))
        return
    console.print(ui.steps_table(rows))
    ui.hint("rp approve J<id> then rp run J<id> · rp deny J<id>")


def _step_status(status: str):
    def handler(app: App, args) -> None:
        for ref in args.ids:
            jid = parse_ref(ref, "J")
            if not app.store.get_job(jid):
                ui.fail(f"no step J{jid}")
                continue
            app.store.update_job(jid, status=status, approved_by="user" if status == "approved" else None)
            app.store.audit("user", f"job.{status}", f"J{jid}")
            ui.ok(f"J{jid} {status}" + (f" · run it with: rp run J{jid}" if status == "approved" else ""))
    return handler


# ======================= data out =======================

def cmd_report(app: App, args) -> None:
    if args.format == "html":
        text = build_html_report(app.store, include_drafts=args.drafts)
    else:
        text = build_report(app.store, include_drafts=args.drafts)
    out = args.output or f"{app.project_name()}-report.{args.format}"
    Path(out).write_text(text)
    ui.ok(f"report written to [bold]{out}[/]" + (" [warn](includes drafts)[/]" if args.drafts else ""))
    if not any(f["status"] == "validated" for f in app.store.findings()):
        ui.hint("no accepted findings yet: accept some with rp accept F<id>, or use --drafts")


def cmd_export(app: App, args) -> None:
    text = export(app.store, args.format, in_scope_only=args.in_scope)
    if args.output in (None, "-"):
        sys.stdout.write(text)
        return
    Path(args.output).write_text(text)
    ui.ok(f"exported {args.format} to [bold]{args.output}[/]")


def cmd_log(app: App, args) -> None:
    t = ui.table("Time", "Actor", "Action", "Target", "Detail")
    for a in reversed(app.store.audit_entries(args.limit)):
        actor = "[brand]ai[/]" if a["actor"] == "ai" else a["actor"]
        t.add_row(f"[muted]{a['ts'][:19]}[/]", actor, a["action"], a["target"] or "", (a["detail"] or "")[:60])
    console.print(t)


# ======================= tools and setup =======================

def cmd_tools(app: App, args) -> None:
    rows = [(adapter, adapter.check() if adapter.runnable else None) for adapter in registry().values()]
    if args.json:
        emit_json([{"name": a.name, "runnable": a.runnable, "installed": bool(s and s.installed),
                    "version": s.version if s else None, "problem": s.problem if s else None, "tier": a.tier,
                    "accepts": list(a.accepts), "produces": list(a.produces), "description": a.description,
                    "install": a.install_hint} for a, s in rows])
        return
    console.print(ui.tools_table(rows))
    ui.hint("run one: rp run <tool> <target> · import its file: rp import <file> · install hints: rp doctor")


def cmd_playbooks(app: App, args) -> None:
    playbooks = load_playbooks(app.cfg)
    t = ui.table("Playbook", "Input", "Steps", "Description")
    for pb in playbooks.values():
        steps = " → ".join(s.get("tool", "analyst") for s in pb.steps)
        t.add_row(f"[bold]{pb.name}[/]", pb.input, steps, pb.description)
    console.print(t)
    ui.hint("run one: rp run <playbook> <target> · add your own YAML in ./playbooks/")


def cmd_doctor(app: App, args) -> None:
    good = True
    console.print(f"[bold]Python[/] {platform.python_version()}")
    console.print(f"[bold]Config[/] {app.cfg.get('_source') or '[muted]defaults (no reconpilot.yaml found)[/]'}")
    try:
        app.data_dir.mkdir(parents=True, exist_ok=True)
        probe = app.data_dir / ".write-test"
        probe.write_text("")
        probe.unlink()
        console.print(f"[bold]Data dir[/] {app.data_dir.resolve()}  [ok]writable[/]")
    except OSError as exc:
        good = False
        console.print(f"[bold]Data dir[/] {app.data_dir}  [bad]{exc}[/]")

    console.print("\n[bold]Tools[/]")
    t = ui.table("Tool", "Status", "Version", "Fix")
    for adapter in registry().values():
        if not adapter.runnable:
            continue
        s = adapter.check()
        if s.ok:
            note = ""
            if adapter.tested_version and s.version and s.version != adapter.tested_version:
                note = f"[warn]tested with {adapter.tested_version}[/]"
            t.add_row(adapter.name, "[ok]ready[/]", s.version or "?", note)
        else:
            t.add_row(adapter.name, f"[warn]{s.problem}[/]", s.version or "", f"[muted]{adapter.install_hint}[/]")
    console.print(t)

    console.print("[bold]AI models[/]")
    m = ui.table("Provider", "Status")
    ready = 0
    for name, pcfg in sorted(app.cfg["models"]["providers"].items()):
        status = check_provider(name, pcfg)
        ok = status in ("reachable", "installed", "SDK installed", "configured")
        ready += ok
        m.add_row(name, f"[ok]{status}[/]" if ok else f"[muted]{status}[/]")
    console.print(m)
    if not ready:
        good = False
        ui.warn("no AI backend is ready: install Ollama (ollama pull qwen2.5:14b) or configure a cloud model")
    (ui.ok if good else ui.warn)("doctor finished" + ("" if good else " with problems above"))


def cmd_models(app: App, args) -> None:
    models = app.cfg["models"]
    t = ui.table("Provider", "Runs", "Status", "Example spec")
    examples = {"ollama": "ollama:qwen2.5:14b", "anthropic": "anthropic:claude-opus-5-5",
                "codex-cli": "codex-cli:default", "claude-cli": "claude-cli:default",
                "openai": "openai:<model>", "gemini": "gemini:<model>", "openrouter": "openrouter:<model>",
                "lmstudio": "lmstudio:<model>", "llamacpp": "llamacpp:<model>"}
    good = ("reachable", "installed", "SDK installed", "configured")
    for name, pcfg in sorted(models["providers"].items()):
        status = check_provider(name, pcfg)
        style = "ok" if status in good else "muted"
        runs = "[ok]local[/]" if pcfg.get("local") else "[warn]cloud[/]"
        t.add_row(f"[bold]{name}[/]", runs, f"[{style}]{status}[/]", examples.get(name, f"{name}:<model>"))
    console.print(t)
    console.print(f"[muted]default:[/] {models['default']}")
    for profile, spec in models.get("profiles", {}).items():
        console.print(f"[muted]{profile}:[/] {spec}")
    ui.hint("use a model once: rp ask --model codex-cli:default \"...\" · set defaults in reconpilot.yaml")


def cmd_menu(app: App, args) -> None:
    from .shell import run_menu
    run_menu(app)


# ======================= parser =======================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rp", description="ReconPilot: local-first OSINT workbench with an AI analyst. "
                               "Run with no command for the interactive menu.")
    p.add_argument("-p", "--project", help="project to use (default: the active project)")
    p.add_argument("--config", help="path to reconpilot.yaml")
    p.add_argument("--data-dir", help="override the data directory")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    def add(name, func, help_text, aliases=(), json_flag=False):
        sp = sub.add_parser(name, help=help_text, aliases=list(aliases), description=help_text)
        sp.set_defaults(func=func)
        if json_flag:
            sp.add_argument("--json", action="store_true", help="machine-readable output")
        return sp

    # projects
    sp = add("new", cmd_new, "create a project (asks for details if you leave them out)", ["init"])
    sp.add_argument("name", nargs="?")
    sp.add_argument("--client")
    sp.add_argument("--auth-ref", help="SoW / RoE reference or bug bounty program URL")
    sp.add_argument("--scope", action="append", help="in-scope domain or CIDR (repeatable)")
    sp.add_argument("--exclude", action="append", help="out-of-scope domain or CIDR (repeatable)")
    sp.add_argument("--seed", action="append", metavar="TYPE:VALUE",
                    help="person to investigate, e.g. username:jdoe or email:jane@example.com (repeatable)")
    sp.add_argument("--start", help="engagement start YYYY-MM-DD")
    sp.add_argument("--end", help="engagement end YYYY-MM-DD")
    sp.add_argument("--allow-cloud", action="store_true", help="allow cloud AI models")
    sp.add_argument("--passive-only", action="store_true", help="block tools that touch the target (httpx, holehe)")
    sp = add("use", cmd_use, "switch the active project")
    sp.add_argument("name")
    add("ls", cmd_ls, "list projects", ["projects"])
    add("status", cmd_status, "project dashboard", ["st"], json_flag=True)

    # scope and policy
    sp = add("scope", cmd_scope, "show or change the scope (entities are re-flagged)")
    sp.add_argument("action", choices=["show", "add", "remove", "window"], nargs="?", default="show")
    sp.add_argument("values", nargs="*", help="domains, CIDRs or subject values")
    sp.add_argument("--exclude", action="store_true", help="with add: add as out-of-scope")
    sp.add_argument("--start", help="with window: YYYY-MM-DD (empty clears)")
    sp.add_argument("--end", help="with window: YYYY-MM-DD (empty clears)")
    sp.add_argument("--json", action="store_true")
    sp = add("seed", cmd_seed, "add people to investigate: usernames, emails, phones, names")
    sp.add_argument("type", choices=SUBJECT_TYPES)
    sp.add_argument("values", nargs="+")
    sp.add_argument("--note", help="why this subject is authorized")
    sp = add("policy", cmd_policy, "allow or block low-touch / active tools for this project")
    sp.add_argument("what", choices=["low-touch", "active"])
    sp.add_argument("state", choices=["on", "off"])
    sp = add("cloud", cmd_cloud, "allow or block cloud AI models for this project")
    sp.add_argument("state", choices=["on", "off"])

    # data in
    sp = add("import", cmd_import, "import tool output (auto-detects the tool)", ["i"])
    sp.add_argument("files", nargs="+")
    sp.add_argument("--format", choices=formats(), default="auto")
    sp.add_argument("--ignore-window", action="store_true", help="import even outside the engagement window")
    sp = add("run", cmd_run, "run a tool or playbook on a target, or an approved step J<id>")
    sp.add_argument("what", help="tool name (rp tools), playbook name (rp playbooks) or J<id>")
    sp.add_argument("target", nargs="?")
    sp.add_argument("--type", choices=ENTITY_TYPES, help="target type, if the guess is wrong (e.g. john.doe)")
    sp.add_argument("-y", "--yes", action="store_true", help="approve every playbook step without asking")
    sp.add_argument("-m", "--model", help="model for playbook analyst steps")

    # explore
    sp = add("search", cmd_search, "search entities: hosts, IPs, URLs, accounts, emails...", ["s"], json_flag=True)
    sp.add_argument("text", nargs="?")
    sp.add_argument("-t", "--type", choices=ENTITY_TYPES)
    sp.add_argument("--out", action="store_true", help="only out-of-scope entities")
    sp.add_argument("--all", action="store_true", help="in and out of scope")
    sp = add("show", cmd_show, "details for N<id> (entity), E<id> (evidence) or F<id> (finding)", json_flag=True)
    sp.add_argument("ref")

    # AI
    sp = add("ask", cmd_ask, "ask the AI analyst one question")
    sp.add_argument("question", nargs="+")
    sp.add_argument("-m", "--model", help="provider:model or a profile name")
    sp = add("chat", cmd_chat, "interactive chat with the AI analyst")
    sp.add_argument("-m", "--model")
    sp = add("triage", cmd_triage, "AI review of the attack surface: draft findings and next steps")
    sp.add_argument("-m", "--model")
    sp.add_argument("--identity", action="store_true", help="focus on usernames, accounts and emails")

    # review
    sp = add("findings", cmd_findings, "list findings", ["f"], json_flag=True)
    sp.add_argument("--all", action="store_true", help="include rejected")
    for name, status, text in (("accept", "validated", "accept draft findings"),
                               ("reject", "rejected", "reject draft findings")):
        sp = add(name, _finding_status(status), text)
        sp.add_argument("ids", nargs="+", metavar="F<id>")
    sp = add("steps", cmd_steps, "list recon steps suggested by the AI", ["jobs"], json_flag=True)
    sp.add_argument("--all", action="store_true")
    for name, status in (("approve", "approved"), ("deny", "denied"), ("done", "done")):
        sp = add(name, _step_status(status), f"mark suggested steps as {status}")
        sp.add_argument("ids", nargs="+", metavar="J<id>")

    # data out
    sp = add("report", cmd_report, "write a report (Markdown or HTML)")
    sp.add_argument("-o", "--output")
    sp.add_argument("--format", choices=REPORT_FORMATS, default="md")
    sp.add_argument("--drafts", action="store_true", help="include unaccepted draft findings")
    sp = add("export", cmd_export, "export entities and relationships (JSON, CSV, GraphML)")
    sp.add_argument("--format", choices=EXPORT_FORMATS, default="json")
    sp.add_argument("-o", "--output", help="file to write (default: stdout)")
    sp.add_argument("--in-scope", action="store_true", help="only in-scope entities")
    sp = add("log", cmd_log, "audit log", ["audit"])
    sp.add_argument("-n", "--limit", type=int, default=30)

    # tools and setup
    add("tools", cmd_tools, "available recon tools and whether they are installed", json_flag=True)
    add("playbooks", cmd_playbooks, "available playbooks (chains of tools)")
    add("doctor", cmd_doctor, "check Python, config, data dir, tools and AI models")
    add("models", cmd_models, "available AI model backends")
    add("menu", cmd_menu, "interactive menu (same as running rp with no command)")
    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.config)
    except FileNotFoundError as exc:
        ui.fail(str(exc))
        sys.exit(1)
    if args.data_dir:
        cfg["data_dir"] = args.data_dir
    app = App(cfg, args.project)
    func = getattr(args, "func", None)
    if func is None:
        if not sys.stdin.isatty():
            parser.print_help()
            return
        func = cmd_menu
    try:
        func(app, args)
    except (CLIError, RunError) as exc:
        ui.fail(str(exc), exc.hint)
        sys.exit(1)
    except (FileNotFoundError, FileExistsError, ValueError, ScopeError) as exc:
        ui.fail(str(exc))
        sys.exit(1)
    except KeyboardInterrupt:
        console.print()
        sys.exit(130)


if __name__ == "__main__":
    main()
