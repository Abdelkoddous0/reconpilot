"""ReconPilot command-line interface. Run `rp` with no arguments for the interactive menu."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from . import ui
from .ai.analyst import TRIAGE_PROMPT, Analyst, AnalystError
from .ai.providers import ProviderError, check_provider, get_provider, resolve_spec
from .config import load_config
from .importers import FORMATS, Importer
from .report import build_report
from .scope import Scope
from .store import Store, parse_ref

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


# ======================= commands =======================

def cmd_new(app: App, args) -> None:
    name, client, auth_ref, scope_in = args.name, args.client, args.auth_ref, args.scope
    exclude, allow_cloud = args.exclude or [], args.allow_cloud
    if not (name and client and auth_ref and scope_in):
        if not sys.stdin.isatty():
            raise CLIError("missing details", "rp new NAME --client C --auth-ref REF --scope example.com")
        import questionary
        ui.console.print(ui.BANNER + "\n")
        name = name or questionary.text("Project name (letters, digits, - _):").unsafe_ask()
        client = client or questionary.text("Client name:").unsafe_ask()
        auth_ref = auth_ref or questionary.text(
            "Authorization reference (SoW / RoE ID or bug bounty URL):").unsafe_ask()
        scope_in = scope_in or [s.strip() for s in questionary.text(
            "In-scope domains / CIDRs (comma separated):").unsafe_ask().split(",") if s.strip()]
        if not args.exclude:
            exclude = [s.strip() for s in questionary.text(
                "Out-of-scope domains / CIDRs (comma separated, optional):").unsafe_ask().split(",") if s.strip()]
        if not args.allow_cloud:
            allow_cloud = questionary.confirm("Allow cloud AI models for this client's data?",
                                              default=False).unsafe_ask()
    scope = Scope.from_entries(scope_in, exclude,
                               start=date.fromisoformat(args.start) if args.start else None,
                               end=date.fromisoformat(args.end) if args.end else None)
    Store.create_project(app.data_dir, name, client=client, auth_ref=auth_ref, scope=scope,
                         allow_cloud=bool(allow_cloud))
    app.set_active(name)
    ui.ok(f"created project [bold]{name}[/] and made it active")
    ui.hint("cloud AI " + ("allowed" if allow_cloud else "blocked: local models only (change with: rp cloud on)"))
    ui.hint("next: rp import <file>")


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
    console.print(ui.dashboard(app.store, app.model_spec(None, "analyst")))


def cmd_import(app: App, args) -> None:
    importer = Importer(app.store)
    for file in args.files:
        if not Path(file).is_file():
            ui.fail(f"{file}: file not found")
            continue
        try:
            s = importer.import_file(file, args.format)
        except ValueError as exc:
            ui.fail(f"{file}: {exc}", "set the format explicitly with --format")
            continue
        ui.ok(f"{file} [muted]({s.format})[/]: {s.evidence} evidence records, "
              f"{len(s.entities)} entities" + (f", [warn]{s.skipped} skipped[/]" if s.skipped else ""))


def cmd_search(app: App, args) -> None:
    in_scope = None if args.all else (False if args.out else True)
    rows = app.store.entities(etype=args.type, query=args.text, in_scope=in_scope)
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
        console.print(ui.findings_table([f]))
        ui.markdown(f["description"] or "_no description_")
    else:
        raise CLIError(f"unknown reference {args.ref!r}", "use N12 (entity), E12 (evidence) or F3 (finding)")


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
    run_question(app, TRIAGE_PROMPT, args.model, "triage")
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
            cmd_status(app, args)
            continue
        if question.strip():
            try:
                run_question(app, question, args.model, "analyst")
            except CLIError as exc:
                ui.fail(str(exc), exc.hint)
            console.print()


def cmd_findings(app: App, args) -> None:
    rows = app.store.findings() if args.all else [f for f in app.store.findings() if f["status"] != "rejected"]
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
    if not rows:
        ui.warn("no pending suggestions" + ("" if args.all else " (see all with --all)"))
        return
    console.print(ui.steps_table(rows))
    ui.hint("rp approve J<id> · rp deny J<id> · rp done J<id> (then import the results)")


def _step_status(status: str):
    def handler(app: App, args) -> None:
        for ref in args.ids:
            jid = parse_ref(ref, "J")
            if not app.store.get_job(jid):
                ui.fail(f"no step J{jid}")
                continue
            app.store.update_job(jid, status=status, approved_by="user" if status == "approved" else None)
            app.store.audit("user", f"job.{status}", f"J{jid}")
            ui.ok(f"J{jid} {status}")
    return handler


def cmd_report(app: App, args) -> None:
    text = build_report(app.store, include_drafts=args.drafts)
    out = args.output or f"{app.project_name()}-report.md"
    Path(out).write_text(text)
    ui.ok(f"report written to [bold]{out}[/]" + (" [warn](includes drafts)[/]" if args.drafts else ""))
    if not any(f["status"] == "validated" for f in app.store.findings()):
        ui.hint("no accepted findings yet: accept some with rp accept F<id>, or use --drafts")


def cmd_log(app: App, args) -> None:
    t = ui.table("Time", "Actor", "Action", "Target", "Detail")
    for a in reversed(app.store.audit_entries(args.limit)):
        actor = "[brand]ai[/]" if a["actor"] == "ai" else a["actor"]
        t.add_row(f"[muted]{a['ts'][:19]}[/]", actor, a["action"], a["target"] or "", (a["detail"] or "")[:60])
    console.print(t)


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


def cmd_cloud(app: App, args) -> None:
    allow = args.state == "on"
    app.store.set_meta("allow_cloud", allow)
    if allow:
        ui.warn(f"cloud AI models allowed for [bold]{app.project_name()}[/]: data will leave this machine")
    else:
        ui.ok(f"cloud AI models blocked for [bold]{app.project_name()}[/]")


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

    def add(name, func, help_text, aliases=()):
        sp = sub.add_parser(name, help=help_text, aliases=list(aliases), description=help_text)
        sp.set_defaults(func=func)
        return sp

    sp = add("new", cmd_new, "create a project (asks for details if you leave them out)", ["init"])
    sp.add_argument("name", nargs="?")
    sp.add_argument("--client")
    sp.add_argument("--auth-ref", help="SoW / RoE reference or bug bounty program URL")
    sp.add_argument("--scope", action="append", help="in-scope domain or CIDR (repeatable)")
    sp.add_argument("--exclude", action="append", help="out-of-scope domain or CIDR (repeatable)")
    sp.add_argument("--start", help="engagement start YYYY-MM-DD")
    sp.add_argument("--end", help="engagement end YYYY-MM-DD")
    sp.add_argument("--allow-cloud", action="store_true", help="allow cloud AI models")

    sp = add("use", cmd_use, "switch the active project")
    sp.add_argument("name")
    add("ls", cmd_ls, "list projects", ["projects"])
    add("status", cmd_status, "project dashboard", ["st"])

    sp = add("import", cmd_import, "import recon tool output (auto-detects format)", ["i"])
    sp.add_argument("files", nargs="+")
    sp.add_argument("--format", choices=FORMATS, default="auto")

    sp = add("search", cmd_search, "search hosts, IPs, URLs and technologies", ["s"])
    sp.add_argument("text", nargs="?")
    sp.add_argument("-t", "--type", choices=["domain", "subdomain", "ip", "url", "technology"])
    sp.add_argument("--out", action="store_true", help="only out-of-scope assets")
    sp.add_argument("--all", action="store_true", help="in and out of scope")

    sp = add("show", cmd_show, "details for N<id> (entity), E<id> (evidence) or F<id> (finding)")
    sp.add_argument("ref")

    sp = add("ask", cmd_ask, "ask the AI analyst one question")
    sp.add_argument("question", nargs="+")
    sp.add_argument("-m", "--model", help="provider:model or a profile name")
    sp = add("chat", cmd_chat, "interactive chat with the AI analyst")
    sp.add_argument("-m", "--model")
    sp = add("triage", cmd_triage, "AI review of the attack surface: draft findings and next steps")
    sp.add_argument("-m", "--model")

    sp = add("findings", cmd_findings, "list findings", ["f"])
    sp.add_argument("--all", action="store_true", help="include rejected")
    for name, status, text in (("accept", "validated", "accept draft findings"),
                               ("reject", "rejected", "reject draft findings")):
        sp = add(name, _finding_status(status), text)
        sp.add_argument("ids", nargs="+", metavar="F<id>")

    sp = add("steps", cmd_steps, "list recon steps suggested by the AI", ["jobs"])
    sp.add_argument("--all", action="store_true")
    for name, status in (("approve", "approved"), ("deny", "denied"), ("done", "done")):
        sp = add(name, _step_status(status), f"mark suggested steps as {status}")
        sp.add_argument("ids", nargs="+", metavar="J<id>")

    sp = add("report", cmd_report, "write a Markdown report")
    sp.add_argument("-o", "--output")
    sp.add_argument("--drafts", action="store_true", help="include unaccepted draft findings")

    sp = add("log", cmd_log, "audit log", ["audit"])
    sp.add_argument("-n", "--limit", type=int, default=30)
    add("models", cmd_models, "available AI model backends")
    sp = add("cloud", cmd_cloud, "allow or block cloud AI models for this project")
    sp.add_argument("state", choices=["on", "off"])
    add("menu", cmd_menu, "interactive menu (same as running rp with no command)")
    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = load_config(args.config)
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
    except CLIError as exc:
        ui.fail(str(exc), exc.hint)
        sys.exit(1)
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        ui.fail(str(exc))
        sys.exit(1)
    except KeyboardInterrupt:
        console.print()
        sys.exit(130)


if __name__ == "__main__":
    main()
