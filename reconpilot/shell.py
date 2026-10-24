"""Interactive arrow-key menu: `rp` with no arguments."""

from __future__ import annotations

from argparse import Namespace

import questionary

from . import cli, ui
from .playbook import load_playbooks
from .scope import SUBJECT_TYPES
from .store import ENTITY_TYPES, Store
from .tools import registry

STYLE = questionary.Style([
    ("qmark", "fg:cyan bold"),
    ("pointer", "fg:cyan bold"),
    ("highlighted", "fg:cyan bold"),
    ("selected", "fg:green"),
    ("answer", "fg:green bold"),
])


def _ns(**kwargs) -> Namespace:
    return Namespace(**kwargs)


def _pick_project(app: cli.App) -> None:
    names = Store.list_projects(app.data_dir)
    if not names:
        ui.warn("no projects yet")
        return
    name = questionary.select("Switch to project:", choices=names, default=app.active() or names[0],
                              style=STYLE).ask()
    if name:
        cli.cmd_use(app, _ns(name=name))


def _import(app: cli.App) -> None:
    path = questionary.path("File to import (output of any tool in `rp tools`, or a host list):",
                            style=STYLE).ask()
    if path:
        cli.cmd_import(app, _ns(files=[path.strip()], format="auto", ignore_window=False))


def _run_tool(app: cli.App) -> None:
    choices = []
    for name, adapter in registry().items():
        if adapter.runnable:
            status = adapter.check()
            label = f"{name:<13} {adapter.description}" + ("" if status.ok else f"  ({status.problem})")
            choices.append(questionary.Choice(label, value=name, disabled=None if status.ok else "not ready"))
    if not choices:
        ui.warn("no runnable tools")
        return
    tool = questionary.select("Tool:", choices=choices, style=STYLE).ask()
    if not tool:
        return
    target = questionary.text(f"Target ({', '.join(registry()[tool].accepts)}):", style=STYLE).ask()
    if target and target.strip():
        cli.cmd_run(app, _ns(what=tool, target=target.strip(), type=None, yes=False, model=None))


def _run_playbook(app: cli.App) -> None:
    playbooks = load_playbooks(app.cfg)
    if not playbooks:
        ui.warn("no playbooks found")
        return
    name = questionary.select("Playbook:", choices=[questionary.Choice(f"{pb.name:<16} {pb.description}", value=n)
                                                    for n, pb in playbooks.items()], style=STYLE).ask()
    if not name:
        return
    target = questionary.text(f"Target ({playbooks[name].input}):", style=STYLE).ask()
    if target and target.strip():
        cli.cmd_run(app, _ns(what=name, target=target.strip(), type=None, yes=False, model=None))


def _seed(app: cli.App) -> None:
    stype = questionary.select("Subject type:", choices=list(SUBJECT_TYPES), style=STYLE).ask()
    if not stype:
        return
    value = questionary.text(f"{stype} to add to scope:", style=STYLE).ask()
    if value and value.strip():
        note = questionary.text("Why is this subject authorized? (optional):", style=STYLE).ask()
        cli.cmd_seed(app, _ns(type=stype, values=[value.strip()], note=note or ""))


def _search(app: cli.App) -> None:
    etype = questionary.select("Type:", choices=["all", *ENTITY_TYPES], style=STYLE).ask()
    if etype is None:
        return
    text = questionary.text("Contains (empty for everything):", style=STYLE).ask()
    cli.cmd_search(app, _ns(text=text or None, type=None if etype == "all" else etype, out=False, all=False,
                            json=False))


def _review_findings(app: cli.App) -> None:
    drafts = [f for f in app.store.findings() if f["status"] == "draft"]
    cli.cmd_findings(app, _ns(all=False))
    if not drafts:
        return
    choices = [questionary.Choice(f"F{f['id']}  [{f['severity']}] {f['title']}", value=f"F{f['id']}")
               for f in drafts]
    picked = questionary.checkbox("Select drafts to review (space to select, enter to confirm):",
                                  choices=choices, style=STYLE).ask()
    if not picked:
        return
    action = questionary.select("Mark selected as:", choices=["accept", "reject", "cancel"], style=STYLE).ask()
    if action == "accept":
        cli._finding_status("validated")(app, _ns(ids=picked))
    elif action == "reject":
        cli._finding_status("rejected")(app, _ns(ids=picked))


def _review_steps(app: cli.App) -> None:
    pending = app.store.jobs("suggested")
    cli.cmd_steps(app, _ns(all=False))
    if not pending:
        return
    choices = [questionary.Choice(f"J{j['id']}  {j['module']} → {j['target']}", value=f"J{j['id']}")
               for j in pending]
    picked = questionary.checkbox("Select steps:", choices=choices, style=STYLE).ask()
    if not picked:
        return
    action = questionary.select("Mark selected as:", choices=["approve", "deny", "cancel"], style=STYLE).ask()
    if action in ("approve", "deny"):
        cli._step_status("approved" if action == "approve" else "denied")(app, _ns(ids=picked))
    if action == "approve" and questionary.confirm("Run the approved steps now?", default=True,
                                                   style=STYLE).ask():
        for ref in picked:
            try:
                cli.cmd_run(app, _ns(what=ref, target=None, type=None, yes=False, model=None))
            except cli.RunError as exc:
                ui.fail(f"{ref}: {exc}", exc.hint)


MENU = [
    ("Dashboard", lambda app: cli.cmd_status(app, _ns(json=False))),
    ("Run a tool", _run_tool),
    ("Run a playbook", _run_playbook),
    ("Import tool output", _import),
    ("Add a person to investigate", _seed),
    ("Search assets", _search),
    ("AI triage", lambda app: cli.cmd_triage(app, _ns(model=None))),
    ("Chat with the AI analyst", lambda app: cli.cmd_chat(app, _ns(model=None))),
    ("Review findings", _review_findings),
    ("Review suggested steps", _review_steps),
    ("Write report", lambda app: cli.cmd_report(app, _ns(output=None, drafts=False, format="html"))),
    ("Scope", lambda app: cli.cmd_scope(app, _ns(action="show", json=False))),
    ("Tools and setup check", lambda app: cli.cmd_doctor(app, _ns())),
    ("Audit log", lambda app: cli.cmd_log(app, _ns(limit=30))),
    ("AI models", lambda app: cli.cmd_models(app, _ns())),
    ("Switch project", _pick_project),
    ("New project", lambda app: cli.cmd_new(app, _ns(name=None, client=None, auth_ref=None, scope=None,
                                                     exclude=None, seed=None, start=None, end=None,
                                                     allow_cloud=False, passive_only=False))),
    ("Quit", None),
]


def run_menu(app: cli.App) -> None:
    ui.console.print(ui.BANNER + "\n")
    actions = dict(MENU)
    while True:
        try:
            current = app.project_name()
        except cli.CLIError:
            current = None
        title = f"[{current}]" if current else "[no project]"
        choice = questionary.select(f"{title} What do you want to do?", choices=[name for name, _ in MENU],
                                    style=STYLE, qmark="◆").ask()
        action = actions.get(choice) if choice else None
        if action is None:
            return
        try:
            action(app)
        except (cli.CLIError, cli.RunError) as exc:
            ui.fail(str(exc), exc.hint)
        except (cli.ScopeError, FileNotFoundError, FileExistsError, ValueError) as exc:
            ui.fail(str(exc))
        except KeyboardInterrupt:
            pass
        ui.console.print()
