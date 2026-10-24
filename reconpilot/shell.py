"""Interactive arrow-key menu: `rp` with no arguments."""

from __future__ import annotations

from argparse import Namespace

import questionary

from . import cli, ui
from .store import Store

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
    path = questionary.path("File to import (subfinder / amass / dnsx / httpx JSON, or a host list):",
                            style=STYLE).ask()
    if path:
        cli.cmd_import(app, _ns(files=[path.strip()], format="auto"))


def _search(app: cli.App) -> None:
    etype = questionary.select("Type:", choices=["all", "domain", "subdomain", "ip", "url", "technology"],
                               style=STYLE).ask()
    if etype is None:
        return
    text = questionary.text("Contains (empty for everything):", style=STYLE).ask()
    cli.cmd_search(app, _ns(text=text or None, type=None if etype == "all" else etype, out=False, all=False))


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


MENU = [
    ("Dashboard", lambda app: cli.cmd_status(app, _ns())),
    ("Import tool output", _import),
    ("Search assets", _search),
    ("AI triage", lambda app: cli.cmd_triage(app, _ns(model=None))),
    ("Chat with the AI analyst", lambda app: cli.cmd_chat(app, _ns(model=None))),
    ("Review findings", _review_findings),
    ("Review suggested steps", _review_steps),
    ("Write report", lambda app: cli.cmd_report(app, _ns(output=None, drafts=False))),
    ("Audit log", lambda app: cli.cmd_log(app, _ns(limit=30))),
    ("AI models", lambda app: cli.cmd_models(app, _ns())),
    ("Switch project", _pick_project),
    ("New project", lambda app: cli.cmd_new(app, _ns(name=None, client=None, auth_ref=None, scope=None,
                                                     exclude=None, start=None, end=None, allow_cloud=False))),
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
        if choice in (None, "Quit"):
            return
        try:
            actions[choice](app)
        except cli.CLIError as exc:
            ui.fail(str(exc), exc.hint)
        except (FileNotFoundError, FileExistsError, ValueError) as exc:
            ui.fail(str(exc))
        except KeyboardInterrupt:
            pass
        ui.console.print()
