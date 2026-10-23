"""Terminal rendering: theme, tables, panels and the project dashboard."""

from __future__ import annotations

import json

from rich import box
from rich.columns import Columns
from rich.console import Console, Group
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from .store import Store

THEME = Theme({
    "brand": "bold cyan",
    "ok": "green",
    "warn": "yellow",
    "bad": "bold red",
    "muted": "grey50",
    "id": "bold magenta",
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "grey62",
})

console = Console(theme=THEME, highlight=False)

BANNER = "[brand]◆ ReconPilot[/]  [muted]local-first OSINT workbench · AI analyst · evidence-cited[/]"


def ok(msg: str) -> None:
    console.print(f"[ok]✔[/] {msg}")


def warn(msg: str) -> None:
    console.print(f"[warn]![/] {msg}")


def fail(msg: str, hint: str | None = None) -> None:
    console.print(f"[bad]✖ {msg}[/]")
    if hint:
        console.print(f"  [muted]hint:[/] {hint}")


def hint(msg: str) -> None:
    console.print(f"[muted]→ {msg}[/]")


def table(*columns: str, title: str | None = None) -> Table:
    t = Table(*columns, title=title, box=box.SIMPLE_HEAVY, header_style="bold", title_style="bold",
              title_justify="left", pad_edge=False)
    return t


def sev(severity: str) -> Text:
    return Text(severity.upper(), style=severity)


def markdown(text: str) -> None:
    console.print(Markdown(text))


def projects_table(names: list[str], active: str | None) -> Table:
    t = table("", "Project")
    for name in names:
        t.add_row("[ok]●[/]" if name == active else " ", f"[bold]{name}[/]" if name == active else name)
    return t


def entities_table(store: Store, rows) -> Table:
    t = table("ID", "Type", "Value", "Scope", "Evidence")
    for r in rows:
        ev = ", ".join(f"E{i}" for i in store.entity_evidence_ids(r["id"])[:4])
        scope = "[ok]in[/]" if r["in_scope"] else "[warn]out[/]"
        t.add_row(f"[id]N{r['id']}[/]", r["type"], r["value"], scope, f"[muted]{ev}[/]")
    return t


def findings_table(rows) -> Table:
    t = table("ID", "Severity", "Title", "Status", "Evidence", "By")
    for f in rows:
        ev = ", ".join(f"E{i}" for i in json.loads(f["evidence_ids"]))
        status = {"validated": "[ok]accepted[/]", "rejected": "[muted]rejected[/]"}.get(f["status"], "[warn]draft[/]")
        t.add_row(f"[id]F{f['id']}[/]", sev(f["severity"]), f["title"], status, f"[muted]{ev}[/]", f["created_by"])
    return t


def steps_table(rows) -> Table:
    t = table("ID", "Step", "Target", "Status", "Why")
    colors = {"suggested": "warn", "approved": "ok", "done": "muted", "denied": "muted"}
    for j in rows:
        style = colors.get(j["status"], "")
        t.add_row(f"[id]J{j['id']}[/]", j["module"], j["target"], f"[{style}]{j['status']}[/]", j["reason"] or "")
    return t


def dashboard(store: Store, model_spec: str) -> Panel:
    meta = store.meta()
    scope = meta["scope"]
    stats = store.stats()
    counts = stats["in_scope_entities"]

    header = Table.grid(padding=(0, 2))
    header.add_column(style="muted")
    header.add_column()
    header.add_row("Client", meta["client"])
    header.add_row("Authorization", meta["auth_ref"])
    header.add_row("In scope", ", ".join(scope["domains"] + scope["networks"]))
    header.add_row("Excluded", ", ".join(scope["exclude_domains"] + scope["exclude_networks"]) or "[muted]none[/]")
    if scope.get("start") or scope.get("end"):
        header.add_row("Window", f"{scope.get('start') or '…'} → {scope.get('end') or '…'}")
    cloud = "[warn]allowed[/]" if meta["allow_cloud"] else "[ok]blocked (local only)[/]"
    header.add_row("Cloud AI", cloud)
    header.add_row("Model", model_spec)

    def tile(label: str, value: int, style: str = "bold") -> Panel:
        return Panel(Text(str(value), style=style, justify="center"), title=label, width=14, box=box.ROUNDED)

    findings = store.findings()
    open_findings = [f for f in findings if f["status"] == "draft"]
    pending = store.jobs("suggested")
    tiles = Columns([
        tile("domains", counts.get("domain", 0) + counts.get("subdomain", 0)),
        tile("IPs", counts.get("ip", 0)),
        tile("URLs", counts.get("url", 0)),
        tile("tech", counts.get("technology", 0)),
        tile("evidence", stats["evidence_records"], "muted"),
        tile("outside", stats["out_of_scope_entities"], "warn"),
    ])

    parts = [header, Text(), tiles]
    if findings:
        parts += [Text(), findings_table(findings[:6])]
    if pending:
        parts += [Text(), steps_table(pending[:5])]

    next_steps = []
    if stats["evidence_records"] == 0:
        next_steps.append("rp import <file>   load subfinder / amass / dnsx / httpx output")
    else:
        next_steps.append("rp triage          let the AI analyst review the attack surface")
        next_steps.append("rp chat            ask the analyst questions")
    if open_findings:
        next_steps.append(f"rp accept F{open_findings[0]['id']}       review draft findings")
    if pending:
        next_steps.append(f"rp approve J{pending[0]['id']}      review suggested steps")
    parts += [Text(), Text("Next", style="bold"), *[Text("  " + s, style="muted") for s in next_steps]]

    return Panel(Group(*parts), title=f"[brand]◆ {meta['name']}[/]", border_style="cyan",
                 box=box.ROUNDED, padding=(1, 2))
