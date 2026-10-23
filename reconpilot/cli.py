"""ReconPilot command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from .ai.analyst import TRIAGE_PROMPT, Analyst, AnalystError
from .ai.providers import ProviderError, check_provider, get_provider, resolve_spec
from .config import load_config
from .importers import FORMATS, Importer
from .report import build_report
from .scope import Scope
from .store import Store, parse_ref

console = Console()


def _store(args, cfg) -> Store:
    return Store.open_project(cfg["data_dir"], args.project)


def cmd_init(args, cfg):
    scope = Scope.from_entries(args.scope, args.exclude,
                               start=date.fromisoformat(args.start) if args.start else None,
                               end=date.fromisoformat(args.end) if args.end else None)
    store = Store.create_project(cfg["data_dir"], args.project, client=args.client, auth_ref=args.auth_ref,
                                 scope=scope, allow_cloud=args.allow_cloud)
    console.print(f"[green]Created project[/] {args.project} at {store.path}")
    console.print(f"Cloud models: {'allowed' if args.allow_cloud else 'blocked (local models only)'}")


def cmd_projects(args, cfg):
    for name in Store.list_projects(cfg["data_dir"]):
        console.print(name)


def cmd_show(args, cfg):
    store = _store(args, cfg)
    meta = store.meta()
    console.print_json(json.dumps({**meta, "stats": store.stats()}))


def cmd_set(args, cfg):
    store = _store(args, cfg)
    if args.key != "allow_cloud":
        sys.exit("only 'allow_cloud' can be changed")
    store.set_meta("allow_cloud", args.value.lower() in ("1", "true", "yes"))
    console.print(f"allow_cloud = {store.meta()['allow_cloud']}")


def cmd_import(args, cfg):
    store = _store(args, cfg)
    summary = Importer(store).import_file(args.file, args.format)
    console.print(f"[green]Imported[/] {args.file} as {summary.format}: {summary.lines} lines, "
                  f"{summary.evidence} evidence records, {len(summary.entities)} entities, "
                  f"{summary.skipped} skipped")


def cmd_entities(args, cfg):
    store = _store(args, cfg)
    rows = store.entities(etype=args.type, query=args.search,
                          in_scope=None if args.all else (False if args.out_of_scope else True))
    table = Table("ID", "Type", "Value", "In scope", "Evidence")
    for r in rows:
        ev = ", ".join(f"E{i}" for i in store.entity_evidence_ids(r["id"])[:5])
        table.add_row(f"N{r['id']}", r["type"], r["value"], "yes" if r["in_scope"] else "no", ev)
    console.print(table)


def cmd_evidence(args, cfg):
    store = _store(args, cfg)
    row = store.get_evidence(parse_ref(args.evidence_id, "E"))
    if not row:
        sys.exit("no such evidence")
    console.print(f"E{row['id']}  module={row['module']}  source={row['query']}  "
                  f"fetched_at={row['fetched_at']}\nsha256={row['sha256']}")
    console.print(row["raw"], markup=False, highlight=False)


def _run_analyst(args, cfg, question: str, profile: str):
    store = _store(args, cfg)
    spec = resolve_spec(cfg, args.model, profile)
    try:
        provider = get_provider(spec, cfg, allow_cloud=store.meta()["allow_cloud"])
        with console.status(f"Analyst thinking with {spec}..."):
            result = Analyst(store, provider, cfg).ask(question)
    except (ProviderError, AnalystError) as exc:
        sys.exit(f"error: {exc}")
    console.print(Markdown(result.answer))
    console.print(f"\n[dim]model {result.model} · {result.steps} steps · {len(result.tool_calls)} tool calls · "
                  f"{len(result.claims)} cited claims[/]")
    if not result.validated:
        console.print("[red]Warning: this answer failed the citation check. Treat it as unverified.[/]")


def cmd_ask(args, cfg):
    _run_analyst(args, cfg, args.question, "analyst")


def cmd_triage(args, cfg):
    _run_analyst(args, cfg, TRIAGE_PROMPT, "triage")


def cmd_jobs(args, cfg):
    store = _store(args, cfg)
    table = Table("ID", "Step", "Target", "By", "Status", "Reason")
    for j in store.jobs(args.status):
        table.add_row(f"J{j['id']}", j["module"], j["target"], j["requested_by"], j["status"], j["reason"] or "")
    console.print(table)


def _set_job(args, cfg, status: str):
    store = _store(args, cfg)
    job_id = parse_ref(args.job_id, "J")
    if not store.get_job(job_id):
        sys.exit("no such job")
    store.update_job(job_id, status=status, approved_by="user" if status == "approved" else None)
    store.audit("user", f"job.{status}", f"J{job_id}")
    console.print(f"J{job_id} -> {status}")


def cmd_findings(args, cfg):
    store = _store(args, cfg)
    table = Table("ID", "Severity", "Title", "Status", "Evidence", "By")
    for f in store.findings(args.status):
        ev = ", ".join(f"E{i}" for i in json.loads(f["evidence_ids"]))
        table.add_row(f"F{f['id']}", f["severity"], f["title"], f["status"], ev, f["created_by"])
    console.print(table)


def _set_finding(args, cfg, status: str):
    store = _store(args, cfg)
    store.set_finding_status(parse_ref(args.finding_id, "F"), status)
    console.print(f"{args.finding_id} -> {status}")


def cmd_report(args, cfg):
    store = _store(args, cfg)
    text = build_report(store, include_drafts=args.drafts)
    if args.output:
        Path(args.output).write_text(text)
        console.print(f"[green]Report written to[/] {args.output}")
    else:
        console.print(Markdown(text))


def cmd_audit(args, cfg):
    store = _store(args, cfg)
    table = Table("Time", "Actor", "Action", "Target", "Detail")
    for a in reversed(store.audit_entries(args.limit)):
        table.add_row(a["ts"], a["actor"], a["action"], a["target"] or "", (a["detail"] or "")[:80])
    console.print(table)


def cmd_models(args, cfg):
    models = cfg["models"]
    table = Table("Provider", "Type", "Runs", "Status")
    for name, pcfg in sorted(models["providers"].items()):
        table.add_row(name, pcfg.get("type", "?"), "local" if pcfg.get("local") else "cloud",
                      check_provider(name, pcfg))
    console.print(table)
    console.print(f"default: {models['default']}")
    for profile, spec in models.get("profiles", {}).items():
        console.print(f"profile {profile}: {spec}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="reconpilot", description="Local-first OSINT workbench with an AI analyst")
    p.add_argument("--config", help="path to reconpilot.yaml")
    p.add_argument("--data-dir", help="override the data directory")
    sub = p.add_subparsers(dest="command", required=True)

    def cmd(name, func, help_text, project=True):
        sp = sub.add_parser(name, help=help_text)
        if project:
            sp.add_argument("project")
        sp.set_defaults(func=func)
        return sp

    sp = cmd("init", cmd_init, "create an engagement (requires authorization and scope)")
    sp.add_argument("--client", required=True)
    sp.add_argument("--auth-ref", required=True, help="SoW / RoE reference or bug bounty program URL")
    sp.add_argument("--scope", action="append", required=True, help="in-scope domain or CIDR (repeatable)")
    sp.add_argument("--exclude", action="append", default=[], help="out-of-scope domain or CIDR (repeatable)")
    sp.add_argument("--start", help="engagement start date YYYY-MM-DD")
    sp.add_argument("--end", help="engagement end date YYYY-MM-DD")
    sp.add_argument("--allow-cloud", action="store_true", help="allow cloud AI models for this project")

    cmd("projects", cmd_projects, "list projects", project=False)
    cmd("show", cmd_show, "show project details and stats")
    sp = cmd("set", cmd_set, "change a project setting")
    sp.add_argument("key", choices=["allow_cloud"])
    sp.add_argument("value")

    sp = cmd("import", cmd_import, "import recon tool output")
    sp.add_argument("file")
    sp.add_argument("--format", choices=FORMATS, default="auto")

    sp = cmd("entities", cmd_entities, "list entities")
    sp.add_argument("--type")
    sp.add_argument("--search")
    sp.add_argument("--out-of-scope", action="store_true")
    sp.add_argument("--all", action="store_true")

    sp = cmd("evidence", cmd_evidence, "show one evidence record")
    sp.add_argument("evidence_id")

    for name, func, text in (("ask", cmd_ask, "ask the AI analyst a question"),
                             ("triage", cmd_triage, "let the AI analyst triage the attack surface")):
        sp = cmd(name, func, text)
        if name == "ask":
            sp.add_argument("question")
        sp.add_argument("--model", help="model spec (provider:model) or profile name")

    sp = cmd("jobs", cmd_jobs, "list suggested recon steps")
    sp.add_argument("--status")
    for name, status in (("approve", "approved"), ("deny", "denied"), ("done", "done")):
        sp = cmd(name, lambda a, c, s=status: _set_job(a, c, s), f"mark a suggested step {status}")
        sp.add_argument("job_id")

    sp = cmd("findings", cmd_findings, "list findings")
    sp.add_argument("--status")
    for name, status in (("validate", "validated"), ("reject", "rejected")):
        sp = cmd(name, lambda a, c, s=status: _set_finding(a, c, s), f"mark a finding {status}")
        sp.add_argument("finding_id")

    sp = cmd("report", cmd_report, "export a Markdown report")
    sp.add_argument("-o", "--output")
    sp.add_argument("--drafts", action="store_true", help="include unvalidated draft findings")

    sp = cmd("audit", cmd_audit, "show the audit log")
    sp.add_argument("--limit", type=int, default=50)

    cmd("models", cmd_models, "list model providers and their status", project=False)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    cfg = load_config(args.config)
    if args.data_dir:
        cfg["data_dir"] = args.data_dir
    try:
        args.func(args, cfg)
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        sys.exit(f"error: {exc}")


if __name__ == "__main__":
    main()
