"""Markdown report export. Every finding links back to its evidence."""

from __future__ import annotations

import json

from .store import Store, now


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "_None._\n"
    esc = lambda v: str(v).replace("|", "\\|").replace("\n", " ")  # noqa: E731
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]
    return "\n".join(lines) + "\n"


def build_report(store: Store, include_drafts: bool = False) -> str:
    meta = store.meta()
    scope = meta["scope"]
    stats = store.stats()
    out = [f"# Reconnaissance report: {meta['name']}\n",
           f"- **Client:** {meta['client']}",
           f"- **Authorization:** {meta['auth_ref']}",
           f"- **Generated:** {now()}",
           f"- **In scope:** {', '.join(scope['domains'] + scope['networks'])}",
           f"- **Out of scope:** {', '.join(scope['exclude_domains'] + scope['exclude_networks']) or 'none'}\n",
           "## Attack surface summary\n",
           _table(["Entity type", "Count (in scope)"],
                  [[k, str(v)] for k, v in sorted(stats["in_scope_entities"].items())]),
           f"Out-of-scope assets discovered but not investigated: {stats['out_of_scope_entities']}.\n"]

    statuses = ("validated", "draft") if include_drafts else ("validated",)
    findings = [f for f in store.findings() if f["status"] in statuses]
    out.append("## Findings\n")
    if not findings:
        out.append("_No validated findings._\n")
    for f in findings:
        ids = json.loads(f["evidence_ids"])
        label = "" if f["status"] == "validated" else " (DRAFT, not validated)"
        out += [f"### F{f['id']}: {f['title']}{label}\n",
                f"- **Severity:** {f['severity']}",
                f"- **Evidence:** {', '.join(f'E{i}' for i in ids)}",
                f"- **Raised by:** {f['created_by']}\n",
                f"{f['description']}\n"]
        for i in ids:
            ev = store.get_evidence(i)
            if ev:
                out.append(f"> E{i}: `{ev['module']}` from `{ev['query']}` at {ev['fetched_at']}, "
                           f"sha256 `{ev['sha256'][:16]}`\n")

    out.append("## Hosts\n")
    hosts = store.entities(etype="subdomain", in_scope=True) + store.entities(etype="domain", in_scope=True)
    out.append(_table(["Host", "First seen"], [[h["value"], h["first_seen"]] for h in hosts]))
    out.append("\n## Technologies\n")
    out.append(_table(["Technology"], [[t["value"]] for t in store.entities(etype="technology")]))
    out.append("\n## Recommended next steps\n")
    jobs = store.jobs()
    out.append(_table(["Job", "Step", "Target", "Status", "Reason"],
                      [[f"J{j['id']}", j["module"], j["target"], j["status"], j["reason"] or ""] for j in jobs]))
    return "\n".join(out)
