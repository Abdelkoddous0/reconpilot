"""Report export (Markdown or single-file HTML). Every finding links back to its evidence."""

from __future__ import annotations

import json
from html import escape

from .store import Store, now

REPORT_FORMATS = ("md", "html")
MAX_ROWS = 1000  # per entity table; the full list is one `rp export` away


def _collect(store: Store, include_drafts: bool) -> dict:
    meta = store.meta()
    scope = meta["scope"]
    statuses = ("validated", "draft") if include_drafts else ("validated",)
    findings = []
    for f in store.findings():
        if f["status"] not in statuses:
            continue
        ids = json.loads(f["evidence_ids"])
        evidence = [store.get_evidence(i) for i in ids]
        findings.append({"f": f, "ids": ids, "evidence": [e for e in evidence if e]})
    in_scope = lambda t: store.entities(etype=t, in_scope=True, limit=10**9)  # noqa: E731
    subjects = [f"{s['type']}: {s['value']}" for s in scope.get("subjects", [])]
    return {
        "meta": meta,
        "in_scope": scope["domains"] + scope["networks"] + subjects,
        "excluded": scope["exclude_domains"] + scope["exclude_networks"],
        "stats": store.stats(),
        "findings": findings,
        "hosts": in_scope("domain") + in_scope("subdomain"),
        "tech": store.entities(etype="technology", limit=10**9),
        "accounts": in_scope("account"),
        "emails": in_scope("email"),
        "jobs": store.jobs(),
    }


def _truncated(total: int) -> str:
    return (f"Showing {MAX_ROWS:,} of {total:,}. Full list: `rp export --format csv --in-scope`."
            if total > MAX_ROWS else "")


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "_None._\n"
    note = _truncated(len(rows))
    rows = rows[:MAX_ROWS]
    esc = lambda v: str(v).replace("|", "\\|").replace("\n", " ")  # noqa: E731
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]
    return "\n".join(lines) + "\n" + (f"\n_{note}_\n" if note else "")


def build_report(store: Store, include_drafts: bool = False) -> str:
    d = _collect(store, include_drafts)
    meta, stats = d["meta"], d["stats"]
    out = [f"# Reconnaissance report: {meta['name']}\n",
           f"- **Client:** {meta['client']}",
           f"- **Authorization:** {meta['auth_ref']}",
           f"- **Generated:** {now()}",
           f"- **In scope:** {', '.join(d['in_scope'])}",
           f"- **Out of scope:** {', '.join(d['excluded']) or 'none'}\n",
           "## Attack surface summary\n",
           _md_table(["Entity type", "Count (in scope)"],
                     [[k, str(v)] for k, v in sorted(stats["in_scope_entities"].items())]),
           f"Out-of-scope assets discovered but not investigated: {stats['out_of_scope_entities']}.\n",
           "## Findings\n"]
    if not d["findings"]:
        out.append("_No validated findings._\n")
    for item in d["findings"]:
        f = item["f"]
        label = "" if f["status"] == "validated" else " (DRAFT, not validated)"
        out += [f"### F{f['id']}: {f['title']}{label}\n",
                f"- **Severity:** {f['severity']}",
                f"- **Evidence:** {', '.join(f'E{i}' for i in item['ids'])}",
                f"- **Raised by:** {f['created_by']}\n",
                f"{f['description']}\n"]
        for ev in item["evidence"]:
            out.append(f"> E{ev['id']}: `{ev['module']}` from `{ev['query']}` at {ev['fetched_at']}, "
                       f"sha256 `{ev['sha256'][:16]}`\n")
    out += ["## Hosts\n", _md_table(["Host", "First seen"], [[h["value"], h["first_seen"]] for h in d["hosts"]])]
    if d["accounts"] or d["emails"]:
        out += ["\n## Accounts\n", _md_table(["Account", "First seen"],
                                            [[a["value"], a["first_seen"]] for a in d["accounts"]])]
        out += ["\n## Emails\n", _md_table(["Email", "First seen"],
                                          [[e["value"], e["first_seen"]] for e in d["emails"]])]
    out += ["\n## Technologies\n", _md_table(["Technology"], [[t["value"]] for t in d["tech"]])]
    out += ["\n## Recon steps\n", _md_table(
        ["Job", "Tool", "Target", "Status", "Reason"],
        [[f"J{j['id']}", j["module"], j["target"], j["status"], j["reason"] or ""] for j in d["jobs"]])]
    return "\n".join(out)


_CSS = """
:root { --bg:#fff; --fg:#1a1a1a; --muted:#666; --line:#ddd; --accent:#0b6bcb; --card:#f6f8fa; }
@media (prefers-color-scheme: dark) { :root { --bg:#111; --fg:#eee; --muted:#999; --line:#333; --card:#1b1f24; } }
body { background:var(--bg); color:var(--fg); font:15px/1.5 system-ui, sans-serif; max-width:960px;
       margin:0 auto; padding:24px 16px; }
h1 { font-size:26px; } h2 { border-bottom:1px solid var(--line); padding-bottom:4px; margin-top:32px; }
table { border-collapse:collapse; width:100%; margin:8px 0; } td, th { border-bottom:1px solid var(--line);
       padding:6px 8px; text-align:left; vertical-align:top; word-break:break-word; }
.meta td:first-child { color:var(--muted); width:160px; } .muted { color:var(--muted); }
.finding { background:var(--card); border-radius:8px; padding:12px 16px; margin:12px 0; }
.sev { font-weight:700; text-transform:uppercase; } .critical,.high { color:#d1242f; } .medium { color:#b58a00; }
.low { color:var(--accent); } code { font-size:13px; } .draft { color:#b58a00; }
"""


def _html_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return '<p class="muted">None.</p>'
    note = _truncated(len(rows))
    rows = rows[:MAX_ROWS]
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{escape(str(c))}</td>" for c in r) + "</tr>" for r in rows)
    return (f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
            + (f'<p class="muted">{escape(note)}</p>' if note else ""))


def build_html_report(store: Store, include_drafts: bool = False) -> str:
    d = _collect(store, include_drafts)
    meta, stats = d["meta"], d["stats"]
    meta_rows = [("Client", meta["client"]), ("Authorization", meta["auth_ref"]), ("Generated", now()),
                 ("In scope", ", ".join(d["in_scope"])), ("Out of scope", ", ".join(d["excluded"]) or "none")]
    parts = [f"<h1>Reconnaissance report: {escape(meta['name'])}</h1>",
             '<table class="meta">' + "".join(f"<tr><td>{escape(k)}</td><td>{escape(str(v))}</td></tr>"
                                              for k, v in meta_rows) + "</table>",
             "<h2>Attack surface summary</h2>",
             _html_table(["Entity type", "Count (in scope)"],
                         [[k, v] for k, v in sorted(stats["in_scope_entities"].items())]),
             f'<p class="muted">Out-of-scope assets discovered but not investigated: '
             f'{stats["out_of_scope_entities"]}.</p>',
             "<h2>Findings</h2>"]
    if not d["findings"]:
        parts.append('<p class="muted">No validated findings.</p>')
    for item in d["findings"]:
        f = item["f"]
        draft = '' if f["status"] == "validated" else ' <span class="draft">(draft, not validated)</span>'
        evidence = "".join(
            f"<li><code>E{e['id']}</code> {escape(e['module'])} from {escape(e['query'])} at {escape(e['fetched_at'])}"
            f", sha256 <code>{e['sha256'][:16]}</code><pre>{escape(e['raw'][:1500])}</pre></li>"
            for e in item["evidence"])
        parts.append(
            f'<div class="finding"><h3>F{f["id"]}: {escape(f["title"])}{draft}</h3>'
            f'<p><span class="sev {escape(f["severity"])}">{escape(f["severity"])}</span> · raised by '
            f'{escape(f["created_by"])}</p><p>{escape(f["description"] or "")}</p>'
            f'<details><summary>Evidence ({len(item["evidence"])})</summary><ul>{evidence}</ul></details></div>')
    parts += ["<h2>Hosts</h2>",
              _html_table(["Host", "First seen"], [[h["value"], h["first_seen"]] for h in d["hosts"]])]
    if d["accounts"] or d["emails"]:
        parts += ["<h2>Accounts</h2>", _html_table(["Account", "First seen"],
                                                   [[a["value"], a["first_seen"]] for a in d["accounts"]]),
                  "<h2>Emails</h2>", _html_table(["Email", "First seen"],
                                                 [[e["value"], e["first_seen"]] for e in d["emails"]])]
    parts += ["<h2>Technologies</h2>", _html_table(["Technology"], [[t["value"]] for t in d["tech"]]),
              "<h2>Recon steps</h2>", _html_table(
                  ["Job", "Tool", "Target", "Status", "Reason"],
                  [[f"J{j['id']}", j["module"], j["target"], j["status"], j["reason"] or ""] for j in d["jobs"]])]
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<title>{escape(meta["name"])} report</title><style>{_CSS}</style></head><body>'
            + "\n".join(parts) + "</body></html>\n")
