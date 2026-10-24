"""Export the entity graph for other tools: JSON (scripts), CSV (spreadsheets), GraphML (Gephi, yEd, Maltego)."""

from __future__ import annotations

import csv
import io
import json
from xml.sax.saxutils import escape, quoteattr

from .store import Store

EXPORT_FORMATS = ("json", "csv", "graphml")


def entity_dict(store: Store, row) -> dict:
    return {"id": f"N{row['id']}", "type": row["type"], "value": row["value"], "in_scope": bool(row["in_scope"]),
            "first_seen": row["first_seen"], "last_seen": row["last_seen"],
            "evidence": [f"E{i}" for i in store.entity_evidence_ids(row["id"])]}


def to_json(store: Store, in_scope_only: bool = False) -> str:
    rows = store.entities(in_scope=True if in_scope_only else None, limit=10**9)
    ids = {r["id"] for r in rows}
    meta = store.meta()
    return json.dumps({
        "project": {k: meta[k] for k in ("name", "client", "auth_ref", "scope")},
        "entities": [entity_dict(store, r) for r in rows],
        "relationships": [{"src": f"N{r['src_id']}", "dst": f"N{r['dst_id']}", "type": r["type"],
                           "evidence": f"E{r['evidence_id']}"}
                          for r in store.relationships() if r["src_id"] in ids and r["dst_id"] in ids],
        "findings": [{"id": f"F{f['id']}", "title": f["title"], "severity": f["severity"], "status": f["status"],
                      "evidence": [f"E{i}" for i in json.loads(f["evidence_ids"])], "description": f["description"]}
                     for f in store.findings()],
    }, indent=2)


def to_csv(store: Store, in_scope_only: bool = False) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "type", "value", "in_scope", "first_seen", "last_seen", "evidence"])
    for r in store.entities(in_scope=True if in_scope_only else None, limit=10**9):
        d = entity_dict(store, r)
        writer.writerow([d["id"], d["type"], d["value"], int(d["in_scope"]), d["first_seen"], d["last_seen"],
                         " ".join(d["evidence"])])
    return buf.getvalue()


def to_graphml(store: Store, in_scope_only: bool = False) -> str:
    rows = store.entities(in_scope=True if in_scope_only else None, limit=10**9)
    ids = {r["id"] for r in rows}
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
           '  <key id="type" for="node" attr.name="type" attr.type="string"/>',
           '  <key id="value" for="node" attr.name="value" attr.type="string"/>',
           '  <key id="in_scope" for="node" attr.name="in_scope" attr.type="boolean"/>',
           '  <key id="rel" for="edge" attr.name="relation" attr.type="string"/>',
           '  <key id="evidence" for="edge" attr.name="evidence" attr.type="string"/>',
           '  <graph id="reconpilot" edgedefault="directed">']
    for r in rows:
        out += [f'    <node id="N{r["id"]}">',
                f'      <data key="type">{escape(r["type"])}</data>',
                f'      <data key="value">{escape(r["value"])}</data>',
                f'      <data key="in_scope">{"true" if r["in_scope"] else "false"}</data>',
                '    </node>']
    for rel in store.relationships():
        if rel["src_id"] in ids and rel["dst_id"] in ids:
            out += [f'    <edge id={quoteattr("R" + str(rel["id"]))} source="N{rel["src_id"]}" '
                    f'target="N{rel["dst_id"]}">',
                    f'      <data key="rel">{escape(rel["type"])}</data>',
                    f'      <data key="evidence">E{rel["evidence_id"]}</data>',
                    '    </edge>']
    out += ["  </graph>", "</graphml>"]
    return "\n".join(out) + "\n"


def export(store: Store, fmt: str, in_scope_only: bool = False) -> str:
    if fmt not in EXPORT_FORMATS:
        raise ValueError(f"format must be one of {EXPORT_FORMATS}")
    return {"json": to_json, "csv": to_csv, "graphml": to_graphml}[fmt](store, in_scope_only)
