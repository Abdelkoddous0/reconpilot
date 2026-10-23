"""Import results from recon tools you already run (subfinder, amass, dnsx, httpx, plain lists).

Every input line becomes one evidence record, so the AI analyst can cite the exact line behind a fact.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .scope import normalize_host
from .store import Store

FORMATS = ("auto", "subfinder", "amass", "dnsx", "httpx", "list")


@dataclass
class ImportSummary:
    format: str
    lines: int = 0
    evidence: int = 0
    entities: set[int] = field(default_factory=set)
    skipped: int = 0


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def detect_format(record: dict) -> str:
    if "url" in record and ("status_code" in record or "status-code" in record):
        return "httpx"
    if "addresses" in record and "name" in record:
        return "amass"
    if "host" in record and any(k in record for k in ("a", "aaaa", "cname", "status_code")):
        return "dnsx"
    if "host" in record and ("source" in record or "input" in record):
        return "subfinder"
    raise ValueError(f"cannot detect format from keys {sorted(record)}")


class Importer:
    def __init__(self, store: Store):
        self.store = store
        self.roots = sorted(store.scope.domains, key=len, reverse=True)

    # ---------- helpers ----------
    def _root_for(self, host: str) -> str | None:
        return next((r for r in self.roots if host == r or host.endswith("." + r)), None)

    def _host(self, host: str, ev: int, summary: ImportSummary) -> int | None:
        host = normalize_host(host)
        if not host:
            return None
        if _is_ip(host):
            eid = self.store.upsert_entity("ip", host, ev)
            summary.entities.add(eid)
            return eid
        root = self._root_for(host)
        if root == host:
            eid = self.store.upsert_entity("domain", host, ev)
        else:
            eid = self.store.upsert_entity("subdomain", host, ev)
            if root:
                rid = self.store.upsert_entity("domain", root, ev)
                self.store.add_relationship(rid, eid, "has_subdomain", ev)
                summary.entities.add(rid)
        summary.entities.add(eid)
        return eid

    def _link(self, src: int | None, rel: str, etype: str, value: str, ev: int, summary: ImportSummary) -> int | None:
        if src is None or not value:
            return None
        if etype in ("ip", "domain", "subdomain"):
            dst = self._host(value, ev, summary)
        else:
            dst = self.store.upsert_entity(etype, value, ev)
            summary.entities.add(dst)
        if dst is not None:
            self.store.add_relationship(src, dst, rel, ev)
        return dst

    # ---------- per-format handlers ----------
    def _subfinder(self, rec: dict, ev: int, s: ImportSummary) -> None:
        self._host(rec["host"], ev, s)

    def _amass(self, rec: dict, ev: int, s: ImportSummary) -> None:
        host = self._host(rec["name"], ev, s)
        for addr in rec.get("addresses") or []:
            self._link(host, "resolves_to", "ip", addr.get("ip", ""), ev, s)

    def _dnsx(self, rec: dict, ev: int, s: ImportSummary) -> None:
        host = self._host(rec["host"], ev, s)
        for ip in (rec.get("a") or []) + (rec.get("aaaa") or []):
            self._link(host, "resolves_to", "ip", ip, ev, s)
        for cname in rec.get("cname") or []:
            self._link(host, "cname", "subdomain", cname, ev, s)

    def _httpx(self, rec: dict, ev: int, s: ImportSummary) -> None:
        url = rec["url"]
        hostname = urlparse(url).hostname or rec.get("input", "")
        host = self._host(hostname, ev, s)
        url_id = self.store.upsert_entity("url", url, ev)
        s.entities.add(url_id)
        if host is not None:
            self.store.add_relationship(host, url_id, "serves", ev)
        for ip in rec.get("a") or ([rec["host"]] if _is_ip(str(rec.get("host", ""))) else []):
            self._link(host, "resolves_to", "ip", ip, ev, s)
        techs = list(rec.get("tech") or [])
        if rec.get("webserver"):
            techs.append(rec["webserver"])
        for tech in dict.fromkeys(techs):
            self._link(url_id, "runs", "technology", str(tech), ev, s)

    def _list(self, line: str, ev: int, s: ImportSummary) -> None:
        self._host(line, ev, s)

    # ---------- entry point ----------
    def import_file(self, path: str | Path, fmt: str = "auto") -> ImportSummary:
        if fmt not in FORMATS:
            raise ValueError(f"format must be one of {FORMATS}")
        path = Path(path)
        lines = [ln.strip() for ln in path.read_text(errors="replace").splitlines() if ln.strip()]
        if fmt == "auto":
            fmt = "list"
            for ln in lines:
                if ln.startswith("{"):
                    fmt = detect_format(json.loads(ln))
                    break
        summary = ImportSummary(format=fmt)
        handler = getattr(self, f"_{fmt}")
        for ln in lines:
            summary.lines += 1
            if fmt == "list":
                if ln.startswith("#"):
                    summary.skipped += 1
                    continue
                payload = ln
            else:
                try:
                    payload = json.loads(ln)
                except json.JSONDecodeError:
                    summary.skipped += 1
                    continue
            ev = self.store.add_evidence(f"import:{fmt}", path.name, payload)
            summary.evidence += 1
            try:
                handler(payload, ev, summary)
            except (KeyError, TypeError, AttributeError):
                summary.skipped += 1
        self.store.audit("user", "import", str(path),
                         json.dumps({"format": fmt, "lines": summary.lines, "evidence": summary.evidence}))
        return summary
