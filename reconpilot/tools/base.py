"""Tool adapter interface. One adapter per external tool: how to check it, run it and parse its output.

To add a tool, subclass ToolAdapter, set its class attributes, implement handle() (and command()
if it can be run), then register it in reconpilot/tools/__init__.py or through the
`reconpilot.tools` entry point group from your own package.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..scope import DERIVED_TYPES, normalize_host
from ..store import Store

_VERSION_RE = re.compile(r"v?(\d+\.\d+(?:\.\d+)?)")
_LABELLED_VERSION_RE = re.compile(r"[Vv]ersion:?\s*v?(\d+\.\d+(?:\.\d+)?)")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


@dataclass
class ToolStatus:
    installed: bool
    path: str | None = None
    version: str | None = None
    problem: str | None = None

    @property
    def ok(self) -> bool:
        return self.installed and not self.problem


@dataclass
class ImportSummary:
    format: str
    lines: int = 0
    evidence: int = 0          # new evidence records
    duplicates: int = 0        # records already stored by an earlier import
    entities: set[int] = field(default_factory=set)
    skipped: int = 0


class ImportContext:
    """What a parser may do with the store: add entities and link them, always citing one evidence ID."""

    def __init__(self, store: Store, summary: ImportSummary):
        self.store = store
        self.summary = summary
        self.roots = sorted(store.scope.domains, key=len, reverse=True)
        self.touched: set[int] = set()

    def _root_for(self, host: str) -> str | None:
        return next((r for r in self.roots if host == r or host.endswith("." + r)), None)

    def entity(self, etype: str, value: str, ev: int, in_scope: bool | None = None) -> int | None:
        if value is None or not str(value).strip():
            return None
        eid = self.store.upsert_entity(etype, str(value), ev, in_scope=in_scope)
        self.touched.add(eid)
        return eid

    def host(self, value: str, ev: int) -> int | None:
        """Add a hostname or IP, linking subdomains to their in-scope root domain."""
        host = normalize_host(str(value or ""))
        if not host:
            return None
        if is_ip(host):
            return self.entity("ip", host, ev)
        root = self._root_for(host)
        if root == host:
            return self.entity("domain", host, ev)
        eid = self.entity("subdomain", host, ev)
        if root:
            self.relate(self.entity("domain", root, ev), eid, "has_subdomain", ev)
        return eid

    def relate(self, src: int | None, dst: int | None, rel: str, ev: int) -> None:
        if src is not None and dst is not None and src != dst:
            self.store.add_relationship(src, dst, rel, ev)

    def link(self, src: int | None, rel: str, etype: str, value: Any, ev: int) -> int | None:
        """Add an entity and a relationship from src to it. Derived types inherit src's scope."""
        if src is None or value is None or not str(value).strip():
            return None
        if etype in ("ip", "domain", "subdomain"):
            dst = self.host(str(value), ev)
        else:
            inherit = None
            if etype in DERIVED_TYPES:
                row = self.store.get_entity(src)
                inherit = bool(row and row["in_scope"])
            dst = self.entity(etype, str(value), ev, in_scope=inherit)
        self.relate(src, dst, rel, ev)
        return dst


class ToolAdapter:
    name: str = ""
    description: str = ""
    homepage: str = ""
    binary: str | None = None            # None = import-only (no runner support)
    accepts: tuple[str, ...] = ()        # target types for `rp run`: domain, username, email, ...
    produces: tuple[str, ...] = ()
    tier: str = "passive"                # passive | low_touch | active
    install_hint: str = ""
    record_format: str = "jsonl"         # jsonl | csv | lines | json
    output_glob: str = "*"               # files in the run directory to parse
    version_args: tuple[str, ...] = ("--version",)
    tested_version: str = ""             # version the parser was written against
    timeout: int = 900

    # ---------- detection and parsing ----------
    def sniff(self, first_line: str, path: Path) -> bool:
        """True if this file looks like this tool's output."""
        return False

    def records(self, path: Path) -> Iterator[Any]:
        """Yield one payload per evidence record; None marks an unreadable record (counted as skipped)."""
        text = path.read_text(errors="replace")
        if self.record_format == "jsonl":
            for line in text.splitlines():
                if line.strip():
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        yield None
        elif self.record_format == "csv":
            yield from csv.DictReader(io.StringIO(text))
        elif self.record_format == "lines":
            for line in text.splitlines():
                line = line.strip()
                if line:
                    yield None if line.startswith("#") else line
        elif self.record_format == "json":
            yield from self.split_document(json.loads(text))
        else:
            raise ValueError(f"unknown record format {self.record_format!r}")

    def split_document(self, doc: Any) -> Iterator[Any]:
        """For single-document JSON output: break it into small records, one per fact."""
        yield doc

    def handle(self, ctx: ImportContext, record: Any, ev: int) -> None:
        raise NotImplementedError

    # ---------- running ----------
    @property
    def runnable(self) -> bool:
        return self.binary is not None

    def prepare(self, target: str, outdir: Path, options: dict) -> None:
        """Write any input files the command needs (e.g. a target list)."""

    def command(self, target: str, outdir: Path, options: dict) -> list[str]:
        raise NotImplementedError(f"{self.name} cannot be run, only imported")

    def output_files(self, outdir: Path, target: str) -> list[Path]:
        return sorted(p for p in outdir.glob(self.output_glob) if p.is_file() and p.stat().st_size)

    def verify(self, version_output: str) -> str | None:
        """Return a problem if the binary on PATH is not the expected tool."""
        return None

    def check(self) -> ToolStatus:
        if not self.binary:
            return ToolStatus(installed=False, problem="import only")
        path = shutil.which(self.binary)
        if not path:
            return ToolStatus(installed=False, problem="not installed")
        try:
            proc = subprocess.run([path, *self.version_args], capture_output=True, text=True, timeout=20)
            output = proc.stdout + proc.stderr
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ToolStatus(installed=True, path=path, problem=f"version check failed: {exc}")
        match = _LABELLED_VERSION_RE.search(output) or _VERSION_RE.search(output)
        return ToolStatus(installed=True, path=path, version=match.group(1) if match else None,
                          problem=self.verify(output))
