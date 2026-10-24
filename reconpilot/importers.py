"""Import results from recon and OSINT tools. Parsing lives in the tool adapters (reconpilot/tools/).

Every input record becomes one evidence record, so the AI analyst can cite the exact line behind a fact.
Re-importing the same file does not duplicate evidence.
"""

from __future__ import annotations

import json
from pathlib import Path

from .scope import ScopeError
from .store import Store
from .tools import ImportContext, ImportSummary, detect_adapter, get_adapter, registry

PARSE_ERRORS = (KeyError, TypeError, AttributeError, ValueError, IndexError)


def formats() -> tuple[str, ...]:
    return ("auto", *registry())


class Importer:
    def __init__(self, store: Store, ignore_window: bool = False):
        self.store = store
        self.ignore_window = ignore_window

    def import_file(self, path: str | Path, fmt: str = "auto", *, module: str | None = None,
                    query: str | None = None) -> ImportSummary:
        path = Path(path)
        if not self.ignore_window:
            try:
                self.store.scope.require_window()
            except ScopeError as exc:
                raise ScopeError(f"{exc}; refusing to import (use --ignore-window to override)") from None
        adapter = detect_adapter(path) if fmt == "auto" else get_adapter(fmt)
        module = module or f"import:{adapter.name}"
        query = query or path.name
        summary = ImportSummary(format=adapter.name)
        ctx = ImportContext(self.store, summary)
        with self.store.transaction():
            for payload in adapter.records(path):
                summary.lines += 1
                if payload is None:
                    summary.skipped += 1
                    continue
                ctx.touched = set()
                try:
                    with self.store.savepoint():
                        ev, created = self.store.insert_evidence(module, query, payload)
                        adapter.handle(ctx, payload, ev)
                except PARSE_ERRORS:
                    summary.skipped += 1
                    continue
                summary.entities |= ctx.touched
                if created:
                    summary.evidence += 1
                else:
                    summary.duplicates += 1
            self.store.audit("user", "import", str(path), json.dumps(
                {"format": adapter.name, "lines": summary.lines, "evidence": summary.evidence,
                 "duplicates": summary.duplicates, "skipped": summary.skipped,
                 "ignore_window": self.ignore_window}))
        return summary
