"""Run a tool adapter against one target, under the scope gate, and import what it produced.

This is the only place ReconPilot executes external programs. Order of checks:
adapter known and installed -> engagement window -> target in scope -> tier allowed by the project.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..scope import ScopeError, guess_type
from ..store import Store
from . import get_adapter
from .base import ImportSummary, ToolAdapter


class RunError(Exception):
    def __init__(self, message: str, hint: str | None = None):
        super().__init__(message)
        self.hint = hint


@dataclass
class RunResult:
    job_id: int
    adapter: str
    target: str
    outdir: Path
    returncode: int
    summaries: list[ImportSummary] = field(default_factory=list)

    @property
    def entities(self) -> set[int]:
        return set().union(*(s.entities for s in self.summaries)) if self.summaries else set()

    @property
    def evidence(self) -> int:
        return sum(s.evidence for s in self.summaries)


def target_type(adapter: ToolAdapter, target: str, explicit: str | None = None) -> str:
    """Decide what kind of target this is for this adapter (a username may look like a domain: john.doe)."""
    if explicit:
        ttype = explicit
    elif len(adapter.accepts) == 1:
        ttype = adapter.accepts[0]
    else:
        ttype = guess_type(target)
        if ttype == "domain" and "subdomain" in adapter.accepts and "domain" not in adapter.accepts:
            ttype = "subdomain"
    if ttype not in adapter.accepts:
        raise RunError(f"{adapter.name} takes {', '.join(adapter.accepts)}, not a {ttype} ({target!r})",
                       "pass --type if the guess is wrong")
    return ttype


class Runner:
    def __init__(self, store: Store, config: dict, actor: str = "user"):
        self.store = store
        self.cfg = config.get("tools", {})
        self.actor = actor

    def options(self, adapter: ToolAdapter) -> dict:
        return dict(self.cfg.get(adapter.name, {}))

    def check(self, adapter: ToolAdapter, target: str, ttype: str | None = None) -> str:
        """Every gate before running. Returns the target type."""
        if not adapter.runnable:
            raise RunError(f"{adapter.name} is import-only", f"run it yourself, then: rp import <file> "
                                                             f"--format {adapter.name}")
        status = adapter.check()
        if not status.installed:
            raise RunError(f"{adapter.name} is not installed", adapter.install_hint or None)
        if status.problem:
            raise RunError(f"{adapter.name}: {status.problem}", adapter.install_hint or None)
        ttype = target_type(adapter, target, ttype)
        meta = self.store.meta()
        try:
            self.store.scope.require(target, ttype=ttype)
        except ScopeError as exc:
            self.store.audit(self.actor, "run.refused", target, f"{adapter.name}: {exc}")
            raise RunError(str(exc), "check the scope with: rp scope show") from None
        if adapter.tier == "active" and not meta.get("allow_active", False):
            raise RunError(f"{adapter.name} is an active tool and this project does not allow active testing",
                           "enable it with: rp policy active on")
        if adapter.tier == "low_touch" and not meta.get("allow_low_touch", True):
            raise RunError(f"{adapter.name} touches the target and this project is passive-only",
                           "enable it with: rp policy low-touch on")
        return ttype

    def run(self, tool: str, target: str, *, ttype: str | None = None, job_id: int | None = None,
            reason: str | None = None) -> RunResult:
        adapter = get_adapter(tool)
        self.check(adapter, target, ttype)
        if job_id is None:
            job_id = self.store.create_job(adapter.name, target, adapter.tier, self.actor, reason, "running")
        else:
            self.store.update_job(job_id, status="running", tier=adapter.tier)
        self.store.audit(self.actor, "run.start", f"J{job_id}", f"{adapter.name} {target}")
        outdir = (self.store.runs_dir / f"J{job_id}").resolve()
        outdir.mkdir(parents=True, exist_ok=True)
        options = self.options(adapter)
        try:
            adapter.prepare(target, outdir, options)
            argv = adapter.command(target, outdir, options)
            (outdir / "command.json").write_text(json.dumps(argv))
            proc = subprocess.run(argv, cwd=outdir, capture_output=True, text=True,
                                  timeout=int(options.get("timeout", adapter.timeout)),
                                  env={**os.environ, "NO_COLOR": "1"})
        except subprocess.TimeoutExpired:
            self._fail(job_id, "timed out")
            raise RunError(f"{adapter.name} timed out", "raise tools.<name>.timeout in reconpilot.yaml") from None
        except OSError as exc:
            self._fail(job_id, str(exc))
            raise RunError(f"{adapter.name} could not start: {exc}") from None
        (outdir / "stdout.txt").write_text(proc.stdout)
        (outdir / "stderr.txt").write_text(proc.stderr)

        from ..importers import Importer  # local import: importers imports this package
        result = RunResult(job_id, adapter.name, target, outdir, proc.returncode)
        importer = Importer(self.store)
        for path in adapter.output_files(outdir, target):
            result.summaries.append(importer.import_file(path, adapter.name, module=f"tool:{adapter.name}",
                                                         query=f"J{job_id} {target}"))
        # Some tools exit non-zero after writing results (holehe always does), so judge by the output.
        if proc.returncode != 0 and not result.summaries:
            error = (proc.stderr.strip() or proc.stdout.strip())[-500:]
            self._fail(job_id, f"exit {proc.returncode}, no output: {error}")
            raise RunError(f"{adapter.name} exited with {proc.returncode} and produced no output",
                           f"see {outdir / 'stderr.txt'}")
        self.store.update_job(job_id, status="done")
        self.store.audit(self.actor, "run.done", f"J{job_id}",
                         json.dumps({"files": len(result.summaries), "evidence": result.evidence,
                                     "entities": len(result.entities), "exit": proc.returncode}))
        return result

    def run_job(self, job_id: int) -> RunResult:
        job = self.store.get_job(job_id)
        if job is None:
            raise RunError(f"no step J{job_id}")
        if job["status"] != "approved":
            raise RunError(f"J{job_id} is {job['status']}, not approved", f"approve it first: rp approve J{job_id}")
        return self.run(job["module"], job["target"], job_id=job_id)

    def _fail(self, job_id: int, error: str) -> None:
        self.store.update_job(job_id, status="failed", error=error)
        self.store.audit(self.actor, "run.failed", f"J{job_id}", error[:500])
