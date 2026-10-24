"""Playbooks: YAML files that chain tool adapters, feeding each step what earlier steps found.

    name: username-sweep
    input: username
    steps:
      - tool: sherlock                 # runs on the playbook input
      - tool: holehe
        for_each: email                # runs on in-scope emails found by earlier steps
        requires_approval: true        # ask before each run
        max_targets: 5
      - analyst: "Summarize ..."       # question for the AI analyst

Every run still goes through the runner, so scope, engagement window and tier checks apply.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .store import Store
from .tools import get_adapter
from .tools.runner import RunError, Runner

BUILTIN_DIR = Path(__file__).parent / "playbooks"


@dataclass
class Playbook:
    name: str
    input: str
    steps: list[dict]
    description: str = ""
    path: Path | None = None

    @classmethod
    def from_file(cls, path: Path) -> "Playbook":
        data = yaml.safe_load(path.read_text()) or {}
        pb = cls(name=str(data.get("name") or path.stem), input=str(data.get("input", "")),
                 steps=list(data.get("steps") or []), description=str(data.get("description", "")), path=path)
        pb.validate()
        return pb

    def validate(self) -> None:
        if not self.input:
            raise ValueError(f"playbook {self.name}: 'input' (the target type) is required")
        if not self.steps:
            raise ValueError(f"playbook {self.name}: no steps")
        for i, step in enumerate(self.steps, 1):
            if not isinstance(step, dict) or not ({"tool", "analyst"} & set(step)):
                raise ValueError(f"playbook {self.name}: step {i} needs 'tool' or 'analyst'")
            if "tool" in step:
                get_adapter(step["tool"])  # raises on unknown tools


def playbook_dirs(config: dict) -> list[Path]:
    dirs = [BUILTIN_DIR, Path.home() / ".config" / "reconpilot" / "playbooks", Path("playbooks")]
    return dirs + [Path(d).expanduser() for d in config.get("playbook_dirs", [])]


def load_playbooks(config: dict) -> dict[str, Playbook]:
    """Later directories override earlier ones, so a local playbook can replace a built-in."""
    found: dict[str, Playbook] = {}
    for directory in playbook_dirs(config):
        if directory.is_dir():
            for path in sorted(directory.glob("*.y*ml")):
                pb = Playbook.from_file(path)
                found[pb.name] = pb
    return found


@dataclass
class PlaybookReport:
    runs: list[int] = field(default_factory=list)       # job IDs
    skipped: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)


Event = Callable[[str, str], None]


def run_playbook(pb: Playbook, target: str, store: Store, runner: Runner, *,
                 confirm: Callable[[str], bool], on_event: Event, ask: Callable[[str], None]) -> PlaybookReport:
    report = PlaybookReport()
    found: set[int] = set()
    store.audit(runner.actor, "playbook.start", pb.name, target)
    for i, step in enumerate(pb.steps, 1):
        if "analyst" in step:
            on_event("step", f"{i}. analyst")
            ask(str(step["analyst"]))
            continue
        tool = str(step["tool"])
        adapter = get_adapter(tool)
        if "for_each" in step:
            etype = str(step["for_each"])
            rows = [store.get_entity(eid) for eid in sorted(found)]
            targets = [r["value"] for r in rows if r and r["type"] == etype and r["in_scope"]]
            outside = [r["value"] for r in rows if r and r["type"] == etype and not r["in_scope"]]
            for value in outside:
                report.skipped.append(f"{tool} {value}: out of scope")
            targets = targets[: int(step.get("max_targets", 10))]
            ttype = etype
        else:
            targets, ttype = [target], pb.input
        on_event("step", f"{i}. {tool} on {len(targets)} target(s)")
        for value in targets:
            label = f"{tool} {value}"
            if step.get("requires_approval") and not confirm(f"Run {label}? ({adapter.tier})"):
                report.skipped.append(f"{label}: not approved")
                continue
            try:
                result = runner.run(tool, value, ttype=ttype if ttype in adapter.accepts else None,
                                    reason=f"playbook {pb.name} step {i}")
            except RunError as exc:
                report.failed.append(f"{label}: {exc}")
                on_event("fail", f"{label}: {exc}")
                continue
            report.runs.append(result.job_id)
            found |= result.entities
            on_event("ok", f"J{result.job_id} {label}: {result.evidence} evidence, {len(result.entities)} entities")
    store.audit(runner.actor, "playbook.done", pb.name,
                f"{len(report.runs)} runs, {len(report.skipped)} skipped, {len(report.failed)} failed")
    return report
