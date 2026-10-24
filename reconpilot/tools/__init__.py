"""Tool adapter registry: built-in adapters plus any registered through the `reconpilot.tools` entry point."""

from __future__ import annotations

from importlib.metadata import entry_points
from pathlib import Path

from .base import ImportContext, ImportSummary, ToolAdapter, ToolStatus
from .identity import Holehe, Maigret, Sherlock, TheHarvester
from .infra import Amass, Dnsx, HostList, Httpx, Subfinder

# Order matters for auto-detection: the most specific formats first, the plain list last.
BUILTIN: list[type[ToolAdapter]] = [Httpx, Amass, Dnsx, Subfinder, Sherlock, Maigret, Holehe, TheHarvester,
                                    HostList]

_registry: dict[str, ToolAdapter] | None = None


def registry() -> dict[str, ToolAdapter]:
    global _registry
    if _registry is None:
        found: dict[str, ToolAdapter] = {}
        for cls in BUILTIN:
            found[cls.name] = cls()
        for ep in entry_points(group="reconpilot.tools"):
            try:
                cls = ep.load()
                adapter = cls()
            except Exception:  # a broken plugin must not break the CLI
                continue
            # Plugins are inserted before the plain-list fallback so they are tried during detection.
            found = {k: v for k, v in found.items() if k != "list"} | {adapter.name: adapter, "list": found["list"]}
        _registry = found
    return _registry


def get_adapter(name: str) -> ToolAdapter:
    try:
        return registry()[name]
    except KeyError:
        raise ValueError(f"unknown tool {name!r}; known: {', '.join(registry())}") from None


def runnable_names() -> list[str]:
    return [name for name, a in registry().items() if a.runnable]


def detect_adapter(path: Path) -> ToolAdapter:
    """Pick the adapter whose output this file looks like."""
    first = ""
    with path.open(errors="replace") as fh:
        for line in fh:
            if line.strip() and not line.lstrip().startswith("#"):
                first = line.strip()
                break
    for adapter in registry().values():
        if adapter.name != "list" and adapter.sniff(first, path):
            return adapter
    if first.startswith("{") or first.startswith("["):
        raise ValueError("cannot detect the tool that produced this JSON")
    return registry()["list"]


__all__ = ["ImportContext", "ImportSummary", "ToolAdapter", "ToolStatus", "detect_adapter", "get_adapter",
           "registry", "runnable_names"]
