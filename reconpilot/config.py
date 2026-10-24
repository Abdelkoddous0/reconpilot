"""Configuration loading: data directory, model providers and profiles."""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "data_dir": "./data",
    "models": {
        "default": "ollama:qwen2.5:14b",
        "profiles": {},
        "providers": {
            "ollama": {"type": "openai_compat", "base_url": "http://127.0.0.1:11434/v1", "local": True},
            "lmstudio": {"type": "openai_compat", "base_url": "http://127.0.0.1:1234/v1", "local": True},
            "llamacpp": {"type": "openai_compat", "base_url": "http://127.0.0.1:8080/v1", "local": True},
            "openai": {
                "type": "openai_compat",
                "base_url": "https://api.openai.com/v1",
                "api_key_env": "OPENAI_API_KEY",
                "local": False,
            },
            "openrouter": {
                "type": "openai_compat",
                "base_url": "https://openrouter.ai/api/v1",
                "api_key_env": "OPENROUTER_API_KEY",
                "local": False,
            },
            "gemini": {
                "type": "openai_compat",
                "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
                "api_key_env": "GEMINI_API_KEY",
                "local": False,
            },
            "anthropic": {"type": "anthropic", "local": False},
            # CLI backends reuse your existing subscription. The model runs in the cloud.
            "codex-cli": {
                "type": "cli",
                "command": ["codex", "exec", "--skip-git-repo-check", "--sandbox", "read-only", "-"],
                "model_flag": "-m",
                "model_flag_index": 2,  # after "codex exec"
                "local": False,
            },
            "claude-cli": {
                "type": "cli",
                # The analyst only needs text in, text out. Every built-in tool is disabled, including
                # Read/Glob/Grep: they accept absolute paths, so injected evidence could ask for ~/.ssh.
                "command": ["claude", "-p", "--output-format", "text",
                            "--disallowedTools", "Bash", "Edit", "Write", "MultiEdit", "NotebookEdit", "Read",
                            "Glob", "Grep", "LS", "WebFetch", "WebSearch", "Task", "Agent", "TodoWrite"],
                "model_flag": "--model",
                "local": False,
            },
        },
    },
    "analyst": {
        "max_steps": 20,
        "max_citation_retries": 2,
        "evidence_char_limit": 4000,
        # Older tool results are shortened to this many characters so long sessions fit small contexts.
        "history_char_limit": 1500,
    },
    # Per-tool options for `rp run`, e.g. tools: {sherlock: {timeout: 600}, theharvester: {sources: "crtsh"}}
    "tools": {},
    # Extra directories searched for playbook YAML files (built-ins and ./playbooks are always searched).
    "playbook_dirs": [],
}

CONFIG_LOCATIONS = [
    Path("reconpilot.yaml"),
    Path.home() / ".config" / "reconpilot" / "config.yaml",
]


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: str | os.PathLike | None = None) -> dict[str, Any]:
    """Load config from an explicit path, ./reconpilot.yaml, or ~/.config/reconpilot/config.yaml."""
    candidates = [Path(path)] if path else CONFIG_LOCATIONS
    if path and not Path(path).is_file():
        raise FileNotFoundError(f"config file {path} not found")
    for candidate in candidates:
        if candidate.is_file():
            with candidate.open() as fh:
                user_cfg = yaml.safe_load(fh) or {}
            cfg = _merge(DEFAULT_CONFIG, user_cfg)
            cfg["_source"] = str(candidate)
            return cfg
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["_source"] = None
    return cfg
