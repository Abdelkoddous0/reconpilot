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
                "command": ["claude", "-p", "--output-format", "text",
                            "--disallowedTools", "Bash", "Edit", "Write", "WebFetch", "WebSearch"],
                "model_flag": "--model",
                "local": False,
            },
        },
    },
    "analyst": {
        "max_steps": 12,
        "max_citation_retries": 2,
        "evidence_char_limit": 4000,
    },
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
    for candidate in candidates:
        if candidate.is_file():
            with candidate.open() as fh:
                user_cfg = yaml.safe_load(fh) or {}
            return _merge(DEFAULT_CONFIG, user_cfg)
    return copy.deepcopy(DEFAULT_CONFIG)
