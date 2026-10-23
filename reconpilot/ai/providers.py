"""Model provider layer: one interface, any model, local or cloud.

A model spec is "<provider>:<model>", for example "ollama:qwen2.5:14b",
"anthropic:claude-opus-5-5", "openai:gpt-5" or "codex-cli:default".
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from typing import Any

import httpx

Message = dict[str, str]  # {"role": "user" | "assistant", "content": str}


class ProviderError(Exception):
    pass


class PrivacyError(ProviderError):
    """Raised when a project forbids cloud models and a cloud provider was requested."""


class ModelProvider:
    def __init__(self, name: str, model: str, cfg: dict[str, Any]):
        self.name = name
        self.model = model
        self.cfg = cfg
        self.local = bool(cfg.get("local", False))

    @property
    def spec(self) -> str:
        return f"{self.name}:{self.model}"

    def complete(self, system: str, messages: list[Message]) -> str:  # pragma: no cover - interface
        raise NotImplementedError


def _merge_roles(messages: list[Message]) -> list[Message]:
    """Collapse consecutive same-role messages; some APIs require strict alternation."""
    out: list[Message] = []
    for m in messages:
        if out and out[-1]["role"] == m["role"]:
            out[-1] = {"role": m["role"], "content": out[-1]["content"] + "\n\n" + m["content"]}
        else:
            out.append(dict(m))
    return out


class OpenAICompatProvider(ModelProvider):
    """Ollama, LM Studio, llama.cpp, vLLM, OpenAI, OpenRouter, Gemini (OpenAI-compatible endpoints)."""

    def complete(self, system: str, messages: list[Message]) -> str:
        headers = {}
        key_env = self.cfg.get("api_key_env")
        if key_env:
            key = os.environ.get(key_env)
            if not key:
                raise ProviderError(f"{self.name}: set the {key_env} environment variable")
            headers["Authorization"] = f"Bearer {key}"
        body = {"model": self.model,
                "messages": [{"role": "system", "content": system}, *_merge_roles(messages)]}
        if self.cfg.get("temperature") is not None:
            body["temperature"] = self.cfg["temperature"]
        url = self.cfg["base_url"].rstrip("/") + "/chat/completions"
        try:
            resp = httpx.post(url, json=body, headers=headers, timeout=self.cfg.get("timeout", 600))
        except httpx.HTTPError as exc:
            raise ProviderError(f"{self.name}: cannot reach {url}: {exc}") from exc
        if resp.status_code >= 400:
            raise ProviderError(f"{self.name}: HTTP {resp.status_code}: {resp.text[:300]}")
        try:
            return resp.json()["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, ValueError) as exc:
            raise ProviderError(f"{self.name}: unexpected response: {resp.text[:300]}") from exc


class AnthropicProvider(ModelProvider):
    """Claude via the official Anthropic SDK (pip install 'reconpilot[anthropic]')."""

    def complete(self, system: str, messages: list[Message]) -> str:
        try:
            import anthropic
        except ImportError as exc:
            raise ProviderError("install the Anthropic SDK: pip install 'reconpilot[anthropic]'") from exc
        client = anthropic.Anthropic()
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.cfg.get("max_tokens", 16000),
            "system": system,
            "messages": _merge_roles(messages),
        }
        try:
            if self.cfg.get("fallbacks", True):
                # Server-side fallback: if a request is declined, the API retries it on a fallback model.
                response = client.beta.messages.create(
                    **kwargs, betas=["server-side-fallback-2026-07-01"], extra_body={"fallbacks": "default"})
            else:
                response = client.messages.create(**kwargs)
        except anthropic.APIConnectionError as exc:
            raise ProviderError(f"anthropic: connection failed: {exc}") from exc
        except anthropic.APIStatusError as exc:
            raise ProviderError(f"anthropic: HTTP {exc.status_code}: {exc.message}") from exc
        if response.stop_reason == "refusal":
            raise ProviderError("anthropic: the model declined this request")
        return "".join(block.text for block in response.content if block.type == "text")


class CLIProvider(ModelProvider):
    """Drive a model CLI (Codex CLI, Claude Code) as a subprocess, using your existing subscription."""

    def complete(self, system: str, messages: list[Message]) -> str:
        command = list(self.cfg["command"])
        if not shutil.which(command[0]):
            raise ProviderError(f"{self.name}: '{command[0]}' is not installed or not on PATH")
        if self.model and self.model != "default" and self.cfg.get("model_flag"):
            index = self.cfg.get("model_flag_index", 1)
            command[index:index] = [self.cfg["model_flag"], self.model]
        transcript = "\n\n".join(f"[{m['role'].upper()}]\n{m['content']}" for m in messages)
        prompt = f"{system}\n\n=== CONVERSATION ===\n{transcript}\n\n[ASSISTANT]\n"
        # Run in an empty directory so the CLI agent has nothing local to read or modify.
        with tempfile.TemporaryDirectory(prefix="reconpilot-") as workdir:
            try:
                proc = subprocess.run(command, input=prompt, capture_output=True, text=True,
                                      cwd=workdir, timeout=self.cfg.get("timeout", 900))
            except subprocess.TimeoutExpired as exc:
                raise ProviderError(f"{self.name}: timed out") from exc
        if proc.returncode != 0:
            raise ProviderError(f"{self.name}: exit {proc.returncode}: {proc.stderr.strip()[:300]}")
        return proc.stdout.strip()


PROVIDER_TYPES = {
    "openai_compat": OpenAICompatProvider,
    "anthropic": AnthropicProvider,
    "cli": CLIProvider,
}


def parse_spec(spec: str) -> tuple[str, str]:
    provider, sep, model = spec.partition(":")
    if not sep or not provider or not model:
        raise ProviderError(f"model spec must look like 'provider:model', got {spec!r}")
    return provider, model


def resolve_spec(config: dict, override: str | None = None, profile: str | None = None) -> str:
    models = config["models"]
    if override:
        return models.get("profiles", {}).get(override, override)
    if profile and profile in models.get("profiles", {}):
        return models["profiles"][profile]
    return models["default"]


def get_provider(spec: str, config: dict, *, allow_cloud: bool) -> ModelProvider:
    name, model = parse_spec(spec)
    providers = config["models"]["providers"]
    if name not in providers:
        raise ProviderError(f"unknown provider {name!r}; known: {', '.join(sorted(providers))}")
    pcfg = providers[name]
    cls = PROVIDER_TYPES.get(pcfg.get("type", ""))
    if cls is None:
        raise ProviderError(f"provider {name!r} has unknown type {pcfg.get('type')!r}")
    provider = cls(name, model, pcfg)
    if not provider.local and not allow_cloud:
        raise PrivacyError(
            f"{spec} is a cloud model but this project has allow_cloud=false; "
            "use a local model or enable cloud with `reconpilot set <project> allow_cloud true`")
    return provider


def check_provider(name: str, pcfg: dict) -> str:
    """Best-effort availability check for `reconpilot models`."""
    ptype = pcfg.get("type")
    if ptype == "cli":
        return "installed" if shutil.which(pcfg["command"][0]) else "not installed"
    if ptype == "anthropic":
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return "SDK not installed"
        return "SDK installed"
    if pcfg.get("api_key_env") and not os.environ.get(pcfg["api_key_env"]):
        return f"{pcfg['api_key_env']} not set"
    if pcfg.get("local"):
        try:
            httpx.get(pcfg["base_url"].rstrip("/") + "/models", timeout=2)
            return "reachable"
        except httpx.HTTPError:
            return "not running"
    return "configured"
