"""Scope engine: every collector call and AI-proposed job is checked here first."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import date
from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when an action falls outside the authorized engagement."""


def _is_ip_or_net(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def normalize_host(value: str) -> str:
    value = value.strip().lower()
    if "://" in value:
        value = urlparse(value).hostname or ""
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    return value.rstrip(".").removeprefix("*.")


@dataclass
class Scope:
    domains: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)
    exclude_domains: list[str] = field(default_factory=list)
    exclude_networks: list[str] = field(default_factory=list)
    start: date | None = None
    end: date | None = None

    @classmethod
    def from_entries(cls, include: list[str], exclude: list[str] | None = None, **kwargs) -> "Scope":
        scope = cls(**kwargs)
        for entry in include:
            (scope.networks if _is_ip_or_net(entry) else scope.domains).append(
                entry if _is_ip_or_net(entry) else normalize_host(entry))
        for entry in exclude or []:
            (scope.exclude_networks if _is_ip_or_net(entry) else scope.exclude_domains).append(
                entry if _is_ip_or_net(entry) else normalize_host(entry))
        return scope

    @staticmethod
    def _domain_match(host: str, patterns: list[str]) -> bool:
        return any(host == p or host.endswith("." + p) for p in patterns)

    @staticmethod
    def _ip_match(ip: str, nets: list[str]) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(n, strict=False) for n in nets)

    def contains(self, value: str) -> bool:
        """True if a host, URL, email or IP is inside the authorized scope."""
        host = normalize_host(value)
        if not host:
            return False
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if self._domain_match(host, self.exclude_domains):
                return False
            return self._domain_match(host, self.domains)
        if self._ip_match(host, self.exclude_networks):
            return False
        return self._ip_match(host, self.networks)

    def is_active_window(self, today: date | None = None) -> bool:
        today = today or date.today()
        if self.start and today < self.start:
            return False
        if self.end and today > self.end:
            return False
        return True

    def require(self, value: str, today: date | None = None) -> None:
        if not self.is_active_window(today):
            raise ScopeError(f"engagement window {self.start}..{self.end} is not active")
        if not self.contains(value):
            raise ScopeError(f"{value!r} is out of scope")

    def to_dict(self) -> dict:
        return {
            "domains": self.domains,
            "networks": self.networks,
            "exclude_domains": self.exclude_domains,
            "exclude_networks": self.exclude_networks,
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Scope":
        return cls(
            domains=list(data.get("domains", [])),
            networks=list(data.get("networks", [])),
            exclude_domains=list(data.get("exclude_domains", [])),
            exclude_networks=list(data.get("exclude_networks", [])),
            start=date.fromisoformat(data["start"]) if data.get("start") else None,
            end=date.fromisoformat(data["end"]) if data.get("end") else None,
        )
