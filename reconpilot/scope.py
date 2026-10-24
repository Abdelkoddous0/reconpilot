"""Scope engine: every collector call and AI-proposed job is checked here first.

Infrastructure scope is a list of domains and CIDRs. Identity scope is a list of *subjects*
(usernames, emails, phone numbers, people) that the engagement authorizes you to investigate.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import date
from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when an action falls outside the authorized engagement."""


SUBJECT_TYPES = ("username", "email", "phone", "person")
# Entities that describe software or records rather than a target: always "in scope".
NEUTRAL_TYPES = ("technology", "registrar", "txt", "breach", "organization", "location")
# Entities whose scope comes from the entity they were found from (e.g. an account of an in-scope username).
DERIVED_TYPES = ("account",)

_PHONE_RE = re.compile(r"^\+?[\d\s().-]{7,20}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _is_ip_or_net(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
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


def normalize_phone(value: str) -> str:
    value = value.strip()
    digits = re.sub(r"\D", "", value)
    return ("+" if value.startswith("+") else "") + digits


def normalize_subject(stype: str, value: str) -> str:
    value = value.strip()
    if stype == "phone":
        return normalize_phone(value)
    if stype in ("email", "username"):
        return value.lower()
    return " ".join(value.split()).lower()


def guess_type(value: str) -> str:
    """Best guess of what a bare target string is: url, email, ip, phone, domain or username."""
    value = value.strip()
    if "://" in value:
        return "url"
    if "@" in value and "." in value.rsplit("@", 1)[-1]:
        return "email"
    if _is_ip(value):
        return "ip"
    if _PHONE_RE.match(value) and sum(c.isdigit() for c in value) >= 7:
        return "phone"
    if "." in value and " " not in value and not value.startswith("."):
        return "domain"
    if _USERNAME_RE.match(value):
        return "username"
    return "person"


@dataclass
class Scope:
    domains: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)
    exclude_domains: list[str] = field(default_factory=list)
    exclude_networks: list[str] = field(default_factory=list)
    subjects: list[dict] = field(default_factory=list)  # {"type": "username", "value": "jdoe", "note": "..."}
    start: date | None = None
    end: date | None = None

    @classmethod
    def from_entries(cls, include: list[str], exclude: list[str] | None = None, **kwargs) -> "Scope":
        scope = cls(**kwargs)
        for entry in include:
            scope.add(entry)
        for entry in exclude or []:
            scope.add(entry, exclude=True)
        return scope

    # ---------- editing ----------
    def add(self, entry: str, exclude: bool = False) -> None:
        entry = entry.strip()
        if _is_ip_or_net(entry):
            target = self.exclude_networks if exclude else self.networks
        else:
            entry = normalize_host(entry)
            target = self.exclude_domains if exclude else self.domains
        if entry and entry not in target:
            target.append(entry)

    def remove(self, entry: str) -> bool:
        entry = entry.strip()
        key = entry if _is_ip_or_net(entry) else normalize_host(entry)
        removed = False
        for bucket in (self.domains, self.networks, self.exclude_domains, self.exclude_networks):
            if key in bucket:
                bucket.remove(key)
                removed = True
        before = len(self.subjects)
        self.subjects = [s for s in self.subjects
                         if normalize_subject(s["type"], s["value"]) != normalize_subject(s["type"], entry)]
        return removed or len(self.subjects) != before

    def add_subject(self, stype: str, value: str, note: str = "") -> None:
        if stype not in SUBJECT_TYPES:
            raise ValueError(f"subject type must be one of {SUBJECT_TYPES}")
        if not value.strip():
            raise ValueError("subject value is empty")
        if not self.has_subject(stype, value):
            self.subjects.append({"type": stype, "value": value.strip(), "note": note})

    def has_subject(self, stype: str, value: str) -> bool:
        key = normalize_subject(stype, value)
        return any(s["type"] == stype and normalize_subject(stype, s["value"]) == key for s in self.subjects)

    @property
    def is_empty(self) -> bool:
        return not (self.domains or self.networks or self.subjects)

    # ---------- checks ----------
    @staticmethod
    def _domain_match(host: str, patterns: list[str]) -> bool:
        return any(host == p or host.endswith("." + p) for p in patterns)

    @staticmethod
    def _ip_match(ip: str, nets: list[str]) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(n, strict=False) for n in nets)

    def contains(self, value: str) -> bool:
        """True if a host, URL, email or IP is inside the authorized infrastructure scope."""
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

    def contains_entity(self, etype: str, value: str) -> bool | None:
        """Scope decision for an entity. None means "inherit from the entity it was found from"."""
        if etype in NEUTRAL_TYPES:
            return True
        if etype in DERIVED_TYPES:
            return None
        if etype in ("username", "phone", "person"):
            return self.has_subject(etype, value)
        if etype == "email":
            return self.has_subject("email", value) or self.contains(value)
        return self.contains(value)

    def contains_target(self, target: str, ttype: str | None = None) -> bool:
        ttype = ttype or guess_type(target)
        if ttype in ("url", "ip", "domain", "subdomain"):
            return self.contains(target)
        return bool(self.contains_entity(ttype, target))

    def is_active_window(self, today: date | None = None) -> bool:
        today = today or date.today()
        if self.start and today < self.start:
            return False
        if self.end and today > self.end:
            return False
        return True

    def require_window(self, today: date | None = None) -> None:
        if not self.is_active_window(today):
            raise ScopeError(f"engagement window {self.start or '…'}..{self.end or '…'} is not active")

    def require(self, value: str, today: date | None = None, ttype: str | None = None) -> None:
        self.require_window(today)
        if not self.contains_target(value, ttype):
            raise ScopeError(f"{value!r} is out of scope")

    # ---------- serialization ----------
    def to_dict(self) -> dict:
        return {
            "domains": self.domains,
            "networks": self.networks,
            "exclude_domains": self.exclude_domains,
            "exclude_networks": self.exclude_networks,
            "subjects": self.subjects,
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
            subjects=[dict(s) for s in data.get("subjects", [])],
            start=date.fromisoformat(data["start"]) if data.get("start") else None,
            end=date.fromisoformat(data["end"]) if data.get("end") else None,
        )
