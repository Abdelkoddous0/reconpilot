"""Identity OSINT adapters: Sherlock, Maigret, holehe and theHarvester.

Output formats were checked against: sherlock 0.16.2, maigret 0.6.6, holehe 1.61, theHarvester 4.11.1 / 5.0.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .base import ImportContext, ToolAdapter

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")

SHERLOCK_HEADER = ["username", "name", "url_main", "url_user", "exists", "http_status", "response_time_s"]
HOLEHE_HEADER_START = ["name", "domain", "method", "frequent_rate_limit", "rateLimit", "exists"]


def _csv_header(first_line: str) -> list[str]:
    try:
        return next(csv.reader(io.StringIO(first_line)))
    except (StopIteration, csv.Error):
        return []


class Sherlock(ToolAdapter):
    name = "sherlock"
    description = "find accounts for a username on ~400 sites"
    homepage = "https://github.com/sherlock-project/sherlock"
    binary = "sherlock"
    accepts = ("username",)
    produces = ("account",)
    tier = "passive"
    install_hint = "pipx install sherlock-project"
    record_format = "csv"
    output_glob = "*.csv"
    tested_version = "0.16.2"

    def sniff(self, first_line: str, path: Path) -> bool:
        return _csv_header(first_line) == SHERLOCK_HEADER

    def command(self, target: str, outdir: Path, options: dict) -> list[str]:
        argv = ["sherlock", "--no-color", "--csv", "--folderoutput", str(outdir),
                "--timeout", str(options.get("request_timeout", 30))]
        if options.get("local"):
            argv.append("--local")  # bundled site list instead of downloading the latest
        return argv + [target]

    def handle(self, ctx: ImportContext, rec: dict, ev: int) -> None:
        if rec.get("exists") != "Claimed":
            raise ValueError("not a claimed account")
        uid = ctx.entity("username", rec["username"], ev)
        acc = ctx.link(uid, "has_account", "account", rec["url_user"], ev)
        ctx.link(acc, "on_site", "organization", rec.get("name"), ev)


class Maigret(ToolAdapter):
    name = "maigret"
    description = "find accounts for a username and extract profile data"
    homepage = "https://github.com/soxoj/maigret"
    binary = "maigret"
    accepts = ("username",)
    produces = ("account", "username", "email", "url", "person")
    tier = "passive"
    install_hint = "pipx install maigret"
    output_glob = "report_*_ndjson.json"
    tested_version = "0.6.6"

    def sniff(self, first_line: str, path: Path) -> bool:
        try:
            rec = json.loads(first_line)
        except json.JSONDecodeError:
            return False
        return isinstance(rec, dict) and "sitename" in rec and isinstance(rec.get("status"), dict)

    def command(self, target: str, outdir: Path, options: dict) -> list[str]:
        # --no-recursion: otherwise every extracted username gets its own scan and report file.
        argv = ["maigret", target, "--json", "ndjson", "--folderoutput", str(outdir), "--no-color",
                "--no-progressbar", "--no-recursion", "--no-autoupdate",
                "--timeout", str(options.get("request_timeout", 30))]
        if options.get("all_sites"):
            argv.append("-a")
        return argv

    def handle(self, ctx: ImportContext, rec: dict, ev: int) -> None:
        status = rec.get("status") or {}
        if status.get("status", "Claimed") != "Claimed":
            raise ValueError("not a claimed account")
        url = rec.get("url_user") or status["url"]
        uid = ctx.entity("username", rec.get("username") or status["username"], ev)
        acc = ctx.link(uid, "has_account", "account", url, ev)
        ctx.link(acc, "on_site", "organization", rec.get("sitename") or status.get("site_name"), ev)
        ids = status.get("ids") or {}
        for key in ("fullname", "name"):
            if ids.get(key):
                ctx.link(acc, "profile_name", "person", ids[key], ev)
                break
        for value in ids.values():
            if isinstance(value, str) and _EMAIL_RE.match(value.strip()):
                ctx.link(acc, "exposes_email", "email", value.strip(), ev)
        for other in (rec.get("ids_usernames") or {}):
            ctx.link(acc, "mentions_username", "username", other, ev)
        for link in rec.get("ids_links") or []:
            ctx.link(acc, "links_to", "url", link, ev)


class Holehe(ToolAdapter):
    name = "holehe"
    description = "check which sites an email is registered on"
    homepage = "https://github.com/megadose/holehe"
    binary = "holehe"
    accepts = ("email",)
    produces = ("account",)
    # It queries sign-up and recovery endpoints of third-party sites with the email.
    tier = "low_touch"
    install_hint = "pipx install holehe==1.61   (pin it: newer PyPI releases make it self-update and exit)"
    record_format = "csv"
    output_glob = "holehe_*_results.csv"
    tested_version = "1.61"
    version_args = ("--help",)  # holehe has no --version flag
    _NAME_RE = re.compile(r"holehe_\d+_(.+)_results\.csv$")

    def sniff(self, first_line: str, path: Path) -> bool:
        return _csv_header(first_line)[:6] == HOLEHE_HEADER_START

    def command(self, target: str, outdir: Path, options: dict) -> list[str]:
        # No output-dir flag: the runner starts it inside the run directory. Exit code 1 is normal.
        return ["holehe", "--no-color", "--no-clear", "--only-used", "-C", target]

    def output_files(self, outdir: Path, target: str) -> list[Path]:
        files = super().output_files(outdir, target)
        if files:
            return files
        # holehe skips the CSV when a module errors; fall back to the "[+] domain" lines on stdout.
        stdout = outdir / "stdout.txt"
        domains = re.findall(r"^\[\+\] (\S+)", stdout.read_text(errors="replace"), re.M) if stdout.exists() else []
        if not domains:
            return []
        path = outdir / f"holehe_0_{target}_results.csv"
        with path.open("w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(HOLEHE_HEADER_START + ["emailrecovery", "phoneNumber", "others"])
            for domain in domains:
                writer.writerow([domain.split(".")[0], domain, "", "", "False", "True", "", "", ""])
        return [path]

    def records(self, path: Path) -> Iterator[Any]:
        match = self._NAME_RE.search(path.name)
        email = match.group(1) if match else None
        for rec in super().records(path):
            if rec is not None:
                rec["email"] = rec.get("email") or email
            yield rec

    def handle(self, ctx: ImportContext, rec: dict, ev: int) -> None:
        if rec.get("exists") != "True" or rec.get("rateLimit") == "True":
            raise ValueError("not registered, or rate limited")
        if not rec.get("email"):
            raise ValueError("email unknown: keep holehe's original file name")
        eid = ctx.entity("email", rec["email"], ev)
        acc = ctx.link(eid, "registered_on", "account", f"{rec['domain']}:{rec['email']}", ev)
        ctx.link(acc, "on_site", "organization", rec["domain"], ev)


class TheHarvester(ToolAdapter):
    name = "theharvester"
    description = "emails, hosts and IPs for a domain from public sources"
    homepage = "https://github.com/laramies/theHarvester"
    binary = "theHarvester"
    accepts = ("domain",)
    produces = ("email", "subdomain", "ip", "url")
    tier = "passive"
    install_hint = "pipx install git+https://github.com/laramies/theHarvester@4.11.1   (the PyPI package is not it)"
    record_format = "json"
    output_glob = "harvest.json"
    version_args = ("-h",)
    tested_version = "4.11.1"
    timeout = 1800
    # Sources that work without API keys. Override with tools: {theharvester: {sources: "..."}}.
    default_sources = "crtsh,certspotter,hackertarget,otx,rapiddns,urlscan"

    def sniff(self, first_line: str, path: Path) -> bool:
        return first_line.startswith("{") and '"cmd":' in first_line and '"hosts":' in first_line

    def verify(self, version_output: str) -> str | None:
        if "theharvester" not in version_output.lower():
            return "the 'theHarvester' on PATH is not the real tool (the PyPI package is a placeholder)"
        return None

    def command(self, target: str, outdir: Path, options: dict) -> list[str]:
        # -f must be absolute: a relative path is cut to its basename and written to the working directory.
        return ["theHarvester", "-d", target, "-b", str(options.get("sources", self.default_sources)),
                "-l", str(options.get("limit", 500)), "-f", str((outdir / "harvest.json").resolve()), "-q"]

    def split_document(self, doc: Any) -> Iterator[Any]:
        if not isinstance(doc, dict):
            raise ValueError("theHarvester output must be a JSON object")
        for email in doc.get("emails") or []:
            yield {"kind": "email", "value": email}
        for host in doc.get("hosts") or []:
            yield {"kind": "host", "value": host}
        for ip in doc.get("ips") or []:
            yield {"kind": "ip", "value": ip}
        for key in ("urls", "interesting_urls"):
            for url in doc.get(key) or []:
                yield {"kind": "url", "value": url}

    def handle(self, ctx: ImportContext, rec: dict, ev: int) -> None:
        kind, value = rec["kind"], str(rec["value"]).strip()
        if kind == "email":
            if not _EMAIL_RE.match(value):
                raise ValueError("not an email")
            domain = ctx.host(value.rsplit("@", 1)[1], ev)
            ctx.relate(domain, ctx.entity("email", value, ev), "has_email", ev)
        elif kind == "host":
            name, _, ip = value.partition(":")  # "sub.example.com:1.2.3.4" after resolution
            host = ctx.host(name, ev)
            for addr in filter(None, (a.strip() for a in ip.split(","))):
                ctx.link(host, "resolves_to", "ip", addr, ev)
        elif kind == "ip":
            ctx.host(value, ev)
        elif kind == "url":
            ctx.entity("url", value, ev)
