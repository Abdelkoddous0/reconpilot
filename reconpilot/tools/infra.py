"""Infrastructure recon adapters: subfinder, amass, dnsx, httpx and plain host lists."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from .base import ImportContext, ToolAdapter, is_ip


def _first_json(line: str) -> dict | None:
    if not line.lstrip().startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def _require_host(entity_id: int | None) -> int:
    if entity_id is None:
        raise ValueError("record has no host")
    return entity_id


class ProjectDiscoveryTool(ToolAdapter):
    version_args = ("-version",)

    def verify(self, version_output: str) -> str | None:
        # The Python httpx library ships an unrelated `httpx` CLI; ProjectDiscovery tools print this line.
        if "current version" not in version_output.lower():
            return f"'{self.binary}' on PATH is not ProjectDiscovery's {self.name}"
        return None


class Subfinder(ProjectDiscoveryTool):
    name = "subfinder"
    description = "passive subdomain enumeration"
    homepage = "https://github.com/projectdiscovery/subfinder"
    binary = "subfinder"
    accepts = ("domain",)
    produces = ("subdomain",)
    tier = "passive"
    install_hint = "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    output_glob = "subfinder.json"

    def sniff(self, first_line: str, path: Path) -> bool:
        rec = _first_json(first_line)
        return bool(rec and "host" in rec and ("source" in rec or "input" in rec)
                    and not any(k in rec for k in ("a", "aaaa", "cname", "status_code", "url")))

    def command(self, target: str, outdir: Path, options: dict) -> list[str]:
        return ["subfinder", "-d", target, "-oJ", "-o", str(outdir / "subfinder.json"), "-silent", "-nc", "-duc"]

    def handle(self, ctx: ImportContext, rec: dict, ev: int) -> None:
        _require_host(ctx.host(rec["host"], ev))


class Amass(ToolAdapter):
    name = "amass"
    description = "amass v3 `enum -json` output (import only)"
    homepage = "https://github.com/owasp-amass/amass"

    def sniff(self, first_line: str, path: Path) -> bool:
        rec = _first_json(first_line)
        return bool(rec and "addresses" in rec and "name" in rec)

    def handle(self, ctx: ImportContext, rec: dict, ev: int) -> None:
        host = _require_host(ctx.host(rec["name"], ev))
        for addr in rec.get("addresses") or []:
            ctx.link(host, "resolves_to", "ip", addr.get("ip", ""), ev)


class Dnsx(ProjectDiscoveryTool):
    name = "dnsx"
    description = "DNS resolution (A, AAAA, CNAME)"
    homepage = "https://github.com/projectdiscovery/dnsx"
    binary = "dnsx"
    accepts = ("domain", "subdomain")
    produces = ("ip", "subdomain")
    tier = "passive"
    install_hint = "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    output_glob = "dnsx.json"

    def sniff(self, first_line: str, path: Path) -> bool:
        rec = _first_json(first_line)
        return bool(rec and "host" in rec and "url" not in rec
                    and any(k in rec for k in ("a", "aaaa", "cname", "status_code")))

    def prepare(self, target: str, outdir: Path, options: dict) -> None:
        (outdir / "targets.txt").write_text(target + "\n")

    def command(self, target: str, outdir: Path, options: dict) -> list[str]:
        return ["dnsx", "-l", str(outdir / "targets.txt"), "-json", "-o", str(outdir / "dnsx.json"),
                "-a", "-aaaa", "-cname", "-silent", "-nc", "-duc"]

    def handle(self, ctx: ImportContext, rec: dict, ev: int) -> None:
        host = _require_host(ctx.host(rec["host"], ev))
        for ip in (rec.get("a") or []) + (rec.get("aaaa") or []):
            ctx.link(host, "resolves_to", "ip", ip, ev)
        for cname in rec.get("cname") or []:
            ctx.link(host, "cname", "subdomain", cname, ev)


class Httpx(ProjectDiscoveryTool):
    name = "httpx"
    description = "HTTP probing: status, title, web server, technologies"
    homepage = "https://github.com/projectdiscovery/httpx"
    binary = "httpx"
    accepts = ("domain", "subdomain", "url", "ip")
    produces = ("url", "technology", "ip")
    tier = "low_touch"
    install_hint = "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    output_glob = "httpx.json"

    def sniff(self, first_line: str, path: Path) -> bool:
        rec = _first_json(first_line)
        return bool(rec and "url" in rec and ("status_code" in rec or "status-code" in rec))

    def command(self, target: str, outdir: Path, options: dict) -> list[str]:
        return ["httpx", "-u", target, "-json", "-o", str(outdir / "httpx.json"), "-silent",
                "-title", "-web-server", "-tech-detect", "-ip", "-nc", "-duc"]

    def handle(self, ctx: ImportContext, rec: dict, ev: int) -> None:
        url = rec["url"]
        host = ctx.host(urlparse(url).hostname or rec.get("input", ""), ev)
        url_id = ctx.entity("url", url, ev)
        ctx.relate(host, url_id, "serves", ev)
        for ip in rec.get("a") or ([rec["host"]] if is_ip(str(rec.get("host", ""))) else []):
            ctx.link(host, "resolves_to", "ip", ip, ev)
        techs = list(rec.get("tech") or [])
        if rec.get("webserver"):
            techs.append(rec["webserver"])
        for tech in dict.fromkeys(techs):
            ctx.link(url_id, "runs", "technology", str(tech), ev)


class HostList(ToolAdapter):
    name = "list"
    description = "plain text list of hosts, IPs or URLs, one per line"
    record_format = "lines"

    def handle(self, ctx: ImportContext, line: str, ev: int) -> None:
        _require_host(ctx.host(line, ev))
