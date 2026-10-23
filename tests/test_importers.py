import json

from reconpilot.importers import Importer


def write_lines(path, records):
    path.write_text("\n".join(json.dumps(r) if isinstance(r, dict) else r for r in records))
    return path


def test_subfinder_import(store, tmp_path):
    f = write_lines(tmp_path / "subs.json", [
        {"host": "www.example.com", "input": "example.com", "source": "crtsh"},
        {"host": "dev.example.com", "input": "example.com", "source": "crtsh"},
    ])
    summary = Importer(store).import_file(f)
    assert summary.format == "subfinder"
    assert summary.evidence == 2
    www = store.find_entity("subdomain", "www.example.com")
    assert www["in_scope"] == 1
    assert store.find_entity("subdomain", "dev.example.com")["in_scope"] == 0
    root = store.find_entity("domain", "example.com")
    assert any(n["value"] == "www.example.com" for n in store.neighbors(root["id"]))


def test_httpx_import_links_tech_and_ips(store, tmp_path):
    f = write_lines(tmp_path / "httpx.json", [
        {"url": "https://www.example.com", "input": "www.example.com", "status_code": 200,
         "title": "Welcome", "webserver": "nginx/1.18.0", "tech": ["WordPress:6.1"], "a": ["10.0.0.7"]},
    ])
    Importer(store).import_file(f)
    url = store.find_entity("url", "https://www.example.com")
    related = {n["value"] for n in store.neighbors(url["id"])}
    assert {"nginx/1.18.0", "WordPress:6.1", "www.example.com"} <= related
    host = store.find_entity("subdomain", "www.example.com")
    assert "10.0.0.7" in {n["value"] for n in store.neighbors(host["id"])}


def test_plain_list_and_bad_lines(store, tmp_path):
    f = write_lines(tmp_path / "hosts.txt", ["# comment", "api.example.com", "mail.example.com"])
    summary = Importer(store).import_file(f)
    assert summary.format == "list"
    assert summary.evidence == 2 and summary.skipped == 1
