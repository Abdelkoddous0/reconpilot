# ReconPilot usage guide

This guide walks through ReconPilot from installation to a finished report. Every command shown here
works as written; `rp --help` and `rp <command> --help` list every option.

> **Use ReconPilot only on targets you are authorized to investigate.** Every project needs an
> authorization reference, and every tool run is checked against the project's scope.

- [1. Install](#1-install)
- [2. Check your setup](#2-check-your-setup)
- [3. Create a project](#3-create-a-project)
- [4. Collect data: run tools](#4-collect-data-run-tools)
- [5. Collect data: playbooks](#5-collect-data-playbooks)
- [6. Collect data: import files](#6-collect-data-import-files)
- [7. Explore the results](#7-explore-the-results)
- [8. Let the AI analyst work](#8-let-the-ai-analyst-work)
- [9. Review findings and steps](#9-review-findings-and-steps)
- [10. Reports and exports](#10-reports-and-exports)
- [11. Scope, subjects and policy](#11-scope-subjects-and-policy)
- [12. Configuration](#12-configuration)
- [13. Add your own tool](#13-add-your-own-tool)
- [14. Troubleshooting](#14-troubleshooting)

---

## 1. Install

ReconPilot needs Python 3.11 or newer.

```bash
git clone <your-repo-url> reconpilot && cd reconpilot
uv venv && uv pip install -e .          # or: python -m venv .venv && .venv/bin/pip install -e .
source .venv/bin/activate
rp --help
```

### Install the recon tools you want

ReconPilot runs these tools for you. Install only the ones you need; `rp tools` shows which are ready.

| Tool | What it finds | Install |
| --- | --- | --- |
| sherlock | accounts for a username | `pipx install sherlock-project` |
| maigret | accounts + profile data for a username | `pipx install maigret` |
| holehe | sites an email is registered on | `pipx install holehe==1.61` (pin it, see [troubleshooting](#14-troubleshooting)) |
| theHarvester | emails, hosts, IPs for a domain | `pipx install git+https://github.com/laramies/theHarvester@4.11.1` |
| subfinder | subdomains | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| dnsx | DNS records | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| httpx | live web services, titles, technologies | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| amass | subdomains (import only, v3 JSON) | see the amass docs |

Use `pipx` for the Python tools so each one gets its own environment and they do not clash with
ReconPilot's dependencies.

### Install an AI model

A local model keeps client data on your machine (recommended):

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:14b
```

Cloud models (Claude, OpenAI, Gemini, OpenRouter, Codex CLI, Claude Code CLI) also work. See
[section 12](#12-configuration).

## 2. Check your setup

```bash
rp doctor
```

`doctor` checks Python, your config file, the data directory, every tool (installed, version, the
right binary) and every AI backend. For each problem it prints the command that fixes it.

```bash
rp tools        # tools, their tier and what target they take
rp playbooks    # ready-made chains of tools
rp models       # AI backends
```

## 3. Create a project

One project per engagement. Each project is one SQLite file in `./data/`.

**Infrastructure engagement** (domains, IP ranges):

```bash
rp new acme --client "Acme Corp" --auth-ref "RoE-2026-07" \
   --scope acme.com --scope 10.0.0.0/24 --exclude vpn.acme.com \
   --start 2026-11-01 --end 2026-11-30
```

**Person-focused investigation** (usernames, emails, phones, names):

```bash
rp new case42 --client "Internal investigation" --auth-ref "Case 42, signed consent" \
   --seed username:jdoe --seed email:jane@example.com
```

You can mix both in one project. Run `rp new` with no arguments to be asked for each detail.

| Option | Meaning |
| --- | --- |
| `--auth-ref` | Required. Your SoW / RoE ID, bug bounty URL or consent reference. |
| `--scope` | In-scope domain (includes its subdomains) or CIDR. Repeatable. |
| `--exclude` | Out-of-scope domain or CIDR, even if inside a scope entry. |
| `--seed TYPE:VALUE` | A person to investigate: `username`, `email`, `phone` or `person`. Repeatable. |
| `--start`, `--end` | Engagement window. Nothing runs or imports outside it. |
| `--passive-only` | Block tools that touch the target or third parties with the target's data (httpx, holehe). |
| `--allow-cloud` | Allow cloud AI models for this project. Off by default. |

The new project becomes the **active project**. Switch with `rp use <name>`, list with `rp ls`, or
target another project once with `rp -p <name> <command>`.

## 4. Collect data: run tools

```bash
rp run sherlock jdoe
rp run maigret jdoe
rp run holehe jane@example.com
rp run theharvester acme.com
rp run subfinder acme.com
rp run httpx www.acme.com
```

Before anything runs, ReconPilot checks, in this order:

1. the tool is installed and is the right program;
2. the engagement window is active;
3. the target is in scope (a seeded subject, or inside a scoped domain or network);
4. the tool's tier is allowed (see [policy](#policy-what-tools-may-do)).

Then it runs the tool (no shell, with a timeout), saves everything it produced in
`data/runs/<project>/J<id>/` (command, stdout, stderr, output files), and imports the results.
Each run is a step `J<id>` in `rp steps --all` and in the audit log.

**Target type.** ReconPilot guesses whether a target is a domain, username, email and so on. A username
with a dot looks like a domain; tell it with `--type`:

```bash
rp run sherlock john.doe --type username
```

### Tool tiers

| Tier | Meaning | Tools |
| --- | --- | --- |
| passive | queries public sources, never the target | sherlock, maigret, theharvester, subfinder, dnsx |
| low-touch | sends light requests to the target or to services using the target's data | httpx, holehe |
| active | scans or attacks the target | none ship by default; blocked unless allowed |

## 5. Collect data: playbooks

A playbook runs several tools in a row. Later steps use what earlier steps found.

```bash
rp run username-sweep jdoe          # sherlock, maigret, holehe on found emails, AI summary
rp run email-footprint jane@example.com
rp run domain-surface acme.com      # subfinder, theHarvester, dnsx and httpx on subdomains, AI triage
```

- Steps marked `requires_approval` ask before each run. Add `--yes` to approve all of them.
- A step that runs "for each" found entity only uses **in-scope** ones. Out-of-scope leads are listed as
  skipped. To include one, seed it first (`rp seed email x@example.org`) and rerun.
- `-m <model>` picks the model for the AI steps.

### Write your own playbook

Put a YAML file in `./playbooks/` (or `~/.config/reconpilot/playbooks/`). A file with the same `name`
as a built-in replaces it.

```yaml
# playbooks/quick-user.yaml
name: quick-user
description: Sherlock only, then a short summary.
input: username            # the type of target the playbook takes
steps:
  - tool: sherlock         # runs on the input
  - tool: holehe
    for_each: email        # runs on every in-scope email found so far
    requires_approval: true
    max_targets: 3         # at most 3 runs of this step (default 10)
  - analyst: "List the accounts found for this username, with evidence."
```

Check it with `rp playbooks`, run it with `rp run quick-user jdoe`.

## 6. Collect data: import files

If you already ran a tool yourself, import its output. The tool is detected from the file.

```bash
rp import results/subfinder.json results/httpx.json sherlock/jdoe.csv
```

| Tool | File to import |
| --- | --- |
| sherlock | `<username>.csv` (from `--csv`) |
| maigret | `report_<username>_ndjson.json` (from `--json ndjson`) |
| holehe | `holehe_<time>_<email>_results.csv` (from `-C`; keep the original file name, it holds the email) |
| theHarvester | the `.json` file from `-f` |
| subfinder, dnsx, httpx | JSON lines (`-oJ` / `-json`) |
| amass | v3 `enum -json` |
| anything else | a plain text list of hosts, IPs or URLs, one per line |

Force the format with `--format <tool>` if detection guesses wrong. Importing the same file twice does
not create duplicates. Imports outside the engagement window are refused unless you pass
`--ignore-window` (recorded in the audit log).

## 7. Explore the results

```bash
rp status                     # dashboard: scope, counts, findings, pending steps, what to do next
rp search admin               # in-scope entities containing "admin"
rp search -t account          # all accounts
rp search -t email --all      # emails, in and out of scope
rp search --out               # everything found outside the scope (leads)
rp show N12                   # an entity, its relationships and evidence
rp show E7                    # the raw record behind a fact
```

**IDs:** `N` entity, `E` evidence (one raw output record), `F` finding, `J` step.

**Entity types:** domain, subdomain, ip, url, technology, person, username, account, email, phone,
organization, breach.

**Relationships** include `has_subdomain`, `resolves_to`, `serves`, `runs`, `has_account`, `on_site`,
`registered_on`, `exposes_email`, `mentions_username`, `profile_name`, `links_to` and `has_email`.

## 8. Let the AI analyst work

```bash
rp triage                     # reviews the attack surface: draft findings + suggested steps
rp triage --identity          # focuses on usernames, accounts, emails and people
rp ask "which accounts reuse the same username?"
rp chat                       # conversation; /status for the dashboard, /exit to leave
```

What the analyst can and cannot do:

- It only **reads** the data. It never runs a tool itself.
- It can draft findings, but each must cite real evidence IDs. Answers with missing or invented IDs are
  sent back to it, then marked **unverified** if still wrong.
- It can suggest next steps, but only with a tool from `rp tools` and only for in-scope targets.
  It does not suggest a step or a finding that already exists.
- Text from collected data is treated as untrusted, so instructions planted in a web page or profile
  are not followed.

## 9. Review findings and steps

```bash
rp findings                   # draft and accepted findings
rp show F1
rp accept F1 F3               # keep these
rp reject F2

rp steps                      # steps the AI suggested
rp approve J4                 # approve...
rp run J4                     # ...then run it (scope and tier are checked again)
rp deny J5
```

In the interactive menu (`rp`), "Review suggested steps" can approve and run in one go.

## 10. Reports and exports

```bash
rp report                         # acme-report.md, accepted findings only
rp report --format html           # one self-contained HTML file, light and dark mode
rp report --drafts                # include draft findings, clearly marked
rp export --format json -o acme.json        # everything: entities, relationships, findings
rp export --format csv -o entities.csv      # one row per entity
rp export --format graphml -o acme.graphml  # open in Gephi, yEd or Maltego
rp export --in-scope                        # JSON to stdout, in-scope only
```

### Scripting

`status`, `search`, `show`, `findings`, `steps`, `tools` and `scope show` accept `--json`:

```bash
rp search -t account --json | jq -r '.[].value'
rp findings --json | jq '.[] | select(.severity == "high")'
rp tools --json | jq -r '.[] | select(.installed | not) | .install'
```

## 11. Scope, subjects and policy

### Scope

```bash
rp scope                          # show
rp scope add api.acme.com 10.1.0.0/24
rp scope add --exclude legacy.acme.com
rp scope remove 10.1.0.0/24
rp scope window --start 2026-11-01 --end 2026-12-15
```

Every change re-checks every stored entity, so in/out-of-scope flags never go stale.

### Subjects (people)

```bash
rp seed username jdoe janedoe --note "named in consent form"
rp seed email jane@example.com
rp seed phone "+33 6 12 34 56 78"
rp seed person "Jane Doe"
```

How identity scope works:

- A seeded username, email, phone or person is in scope.
- An email whose domain is in scope is in scope.
- An account is in scope when it was found from an in-scope username or email.
- Anything else found (a second username, a personal email) is kept as an **out-of-scope lead**: visible
  with `rp search --out`, never used by playbooks or the AI until you seed it.

### Policy: what tools may do

```bash
rp policy low-touch off      # passive tools only
rp policy active on          # allow active tools (none ship by default)
rp cloud on                  # allow cloud AI models for this project
```

## 12. Configuration

Copy `reconpilot.example.yaml` to `reconpilot.yaml` (in the folder you run `rp` from) or to
`~/.config/reconpilot/config.yaml`. `rp doctor` shows which file is used.

```yaml
data_dir: ./data

models:
  default: ollama:qwen2.5:14b
  profiles:
    triage: ollama:qwen2.5:14b           # rp triage
    analyst: anthropic:claude-opus-5-5   # rp ask / chat (needs rp cloud on)

tools:
  sherlock:   {timeout: 900, request_timeout: 30, local: false}
  maigret:    {timeout: 1200, all_sites: false}
  theharvester: {sources: "crtsh,certspotter,hackertarget,otx,rapiddns,urlscan", limit: 500}

analyst:
  max_steps: 20
  history_char_limit: 1500    # shorten old tool results for small local models

playbook_dirs: [~/my-playbooks]
```

Model specs are `provider:model`. Built-in providers: `ollama`, `lmstudio`, `llamacpp` (local);
`anthropic`, `openai`, `gemini`, `openrouter` (cloud, API key in an environment variable);
`codex-cli`, `claude-cli` (cloud, uses your subscription; all file and web tools are disabled for the
analyst).

## 13. Add your own tool

An adapter is one small class. This example adds a tool that prints `{"email": ...}` JSON lines:

```python
# my_adapters.py
from reconpilot.tools.base import ToolAdapter

class MailFinder(ToolAdapter):
    name = "mailfinder"
    description = "find emails for a domain"
    binary = "mailfinder"                 # on PATH; None = import-only
    accepts = ("domain",)                 # target types for `rp run`
    produces = ("email",)
    tier = "passive"                      # passive | low_touch | active
    install_hint = "pipx install mailfinder"
    output_glob = "out.json"              # files to import from the run directory

    def command(self, target, outdir, options):
        return ["mailfinder", "--domain", target, "--json", "-o", str(outdir / "out.json")]

    def sniff(self, first_line, path):    # for `rp import` auto-detection
        return first_line.startswith('{"email"')

    def handle(self, ctx, record, ev):    # one record = one evidence ID
        domain = ctx.host(record["email"].split("@")[1], ev)
        ctx.relate(domain, ctx.entity("email", record["email"], ev), "has_email", ev)
```

Register it from your package's `pyproject.toml`, then reinstall it next to ReconPilot:

```toml
[project.entry-points."reconpilot.tools"]
mailfinder = "my_adapters:MailFinder"
```

`ctx` helpers: `ctx.host(name, ev)` (domain/subdomain/IP, linked to its root domain),
`ctx.entity(type, value, ev)`, `ctx.link(src, relation, type, value, ev)` and
`ctx.relate(src, dst, relation, ev)`. Raise `ValueError` in `handle` to skip a record; nothing from
it is stored. Add a real output sample under `tests/fixtures/<tool>/` and a test for it.

## 14. Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `'httpx' on PATH is not ProjectDiscovery's httpx` | The Python `httpx` library installs its own `httpx` command. Put Go's bin directory first in `PATH`, or install ProjectDiscovery httpx and check with `httpx -version`. |
| holehe runs but finds nothing | holehe updates itself and exits when PyPI has a newer version than the installed one. Pin it: `pipx install holehe==1.61`. Its non-zero exit code after a scan is normal. |
| `the 'theHarvester' on PATH is not the real tool` | The PyPI package named theHarvester is a placeholder. Install from GitHub (see [install](#1-install)). |
| theHarvester returns nothing | Some sources need API keys. Set `tools.theharvester.sources` to keyless sources, or add keys in `~/.theHarvester/api-keys.yaml`. |
| `engagement window ... is not active` | The project's `--start`/`--end` exclude today. Fix with `rp scope window`. |
| `... is out of scope` | Add the target with `rp scope add` or `rp seed`, if your authorization covers it. |
| `... touches the target and this project is passive-only` | `rp policy low-touch on`, if allowed. |
| AI answer marked unverified | The model failed the citation check. Try a larger model (14B+ locally) or rephrase. |
| A run failed | Its output is in `data/runs/<project>/J<id>/` (`stderr.txt`, `command.json`). |
| Sherlock or Maigret "find" accounts for a username that does not exist | Some sites answer every username with a page, so these tools report false positives. Treat accounts as candidates and open the profile (`rp show N<id>`, then the URL) before reporting them. In testing, a made-up username got 4 Sherlock and 3 Maigret hits. |
| holehe finds nothing | Many sites rate-limit its checks (79 of 122 in testing). Rate-limited rows are skipped, not counted as "not registered". Retry later or from another network. |

Everything ReconPilot does is in the audit log: `rp log`.
