# ReconPilot

**An OSINT workbench that runs your recon tools, connects their results, and lets an AI analyst review them, with evidence for every claim.**

[![CI](https://github.com/Abdelkoddous0/reconpilot/actions/workflows/ci.yml/badge.svg)](https://github.com/Abdelkoddous0/reconpilot/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Local first](https://img.shields.io/badge/data-local%20first-green)

ReconPilot is a command-line tool for open-source intelligence (OSINT) and external reconnaissance.
You give it a target you are authorized to investigate (a domain, a username, an email). It runs
well-known tools such as **Sherlock**, **Maigret**, **holehe**, **theHarvester**, **subfinder**, **dnsx** and **httpx**, then
stores everything they find in one local database where results are linked together.

An AI analyst (a local model or a cloud model, your choice) can then review the data, answer questions,
draft findings and suggest next steps. It cannot make things up: every statement it makes must point to
a stored record, and answers that don't are rejected.

---

## Contents

- [Why ReconPilot](#why-reconpilot)
- [How it works](#how-it-works)
- [Supported tools](#supported-tools)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Example workflows](#example-workflows)
- [The AI analyst](#the-ai-analyst)
- [Safety and scope](#safety-and-scope)
- [Command reference](#command-reference)
- [Configuration](#configuration)
- [Project structure](#project-structure)
- [Development](#development)
- [Legal](#legal)

---

## Why ReconPilot

Running OSINT tools one by one leaves you with a folder of CSV and JSON files that don't talk to each
other. ReconPilot fixes that:

| Problem | What ReconPilot does |
| --- | --- |
| Every tool has its own output format | Reads them all and stores the results in one place |
| Results are disconnected | Links them: a username → its accounts → the emails and names they expose |
| Easy to scan something you shouldn't | Checks every target against the scope you set before anything runs |
| AI tools invent facts | The analyst must cite a stored record for every claim, or its answer is rejected |
| Client data sent to the cloud | Cloud AI is off by default; local models (Ollama, LM Studio) work out of the box |
| No record of what was done | Every tool run, import and AI action is written to a log that cannot be edited |

---

## How it works

```text
1. Create a project   →  rp new      what you are allowed to investigate (domains, usernames, emails)
2. Collect data       →  rp run      runs a tool, or a chain of tools, after checking the scope
                         rp import   or loads output files you already have
3. Explore            →  rp search   everything is linked: accounts, emails, hosts, IPs
4. Analyse            →  rp triage   the AI reviews the data and drafts findings with evidence
5. Review             →  rp accept   you decide what is real
6. Report             →  rp report   Markdown or HTML report, plus CSV / JSON / GraphML export
```

Each piece of data keeps a reference to the exact tool output it came from (shown as `E12`). Entities
such as hosts, accounts and emails are shown as `N12`, findings as `F3`, and tool runs as `J4`.

---

## Supported tools

| Tool | What it finds | Input |
| --- | --- | --- |
| [Sherlock](https://github.com/sherlock-project/sherlock) | Accounts using a username on 400+ sites | username |
| [Maigret](https://github.com/soxoj/maigret) | Accounts plus profile details (names, links, emails) | username |
| [holehe](https://github.com/megadose/holehe) | Websites where an email is registered | email |
| [theHarvester](https://github.com/laramies/theHarvester) | Emails, hosts and IPs from public sources | domain |
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomains | domain |
| [dnsx](https://github.com/projectdiscovery/dnsx) | DNS records (A, AAAA, CNAME) | host |
| [httpx](https://github.com/projectdiscovery/httpx) | Live websites, page titles, technologies | host or URL |
| [amass](https://github.com/owasp-amass/amass) | Subdomains (file import only) | file |

Any plain list of hosts can also be imported. New tools can be added with a small Python class; see the
[usage guide](docs/USAGE.md#13-add-your-own-tool).

---

## Installation

**Requirements:** Python 3.11 or newer, on Linux or macOS.

```bash
git clone https://github.com/Abdelkoddous0/reconpilot.git
cd reconpilot
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

Then install the tools you want to use. You don't need all of them.

```bash
pipx install sherlock-project
pipx install maigret
pipx install holehe==1.61
pipx install git+https://github.com/laramies/theHarvester@4.11.1
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

For the AI analyst, install a local model (recommended, nothing leaves your machine):

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:14b
```

Finally, check that everything is ready:

```bash
rp doctor
```

`rp doctor` lists each tool and AI backend as ready or not, with the command to fix anything missing.

---

## Quick start

Try it with the sample data in this repository, no tools needed:

```bash
rp new lab --client "Example Corp" --auth-ref "RoE-2026-001" \
   --scope example.com --seed username:jdoe_test

rp import examples/subfinder.json examples/httpx.json tests/fixtures/sherlock/jdoe_test.csv

rp status                 # dashboard
rp search -t account      # accounts found for jdoe_test
rp search admin           # anything containing "admin"
rp show N3                # one item, what it is linked to, and its evidence
rp report --format html   # writes lab-report.html
```

Or run `rp` on its own for an interactive menu you can use with the arrow keys.

---

## Example workflows

### Investigate a username

```bash
rp new case42 --client "Internal" --auth-ref "Case 42 consent form" --seed username:jdoe
rp run username-sweep jdoe        # Sherlock + Maigret + holehe on found emails + AI summary
rp search -t account              # accounts found
rp search --out                   # leads found outside your scope (other usernames, emails)
rp triage --identity              # AI review of the person's footprint
rp report --format html
```

### Map a company's external footprint

```bash
rp new acme --client "Acme Corp" --auth-ref "RoE-2026-07" \
   --scope acme.com --scope 203.0.113.0/24 --exclude vpn.acme.com
rp run domain-surface acme.com    # subfinder + theHarvester + dnsx + httpx + AI triage
rp findings                       # draft findings from the AI
rp accept F1 F3                   # keep the real ones
rp report --format html
```

### Run a single tool

```bash
rp run sherlock jdoe
rp run holehe jane@example.com
rp run theharvester acme.com
```

### Import results you already have

```bash
rp import sherlock/jdoe.csv results/subfinder.json   # the tool is detected automatically
```

Importing the same file twice does not create duplicates.

---

## The AI analyst

```bash
rp triage                                    # review everything, draft findings, suggest next steps
rp ask "which usernames appear on more than three sites?"
rp chat                                      # back-and-forth conversation
```

Example answer:

```text
rp_selftest_alpha77 has 6 accounts:

 Platform    Account URL                                      Evidence
 f3.cool     https://f3.cool/rp_selftest_alpha77/             [E26096]
 YouTube     https://www.youtube.com/@rp_selftest_alpha77     [E26097]
 ...

These may be false positives: a second made-up username got hits on the same sites.

✔ citations verified  claude-cli:default · 4 steps · 3 tool calls · 13 cited claims
```

How it stays trustworthy:

- **Read-only.** The AI never runs tools. It can only *suggest* a step, which you approve with
  `rp approve J4` and then run with `rp run J4`.
- **Evidence required.** Every claim must cite a real record. If it doesn't, the answer is sent back to
  the model. If it still fails, the answer is clearly marked **unverified**.
- **Scope-aware.** It cannot suggest anything outside your scope.
- **Resistant to prompt injection.** Collected text (web pages, profiles) is treated as data, so
  instructions hidden inside it are ignored.

### Supported models

| Model | Where it runs | Setup |
| --- | --- | --- |
| `ollama:qwen2.5:14b` (default) | your machine | `ollama pull qwen2.5:14b` |
| `lmstudio:<model>`, `llamacpp:<model>` | your machine | start the local server |
| `anthropic:claude-opus-5-5` | cloud | `pip install -e '.[anthropic]'`, set `ANTHROPIC_API_KEY` |
| `openai:<model>`, `gemini:<model>`, `openrouter:<model>` | cloud | set the matching API key |
| `claude-cli:default`, `codex-cli:default` | cloud | uses your Claude Code or Codex subscription |

Pick a model per command with `-m`, or set defaults in `reconpilot.yaml`. Cloud models are blocked for
each project until you run `rp cloud on`. For a local model, use 14B parameters or more for reliable
results.

---

## Safety and scope

ReconPilot is built for **authorized** work: penetration tests, bug bounty programs, internal
investigations, and research with consent.

- **Authorization is required.** Every project needs an authorization reference (contract, rules of
  engagement, bug bounty URL or consent form).
- **Scope is checked before every run.** Targets must be inside your scope: listed domains and IP ranges,
  or people you added with `rp seed`. Anything else is refused.
- **Dates are enforced.** With `--start` and `--end`, nothing runs or imports outside the engagement window.
- **Tools are graded by impact.** *Passive* tools only query public sources. *Low-touch* tools (httpx,
  holehe) send light requests and can be turned off with `rp policy low-touch off`. *Active* tools are
  blocked unless you allow them.
- **Leads stay out until you add them.** If Maigret finds a second username or a personal email, it is
  stored as out of scope. Playbooks and the AI ignore it until you add it with `rp seed`.
- **Everything is logged.** `rp log` shows every import, tool run and AI action.

---

## Command reference

| Command | What it does |
| --- | --- |
| `rp` | Interactive menu |
| `rp doctor` | Check Python, tools and AI models |
| `rp new <name>` | Create a project (asks for missing details) |
| `rp use <name>` / `rp ls` | Switch project / list projects |
| `rp status` | Dashboard |
| `rp scope [add\|remove\|window]` | View or change the scope |
| `rp seed <type> <value>` | Add a person to investigate (`username`, `email`, `phone`, `person`) |
| `rp tools` / `rp playbooks` | Available tools / ready-made chains of tools |
| `rp run <tool or playbook> <target>` | Run a tool or playbook |
| `rp run J<id>` | Run a step the AI suggested, after you approve it |
| `rp import <files>` | Load output files from any supported tool |
| `rp search [text] [-t type]` | Search everything collected |
| `rp show <N\|E\|F id>` | Details of an item, a piece of evidence or a finding |
| `rp triage` / `rp ask` / `rp chat` | Use the AI analyst |
| `rp findings`, `rp accept`, `rp reject` | Review findings |
| `rp steps`, `rp approve`, `rp deny` | Review suggested next steps |
| `rp report [--format html]` | Write a report |
| `rp export --format json\|csv\|graphml` | Export data for spreadsheets, scripts, Gephi or Maltego |
| `rp policy`, `rp cloud` | Allow or block tool types and cloud AI |
| `rp log` | Audit log |

Add `--json` to `status`, `search`, `show`, `findings`, `steps`, `tools` or `scope show` for
machine-readable output. Run `rp <command> --help` for every option.

**Full documentation:** [docs/USAGE.md](docs/USAGE.md) covers each step in detail, writing your own
playbooks, adding new tools and troubleshooting.

---

## Configuration

Settings are optional. Copy the example file and edit it:

```bash
cp reconpilot.example.yaml reconpilot.yaml
```

```yaml
data_dir: ./data                     # where projects are stored (one SQLite file each)

models:
  default: ollama:qwen2.5:14b
  profiles:
    triage: ollama:qwen2.5:14b       # model for rp triage
    analyst: claude-cli:default      # model for rp ask / rp chat

tools:
  theharvester:
    sources: crtsh,certspotter,hackertarget,otx,rapiddns,urlscan   # sources that need no API key
```

ReconPilot looks for `reconpilot.yaml` in the current folder, then in `~/.config/reconpilot/config.yaml`.

---

## Project structure

```text
reconpilot/
├── cli.py              commands
├── shell.py            interactive menu
├── scope.py            scope rules (domains, networks, people)
├── store.py            local database: evidence, entities, links, findings, audit log
├── importers.py        reading tool output files
├── playbook.py         chains of tools
├── playbooks/          built-in playbooks (YAML)
├── report.py           Markdown and HTML reports
├── export.py           JSON, CSV and GraphML export
├── tools/
│   ├── base.py         how a tool is described (adapter interface)
│   ├── runner.py       runs tools safely after the scope checks
│   ├── identity.py     Sherlock, Maigret, holehe, theHarvester
│   └── infra.py        subfinder, dnsx, httpx, amass, host lists
└── ai/
    ├── analyst.py      the AI analyst and its evidence check
    └── providers.py    connections to local and cloud models
docs/USAGE.md           full usage guide
tests/                  test suite, with real output samples from each tool
examples/               sample data
```

---

## Development

```bash
pip install -e '.[dev]'
pytest                      # tests
ruff check reconpilot tests # lint
mypy reconpilot             # type check
```

All three run on every push via GitHub Actions.

To add support for a new tool, write an adapter class (usually under 60 lines), add a real output sample
under `tests/fixtures/<tool>/`, and add a test. The [usage guide](docs/USAGE.md#13-add-your-own-tool)
walks through an example.

---

## Legal

Use ReconPilot only on targets you own or are explicitly authorized to investigate. You are responsible
for complying with the law, your rules of engagement, data-protection rules that apply to personal data,
and the terms of service of every source and tool used.
