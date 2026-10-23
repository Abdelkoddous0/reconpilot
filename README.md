# ReconPilot (prototype)

Local-first OSINT workbench with a bring-your-own-model AI analyst. You run your usual recon tools
against **authorized** targets, import their output, and ask an AI analyst (local Qwen, Claude, Codex,
GPT, Gemini...) to triage it. Every claim the AI makes must cite stored evidence.

## Install

```bash
uv venv && uv pip install -e '.[dev]'           # add ',anthropic' for the Claude API provider
source .venv/bin/activate
pytest                                         # run the test suite
```

## Quick start (with the bundled fictional sample data)

```bash
reconpilot init lab --client "Example Corp" --auth-ref "RoE-2026-001" \
    --scope example.com --scope 10.0.0.0/24 --exclude dev.example.com
reconpilot import lab examples/subfinder.json
reconpilot import lab examples/httpx.json
reconpilot entities lab
reconpilot models                              # which model backends are available
reconpilot triage lab --model ollama:qwen2.5:14b
reconpilot findings lab
reconpilot validate lab F1
reconpilot report lab -o report.md
```

## Choosing a model

| Spec example | Runs | Needs |
| --- | --- | --- |
| `ollama:qwen2.5:14b` | local | `ollama serve` + `ollama pull qwen2.5:14b` |
| `lmstudio:<model>` | local | LM Studio server on port 1234 |
| `anthropic:claude-opus-5-5` | cloud | `pip install anthropic`, `ANTHROPIC_API_KEY` |
| `openai:<model>` | cloud | `OPENAI_API_KEY` |
| `gemini:<model>` | cloud | `GEMINI_API_KEY` |
| `codex-cli:default` | cloud via CLI | `codex` logged in |
| `claude-cli:default` | cloud via CLI | `claude` logged in |

Projects block cloud models by default. Allow them only when the client agrees:
`reconpilot set lab allow_cloud true`.

## Supported imports

`subfinder -oJ`, `amass enum -json` (v3), `dnsx -json`, `httpx -json`, or a plain list of hosts.
The format is auto-detected. Each line becomes one evidence record (`E<n>`).

## Safety design

- A project cannot exist without an authorization reference and a scope.
- Out-of-scope assets are stored but flagged; the AI cannot suggest steps against them.
- The AI only reads the graph. It cannot run scans; its suggestions wait in `reconpilot jobs`.
- Answers and findings without valid evidence IDs are rejected and sent back to the model.
- Collected text is wrapped as untrusted data to blunt prompt injection.
- The audit log is append-only (enforced by SQLite triggers).
