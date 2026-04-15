# AI Supply Chain Auditor

> Find the Shadow AI in any codebase — models, APIs, datasets, and the risks hiding inside them.

An agentic AI tool that audits software projects for supply chain risks across 5 dimensions: **inventory, provenance, integrity, compliance, behavior**. Point it at a directory; get back a prioritized risk report with remediation steps.

If you don't know what's in your AI stack, you don't understand your risk profile. This tool shines a light on it.

---

## What it finds

A non-exhaustive list of things the auditor will catch:

- Hardcoded API keys (`sk-`, `sk-ant-`, `hf_`) in source
- `pickle.load()` or `torch.load()` without `weights_only=True` — arbitrary code execution risk
- Pickle model files containing dangerous opcodes (`GLOBAL`, `REDUCE`, `INST`, `BUILD`)
- Unpinned dependencies that can silently swap under you
- HuggingFace models with no organization prefix (namespace-hijack risk)
- Models from anonymous or unverified authors
- License conflicts between your use case (commercial / research / internal / open-source) and component licenses
- Remote data downloads without checksum verification
- `exec()` / `eval()` with string interpolation
- Missing `MODEL_CARD.md` / `LICENSE` documentation
- Backdoor indicators and suspicious network patterns in model-loading code

---

## Quick start

```bash
# 1. Clone
git clone https://github.com/rzawadzk/ai-supply-chain-auditor.git
cd ai-supply-chain-auditor

# 2. Install
pip install -r requirements.txt

# 3. Make sure you're logged into Claude Code
#    (the tool uses the Claude Agent SDK — no API key needed)

# 4. Run the included demo audit
python main.py
```

The default run audits `sample_project/` — a deliberately vulnerable demo with 8+ planted issues — so you can see the output shape before pointing it at anything real.

To audit your own project:

```bash
python main.py /path/to/your/project
```

Add `--verbose` to watch the agent reason, pick tools, and iterate:

```bash
python main.py /path/to/your/project --verbose
```

### Use a different LLM

The auditor is model-agnostic. Pick any supported backend with `--backend`:

```bash
# Claude (default, uses Claude Code login — no API key needed)
python main.py --backend claude

# OpenAI (needs OPENAI_API_KEY)
OPENAI_API_KEY=sk-... python main.py --backend openai

# Groq — fast, Llama 3.3 70B by default (needs GROQ_API_KEY)
GROQ_API_KEY=gsk_... python main.py --backend groq

# Together AI (needs TOGETHER_API_KEY)
TOGETHER_API_KEY=... python main.py --backend together

# OpenRouter — unified access to many models (needs OPENROUTER_API_KEY)
OPENROUTER_API_KEY=... python main.py --backend openrouter

# Ollama — fully local, fully private. Requires `ollama serve` running.
ollama pull llama3.1
python main.py --backend ollama
```

Override the default model per backend with `OPENAI_MODEL=...`. Point at a
custom OpenAI-compatible endpoint (e.g., local vLLM) with `OPENAI_BASE_URL=...`.

**Note on Ollama and open models:** tool-use quality varies sharply by
model. Llama 3.1/3.2/3.3, Qwen 2.5, and Mistral-Nemo work reliably;
smaller models often can't complete a full audit loop. The adapter
health-checks the Ollama server and verifies the requested model is
pulled before starting, and warns on models not known to support tools.

---

## Three ways to run it

### 1. CLI (self-contained)

The tool runs its own agentic loop and prints a full report. Good for scheduled audits and CI/CD.

```bash
python main.py /path/to/project
```

### 2. From any Claude Code session (MCP mode)

Register the auditor once; call it from any Claude Code conversation. Good for interactive, investigative work where you want the calling session's context in the loop.

**Project-scoped** (auto-loaded when you open this repo in Claude Code) — the `.mcp.json` in this repo already does this.

**Global** — add to `~/.claude.json` so it's available everywhere:

```json
{
  "mcpServers": {
    "ai-supply-chain-auditor": {
      "command": "python",
      "args": ["/absolute/path/to/ai-supply-chain-auditor/mcp_server.py"]
    }
  }
}
```

Then in any Claude Code session:

> Audit the AI supply chain of this repo. Start with inventory and drill into anything CRITICAL.

Five tools become available: `scan_inventory`, `check_provenance`, `verify_integrity`, `audit_compliance`, `probe_behavior`. The calling session orchestrates them.

### Track audits over time

Pass `--db` to persist every tool invocation to a SQLite database. Then use
`findings_cli.py` to compare runs — useful for catching when a new
dependency or code change introduces a risk.

```bash
# First audit — records into audits.db
python main.py --db audits.db

# Later (after code changes) — records a new audit
python main.py --db audits.db

# See all recorded audits
python findings_cli.py list

# Compare two audits
python findings_cli.py diff 1 2

# Inspect one audit in detail
python findings_cli.py show 2 --full
```

What gets stored: the structured JSON output of each tool (inventory,
provenance, integrity, compliance, behavior). What does **not** get
stored: the LLM's prose report — it's non-deterministic and unsafe to
diff. The CLI compares tool outputs by hash and summarizes structural
changes (added/removed findings, list length deltas).

### 3. Deterministic scan (no LLM — built for CI)

Runs every tool in a hardcoded order, writes structured JSON to the findings
DB, exits non-zero when a severity threshold is hit. No LLM, no API key, no
non-determinism.

```bash
# One-off scan
python scan.py /path/to/project

# CI-style: gate on CRITICAL, persist to DB
python scan.py /path/to/project --db audit.db --fail-on CRITICAL
echo $?   # 0 = passed, 1 = CRITICAL found
```

A ready-to-use GitHub Actions workflow is in `.github/workflows/audit.yml`.
It scans the PR branch vs its base, posts a sticky diff comment, and fails
the check on any CRITICAL finding — all without an API key.

You can also invoke the underlying tools directly for custom pipelines:

```python
from tools.inventory import run_inventory
import json
inv = json.loads(run_inventory({"project_path": "./my-repo"}))
for mf in inv["model_files"]:
    print(f"{mf['path']}: {mf['risk']}")
```

---

## Input format

Just a directory path. No config file. No manifest. The tool crawls the tree and knows how to read:

| File type | What it extracts |
|---|---|
| `requirements.txt`, `pyproject.toml`, `Pipfile`, `setup.py` | Python ML dependencies + version pinning |
| `package.json` | Node ML dependencies |
| `.py`, `.js`, `.ts`, `.jsx`, `.tsx` | API calls, model loading, hardcoded secrets, risky patterns |
| `.yaml`, `.yml`, `.json`, `.toml` | Model names, API endpoints |
| `.pt`, `.pth`, `.pkl`, `.safetensors`, `.onnx`, `.bin`, `.gguf`, `.h5` | Format safety, pickle opcode inspection, file hashes |
| `LICENSE*` | Project license |

It does NOT download anything over the network — it inspects references, not content. And it skips `node_modules/` and `.venv/` automatically.

---

## The 5 audit dimensions

1. **Inventory** — *What AI is in the stack?* Discovers ML libraries, model files, AI APIs, and dataset references.
2. **Provenance** — *Where did each component come from?* Checks model cards, authorship, trusted sources, and version pinning.
3. **Integrity** — *Has anything been tampered with?* Inspects model files for unsafe serialization, dangerous pickle opcodes, and embedded suspicious patterns.
4. **Compliance** — *Does the license match the use case?* Cross-references project licenses against commercial / research / internal / open-source intents.
5. **Behavior** — *Is the code doing anything shady?* Pattern-matches unsafe loading, network exfiltration, credential leaks, and backdoor indicators.

---

## Example: what the output looks like

Running on `sample_project/` produces a report with an executive summary, an overall risk score (CRITICAL / HIGH / MEDIUM / LOW), findings grouped and prioritized by dimension, and a three-tier remediation plan (immediate / short-term / medium-term). On the demo project it surfaces 16 findings — 6 CRITICAL — including an executable pickle file, a hardcoded API key, and a model loaded from an unverified author.

See [`sample_project/app.py`](sample_project/app.py) for the intentionally vulnerable demo code.

---

## Architecture

```
main.py              CLI entry point
agent.py             Dispatcher — picks adapter, delegates audit
mcp_server.py        Standalone MCP server (stdio, exposes tools to any CC session)
.mcp.json            Claude Code auto-registration
adapters/            Model-agnostic layer
    base.py          AgentAdapter Protocol + shared system prompt
    claude_sdk.py    Claude adapter (SDK-managed loop)
    openai_compat.py Unified adapter for OpenAI/Groq/Together/OpenRouter
tools/
    inventory.py     Scan for AI components
    provenance.py    Check origins and sources
    integrity.py     Verify file safety (pickle scanning, hashes)
    compliance.py    License matrix and conflict detection
    behavior.py      Pattern-match risky code
sample_project/      Deliberately vulnerable demo
```

Design principle: **you write the tools; the agent writes the strategy.** Tools are deterministic and independently useful. The LLM decides composition, prioritization, and narrative.

---

## Requirements

- Python 3.10+
- [Claude Code](https://claude.com/claude-code) installed and logged in (the Agent SDK authenticates through it — no `ANTHROPIC_API_KEY` needed)
- Dependencies in `requirements.txt`: `claude-agent-sdk`, `anyio`

---

## Honest limitations

- **Pattern-matching is not proof.** A finding is a signal to investigate, not a verdict. The auditor flags `torch.load()` without `weights_only=True`; it can't tell you the file you're loading is actually malicious.
- **No network inspection.** If your code downloads a model at runtime, we see the URL, not the payload.
- **Model quality matters.** The agentic report's depth scales with the backing model. Claude Opus 4.6 is the default; smaller models will produce shallower audits.
- **Not a SAST tool.** This is AI-supply-chain-specific. It won't catch SQL injection or XSS. Pair it with traditional security scanners.

---

## Contributing

PRs welcome. Things worth adding:

- SARIF output for GitHub code scanning
- Integration with SBOM formats (CycloneDX, SPDX)
- More language support (Rust, Go, Java ML frameworks)
- Richer diffs in `findings_cli.py` (e.g., which specific finding appeared)
- Capability benchmark: run all backends against `sample_project/` and report which models can actually complete the audit

If you're learning agentic AI patterns while reading this code, start with [`CLAUDE.md`](CLAUDE.md) — it's written as a teaching artifact.

---

## License

MIT.
