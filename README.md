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

### 3. Direct Python (no LLM)

Deterministic, fast, no API cost. Good for pre-commit hooks and CI gates.

```python
from tools.inventory import run_inventory
from tools.integrity import run_integrity
import json

inv = json.loads(run_inventory({"project_path": "./my-repo"}))
for mf in inv["model_files"]:
    print(f"{mf['path']}: {mf['risk']}")
    check = json.loads(run_integrity({"file_path": mf["path"]}))
    if check.get("dangerous_opcodes"):
        print(f"  BLOCKED: {check['dangerous_opcodes']}")
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
agent.py             Agentic loop (Claude Agent SDK, in-process MCP)
mcp_server.py        Standalone MCP server (stdio, exposes tools to any CC session)
.mcp.json            Claude Code auto-registration
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

- Model-agnostic adapter (swap Claude for OpenAI / Groq / Ollama)
- Persistent findings DB with history tracking
- SARIF output for GitHub code scanning
- Integration with SBOM formats (CycloneDX, SPDX)
- More language support (Rust, Go, Java ML frameworks)

If you're learning agentic AI patterns while reading this code, start with [`CLAUDE.md`](CLAUDE.md) — it's written as a teaching artifact.

---

## License

MIT.
