# AI Supply Chain Auditor

## Project Purpose
An agentic AI tool that audits software projects for Shadow AI risks across 5 dimensions:
1. **Inventory** — Discover AI components (models, APIs, datasets, libraries)
2. **Provenance** — Trace where each component came from
3. **Integrity** — Check for tampering, unsafe serialization, backdoors
4. **Compliance** — Verify licenses match intended use case
5. **Behavior** — Probe for suspicious runtime patterns

This project also serves as a learning exercise for agentic AI patterns.

## My Learning Goals
I am learning agentic AI. When helping with this project:
- **Explain WHY, not just WHAT** — show the patterns behind decisions
- **Point out agentic design choices** — e.g., why a tool exists vs hardcoded logic
- **Show tradeoffs** — when a simpler approach would work, say so
- **Flag model-vs-code boundaries** — make it clear which work the LLM does vs the code
- **Teach through code** — keep comments pedagogical, not just descriptive

## Architecture

```
main.py              → CLI entry point (--backend flag picks adapter)
agent.py             → Dispatcher (picks adapter, delegates audit)
mcp_server.py        → STANDALONE MCP server (exposes 5 tools to any CC session)
.mcp.json            → Claude Code config to register the standalone server
adapters/            → Model-agnostic layer
    base.py          → AgentAdapter Protocol + SYSTEM_PROMPT (shared across backends)
    claude_sdk.py    → Claude Agent SDK adapter (default, uses CC login)
    openai_compat.py → OpenAI/Groq/Together/OpenRouter adapter (one class, presets)
    __init__.py      → get_adapter() registry with lazy imports
tools/               → The 5 audit dimensions (one file per tool)
    __init__.py      → Tool registry (ALL_TOOLS, TOOL_RUNNERS)
    inventory.py     → Scans for AI components
    provenance.py    → Checks origins and sources
    integrity.py     → Verifies file safety (pickle scanning, hashes)
    compliance.py    → License matrix and conflict detection
    behavior.py      → Pattern-matches risky code
sample_project/      → Intentionally vulnerable demo project
```

## Adapter contract (the model-agnostic seam)

Every backend implements `AgentAdapter` (one method: `run_audit`). The seam
is WHOLE-LOOP, not per-call, because the agentic loop itself differs between
providers (SDK-managed for Claude, explicit `while` for OpenAI-compatible).
Abstracting at the single-call layer would leak provider differences into
every caller.

Shared across all adapters: `SYSTEM_PROMPT`, `build_user_prompt()`,
`tool_schemas` (Claude JSON Schema format), `tool_runners` (Python callables).
Adapters translate the schema to their native format on the way in.

Adding a new backend:
1. Write a class with `name: str` and `async def run_audit(...) -> str`
2. Register it in `adapters/__init__.py::get_adapter()`
3. Add the name to `AVAILABLE_BACKENDS`
No other file needs to change.

## Two ways to use this auditor

1. **CLI mode** (`python main.py`): runs the built-in agentic loop. Self-contained
   — one model does inventory → investigate → report. Good for scheduled audits
   and CI/CD.
2. **MCP mode** (`.mcp.json` + `mcp_server.py`): exposes the 5 raw tools to any
   Claude Code session. The calling session becomes the strategy layer. Good for
   ad-hoc, interactive audits where you want the caller's context (codebase
   familiarity, prior conversation) in the loop.

Design rule: the standalone MCP server exposes PRIMITIVES, not a meta-`run_audit`
tool. Tools stay deterministic; strategy stays in the calling agent.

## Conventions
- **Model**: Claude Opus 4.6 (`claude-opus-4-6`) with adaptive thinking
- **Tool definition format**: Each tool file exports `XXX_TOOL` (schema) + `run_xxx()` (runner)
- **New tools**: Must be registered in `tools/__init__.py`
- **Tool outputs**: Always return JSON strings (easier for Claude to parse and reason about)
- **No emojis in code or reports** unless explicitly requested

## Running
```bash
python main.py                    # Audit the sample project
python main.py /path/to/project   # Audit any project
python main.py --verbose          # Watch the agentic loop in action
```

Currently requires `ANTHROPIC_API_KEY`. Alternative: use the Claude Agent SDK
(no API key needed — authenticates via Claude Code login).

## Design Philosophy
- **You write the tools. Claude writes the strategy.** This is the core agentic insight.
- **Tools are deterministic. The agent is adaptive.** Don't put reasoning in tools.
- **Every tool should be independently useful.** Claude decides composition.
- **Fail loudly, not silently.** Tools return rich JSON with warnings and recommendations.

## Known Risks in the Sample Project
(These are INTENTIONAL planted vulnerabilities for the auditor to find)
- Unpinned dependency versions in `requirements.txt`
- `torch.load()` without `weights_only=True`
- `pickle.load()` on untrusted file
- Hardcoded OpenAI API key
- Model loaded without organization prefix (ambiguous provenance)
- Remote CSV download without checksum verification
- `exec()` call for dynamic code execution
- No MODEL_CARD.md documentation

## Future Work / Ideas
- Model-agnostic adapter (swap between Claude, Ollama, Groq)
- MCP server wrapper so auditor can be used from any Claude Code session
- Persistent findings DB with history tracking
- Integration with existing SBOM tools (CycloneDX, SPDX)
- SARIF output for CI/CD integration
