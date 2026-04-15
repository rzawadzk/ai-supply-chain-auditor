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
main.py              → CLI entry point for the AGENTIC audit (--backend, --db flags)
scan.py              → CLI entry point for the DETERMINISTIC scan (no LLM, for CI)
agent.py             → Dispatcher (picks adapter, optionally wraps runners with DB logging)
mcp_server.py        → STANDALONE MCP server (exposes 5 tools to any CC session)
.mcp.json            → Claude Code config to register the standalone server
findings_db.py       → SQLite persistence for audit history + tool invocations
findings_cli.py      → CLI: list / show / diff recorded audits
.github/workflows/
    audit.yml        → GitHub Actions: runs scan.py on PRs, diffs, gates on CRITICAL
adapters/            → Model-agnostic layer
    base.py          → AgentAdapter Protocol + SYSTEM_PROMPT (shared across backends)
    claude_sdk.py    → Claude Agent SDK adapter (default, uses CC login)
    openai_compat.py → OpenAI/Groq/Together/OpenRouter adapter (one class, presets)
    ollama.py        → Local-model adapter (subclass; health check + capability warning)
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

## Persistence layer (findings DB)

What's stored: raw tool invocations (name, args, JSON result, SHA256 of
canonicalized result) per audit run. NOT stored: the LLM's prose report
— non-deterministic, unsafe to diff.

How it plugs in: when `--db PATH` is passed, `agent.py` wraps each tool
runner with a logging decorator before handing the registry to the
adapter. Adapters stay oblivious. This is the "decorate the tool, not
the framework" pattern — extend by wrapping rather than by modifying.

Diffing: `findings_cli.py diff <old_id> <new_id>` compares tools by
hash of their canonicalized output. Changes are summarized structurally
(added/removed/changed keys, list length deltas). No LLM in the diff.

Principle: "structured artifacts are diffable; prose is not." If you
want finding-level diffs, extract them from the stored JSON at query
time — don't try to normalize LLM prose.

## Three ways to use this auditor

1. **Agentic mode** (`python main.py`): runs the built-in LLM loop. One model
   does inventory → investigate → prose report. Good for investigation and
   ad-hoc deep dives.
2. **MCP mode** (`.mcp.json` + `mcp_server.py`): exposes the 5 raw tools to any
   Claude Code session. The calling session becomes the strategy layer. Good for
   interactive audits where you want the caller's context in the loop.
3. **Deterministic mode** (`python scan.py`): runs every tool in a hardcoded
   order, writes structured JSON to the findings DB, exits non-zero on gated
   severity. No LLM, no API key, no non-determinism. Good for CI and pre-commit.

Design rule: the standalone MCP server exposes PRIMITIVES, not a meta-`run_audit`
tool. Tools stay deterministic; strategy stays in the calling agent.

Design rule: **agents for judgment, code for assertions.** The agentic mode
writes prose; the deterministic mode returns structured data you can grep
and gate on. Both use the same tools underneath.

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
