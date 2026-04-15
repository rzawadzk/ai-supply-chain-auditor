"""
ADAPTER CONTRACT — the seam between the auditor and any LLM provider.

=============================================================
  WHY THE SEAM GOES HERE (high-level) AND NOT LOWER
=============================================================

A tempting design is to abstract one layer down — "give me a function
that calls a model once with messages and tools." That fails because
the agentic LOOP itself differs per provider:

  - Claude Agent SDK: the SDK owns the loop; we just consume messages.
  - OpenAI-compatible: we own a `while` loop, handle `tool_calls` in
    assistant messages, append `role: "tool"` response messages.
  - Ollama / open models: tool use is flaky; may need capability checks.

If we abstracted at the single-call layer, every caller would need
`if isinstance(adapter, ClaudeAdapter)` branches to handle the loop
differences. The abstraction would leak.

So the seam is WHOLE-LOOP. One method: run_audit(). Each adapter owns
its loop end-to-end and is idiomatic for its provider. The cost is
~80 lines of loop code duplicated per adapter — a fair price for not
having a leaky abstraction.

=============================================================
  WHAT FLOWS ACROSS THE SEAM
=============================================================

IN:   project_path, tool_schemas (Claude format), tool_runners (Python
      callables), system_prompt, verbose flag.
OUT:  the final report text.

Tool schemas travel in Claude's JSON Schema shape because that's what
tools/*.py already defines. Adapters translate on their way in (Claude's
`input_schema` key → OpenAI's `parameters` key, etc.) — the translation
is a one-liner.
"""

from __future__ import annotations

from typing import Callable, Protocol, runtime_checkable


# =============================================================
#  SHARED PROMPTS — same voice, regardless of backend
# =============================================================
# Keeping the system prompt out of individual adapters means a change
# to audit methodology propagates to every backend automatically.

SYSTEM_PROMPT = """You are an AI Supply Chain Auditor — a security expert specialized
in auditing AI/ML components in software projects for hidden risks.

Your mission: Systematically audit the project at the given path for Shadow AI risks
across 5 dimensions:

1. INVENTORY — Discover all AI components (models, APIs, datasets, libraries)
2. PROVENANCE — Trace where each component came from
3. INTEGRITY — Check for tampering, unsafe serialization, backdoors
4. COMPLIANCE — Verify licenses match the intended use case
5. BEHAVIOR — Probe for suspicious runtime behavior patterns

AUDIT METHODOLOGY:
- ALWAYS start with scan_inventory to discover what's in the stack
- Then investigate the highest-risk findings with the other tools
- Be thorough — check EVERY AI component you find
- Prioritize: CRITICAL > HIGH > MEDIUM > LOW risk findings
- For each finding, explain WHY it's a risk and WHAT to do about it

OUTPUT FORMAT:
After completing your audit, provide a structured report with:
- Executive Summary (1-2 sentences)
- Risk Score (CRITICAL / HIGH / MEDIUM / LOW)
- Findings by dimension (grouped and prioritized)
- Actionable recommendations (specific, not generic)

Remember: You are protecting the organization from risks they don't even know they have.
Shadow AI is the threat — shine a light on it."""


def build_user_prompt(project_path: str) -> str:
    """The opening message sent to the model. Kept as a function so adapters
    can't diverge on wording — this is part of the contract."""
    return (
        f"Audit the AI supply chain of the project at: {project_path}\n\n"
        "Assume this is a commercial product. Check everything — models, "
        "APIs, datasets, dependencies, model files. I want a complete "
        "risk assessment."
    )


# =============================================================
#  THE PROTOCOL — one method, one return type
# =============================================================

# A tool runner takes a dict of args (matching its input schema) and returns
# a JSON string. Runners are synchronous — they do file I/O, not network I/O.
ToolRunner = Callable[[dict], str]


@runtime_checkable
class AgentAdapter(Protocol):
    """Every backend implements this. Nothing more, nothing less."""

    #: A short identifier, used in logs and CLI flag values.
    name: str

    async def run_audit(
        self,
        project_path: str,
        tool_schemas: list[dict],
        tool_runners: dict[str, ToolRunner],
        system_prompt: str,
        verbose: bool = False,
    ) -> str:
        """Run the full agentic audit loop against `project_path`.

        Implementations MUST:
          - Register every tool in `tool_schemas` with the model.
          - Dispatch tool calls to the matching runner in `tool_runners`.
          - Stop when the model produces a final text response or a safety
            cap (max turns) is hit.
          - Return the final report text.

        Implementations MAY:
          - Use any native loop mechanism (SDK-managed, manual while-loop, etc.)
          - Print progress when `verbose=True`.
        """
        ...
