"""
AGENT DISPATCHER — pick a backend and run the audit.

=============================================================
  WHAT HAPPENED TO ALL THE CODE?
=============================================================

Earlier this file contained the whole Claude Agent SDK loop. It now lives
in `adapters/claude_sdk.py`, behind a common Protocol (`AgentAdapter`).

The benefit of the dispatcher pattern: the rest of the system (main.py,
CI scripts, tests) depends on ONE sync function — `run_audit(...)` — and
stays oblivious to which LLM is doing the work.

Swapping backends:
  - CLI flag:  python main.py --backend groq
  - Env var:   AUDITOR_BACKEND=openai python main.py
  - Default:   claude (uses your Claude Code login, no API key)

New backends plug in by implementing `AgentAdapter` and registering in
`adapters/__init__.py::get_adapter()`. Nothing else needs to change.
"""

from __future__ import annotations

import anyio

from adapters import SYSTEM_PROMPT, get_adapter
from tools import ALL_TOOLS, TOOL_RUNNERS


async def _run_audit_async(
    project_path: str,
    verbose: bool = False,
    backend: str = "claude",
) -> str:
    """Instantiate the chosen adapter and delegate the audit to it."""
    adapter = get_adapter(backend)

    if verbose:
        print("=" * 60)
        print(f"  AI SUPPLY CHAIN AUDITOR — backend: {adapter.name}")
        print("=" * 60)
        print(f"\n  Target: {project_path}")
        print("=" * 60)

    return await adapter.run_audit(
        project_path=project_path,
        tool_schemas=ALL_TOOLS,
        tool_runners=TOOL_RUNNERS,
        system_prompt=SYSTEM_PROMPT,
        verbose=verbose,
    )


def run_audit(
    project_path: str,
    verbose: bool = False,
    backend: str = "claude",
) -> str:
    """Sync wrapper — main.py and any non-async caller talk to this."""
    return anyio.run(_run_audit_async, project_path, verbose, backend)
