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

=============================================================
  HOW PERSISTENCE IS WIRED IN (when --db is passed)
=============================================================

The adapters are oblivious to the findings DB. We wrap each tool runner
with a logging decorator BEFORE handing the registry to the adapter.
The adapter still sees a `{name: callable}` dict; the callables just
happen to also write to SQLite on the way out.

This is the "decorate the tool, not the framework" pattern — the same
trick you'd use to add tracing, rate limiting, or caching without
touching adapter code.
"""

from __future__ import annotations

import anyio

from adapters import SYSTEM_PROMPT, get_adapter
from tools import ALL_TOOLS, TOOL_RUNNERS


async def _run_audit_async(
    project_path: str,
    verbose: bool = False,
    backend: str = "claude",
    db_path: str | None = None,
) -> str:
    """Instantiate the chosen adapter and delegate the audit to it."""
    adapter = get_adapter(backend)

    if verbose:
        print("=" * 60)
        print(f"  AI SUPPLY CHAIN AUDITOR — backend: {adapter.name}")
        print("=" * 60)
        print(f"\n  Target: {project_path}")
        if db_path:
            print(f"  DB:     {db_path}")
        print("=" * 60)

    # Optionally wrap tool runners so every invocation is persisted.
    tool_runners = TOOL_RUNNERS
    if db_path:
        from findings_db import FindingsDB
        db = FindingsDB(db_path)
        # Model name is only known for openai-compat adapters; safe getattr.
        audit_id = db.start_audit(
            project_path=project_path,
            backend=adapter.name,
            model=getattr(adapter, "model", None),
        )
        tool_runners = _wrap_runners_with_logging(TOOL_RUNNERS, db, audit_id)
        if verbose:
            print(f"  [db] Recording audit #{audit_id}\n")

    return await adapter.run_audit(
        project_path=project_path,
        tool_schemas=ALL_TOOLS,
        tool_runners=tool_runners,
        system_prompt=SYSTEM_PROMPT,
        verbose=verbose,
    )


def _wrap_runners_with_logging(runners: dict, db, audit_id: int) -> dict:
    """Return a new {name: callable} dict where each callable also logs to db."""
    def make_wrapper(name, runner):
        def wrapped(args):
            result = runner(args)
            try:
                db.log_tool_invocation(audit_id, name, args, result)
            except Exception as e:
                # Never let DB failures break an audit — print and continue.
                print(f"  [db] warning: failed to log {name}: {e}")
            return result
        return wrapped
    return {name: make_wrapper(name, runner) for name, runner in runners.items()}


def run_audit(
    project_path: str,
    verbose: bool = False,
    backend: str = "claude",
    db_path: str | None = None,
) -> str:
    """Sync wrapper — main.py and any non-async caller talk to this."""
    return anyio.run(_run_audit_async, project_path, verbose, backend, db_path)
