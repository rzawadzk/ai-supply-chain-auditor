#!/usr/bin/env python3
"""
SCAN — the deterministic lane.

Runs all 5 audit tools against a project without any LLM in the loop.
Writes results to the findings DB. Exits non-zero when the highest
severity meets or exceeds a threshold. Built for CI.

=============================================================
  WHY A SEPARATE CLI?
=============================================================

`main.py` runs the AGENTIC audit — an LLM decides the strategy, picks
tools, and writes a prose report. That's the right mode for
investigation, but wrong for a PR gate:

  - Non-deterministic: same code, different report each run.
  - Slow: multi-turn tool use is tens of seconds minimum.
  - Costs money / requires auth: no LLM runs free at commercial scale.
  - Hard to assert against: "did this PR introduce a CRITICAL finding?"
    is not a question about prose.

`scan.py` runs every tool in a hardcoded, honest order. The output is
structured JSON in SQLite. You can grep it, diff it, gate on it. The
LLM layer is still available for humans who want a narrative — it
just isn't on the PR-blocking path.

This is the core separation: AGENTS FOR JUDGMENT, CODE FOR ASSERTIONS.
Both paths exist; they use the exact same tools underneath.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from findings_db import FindingsDB, SEVERITY_ORDER
from tools import TOOL_RUNNERS


def _run_and_log(db: FindingsDB, audit_id: int, tool: str, args: dict, verbose: bool) -> dict:
    """Invoke one tool, persist it, return parsed JSON."""
    if verbose:
        print(f"  [run] {tool}({json.dumps(args)[:80]})")
    result = TOOL_RUNNERS[tool](args)
    db.log_tool_invocation(audit_id, tool, args, result)
    try:
        return json.loads(result)
    except json.JSONDecodeError:
        return {}


def scan(
    project_path: str,
    db_path: str,
    use_case: str = "commercial",
    verbose: bool = False,
) -> tuple[int, dict]:
    """Run every tool deterministically. Returns (audit_id, severity_counts)."""
    db = FindingsDB(db_path)
    audit_id = db.start_audit(project_path=project_path, backend="scan-no-llm", model=None)

    if verbose:
        print(f"Audit #{audit_id} — scanning {project_path}")

    # --- 1. Inventory always runs first; downstream tools consume its output.
    inventory = _run_and_log(
        db, audit_id, "scan_inventory",
        {"project_path": project_path}, verbose,
    )

    # --- 2. Integrity check per model file discovered.
    for mf in inventory.get("model_files", []):
        _run_and_log(
            db, audit_id, "verify_integrity",
            {"file_path": mf["path"]}, verbose,
        )

    # --- 3. Provenance and compliance — one pass each with "all".
    _run_and_log(
        db, audit_id, "check_provenance",
        {"project_path": project_path, "component_name": "all"}, verbose,
    )
    _run_and_log(
        db, audit_id, "audit_compliance",
        {"project_path": project_path, "component_name": "all", "use_case": use_case},
        verbose,
    )

    # --- 4. Behavior probe across the whole project.
    _run_and_log(
        db, audit_id, "probe_behavior",
        {"project_path": project_path, "focus_area": "all"}, verbose,
    )

    # --- 5. Severity tally across every invocation in this audit.
    return audit_id, db.severity_counts(audit_id)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic AI supply chain scan (no LLM). Built for CI.",
    )
    parser.add_argument("project_path", help="Path to the project to scan")
    parser.add_argument(
        "--db",
        default=os.environ.get("AUDITOR_DB", "audits.db"),
        help="SQLite DB path (default: %(default)s)",
    )
    parser.add_argument(
        "--use-case",
        choices=["commercial", "research", "internal", "open-source"],
        default="commercial",
    )
    parser.add_argument(
        "--fail-on",
        choices=list(SEVERITY_ORDER),
        default=None,
        help="Exit non-zero when at least one finding at this severity "
             "(or higher) is present. Typical CI value: CRITICAL.",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if not Path(args.project_path).is_dir():
        print(f"Error: not a directory: {args.project_path}", file=sys.stderr)
        return 2

    audit_id, counts = scan(
        project_path=args.project_path,
        db_path=args.db,
        use_case=args.use_case,
        verbose=args.verbose,
    )

    # --- Human-readable summary (also greppable by CI / agents downstream)
    print(f"\nAudit #{audit_id} complete.")
    print("  CRITICAL:", counts["CRITICAL"])
    print("  HIGH:    ", counts["HIGH"])
    print("  MEDIUM:  ", counts["MEDIUM"])
    print("  LOW:     ", counts["LOW"])

    # --- Gate
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        triggered = [s for s, n in counts.items() if n > 0 and SEVERITY_ORDER[s] >= threshold]
        if triggered:
            print(
                f"\nFAIL: found {sum(counts[s] for s in triggered)} "
                f"finding(s) at or above --fail-on={args.fail_on} "
                f"({', '.join(triggered)}).",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
