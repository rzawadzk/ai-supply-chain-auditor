#!/usr/bin/env python3
"""
findings_cli — inspect persisted audits.

Usage:
    python findings_cli.py list [--project PATH] [--db PATH]
    python findings_cli.py show <audit_id> [--tool TOOL_NAME] [--db PATH]
    python findings_cli.py diff <old_id> <new_id> [--db PATH]

Environment:
    AUDITOR_DB  Default DB path (overridden by --db). Default: audits.db
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from findings_db import FindingsDB, SEVERITY_ORDER


def _default_db() -> str:
    return os.environ.get("AUDITOR_DB", "audits.db")


def cmd_list(args: argparse.Namespace) -> int:
    db = FindingsDB(args.db)
    audits = db.list_audits(project_path=args.project, limit=args.limit)
    if not audits:
        print("(no audits recorded)")
        return 0

    print(f"{'ID':>4}  {'TIMESTAMP':<21}  {'BACKEND':<10}  {'MODEL':<24}  {'GIT':<10}  PROJECT")
    print("-" * 110)
    for a in audits:
        git = (a["project_hash"] or "")[:8] or "-"
        model = (a["model"] or "-")[:24]
        print(
            f"{a['id']:>4}  {a['timestamp']:<21}  {a['backend']:<10}  "
            f"{model:<24}  {git:<10}  {a['project_path']}"
        )
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    db = FindingsDB(args.db)
    audit = db.get_audit(args.audit_id)
    if not audit:
        print(f"Audit {args.audit_id} not found", file=sys.stderr)
        return 1

    print(f"Audit #{audit['id']}")
    print(f"  Project:  {audit['project_path']}")
    print(f"  Time:     {audit['timestamp']}")
    print(f"  Backend:  {audit['backend']}  ({audit['model'] or '-'})")
    print(f"  Git HEAD: {audit['project_hash'] or '-'}")
    print()

    invocations = db.get_invocations(args.audit_id)
    if not invocations:
        print("  (no tool invocations recorded)")
        return 0

    for inv in invocations:
        if args.tool and inv["tool_name"] != args.tool:
            continue
        print(f"  [{inv['timestamp']}] {inv['tool_name']}  hash={inv['result_hash']}")
        print(f"    args: {inv['arguments_json']}")
        if args.full:
            # Pretty-print the full JSON result
            try:
                pretty = json.dumps(json.loads(inv["result_json"]), indent=2)
            except json.JSONDecodeError:
                pretty = inv["result_json"]
            for line in pretty.splitlines():
                print(f"    {line}")
            print()
    return 0


def cmd_severity_delta(args: argparse.Namespace) -> int:
    """Compare severity counts between two audits. Exit non-zero on regressions.

    Built for CI: "did this PR introduce new CRITICALs vs the base branch?"
    is a question you can answer without any LLM — just count severities on
    each side and compare.
    """
    db = FindingsDB(args.db)
    old = db.severity_counts(args.old_id)
    new = db.severity_counts(args.new_id)

    print(f"Severity delta: audit #{args.old_id} -> #{args.new_id}")
    print(f"  {'LEVEL':<10} {'OLD':>5} {'NEW':>5} {'DELTA':>7}")
    regressed: list[str] = []
    for level in sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get, reverse=True):
        o, n = old[level], new[level]
        delta = n - o
        sign = "+" if delta > 0 else ""
        marker = "  (regressed)" if delta > 0 and SEVERITY_ORDER[level] >= SEVERITY_ORDER[args.threshold] else ""
        print(f"  {level:<10} {o:>5} {n:>5} {sign}{delta:>6}{marker}")
        if delta > 0 and SEVERITY_ORDER[level] >= SEVERITY_ORDER[args.threshold]:
            regressed.append(level)

    if regressed:
        print(f"\nFAIL: regressions at or above {args.threshold}: {', '.join(regressed)}")
        return 1
    print(f"\nOK: no regressions at or above {args.threshold}.")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    db = FindingsDB(args.db)
    try:
        diff = db.diff_audits(args.old_id, args.new_id)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 1

    old, new = diff["old"], diff["new"]
    print(f"Diff: audit #{old['id']} ({old['timestamp']}) -> #{new['id']} ({new['timestamp']})")
    print(f"      backend: {old['backend']} -> {new['backend']}")
    if old["project_hash"] != new["project_hash"]:
        print(f"      git:     {(old['project_hash'] or '-')[:8]} -> {(new['project_hash'] or '-')[:8]}")
    print()

    any_change = False
    for tool, info in diff["tools"].items():
        status = info["status"]
        if status == "unchanged":
            print(f"  [=] {tool}")
        else:
            any_change = True
            print(f"  [{status[0].upper()}] {tool}")
            if "summary" in info:
                print(f"      {info['summary']}")

    if not any_change:
        print("\n  No changes detected.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect persisted audit history.")
    parser.add_argument("--db", default=_default_db(), help="SQLite DB path (default: %(default)s)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="List recorded audits")
    p_list.add_argument("--project", help="Filter by project path")
    p_list.add_argument("--limit", type=int, default=20)
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", help="Show tool invocations from one audit")
    p_show.add_argument("audit_id", type=int)
    p_show.add_argument("--tool", help="Only show one tool's invocations")
    p_show.add_argument("--full", action="store_true", help="Print full JSON results")
    p_show.set_defaults(func=cmd_show)

    p_diff = sub.add_parser("diff", help="Compare two audits tool-by-tool")
    p_diff.add_argument("old_id", type=int)
    p_diff.add_argument("new_id", type=int)
    p_diff.set_defaults(func=cmd_diff)

    p_sev = sub.add_parser(
        "severity-delta",
        help="Compare severity counts; exit non-zero on regressions at threshold",
    )
    p_sev.add_argument("old_id", type=int)
    p_sev.add_argument("new_id", type=int)
    p_sev.add_argument(
        "--threshold",
        choices=list(SEVERITY_ORDER),
        default="CRITICAL",
        help="Minimum severity that causes a non-zero exit (default: %(default)s)",
    )
    p_sev.set_defaults(func=cmd_severity_delta)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
