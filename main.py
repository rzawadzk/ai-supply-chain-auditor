#!/usr/bin/env python3
"""
AI Supply Chain Auditor — Main Entry Point

Usage:
    python main.py                          # Audit the sample project
    python main.py /path/to/your/project    # Audit any project
    python main.py --verbose                # See the agentic loop in action

Authentication: uses your Claude Code login via the Claude Agent SDK.
No ANTHROPIC_API_KEY required — just make sure you're logged into Claude Code.
"""

import os
import sys

from agent import run_audit


def main():
    # Parse simple CLI args
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("-")]

    # Default to the sample project
    if args:
        project_path = os.path.abspath(args[0])
    else:
        project_path = os.path.join(os.path.dirname(__file__), "sample_project")

    if not os.path.isdir(project_path):
        print(f"Error: Directory not found: {project_path}")
        sys.exit(1)

    # No API key check needed — the Claude Agent SDK authenticates via
    # your Claude Code login. If you're not logged in, the SDK will tell you.

    print(f"\n  Auditing: {project_path}")
    print(f"  Mode:     {'verbose' if verbose else 'standard'}\n")

    # Run the audit
    report = run_audit(project_path, verbose=verbose)

    print("\n" + "=" * 60)
    print("  AUDIT REPORT")
    print("=" * 60 + "\n")
    print(report)


if __name__ == "__main__":
    main()
