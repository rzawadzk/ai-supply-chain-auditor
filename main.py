#!/usr/bin/env python3
"""
AI Supply Chain Auditor — Main Entry Point

Usage:
    python main.py                          # Audit the sample project
    python main.py /path/to/your/project    # Audit any project
    python main.py --verbose                # See the agentic loop in action
    python main.py --backend groq           # Swap to a different LLM provider

Backends:
    claude      Claude Agent SDK (default; uses Claude Code login, no API key)
    openai      OpenAI API (requires OPENAI_API_KEY)
    groq        Groq API (requires GROQ_API_KEY)
    together    Together AI (requires TOGETHER_API_KEY)
    openrouter  OpenRouter (requires OPENROUTER_API_KEY)

Env vars:
    AUDITOR_BACKEND  Default backend if --backend is not passed.
    OPENAI_MODEL     Override the model for any OpenAI-compatible backend.
    OPENAI_BASE_URL  Point any OpenAI-compatible backend at a custom endpoint.
"""

import argparse
import os
import sys

from adapters import AVAILABLE_BACKENDS
from agent import run_audit


def main():
    parser = argparse.ArgumentParser(
        description="Audit a project for AI supply chain risks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "project_path",
        nargs="?",
        help="Path to the project directory (default: sample_project/)",
    )
    parser.add_argument(
        "--backend",
        choices=AVAILABLE_BACKENDS,
        default=os.environ.get("AUDITOR_BACKEND", "claude"),
        help="LLM backend to use (default: %(default)s)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Stream the agent's thinking and tool calls",
    )
    args = parser.parse_args()

    # Default to the sample project
    if args.project_path:
        project_path = os.path.abspath(args.project_path)
    else:
        project_path = os.path.join(os.path.dirname(__file__), "sample_project")

    if not os.path.isdir(project_path):
        print(f"Error: Directory not found: {project_path}")
        sys.exit(1)

    print(f"\n  Auditing: {project_path}")
    print(f"  Backend:  {args.backend}")
    print(f"  Mode:     {'verbose' if args.verbose else 'standard'}\n")

    try:
        report = run_audit(project_path, verbose=args.verbose, backend=args.backend)
    except RuntimeError as e:
        # Surface adapter errors (missing API keys, max-turns, etc.) cleanly.
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)

    print("\n" + "=" * 60)
    print("  AUDIT REPORT")
    print("=" * 60 + "\n")
    print(report)


if __name__ == "__main__":
    main()
