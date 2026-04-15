#!/usr/bin/env python3
"""
AI SUPPLY CHAIN AUDITOR — MCP SERVER WRAPPER

Exposes the 5 deterministic audit tools over the Model Context Protocol (MCP)
so they can be called from ANY Claude Code session (or any MCP-compatible host).

=============================================================
  TWO MCP SERVERS IN THIS PROJECT — DO NOT CONFUSE THEM
=============================================================

  agent.py     →  IN-PROCESS MCP server (SDK-managed).
                  Used by THIS project's own agentic loop.
                  Tools are registered via `@tool` decorator and
                  `create_sdk_mcp_server()`. Never leaves the process.

  mcp_server.py →  STANDALONE MCP server (this file).
                   Speaks MCP stdio protocol on real stdin/stdout.
                   Any Claude Code session can connect to it.
                   This is the PUBLIC INTERFACE to the auditor.

=============================================================
  WHY EXPOSE THE 5 RAW TOOLS (not a single `run_audit`)
=============================================================

Principle from CLAUDE.md: "Tools are deterministic. The agent is adaptive."

A calling Claude Code session is ALREADY an agentic loop. If we expose
`run_audit` as a meta-tool, we'd spawn a nested Claude loop inside it —
extra cost, extra latency, and the caller loses visibility into the
strategy. Instead we hand the caller primitives and let IT orchestrate.

This also enables composition. A caller can:
  - Run just `verify_integrity` on one suspicious file
  - Skip `check_provenance` if they already know the components
  - Interleave these tools with their own reasoning / other MCP tools

The DOWNSIDE: the caller has to know the audit methodology (start with
scan_inventory, then investigate, etc.). We surface that in each tool's
description so the caller can self-direct.

=============================================================
  PROTOCOL DETAILS
=============================================================

MCP is JSON-RPC 2.0 over stdio (for local servers) or HTTP+SSE (for remote).
Claude Code launches local MCP servers as subprocesses and talks to them
over stdin/stdout. Each request is a line of JSON.

We use the official `mcp` Python SDK (installed transitively via
claude-agent-sdk) to handle the protocol — we only register tool handlers.
"""

import asyncio
import json

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

# Import the actual audit logic — unchanged, reused from both agent.py and here
from tools.inventory import run_inventory, INVENTORY_TOOL
from tools.provenance import run_provenance, PROVENANCE_TOOL
from tools.integrity import run_integrity, INTEGRITY_TOOL
from tools.compliance import run_compliance, COMPLIANCE_TOOL
from tools.behavior import run_behavior, BEHAVIOR_TOOL


# =============================================================
#  TOOL REGISTRY — map MCP tool names to their runners + schemas
# =============================================================
# Each entry pairs the tool's JSON schema (shown to the calling LLM)
# with the deterministic Python function that executes it.
#
# The schemas are LIFTED DIRECTLY from tools/*.py so this file stays
# a thin wrapper — no schema duplication, no drift.

TOOLS = [
    (INVENTORY_TOOL,  run_inventory),
    (PROVENANCE_TOOL, run_provenance),
    (INTEGRITY_TOOL,  run_integrity),
    (COMPLIANCE_TOOL, run_compliance),
    (BEHAVIOR_TOOL,   run_behavior),
]

# name -> runner lookup, built once
RUNNERS = {tool["name"]: runner for tool, runner in TOOLS}


# =============================================================
#  MCP SERVER SETUP
# =============================================================
server = Server("ai-supply-chain-auditor")


@server.list_tools()
async def list_tools() -> list[Tool]:
    """Advertise our tools to the MCP client.

    This is called once when the client connects. The client (e.g.,
    Claude Code) uses these Tool objects to know what's available.
    """
    return [
        Tool(
            name=tool["name"],
            description=tool["description"],
            inputSchema=tool["input_schema"],
        )
        for tool, _ in TOOLS
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Execute a tool call from the MCP client.

    The runners are synchronous and CPU-bound (file scanning, regex) —
    for a production server you'd run them in a thread pool to avoid
    blocking the event loop. For a local auditor on one project at a
    time, the simple synchronous call is fine.
    """
    runner = RUNNERS.get(name)
    if runner is None:
        # MCP expects us to raise so the protocol can return a proper error.
        raise ValueError(f"Unknown tool: {name}")

    try:
        result = runner(arguments)
    except Exception as e:
        # Wrap runner errors as tool output rather than crashing the server.
        # The calling LLM can then reason about the failure.
        result = json.dumps({"error": str(e), "tool": name, "arguments": arguments})

    return [TextContent(type="text", text=result)]


# =============================================================
#  ENTRY POINT
# =============================================================
async def main():
    """Run the MCP server over stdio.

    `stdio_server()` is a context manager that:
      1. Takes over stdin/stdout for JSON-RPC framing
      2. Hands back read/write streams
      3. Restores them on exit

    `server.run()` then loops reading requests and dispatching to our
    registered handlers until the client disconnects.
    """
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
