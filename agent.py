"""
THE AGENTIC LOOP — using the Claude Agent SDK (no API key needed).

This version uses the Claude Agent SDK, which authenticates via your Claude Code
login — no ANTHROPIC_API_KEY required.

=============================================================
  AGENT SDK vs RAW API — WHY THIS VERSION IS DIFFERENT
=============================================================

In the raw-API version, YOU wrote the agentic loop:
    while True:
        response = client.messages.create(...)
        if response.stop_reason == "end_turn": break
        execute_tools(response)
        messages.append(results)

In the Agent SDK version, the SDK runs the loop FOR YOU:
    async for message in query(prompt=..., options=...):
        # you just consume messages as they stream

Tradeoff: less visibility into the loop, but much less code.
For learning the pattern, the raw API version is more educational.
For shipping production agents, the SDK is more robust.

=============================================================
  HOW CUSTOM TOOLS WORK IN THE AGENT SDK
=============================================================

The Agent SDK's built-in tools (Read, Write, Bash, etc.) are for
file/shell/web operations. To add OUR domain-specific tools (the
5 audit dimensions), we expose them via an in-process MCP server.

MCP = Model Context Protocol. It's a standard for exposing tools
to LLMs. The SDK creates an "SDK MCP server" that runs in-process
and registers our tools. Claude sees them as regular tools.

This is the same pattern used by Claude Code itself for its
built-in tools — everything is MCP under the hood.
"""

import anyio
import json

from claude_agent_sdk import (
    ClaudeAgentOptions,
    ClaudeSDKClient,
    AssistantMessage,
    TextBlock,
    ThinkingBlock,
    ToolUseBlock,
    create_sdk_mcp_server,
    tool,
)

# Import the actual audit logic — unchanged from the raw API version
from tools.inventory import run_inventory
from tools.provenance import run_provenance
from tools.integrity import run_integrity
from tools.compliance import run_compliance
from tools.behavior import run_behavior


# =============================================================
#  CUSTOM TOOLS — wrapped with the @tool decorator
# =============================================================
# The @tool decorator registers these as callable tools for Claude.
# Arguments:
#   1. Tool name (what Claude will call)
#   2. Description (helps Claude decide when to use it)
#   3. Input schema (simplified type dict)

@tool(
    "scan_inventory",
    "Scan a project directory to discover all AI components: models, ML libraries, "
    "AI API keys/endpoints, dataset references, and model files. Use this FIRST to "
    "understand what AI is in the stack before auditing.",
    {"project_path": str},
)
async def scan_inventory(args):
    result = run_inventory(args)
    return {"content": [{"type": "text", "text": result}]}


@tool(
    "check_provenance",
    "Check the provenance and origin of AI components: model cards, authorship, "
    "download sources, data lineage, and version pinning. Use after scan_inventory "
    "to investigate specific components.",
    {"project_path": str, "component_name": str},
)
async def check_provenance(args):
    result = run_provenance(args)
    return {"content": [{"type": "text", "text": result}]}


@tool(
    "verify_integrity",
    "Verify the integrity of model files: check for unsafe serialization "
    "(pickle/torch.load), compute file hashes, detect suspicious embedded patterns, "
    "and check for weight tampering indicators.",
    {"file_path": str},
)
async def verify_integrity(args):
    result = run_integrity(args)
    return {"content": [{"type": "text", "text": result}]}


@tool(
    "audit_compliance",
    "Audit AI components for license compliance: check model licenses, dataset "
    "licenses, API terms of service, and detect license conflicts. The 'use_case' "
    "argument must be one of: commercial, research, internal, open-source.",
    {"project_path": str, "component_name": str, "use_case": str},
)
async def audit_compliance(args):
    result = run_compliance(args)
    return {"content": [{"type": "text", "text": result}]}


@tool(
    "probe_behavior",
    "Probe AI components for behavioral risks: suspicious code in model loading, "
    "network exfiltration patterns, environment variable access, backdoor indicators, "
    "and runtime safety issues. The 'focus_area' argument must be one of: "
    "model_loading, data_pipeline, api_security, runtime_safety, all.",
    {"project_path": str, "focus_area": str},
)
async def probe_behavior(args):
    result = run_behavior(args)
    return {"content": [{"type": "text", "text": result}]}


# =============================================================
#  MCP SERVER — bundles all our tools together
# =============================================================
# This creates an in-process MCP server that exposes our 5 audit tools.
# The SDK will automatically start/stop this server and connect Claude to it.
AUDIT_SERVER = create_sdk_mcp_server(
    name="supply-chain-auditor",
    tools=[scan_inventory, check_provenance, verify_integrity, audit_compliance, probe_behavior],
)


# =============================================================
#  THE SYSTEM PROMPT — shapes Claude's audit methodology
# =============================================================
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


# =============================================================
#  THE ENTRY POINT — still async because the SDK is async-native
# =============================================================
async def _run_audit_async(project_path: str, verbose: bool = False) -> str:
    """Async implementation of the audit using the Agent SDK."""

    # MCP tools in the Agent SDK are named: mcp__<server_name>__<tool_name>
    # Our server is "supply-chain-auditor" so the tools become:
    allowed_tools = [
        "mcp__supply-chain-auditor__scan_inventory",
        "mcp__supply-chain-auditor__check_provenance",
        "mcp__supply-chain-auditor__verify_integrity",
        "mcp__supply-chain-auditor__audit_compliance",
        "mcp__supply-chain-auditor__probe_behavior",
    ]

    options = ClaudeAgentOptions(
        system_prompt=SYSTEM_PROMPT,
        mcp_servers={"supply-chain-auditor": AUDIT_SERVER},
        allowed_tools=allowed_tools,
        max_turns=20,  # safety limit on agentic loop depth
        permission_mode="bypassPermissions",  # our tools are read-only, safe to auto-run
    )

    prompt = (
        f"Audit the AI supply chain of the project at: {project_path}\n\n"
        f"Assume this is a commercial product. Check everything — models, "
        f"APIs, datasets, dependencies, model files. I want a complete "
        f"risk assessment."
    )

    if verbose:
        print("=" * 60)
        print("  AI SUPPLY CHAIN AUDITOR — Agent SDK Mode")
        print("=" * 60)
        print(f"\n  Target: {project_path}")
        print(f"  Auth:   Claude Code login (no API key needed)")
        print("=" * 60)

    final_text_parts = []

    # The Agent SDK runs the agentic loop internally and streams messages.
    # We just consume them as they arrive.
    async with ClaudeSDKClient(options=options) as client:
        await client.query(prompt)

        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, ThinkingBlock) and verbose:
                        preview = block.thinking[:200]
                        print(f"\n  [thinking] {preview}...")
                    elif isinstance(block, ToolUseBlock) and verbose:
                        args_preview = json.dumps(block.input)[:120]
                        print(f"  [tool_call] {block.name}({args_preview})")
                    elif isinstance(block, TextBlock):
                        # Collect the final report text
                        final_text_parts.append(block.text)
                        if verbose:
                            preview = block.text[:300]
                            print(f"  [text] {preview}...")

    return "\n".join(final_text_parts)


def run_audit(project_path: str, verbose: bool = False) -> str:
    """Sync wrapper — main.py calls this."""
    return anyio.run(_run_audit_async, project_path, verbose)
