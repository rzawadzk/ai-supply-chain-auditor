"""
CLAUDE AGENT SDK ADAPTER — the reference implementation.

This adapter uses the Claude Agent SDK, which authenticates via your
Claude Code login (no ANTHROPIC_API_KEY needed) and runs the agentic
loop internally. We just register tools via an in-process MCP server
and consume streamed messages.

Compared to the OpenAI-compatible adapter (see openai_compat.py), this
one is shorter because the SDK hides the loop. That's the tradeoff:
less to see, less to own.
"""

from __future__ import annotations

import json
from typing import Callable

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    TextBlock,
    ThinkingBlock,
    ToolUseBlock,
    create_sdk_mcp_server,
    tool as sdk_tool,
)

from .base import ToolRunner, build_user_prompt


class ClaudeSDKAdapter:
    """Reference adapter using Anthropic's Claude Agent SDK."""

    name = "claude"

    async def run_audit(
        self,
        project_path: str,
        tool_schemas: list[dict],
        tool_runners: dict[str, ToolRunner],
        system_prompt: str,
        verbose: bool = False,
    ) -> str:
        # -------------------------------------------------------------
        # Step 1: Wrap each runner with the SDK's @tool decorator.
        # -------------------------------------------------------------
        # The SDK wants tools registered as decorated async functions. We
        # generate wrappers dynamically from the same registry the other
        # adapters use — no hardcoded tool list in this file.
        sdk_tools = []
        for schema in tool_schemas:
            sdk_tools.append(_wrap_runner_as_sdk_tool(schema, tool_runners[schema["name"]]))

        # -------------------------------------------------------------
        # Step 2: Stand up an in-process MCP server for these tools.
        # -------------------------------------------------------------
        # "In-process" meaning it never speaks the wire protocol — the
        # SDK shuttles tool calls as Python function calls. Compare to
        # mcp_server.py which IS a wire-protocol MCP server.
        server = create_sdk_mcp_server(name="supply-chain-auditor", tools=sdk_tools)

        # MCP tools get namespaced by the SDK as: mcp__<server>__<tool>
        allowed_tools = [f"mcp__supply-chain-auditor__{s['name']}" for s in tool_schemas]

        options = ClaudeAgentOptions(
            system_prompt=system_prompt,
            mcp_servers={"supply-chain-auditor": server},
            allowed_tools=allowed_tools,
            max_turns=20,
            permission_mode="bypassPermissions",  # our tools are read-only
        )

        # -------------------------------------------------------------
        # Step 3: Stream messages. The SDK owns the loop.
        # -------------------------------------------------------------
        final_text_parts: list[str] = []
        prompt = build_user_prompt(project_path)

        async with ClaudeSDKClient(options=options) as client:
            await client.query(prompt)
            async for message in client.receive_response():
                if not isinstance(message, AssistantMessage):
                    continue
                for block in message.content:
                    if isinstance(block, ThinkingBlock) and verbose:
                        print(f"\n  [thinking] {block.thinking[:200]}...")
                    elif isinstance(block, ToolUseBlock) and verbose:
                        args_preview = json.dumps(block.input)[:120]
                        print(f"  [tool_call] {block.name}({args_preview})")
                    elif isinstance(block, TextBlock):
                        final_text_parts.append(block.text)
                        if verbose:
                            print(f"  [text] {block.text[:300]}...")

        return "\n".join(final_text_parts)


def _wrap_runner_as_sdk_tool(schema: dict, runner: Callable[[dict], str]):
    """Convert a (Claude-format schema, Python runner) pair into an SDK @tool.

    The SDK's @tool decorator wants an async function whose return value is
    an MCP-style content dict. We build that wrapper on the fly so adding a
    new audit tool requires no change to this adapter.
    """
    # Extract the simplified input schema the SDK expects:
    # {prop_name: type} — we derive it from the JSON Schema "properties".
    simple_schema = {
        prop: str  # All our tools take string args; expand if that changes.
        for prop in schema["input_schema"].get("properties", {})
    }

    @sdk_tool(schema["name"], schema["description"], simple_schema)
    async def _wrapped(args):
        result = runner(args)
        return {"content": [{"type": "text", "text": result}]}

    return _wrapped
