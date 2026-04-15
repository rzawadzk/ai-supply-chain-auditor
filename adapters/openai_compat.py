"""
OPENAI-COMPATIBLE ADAPTER — one adapter, many providers.

Works with ANY provider that speaks OpenAI's chat completions wire format:
  - OpenAI          (api.openai.com)
  - Groq            (api.groq.com/openai/v1)
  - Together AI     (api.together.xyz/v1)
  - OpenRouter      (openrouter.ai/api/v1)
  - Fireworks AI    (api.fireworks.ai/inference/v1)
  - Local vLLM / LM Studio servers

Configure via the `provider` constructor arg (picks sensible defaults) or
via env vars (OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL) — the latter
always wins. This keeps the code unified while giving users ergonomic
shortcuts (`--backend groq`).

=============================================================
  WHY THIS IS WHERE YOU LEARN THE LOOP
=============================================================

The Claude SDK adapter is shorter because the SDK hides the `while` loop.
Here you see it explicitly:

    messages = [system, user]
    while True:
        resp = call_model(messages, tools)
        messages.append(resp.assistant_message)
        if not resp.tool_calls:
            return resp.text                        # final answer
        for tc in resp.tool_calls:
            result = run_local_tool(tc)
            messages.append(tool_result_message)    # feed back in
        # loop continues: the model sees tool results, decides next move

This IS the agentic loop, in plain Python. Read it once and you understand
what every agent framework is abstracting.
"""

from __future__ import annotations

import json
import os
from typing import Callable

from openai import AsyncOpenAI

from .base import ToolRunner, build_user_prompt


# =============================================================
#  PROVIDER PRESETS — base_url + default model + env var name
# =============================================================
# Each preset captures how a provider differs from OpenAI. If we need to
# add one (e.g., Fireworks), it's a one-line entry here.

PRESETS: dict[str, dict] = {
    "openai": {
        "base_url": None,  # openai client default
        "default_model": "gpt-4o",
        "api_key_env": "OPENAI_API_KEY",
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "default_model": "llama-3.3-70b-versatile",
        "api_key_env": "GROQ_API_KEY",
    },
    "together": {
        "base_url": "https://api.together.xyz/v1",
        "default_model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "api_key_env": "TOGETHER_API_KEY",
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "default_model": "anthropic/claude-3.5-sonnet",
        "api_key_env": "OPENROUTER_API_KEY",
    },
}


class OpenAICompatAdapter:
    """A single adapter that handles all OpenAI-wire-format providers."""

    def __init__(self, provider: str = "openai"):
        if provider not in PRESETS:
            raise ValueError(
                f"Unknown provider '{provider}'. Known: {list(PRESETS)}"
            )
        self.name = provider
        preset = PRESETS[provider]

        # Env vars always win over presets — lets a user point `--backend openai`
        # at a local vLLM server by just setting OPENAI_BASE_URL.
        self.api_key = os.environ.get(preset["api_key_env"]) or os.environ.get("OPENAI_API_KEY")
        self.base_url = os.environ.get("OPENAI_BASE_URL") or preset["base_url"]
        self.model = os.environ.get("OPENAI_MODEL") or preset["default_model"]

        if not self.api_key:
            raise RuntimeError(
                f"Missing API key. Set {preset['api_key_env']} "
                f"(or OPENAI_API_KEY) in your environment."
            )

    async def run_audit(
        self,
        project_path: str,
        tool_schemas: list[dict],
        tool_runners: dict[str, ToolRunner],
        system_prompt: str,
        verbose: bool = False,
    ) -> str:
        client = AsyncOpenAI(api_key=self.api_key, base_url=self.base_url)

        # ---------------------------------------------------------
        # Translate Claude tool schemas → OpenAI tool schemas.
        # ---------------------------------------------------------
        # The shapes are ALMOST identical. Claude nests the schema under
        # "input_schema"; OpenAI nests it under "function.parameters".
        # One dict-level renaming is the entire translation.
        openai_tools = [
            {
                "type": "function",
                "function": {
                    "name": s["name"],
                    "description": s["description"],
                    "parameters": s["input_schema"],
                },
            }
            for s in tool_schemas
        ]

        messages: list[dict] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": build_user_prompt(project_path)},
        ]

        # ---------------------------------------------------------
        # THE AGENTIC LOOP. Read this carefully — it is 20 lines.
        # ---------------------------------------------------------
        MAX_TURNS = 20  # safety cap; prevents runaway tool-call loops

        for turn in range(MAX_TURNS):
            resp = await client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=openai_tools,
                tool_choice="auto",
            )
            assistant_msg = resp.choices[0].message

            # Append the assistant message verbatim — OpenAI requires the
            # tool_calls reference to stay in history for the next turn.
            messages.append(assistant_msg.model_dump(exclude_none=True))

            # TERMINATION: no tool calls means the model is done.
            if not assistant_msg.tool_calls:
                return assistant_msg.content or ""

            # EXECUTE each tool call and feed results back as "role: tool"
            # messages. Each tool response MUST reference the tool_call_id
            # it answers — that's how the model pairs request/response.
            for tc in assistant_msg.tool_calls:
                name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError as e:
                    result = json.dumps({"error": f"bad tool args: {e}"})
                else:
                    runner = tool_runners.get(name)
                    if runner is None:
                        result = json.dumps({"error": f"unknown tool: {name}"})
                    else:
                        if verbose:
                            args_preview = json.dumps(args)[:120]
                            print(f"  [tool_call] {name}({args_preview})")
                        try:
                            result = runner(args)
                        except Exception as e:
                            result = json.dumps({"error": str(e), "tool": name})

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result,
                })

        # Hit the safety cap without a terminating response.
        raise RuntimeError(
            f"Agent exceeded {MAX_TURNS} turns without finishing. "
            f"This usually means the model got stuck in a tool-call loop — "
            f"try a more capable model (e.g., OPENAI_MODEL=gpt-4o) or raise MAX_TURNS."
        )
