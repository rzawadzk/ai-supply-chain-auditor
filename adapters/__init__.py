"""
ADAPTER REGISTRY — map backend name to adapter instance.

Imports are lazy: we only import an adapter's SDK when that backend is
selected. This means a user who picks `--backend claude` never has to
install `openai`, and vice versa. Keeps the dependency surface honest.
"""

from __future__ import annotations

from .base import AgentAdapter, SYSTEM_PROMPT, build_user_prompt


# The set of backend names the CLI accepts. Listed here so main.py can
# show them in --help without importing every SDK.
AVAILABLE_BACKENDS = ["claude", "openai", "groq", "together", "openrouter"]


def get_adapter(name: str) -> AgentAdapter:
    """Instantiate the adapter for a given backend name.

    Raises ValueError for unknown names; raises the adapter's own errors
    (e.g., missing API key) at instantiation time so failures surface fast.
    """
    if name == "claude":
        from .claude_sdk import ClaudeSDKAdapter
        return ClaudeSDKAdapter()
    if name in ("openai", "groq", "together", "openrouter"):
        from .openai_compat import OpenAICompatAdapter
        return OpenAICompatAdapter(provider=name)
    raise ValueError(
        f"Unknown backend: {name!r}. Available: {AVAILABLE_BACKENDS}"
    )


__all__ = [
    "AgentAdapter",
    "SYSTEM_PROMPT",
    "build_user_prompt",
    "get_adapter",
    "AVAILABLE_BACKENDS",
]
