"""
OLLAMA ADAPTER — local/private audits with honest capability gating.

Ollama speaks OpenAI's wire format on `/v1`, so most of the loop is already
covered by OpenAICompatAdapter. This subclass adds what's DIFFERENT about
running a local model:

  1. Health check: Ollama might not be running. Fail with a helpful message
     instead of an opaque ConnectionRefusedError ten calls deep.
  2. Model check: the requested model might not be pulled yet. Tell the
     user exactly what command to run.
  3. Capability warning: most small open models cannot reliably do multi-turn
     tool use. We list the models known to work and warn on unknown ones.

=============================================================
  THE "NO REACT FALLBACK" DECISION
=============================================================

A tempting feature: if the model doesn't call tools, parse its text output
for `Action: tool_name(...)` patterns and dispatch manually. We deliberately
do NOT do this. ReAct fallbacks hide capability gaps behind fragile parsers
and produce audits that look fine but miss findings silently.

If a model can't do tools, we'd rather the user see a max-turns failure
and switch models, than get a plausible-looking but unreliable report.
"""

from __future__ import annotations

import urllib.error
import urllib.request
import json

from .openai_compat import OpenAICompatAdapter, PRESETS


# Models known to handle multi-turn tool use well in Ollama. Not exhaustive —
# Ollama's tool-use support is a fast-moving target — but a reasonable floor.
# If your model isn't listed, the adapter still runs, it just warns.
KNOWN_TOOL_CAPABLE = {
    "llama3.1",
    "llama3.2",
    "llama3.3",
    "qwen2.5",
    "qwen2.5-coder",
    "mistral-nemo",
    "mistral-small",
    "mixtral",
    "command-r",
    "command-r-plus",
}


class OllamaAdapter(OpenAICompatAdapter):
    """Ollama-specific adapter. Inherits the OpenAI-wire loop; adds pre-flight checks."""

    def __init__(self):
        # Let the base class wire up base_url, model, and the sentinel api_key.
        super().__init__(provider="ollama")

        # Pre-flight checks run at INIT time (not run_audit time) so failures
        # surface before the user waits for a slow model call.
        self._verify_server_running()
        self._verify_model_available()
        self._warn_if_model_unknown()

    # ---------------------------------------------------------------
    # Pre-flight checks
    # ---------------------------------------------------------------

    def _tags_url(self) -> str:
        # The /api/tags endpoint is Ollama-native (not OpenAI-compat). It
        # lives one path up from our /v1 chat endpoint.
        base = self.base_url.rsplit("/v1", 1)[0]
        return f"{base}/api/tags"

    def _verify_server_running(self) -> None:
        try:
            with urllib.request.urlopen(self._tags_url(), timeout=3) as resp:
                resp.read()
        except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
            raise RuntimeError(
                f"Ollama server is not reachable at {self.base_url}.\n"
                f"  - Start it:   `ollama serve` (or install from https://ollama.com)\n"
                f"  - Or point elsewhere: OPENAI_BASE_URL=http://other-host:11434/v1\n"
                f"Underlying error: {e}"
            ) from None

    def _verify_model_available(self) -> None:
        """Check that the chosen model is actually pulled."""
        try:
            with urllib.request.urlopen(self._tags_url(), timeout=3) as resp:
                data = json.loads(resp.read())
        except Exception:
            # Tags endpoint worked in _verify_server_running; if it fails here,
            # don't block — let the chat call surface the real error.
            return

        installed = {m["name"] for m in data.get("models", [])}
        # Model names in Ollama can be "llama3.1" or "llama3.1:latest" or
        # "llama3.1:8b". Accept a match if either side prefixes the other.
        if not any(
            self.model == name or name.startswith(f"{self.model}:") or self.model.startswith(f"{name.split(':')[0]}:")
            for name in installed
        ):
            raise RuntimeError(
                f"Model '{self.model}' is not pulled. Installed: {sorted(installed) or '(none)'}.\n"
                f"  Pull it:   `ollama pull {self.model}`\n"
                f"  Or pick another with: OPENAI_MODEL=<name> python main.py --backend ollama"
            )

    def _warn_if_model_unknown(self) -> None:
        """Emit a friendly heads-up if the model isn't on our tool-capable list."""
        base_name = self.model.split(":")[0]
        if base_name not in KNOWN_TOOL_CAPABLE:
            print(
                f"\n  [ollama] Note: '{self.model}' is not on the known-tool-capable list.\n"
                f"  The audit may fail with 'max turns exceeded' if the model can't reliably\n"
                f"  call tools. Known-good models: {sorted(KNOWN_TOOL_CAPABLE)}\n"
            )
