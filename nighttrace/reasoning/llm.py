"""Optional LLM narrative layer (Anthropic Claude).

Enabled only when `ANTHROPIC_API_KEY` is set *and* the `anthropic` package is
installed. Otherwise every function degrades gracefully to None and the engine
uses its deterministic templates. Nothing is ever sent without an explicit key.
"""
from __future__ import annotations

import os


def available() -> bool:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
        return True
    except Exception:
        return False


def narrate(prompt: str) -> str | None:
    """Return a short natural-language summary, or None if unavailable."""
    if not available():
        return None
    try:
        import anthropic

        client = anthropic.Anthropic()
        model = os.environ.get("NIGHTTRACE_MODEL", "claude-sonnet-4-5")
        msg = client.messages.create(
            model=model,
            max_tokens=900,
            system=("You are a penetration-test report writer. Summarise the confirmed, "
                    "evidence-backed findings clearly and factually. Do not invent findings."),
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(getattr(b, "text", "") for b in msg.content).strip() or None
    except Exception:
        return None
