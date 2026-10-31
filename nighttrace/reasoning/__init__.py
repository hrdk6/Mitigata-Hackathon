"""Reasoning layer.

The default engine is deterministic (rule- and check-driven), which is what
keeps results reproducible and false alarms at zero. An optional LLM layer adds
natural-language report narrative when an API key is configured; it is never
required and the engine never sends data anywhere without one.
"""
