"""Deterministic planning and scoring — the default 'brain'.

No external calls, no randomness: given the same target the same work is done
in the same order, and every finding's rank is explainable.
"""
from __future__ import annotations

from nighttrace.models import SEVERITY_ORDER

# Recon first (it unlocks everything), then surface analysis, then verification.
TASK_PRIORITY = {"recon": 0, "binary": 1, "web": 1, "verify": 2}


def prioritize(tasks: list[dict]) -> list[dict]:
    return sorted(tasks, key=lambda t: (TASK_PRIORITY.get(t["type"], 9), t["id"]))


def score_finding(severity: str, *, confirmed: bool = False, on_attack_path: bool = False) -> float:
    """Severity (impact x exploitability proxy) boosted by chaining value."""
    score = SEVERITY_ORDER.get(severity, 1) * 10.0
    if confirmed:
        score += 15.0
    if on_attack_path:
        score += 20.0
    return score
