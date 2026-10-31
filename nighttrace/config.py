"""Loading and validating the engagement configuration.

Everything a run needs comes from a single scope file (YAML or JSON): what is
in scope, the limits, the difficulty tier. This is the only file a judge edits.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml  # PyYAML
except Exception:  # pragma: no cover - yaml is in requirements, this is a safety net
    yaml = None


# How each difficulty tier changes the engine's behaviour and budget.
TIERS: dict[str, dict[str, Any]] = {
    "recon": {"surfaces": ["network", "web"], "max_hops": 1,
              "chaining": False, "budget_mult": 1.0, "score_multiplier": 1.0},
    "breach": {"surfaces": ["network", "web", "binary"], "max_hops": 2,
               "chaining": True, "budget_mult": 1.0, "score_multiplier": 1.3},
    "deep": {"surfaces": ["network", "web", "binary"], "max_hops": 5,
             "chaining": True, "budget_mult": 1.5, "score_multiplier": 1.6},
}


@dataclass
class Scope:
    networks: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    binaries: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)  # optional: restrict the port scan


@dataclass
class Limits:
    max_runtime_minutes: float = 20.0
    rate_limit_pps: int = 50
    destructive: bool = False
    max_crawl_pages: int = 50
    # TCP connect-scan timeout per port. 1.5s tolerates real WiFi/LAN latency;
    # a too-small value silently misses slow-to-answer open ports.
    connect_timeout: float = 1.5


@dataclass
class Config:
    engagement: str = "engagement"
    tier: str = "breach"
    scope: Scope = field(default_factory=Scope)
    limits: Limits = field(default_factory=Limits)
    flag_pattern: str = r"FLAG\{.*?\}"
    checks_path: str | None = None
    agents_path: str | None = None
    raw: dict = field(default_factory=dict)

    @property
    def tier_settings(self) -> dict[str, Any]:
        return TIERS.get(self.tier, TIERS["breach"])


def _load_structured(path: str | Path) -> dict:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        if yaml is None:
            raise RuntimeError("PyYAML not installed; use a .json scope file or `pip install pyyaml`.")
        return yaml.safe_load(text) or {}
    return json.loads(text)


def load_scope(path: str | Path) -> Config:
    """Parse the scope file into a validated Config."""
    data = _load_structured(path)
    scope_d = data.get("scope", {}) or {}
    limits_d = data.get("limits", {}) or {}
    flags_d = data.get("flags", {}) or {}

    tier = str(data.get("tier", "breach")).lower()
    if tier not in TIERS:
        raise ValueError(f"Unknown tier {tier!r}; choose one of {sorted(TIERS)}.")

    cfg = Config(
        engagement=str(data.get("engagement", "engagement")),
        tier=tier,
        scope=Scope(
            networks=list(scope_d.get("networks", []) or []),
            hosts=list(scope_d.get("hosts", []) or []),
            binaries=list(scope_d.get("binaries", []) or []),
            exclude=list(scope_d.get("exclude", []) or []),
            ports=[int(p) for p in (scope_d.get("ports", []) or [])],
        ),
        limits=Limits(
            max_runtime_minutes=float(limits_d.get("max_runtime_minutes", 20)),
            rate_limit_pps=int(limits_d.get("rate_limit_pps", 50)),
            destructive=bool(limits_d.get("destructive", False)),
            max_crawl_pages=int(limits_d.get("max_crawl_pages", 50)),
            connect_timeout=float(limits_d.get("connect_timeout", 1.5)),
        ),
        flag_pattern=str(flags_d.get("pattern", r"FLAG\{.*?\}")),
        raw=data,
    )
    if not (cfg.scope.networks or cfg.scope.hosts or cfg.scope.binaries):
        raise ValueError("Scope is empty — nothing is in scope, so nothing can be tested.")
    # Hard safety rail: destructive mode is not supported by this engine.
    if cfg.limits.destructive:
        raise ValueError("destructive: true is not supported. NightTrace is non-destructive by design.")
    return cfg


def load_checks(path: str | Path) -> list[dict]:
    data = _load_structured(path)
    return list(data.get("checks", []) or [])


def load_agents(path: str | Path) -> dict:
    data = _load_structured(path)
    return dict(data.get("agents", {}) or {})
