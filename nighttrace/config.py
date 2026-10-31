"""Loading and validating the engagement configuration.

Everything a run needs comes from a single scope file (YAML or JSON): what is
in scope, the limits, the difficulty tier. This is the only file a judge edits.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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
    urls: list[str] = field(default_factory=list)    # website targets, e.g. https://app.example.com:8443/portal
    # Structured web targets parsed from `urls` (and from any URL pasted into
    # `hosts`): {host, port, scheme, path, base_url}. The orchestrator seeds a
    # web task directly from each, so a site on a non-standard port — or at a
    # specific path — is audited even if the port scan never reaches it.
    web_seeds: list[dict] = field(default_factory=list)


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


def parse_web_target(url: str) -> dict:
    """Parse a website target into a structured web seed.

    Accepts the forms people actually paste: ``example.com``,
    ``example.com:8080``, ``http://10.0.0.5:8080/app``, ``https://host/portal``.
    A bare host defaults to http on port 80. Returns
    ``{host, port, scheme, path, base_url}``. Raises ValueError on anything that
    is not a usable http(s) target, so a bad URL is reported, never scanned.
    """
    raw = str(url).strip()
    if not raw:
        raise ValueError("empty URL")
    # A scheme-less value like "example.com:8080" is treated as a host[:port].
    if "://" not in raw:
        raw = "http://" + raw
    pu = urlparse(raw)
    scheme = (pu.scheme or "http").lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"unsupported URL scheme {pu.scheme!r} (use http or https): {url!r}")
    try:
        host = pu.hostname
        port = pu.port or (443 if scheme == "https" else 80)
    except ValueError as exc:  # malformed port, e.g. http://host:notaport
        raise ValueError(f"invalid URL {url!r}: {exc}") from exc
    if not host:
        raise ValueError(f"could not parse a host from URL: {url!r}")
    path = pu.path or "/"
    trimmed = path.rstrip("/")  # keep a sub-path, drop a trailing slash
    base_url = f"{scheme}://{host}:{port}{trimmed}"
    return {"host": host, "port": int(port), "scheme": scheme, "path": path, "base_url": base_url}


def apply_urls(cfg: Config, urls: list[str]) -> Config:
    """Fold website URLs into a Config in place: register a web seed for each and
    add its host to the scope allow-list so the Scope Guard permits it."""
    for u in urls:
        if not str(u).strip():
            continue
        seed = parse_web_target(u)
        if seed["host"] not in cfg.scope.hosts:
            cfg.scope.hosts.append(seed["host"])
        if not any(s["base_url"] == seed["base_url"] for s in cfg.scope.web_seeds):
            cfg.scope.web_seeds.append(seed)
        if str(u) not in cfg.scope.urls:
            cfg.scope.urls.append(str(u))
    return cfg


def config_from_urls(urls: list[str], *, tier: str = "breach",
                     engagement: str = "url-engagement") -> Config:
    """Build a runnable Config from website URLs alone — no scope file needed.
    This backs ``nighttrace run --url https://example.com``."""
    if tier not in TIERS:
        raise ValueError(f"Unknown tier {tier!r}; choose one of {sorted(TIERS)}.")
    cfg = apply_urls(Config(engagement=engagement, tier=tier), urls)
    if not cfg.scope.web_seeds:
        raise ValueError("no valid website URL given")
    return cfg


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

    # Website URLs may be given in their own `urls:` list, or pasted straight
    # into `hosts:` — either way they become structured web seeds, and their
    # host joins the allow-list. Plain IPs/hostnames in `hosts:` pass through.
    plain_hosts: list[str] = []
    url_inputs: list[str] = []
    for h in (scope_d.get("hosts", []) or []):
        (url_inputs if "://" in str(h) else plain_hosts).append(str(h))
    url_inputs.extend(str(u) for u in (scope_d.get("urls", []) or []))

    web_seeds: list[dict] = []
    for u in url_inputs:
        if not u.strip():
            continue
        seed = parse_web_target(u)  # ValueError here surfaces as a scope error
        if not any(s["base_url"] == seed["base_url"] for s in web_seeds):
            web_seeds.append(seed)
        if seed["host"] not in plain_hosts:
            plain_hosts.append(seed["host"])

    cfg = Config(
        engagement=str(data.get("engagement", "engagement")),
        tier=tier,
        scope=Scope(
            networks=list(scope_d.get("networks", []) or []),
            hosts=plain_hosts,
            binaries=list(scope_d.get("binaries", []) or []),
            exclude=list(scope_d.get("exclude", []) or []),
            ports=[int(p) for p in (scope_d.get("ports", []) or [])],
            urls=[u for u in url_inputs if u.strip()],
            web_seeds=web_seeds,
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
