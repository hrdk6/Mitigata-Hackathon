"""Website-URL targets: parsing, scope loading, and a full run driven by a URL.

Proves NightTrace accepts a website URL (not just an IP/host) and still finds and
proves the planted web weaknesses — even when the site is on a non-standard port
the port scan never reaches — while sending zero out-of-scope probes.
"""
from pathlib import Path

import pytest

from nighttrace.config import (apply_urls, config_from_urls, load_scope,
                               load_checks, parse_web_target, Config)
from nighttrace.orchestrator import Orchestrator
from nighttrace.safety import ScopeGuard
from targets import demo_lab

ROOT = Path(__file__).resolve().parents[1]


def test_parse_web_target_forms():
    bare = parse_web_target("example.com")
    assert bare["scheme"] == "http" and bare["port"] == 80
    assert bare["base_url"] == "http://example.com:80"

    https = parse_web_target("https://example.com/portal/")
    assert https["scheme"] == "https" and https["port"] == 443
    assert https["base_url"] == "https://example.com:443/portal"  # trailing slash trimmed

    custom = parse_web_target("http://10.0.0.5:8080/app")
    assert custom["port"] == 8080
    assert custom["base_url"] == "http://10.0.0.5:8080/app"

    hostport = parse_web_target("10.0.0.5:8080")  # scheme-less host:port
    assert hostport["scheme"] == "http" and hostport["port"] == 8080

    for bad in ("", "   ", "ftp://example.com", "http://:notaport"):
        with pytest.raises(ValueError):
            parse_web_target(bad)


def test_config_from_urls_registers_seed_and_is_in_scope():
    cfg = config_from_urls(["https://app.example.com:8443/portal"])
    # A URL target is a focused web audit: its host is NOT added to `hosts`
    # (which would trigger a full-port host sweep), only a web seed.
    assert "app.example.com" not in cfg.scope.hosts
    seed = cfg.scope.web_seeds[0]
    assert seed["port"] == 8443 and seed["scheme"] == "https"
    assert seed["base_url"] == "https://app.example.com:8443/portal"
    # …but the Scope Guard still allows the host (it trusts web-seed hosts).
    assert ScopeGuard(cfg).check_network("app.example.com", 8443).allowed


def test_apply_urls_is_idempotent():
    cfg = apply_urls(Config(), ["http://example.com", "http://example.com"])
    assert "example.com" not in cfg.scope.hosts  # web seed, not a full-scan host
    assert len(cfg.scope.web_seeds) == 1


def test_load_scope_accepts_urls(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        "engagement: t\n"
        "tier: breach\n"
        "scope:\n"
        "  urls:\n"
        "    - https://example.com:8443/app\n"
        "  hosts:\n"
        "    - http://10.0.0.9:8080\n"   # a URL pasted into hosts is parsed too
        "    - 10.0.0.10\n",             # a plain host passes through unchanged
        encoding="utf-8",
    )
    cfg = load_scope(p)
    # Only the plain host is a full-scan host; the URLs become focused web seeds.
    assert cfg.scope.hosts == ["10.0.0.10"]
    bases = {s["base_url"] for s in cfg.scope.web_seeds}
    assert {"https://example.com:8443/app", "http://10.0.0.9:8080"} == bases
    g = ScopeGuard(cfg)
    assert g.check_network("example.com", 8443).allowed
    assert g.check_network("10.0.0.9", 8080).allowed


def test_full_run_from_website_url_finds_and_proves(tmp_path):
    # Bind the intentionally-vulnerable demo lab to an OS-assigned (random) port
    # that is NOT in the default scan list — so only the URL seed can reach it.
    httpd, _ = demo_lab.start("127.0.0.1", 0)
    port = httpd.server_address[1]
    try:
        cfg = config_from_urls([f"http://127.0.0.1:{port}/"], tier="breach")
        cfg.limits.rate_limit_pps = 1000
        cfg.limits.max_runtime_minutes = 2
        orch = Orchestrator(cfg, load_checks(ROOT / "config" / "checks.yaml"))
        report = orch.run()
    finally:
        httpd.shutdown()

    confirmed = {f["type"] for f in report["confirmed_findings"]}
    assert {"reflected_input", "exposed_git"} <= confirmed
    assert report["stats"]["assets"] >= 1
    # Still strictly in scope and non-destructive.
    assert report["scope_safety"]["stray_probe_attempts"] == 0
