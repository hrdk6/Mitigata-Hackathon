"""Tests for the dashboard's exact-host web scan workflow."""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from nighttrace.api.target_scan import TargetScanManager, TargetValidationError, parse_web_target
from nighttrace.blackboard import Blackboard
from nighttrace.config import Config, Limits, load_checks
from targets import demo_lab

ROOT = Path(__file__).resolve().parents[1]


def test_parse_private_ip_target_normalises_default_port():
    target = parse_web_target("http://192.168.60.139/")
    assert target.host == "192.168.60.139"
    assert target.port == 80
    assert target.url == "http://192.168.60.139:80"


@pytest.mark.parametrize("value", [
    "https://example.com/",
    "http://8.8.8.8/",
    "http://192.168.60.139/admin",
    "ftp://192.168.60.139/",
    "http://192.168.60.139/?next=/admin",
])
def test_parse_web_target_rejects_ambiguous_or_public_targets(value):
    with pytest.raises(TargetValidationError):
        parse_web_target(value)


def test_target_manager_runs_checks_against_exact_loopback_target():
    httpd, _ = demo_lab.start("127.0.0.1", 0)
    port = httpd.server_address[1]
    bb = Blackboard()
    manager = TargetScanManager(
        bb,
        Config(limits=Limits(max_runtime_minutes=1, rate_limit_pps=1000)),
        load_checks(ROOT / "config" / "checks.yaml"),
    )
    try:
        started, state = manager.start(parse_web_target(f"http://127.0.0.1:{port}/"))
        assert started and state["status"] == "running"

        deadline = time.monotonic() + 10
        while manager.status()["status"] == "running" and time.monotonic() < deadline:
            time.sleep(0.05)

        assert manager.status()["status"] == "complete"
        found = {f["type"] for f in bb.list_findings(status="Confirmed")}
        assert {"default_credentials", "exposed_git", "reflected_input"} <= found
    finally:
        httpd.shutdown()
