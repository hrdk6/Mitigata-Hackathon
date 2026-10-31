"""API run-control: pressing Run while a scan is in flight must preempt it
cleanly and never block the user with a 409 — the case that bit website-URL
targets, whose remote network tasks are slow to wind down.
"""
import time
from pathlib import Path

from fastapi.testclient import TestClient

from nighttrace.api import create_app
from nighttrace.api import server as apiserver
from nighttrace.blackboard import Blackboard
from nighttrace.config import Config
from targets import demo_lab

ROOT = Path(__file__).resolve().parents[1]


def _write_scope(path: Path, port: int) -> None:
    path.write_text(
        "engagement: t\n"
        "tier: breach\n"
        "scope:\n"
        f"  urls:\n    - http://127.0.0.1:{port}/\n"
        "limits:\n"
        "  max_runtime_minutes: 1\n"
        "  rate_limit_pps: 1000\n",
        encoding="utf-8",
    )


def test_run_preempt_never_returns_409(tmp_path, monkeypatch):
    httpd, _ = demo_lab.start("127.0.0.1", 0)
    port = httpd.server_address[1]
    scope = tmp_path / "scope.yaml"
    _write_scope(scope, port)
    monkeypatch.setattr(apiserver, "_SCOPE_FILE", scope)
    monkeypatch.setattr(apiserver, "_CHECKS_FILE", ROOT / "config" / "checks.yaml")
    try:
        client = TestClient(create_app(Blackboard(), Config(), checks=[], autostart=False))
        r1 = client.post("/run", json={})
        r2 = client.post("/run", json={})  # press Run again immediately -> preempt
        assert r1.status_code == 200, r1.text
        assert r2.status_code == 200, r2.text          # the 409 path is gone
        assert r2.json()["status"] == "running"
        assert r2.json()["preempted"] is True          # it really did preempt run #1
        assert "127.0.0.1" in r2.json()["targets"]["hosts"]

        # The superseded run must not clobber the active run's final state.
        for _ in range(150):
            st = client.get("/run/status").json()
            if not st["running"]:
                break
            time.sleep(0.2)
        assert st["status"] == "done", st
    finally:
        httpd.shutdown()
