"""End-to-end: run the whole engine against the localhost demo lab and assert
it finds + proves the planted weaknesses, chains them to the flag, and sends
zero out-of-scope probes.
"""
from pathlib import Path

from nighttrace.config import Config, Limits, Scope, load_checks
from nighttrace.orchestrator import Orchestrator
from targets import demo_lab, make_sample_binary

ROOT = Path(__file__).resolve().parents[1]


def test_full_run_finds_proves_and_chains(tmp_path):
    binp = tmp_path / "auth_service"
    make_sample_binary.make(binp)
    httpd, _ = demo_lab.start("127.0.0.1", 0)
    port = httpd.server_address[1]
    try:
        cfg = Config(
            engagement="test", tier="breach",
            scope=Scope(hosts=["127.0.0.1"], binaries=[str(binp)], ports=[port]),
            limits=Limits(max_runtime_minutes=2, rate_limit_pps=1000),
        )
        orch = Orchestrator(cfg, load_checks(ROOT / "config" / "checks.yaml"))
        report = orch.run()
    finally:
        httpd.shutdown()

    confirmed = {f["type"] for f in report["confirmed_findings"]}
    assert {"default_credentials", "exposed_git", "reflected_input",
            "hardcoded_credential", "missing_mitigation", "flag_captured"} <= confirmed

    # Non-destructive + strictly in scope.
    assert report["scope_safety"]["stray_probe_attempts"] == 0

    # A full attack path to a flag/crown-jewel was assembled (B-2).
    assert report["attack_paths"], "expected at least one attack path"
    assert any(p["goal"].startswith("flag:") for p in report["attack_paths"])
