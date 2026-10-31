"""Evidence must be visible where operators review a scan, not merely persisted."""
from pathlib import Path

from nighttrace.cli import _print_summary


ROOT = Path(__file__).resolve().parents[1]


def test_cli_summary_prints_captured_evidence(capsys):
    report = {
        "engagement": "test", "tier": "breach", "score_multiplier": 1,
        "scope_safety": {},
        "stats": {"assets": 1, "confirmed": 1, "refuted": 0},
        "confirmed_findings": [{
            "title": "Default credentials", "severity": "high",
            "asset_host": "127.0.0.1", "asset_port": 8080,
            "evidence": [{"kind": "verification", "content": "HTTP 200 authenticated"}],
        }],
        "attack_paths": [],
    }

    _print_summary(report)

    output = capsys.readouterr().out
    assert "Default credentials" in output
    assert "Evidence [verification]: HTTP 200 authenticated" in output


def test_dashboard_contains_expandable_evidence_view():
    dashboard = (ROOT / "nighttrace" / "dashboard" / "index.html").read_text(encoding="utf-8")

    assert "function evidenceMarkup" in dashboard
    assert "data-evidence-finding-id" in dashboard
    assert "View raw finding JSON" in dashboard
