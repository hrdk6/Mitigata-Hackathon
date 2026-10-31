"""Hypothesis-driven threat modeling: the templates, the boost-aware queue
ordering, and the formulate -> validate lifecycle over a full engine run."""
from pathlib import Path

from nighttrace.config import Config, Limits, Scope, load_checks
from nighttrace.orchestrator import Orchestrator
from nighttrace.reasoning import heuristic, hypothesis
from targets import demo_lab, make_sample_binary

ROOT = Path(__file__).resolve().parents[1]


def test_generate_hypotheses_per_signal():
    cases = {
        "http_login": "HYP-AUTH-DEFAULT",
        "http_alive": "HYP-CONFIG-LEAK",
        "binary_present": "HYP-BINARY-SECRETS",
        "params_found": "HYP-INPUT-REFLECTION",
        "creds_leaked": "HYP-CRED-REUSE",
    }
    for signal, tid in cases.items():
        hyps = hypothesis.generate_hypotheses(signal, "target-x")
        assert len(hyps) == 1
        h = hyps[0]
        assert h.id == f"{tid}:target-x"
        assert h.status == "FORMULATED"
        assert 0.80 <= h.confidence <= 0.95
        assert h.priority_boost > 0 and h.suggested_checks
    assert hypothesis.generate_hypotheses("no-such-signal", "t") == []


def test_template_for_check_maps_back():
    assert hypothesis.template_for_check("web-default-credentials")["tid"] == "HYP-AUTH-DEFAULT"
    assert hypothesis.template_for_check("bin-weak-strings")["tid"] == "HYP-BINARY-SECRETS"
    assert hypothesis.template_for_check("web-server-banner") is None
    assert hypothesis.template_for_check(None) is None


def test_prioritize_boosts_within_phase_but_keeps_phase_order():
    tasks = [
        {"id": 3, "type": "verify", "data": {}},
        {"id": 4, "type": "verify", "data": {"priority_boost": 40}},
        {"id": 1, "type": "recon", "data": {}},
        {"id": 2, "type": "web", "data": {"priority_boost": 10}},
    ]
    order = [t["id"] for t in heuristic.prioritize(tasks)]
    # recon first, then web, then the boosted verify (4) ahead of the plain one (3).
    assert order == [1, 2, 4, 3]


def test_hypotheses_formulated_and_validated_end_to_end(tmp_path):
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

    hyp = report["hypotheses"]
    titles = {h["title"] for h in hyp["formulated"]}
    # Signals present in the lab => these hypotheses must have been formulated.
    assert "Default Administrative Credentials" in titles
    assert "Exposed Version Control & Config Secrets" in titles
    assert "Hardcoded Binary Secrets" in titles
    # At least one prediction was proven with evidence.
    assert hyp["validated"], "expected at least one validated hypothesis"
    assert any(h["validated"] for h in hyp["formulated"])

    # The lifecycle is on the audit trail at the right PTES phases.
    bb = orch.bb
    evs = bb.list_events(0, 100000)
    form = [e for e in evs if e["action"] == "hypothesis_formulated"]
    val = [e for e in evs if e["action"] == "hypothesis_validated"]
    assert form and all(e["ptes"] == "threat_modeling" for e in form)
    assert val and all(e["ptes"] == "exploitation" for e in val)
