from pathlib import Path

from nighttrace.checks import CheckEngine
from nighttrace.config import Config, Scope, load_checks
from nighttrace.safety import ScopeGuard
from targets import make_sample_binary

ROOT = Path(__file__).resolve().parents[1]


def test_binary_checks_detect_planted_weaknesses(tmp_path):
    binp = tmp_path / "auth_service"
    make_sample_binary.make(binp)
    engine = CheckEngine(load_checks(ROOT / "config" / "checks.yaml"))
    guard = ScopeGuard(Config(scope=Scope(binaries=[str(binp)])))

    outcomes = []
    for check in engine.applicable("binary", {}):
        outcomes += engine.probe(check, {"path": str(binp)}, guard)
    types = {o.type for o in outcomes}

    assert "hardcoded_credential" in types
    assert "unsafe_function" in types
    assert "missing_mitigation" in types


def test_checks_are_data_driven():
    checks = load_checks(ROOT / "config" / "checks.yaml")
    ids = {c["id"] for c in checks}
    assert "web-default-credentials" in ids and "bin-checksec" in ids
