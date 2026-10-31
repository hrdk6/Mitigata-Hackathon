from nighttrace.config import Config, Scope
from nighttrace.safety import ScopeGuard


def _cfg():
    return Config(scope=Scope(hosts=["127.0.0.1"], networks=["10.0.0.0/24"], exclude=["10.0.0.1"]))


def test_in_scope_allowed():
    g = ScopeGuard(_cfg())
    assert g.check_network("127.0.0.1", 80).allowed
    assert g.check_network("10.0.0.5", 8080).allowed


def test_out_of_scope_blocked_and_counted():
    g = ScopeGuard(_cfg())
    assert not g.check_network("8.8.8.8", 53).allowed
    assert g.stray_probe_attempts == 1


def test_exclude_wins():
    g = ScopeGuard(_cfg())
    assert not g.check_network("10.0.0.1", 80).allowed


def test_url_scope():
    g = ScopeGuard(_cfg())
    assert g.check_url("http://127.0.0.1:8008/x").allowed
    assert not g.check_url("http://example.test/").allowed


def test_binary_scope(tmp_path):
    f = tmp_path / "bin"
    f.write_bytes(b"\x7fELF")
    g = ScopeGuard(Config(scope=Scope(binaries=[str(f)])))
    assert g.check_binary(str(f)).allowed
    assert not g.check_binary(str(tmp_path / "other")).allowed
