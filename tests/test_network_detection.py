"""Network-service vulnerability detection: version->CVE correlation, banner
fingerprinting, and unauthenticated-exposure probing (the Wave-1 upgrade)."""
import socket
import threading

from nighttrace import netservices, vulndb
from nighttrace.checks import CheckEngine
from nighttrace.config import Config, Scope
from nighttrace.safety import ScopeGuard


def _guard(host: str) -> ScopeGuard:
    return ScopeGuard(Config(scope=Scope(hosts=[host])))


def test_vulndb_matches_known_vulnerable_versions():
    assert any(h.cve == "CVE-2018-15473" for h in vulndb.lookup("openssh", "7.6p1"))
    assert any(h.cve == "CVE-2011-2523" for h in vulndb.lookup("vsftpd", "2.3.4"))
    assert any(h.cve == "CVE-2021-41773" for h in vulndb.lookup("apache", "2.4.49"))
    # Patched / unaffected versions must not match (accuracy, not noise).
    assert vulndb.lookup("openssh", "9.6") == []
    assert vulndb.lookup("vsftpd", "3.0.3") == []
    assert vulndb.lookup("apache", "2.4.58") == []
    assert vulndb.lookup(None, None) == []
    assert vulndb.lookup("nginx", "banner-with-no-number") == []


def test_banner_fingerprinting():
    assert netservices.identify("ssh", "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4", None) == ("openssh", "7.6p1")
    assert netservices.identify("ftp", "220 (vsFTPd 2.3.4)", None) == ("vsftpd", "2.3.4")
    assert netservices.identify("http", "", "Apache/2.4.49 (Unix)") == ("apache", "2.4.49")
    assert netservices.identify("http", "", "nginx/1.18.0") == ("nginx", "1.18.0")
    assert netservices.identify("ssh", "", None) == (None, None)


def test_net_version_probe_flags_cve_offline():
    eng = CheckEngine([])
    guard = _guard("10.0.0.5")
    check = {"probe": {"type": "net_version"}, "verify": {"type": "net_version"}}
    vuln = {"host": "10.0.0.5", "port": 22, "service": "ssh",
            "banner": "SSH-2.0-OpenSSH_7.6p1"}
    outs = eng._probe_net_version(check, vuln, guard)
    assert outs and outs[0].type == "vulnerable_version"
    assert outs[0].data["cve"] == "CVE-2018-15473"
    assert outs[0].severity == "medium"
    # A patched banner yields nothing — no false positive.
    patched = {**vuln, "banner": "SSH-2.0-OpenSSH_9.6"}
    assert eng._probe_net_version(check, patched, guard) == []


def _fake_line_server(reply: bytes) -> int:
    """Start a tiny TCP server that answers each connection with `reply`.
    Returns the bound port; the thread is a daemon so it cleans up with pytest."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    srv.settimeout(5)
    port = srv.getsockname()[1]

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            try:
                conn.recv(64)
                conn.sendall(reply)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    threading.Thread(target=serve, daemon=True).start()
    return port


def test_unauthenticated_redis_detected_and_probed():
    port = _fake_line_server(b"# Server\r\nredis_version:5.0.7\r\n")
    guard = _guard("127.0.0.1")

    r = netservices.redis_unauth(guard, "127.0.0.1", port)
    assert r["open"] and r["version"] == "5.0.7"

    eng = CheckEngine([])
    check = {"probe": {"type": "net_unauth"}, "verify": {"type": "net_unauth"}}
    target = {"host": "127.0.0.1", "port": port, "service": "redis"}
    outs = eng._probe_net_unauth(check, target, guard)
    assert outs and outs[0].type == "unauth_service" and outs[0].severity == "high"
    # Scope-safe: the in-scope probe never counts as a stray probe.
    assert guard.summary()["stray_probe_attempts"] == 0
