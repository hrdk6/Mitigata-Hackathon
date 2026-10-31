"""Web information-disclosure detection: verbose errors, server file paths, and
technology fingerprinting — the gaps that made a real site's scan look shallow.

Spins up a tiny server that leaks a PHP error with absolute paths (like the DVWA
/instructions.php page) and asserts the engine detects AND verifies it.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import base64
import threading
import types

from nighttrace import tools
from nighttrace.checks import CheckEngine
from nighttrace.config import Config, Scope, load_checks
from nighttrace.safety import ScopeGuard

ROOT = Path(__file__).resolve().parents[1]

_ERROR_PAGE = (
    b"<b>Warning</b>: include(): Failed opening '/var/www/html/DVWA/config/config.inc.php' "
    b"for inclusion in <b>/var/www/html/instructions.php</b> on line <b>12</b>"
)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep the test quiet
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "nginx/1.31.8")
        self.send_header("X-Powered-By", "PHP/8.5.12")
        self.end_headers()
        if self.path.startswith("/instructions.php"):
            self.wfile.write(_ERROR_PAGE)
        else:
            self.wfile.write(b"<html><body><a href='/instructions.php'>i</a></body></html>")


def _check(engine: CheckEngine, cid: str) -> dict:
    return next(c for c in engine.checks if c["id"] == cid)


def test_info_disclosure_and_tech_detected():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        guard = ScopeGuard(Config(scope=Scope(hosts=["127.0.0.1"])))
        engine = CheckEngine(load_checks(ROOT / "config" / "checks.yaml"))
        base = f"http://127.0.0.1:{port}"
        target = {"host": "127.0.0.1", "port": port, "base_url": base,
                  "params": [], "endpoints": [base + "/", base + "/instructions.php"]}

        info = _check(engine, "web-info-disclosure")
        outs = engine.probe(info, target, guard)
        kinds = {o.type for o in outs}
        assert {"error_disclosure", "path_disclosure"} <= kinds, kinds
        # Every disclosure finding must re-verify (Confirmed, not a one-off).
        for o in outs:
            assert engine.verify(info, {"type": o.type, "data": o.data}, target, guard).confirmed
        # The server path that leaked must be captured as evidence.
        path_out = next(o for o in outs if o.type == "path_disclosure")
        assert any("/var/www/html" in s for s in path_out.data["samples"])

        banner = _check(engine, "web-server-banner")
        bouts = engine.probe(banner, target, guard)
        assert bouts, "expected a technology-disclosure finding"
        assert "PHP/8.5.12" in bouts[0].evidence  # not just the Server header
    finally:
        httpd.shutdown()


class _BasicAuthHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Basic "):
            try:
                creds = base64.b64decode(auth.split(" ", 1)[1]).decode()
            except Exception:
                creds = ""
            if creds == "admin:admin":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>welcome admin</html>")
                return
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Secure Area"')
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"authentication required")


def test_basic_auth_cleartext_and_default_creds():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _BasicAuthHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        guard = ScopeGuard(Config(scope=Scope(hosts=["127.0.0.1"])))
        engine = CheckEngine(load_checks(ROOT / "config" / "checks.yaml"))
        base = f"http://127.0.0.1:{port}"
        target = {"host": "127.0.0.1", "port": port, "base_url": base, "params": [], "endpoints": [base + "/"]}

        chk = _check(engine, "web-basic-auth")
        outs = engine.probe(chk, target, guard)
        kinds = {o.type for o in outs}
        assert "cleartext_basic_auth" in kinds       # Basic auth over http://
        assert "default_credentials" in kinds        # admin:admin accepted
        for o in outs:
            assert engine.verify(chk, {"type": o.type, "data": o.data}, target, guard).confirmed
        dc = next(o for o in outs if o.type == "default_credentials")
        assert (dc.data["username"], dc.data["password"]) == ("admin", "admin")
    finally:
        httpd.shutdown()


def test_nuclei_scan_parses_and_sorts(monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda n: "/usr/bin/nuclei" if n == "nuclei" else None)
    monkeypatch.setattr(tools, "_nuclei_templates_present", lambda: True)
    mock_out = (
        '{"template-id":"tech-detect","info":{"name":"Nginx","severity":"info"},"host":"127.0.0.1"}\n'
        'not-json\n'
        '{"template-id":"CVE-2021-41773","info":{"name":"Apache Path Traversal",'
        '"severity":"critical","description":"d","tags":["cve","lfi"]},"matched-at":"http://127.0.0.1:80/x"}\n'
    )
    monkeypatch.setattr(tools.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(stdout=mock_out, returncode=0))
    guard = ScopeGuard(Config(scope=Scope(hosts=["127.0.0.1"])))
    res = tools.nuclei_scan(guard, "http://127.0.0.1:80/")
    assert len(res) == 2
    assert res[0]["template"] == "CVE-2021-41773" and res[0]["severity"] == "critical"  # most severe first
    assert {r["severity"] for r in res} == {"critical", "info"}


def test_nuclei_scan_noop_without_binary(monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda n: None)
    guard = ScopeGuard(Config(scope=Scope(hosts=["127.0.0.1"])))
    assert tools.nuclei_scan(guard, "http://127.0.0.1/") == []


class _PassiveHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        p = self.path
        if p.startswith("/swagger.json"):
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"openapi":"3.0.0","info":{"title":"x"},"paths":{"/users":{}}}'); return
        if p.startswith("/.well-known/security.txt") or p == "/security.txt":
            self.send_response(404); self.end_headers(); self.wfile.write(b"not found"); return
        if p.startswith("/key"):
            self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers()
            self.wfile.write(b"-----BEGIN RSA PRIVATE KEY-----\nMIIabc123\n-----END RSA PRIVATE KEY-----"); return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "sid=abc; Domain=.example.test; Path=/")
        self.end_headers()
        self.wfile.write(
            b"<html><!-- TODO: remove admin backdoor, password=hunter2 -->"
            b"<body>contact: admin@example.test"
            b"<form method='post' action='/login'><input type=\"password\" name='pw'></form>"
            b"<a href='/report?token=secrettoken123'>r</a></body></html>")


def test_passive_audit_high_recall():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _PassiveHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        guard = ScopeGuard(Config(scope=Scope(hosts=["127.0.0.1"])))
        engine = CheckEngine(load_checks(ROOT / "config" / "checks.yaml"))
        base = f"http://127.0.0.1:{port}"
        target = {"host": "127.0.0.1", "port": port, "base_url": base, "params": [],
                  "endpoints": [base + "/", base + "/key.pem", base + "/report?token=secrettoken123"]}

        chk = _check(engine, "web-passive-audit")
        outs = engine.probe(chk, target, guard)
        kinds = {o.type for o in outs}
        expected = {"missing_security_txt", "exposed_api_docs", "private_key_exposed",
                    "email_disclosure", "sensitive_comment", "insecure_password_form",
                    "sensitive_data_in_url", "loose_cookie_domain"}
        assert expected <= kinds, expected - kinds
        for o in outs:
            assert engine.verify(chk, {"type": o.type, "data": o.data}, target, guard).confirmed
    finally:
        httpd.shutdown()
