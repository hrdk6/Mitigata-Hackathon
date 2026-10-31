"""Extended web checks (Wave 2): security headers, cookies, CORS, HTTP methods,
open redirect, and backup-file exposure — exercised against a controlled server."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from nighttrace.checks import CheckEngine
from nighttrace.checks.engine import _CORS_EVIL, _REDIRECT_EVIL
from nighttrace.config import Config, Scope
from nighttrace.safety import ScopeGuard


class _Vuln(BaseHTTPRequestHandler):
    """A deliberately sloppy server: reflects Origin, redirects open-endedly,
    sets a flagless cookie, ships no security headers, allows TRACE/PUT, and
    returns 200 for everything (a catch-all, to test false-positive avoidance)."""

    def log_message(self, *a):  # keep test output quiet
        pass

    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        for p in ("next", "url", "redirect"):
            if p in q:
                self.send_response(302)
                self.send_header("Location", q[p][0])
                self.end_headers()
                return
        origin = self.headers.get("Origin")
        self.send_response(200)
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Set-Cookie", "sid=abc123")
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>ok</body></html>")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS, TRACE, PUT")
        self.end_headers()

    def do_TRACE(self):
        self.send_response(200)
        self.send_header("Content-Type", "message/http")
        self.end_headers()
        self.wfile.write(b"TRACE / HTTP/1.1\r\nHost: test\r\n")


@pytest.fixture()
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Vuln)
    import threading
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        yield port
    finally:
        httpd.shutdown()


def _setup(port):
    guard = ScopeGuard(Config(scope=Scope(hosts=["127.0.0.1"])))
    eng = CheckEngine([])
    target = {"host": "127.0.0.1", "port": port,
              "base_url": f"http://127.0.0.1:{port}", "params": []}
    return eng, target, guard


def test_security_headers_and_cookies(server):
    eng, target, guard = _setup(server)
    hdr = eng._probe_http_security_headers({}, target, guard)
    assert hdr and "X-Frame-Options" in hdr[0].data["missing"]
    cookies = eng._probe_http_insecure_cookies({}, target, guard)
    assert cookies and "HttpOnly" in cookies[0].data["issues"]


def test_cors_methods_and_open_redirect(server):
    eng, target, guard = _setup(server)

    cors = eng._probe_http_cors({}, target, guard)
    assert cors and cors[0].severity == "high" and cors[0].data["credentials"] is True
    # verify round-trip confirms it
    assert eng._verify_http_cors({}, {"data": cors[0].data}, target, guard).confirmed

    methods = eng._probe_http_methods({}, target, guard)
    assert methods and {"TRACE", "PUT"} <= set(methods[0].data["methods"])

    redir = eng._probe_http_open_redirect({}, target, guard)
    assert redir and redir[0].type == "open_redirect"
    assert redir[0].data["param"] in ("next", "url", "redirect")


def test_backup_files_no_false_positive_on_catchall(server):
    """The server 200s every path with HTML; backup-file detection must not
    fire on that (accuracy over noise)."""
    eng, target, guard = _setup(server)
    assert eng._probe_http_backup_files({}, target, guard) == []
    # and every probe above stayed strictly in scope
    assert guard.summary()["stray_probe_attempts"] == 0
