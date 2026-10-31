"""Web information-disclosure detection: verbose errors, server file paths, and
technology fingerprinting — the gaps that made a real site's scan look shallow.

Spins up a tiny server that leaks a PHP error with absolute paths (like the DVWA
/instructions.php page) and asserts the engine detects AND verifies it.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading

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
