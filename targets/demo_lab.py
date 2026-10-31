"""NightTrace demo lab — an INTENTIONALLY VULNERABLE web app for localhost only.

This exists so NightTrace can be demonstrated end-to-end against a target you
own, with zero external systems involved. It binds to 127.0.0.1 only. The
weaknesses below are planted on purpose (they are the 'ground truth'):

  * default credentials  admin:admin  on /login -> /admin
  * a planted flag on the authenticated /admin page
  * reflected, unescaped input on /search
  * an exposed /.git/config that leaks the deploy credentials
  * directory/paths disclosed via /robots.txt and an open /backup
  * a Server header that discloses a version

Do NOT expose this to a network. It is a deliberately weak teaching target.
"""
from __future__ import annotations

import argparse
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

FLAG = "FLAG{nighttrace_crown_jewel}"
SESSION = "letmein"

_LANDING = """<!doctype html><html><head><title>NightLab</title></head><body>
<h1>NightLab Intranet</h1>
<ul>
  <li><a href="/search?q=hello">Search</a></li>
  <li><a href="/login">Staff login</a></li>
  <li><a href="/admin">Admin console</a></li>
  <li><a href="/robots.txt">robots.txt</a></li>
</ul></body></html>"""

_LOGIN = """<!doctype html><html><body><h2>Staff login</h2>
<form method="POST" action="/login">
  <input name="username" placeholder="username">
  <input name="password" type="password" placeholder="password">
  <button type="submit">Sign in</button>
</form></body></html>"""

_GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tbare = false
# deploy credentials: admin:admin   (TODO: rotate before launch)
[remote "origin"]
\turl = https://example.test/nightlab.git
"""

_ROBOTS = "User-agent: *\nDisallow: /admin\nDisallow: /backup\n"
_BACKUP = "index of /backup:\n db_dump_2026.sql\n config.bak\n"


class Handler(BaseHTTPRequestHandler):
    server_version = "NightLab/1.0"
    sys_version = ""

    def log_message(self, *a):  # keep the demo quiet
        pass

    def _send(self, status: int, body: str, ctype: str = "text/html", headers: dict | None = None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _cookies(self) -> dict:
        raw = self.headers.get("Cookie", "")
        out = {}
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                out[k] = v
        return out

    def do_GET(self):
        u = urlparse(self.path)
        path, qs = u.path, parse_qs(u.query)
        if path == "/":
            return self._send(200, _LANDING)
        if path == "/search":
            q = qs.get("q", [""])[0]
            # planted: reflects the raw query without any output encoding (XSS)
            return self._send(200, f"<html><body><p>Results for: {q}</p></body></html>")
        if path == "/login":
            return self._send(200, _LOGIN)
        if path == "/admin":
            if self._cookies().get("session") == SESSION:
                return self._send(200, f"<html><body><h2>Admin console</h2>"
                                        f"<p>Welcome, admin.</p><pre>{FLAG}</pre></body></html>")
            return self._send(302, "", headers={"Location": "/login"})
        if path == "/.git/config":
            return self._send(200, _GIT_CONFIG, ctype="text/plain")
        if path == "/robots.txt":
            return self._send(200, _ROBOTS, ctype="text/plain")
        if path == "/backup":
            return self._send(200, _BACKUP, ctype="text/plain")
        return self._send(404, "<h1>404</h1>")

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/login":
            length = int(self.headers.get("Content-Length", 0) or 0)
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            user = form.get("username", [""])[0]
            pw = form.get("password", [""])[0]
            if user == "admin" and pw == "admin":  # planted default credentials
                return self._send(302, "", headers={"Location": "/admin",
                                                     "Set-Cookie": f"session={SESSION}; Path=/"})
            return self._send(200, "<html><body><p>Invalid credentials</p></body></html>")
        return self._send(404, "<h1>404</h1>")


def start(host: str = "127.0.0.1", port: int = 8008) -> tuple[ThreadingHTTPServer, threading.Thread]:
    httpd = ThreadingHTTPServer((host, port), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="NightTrace demo lab (intentionally vulnerable; localhost only).")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8008)
    args = ap.parse_args()
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"NightLab demo target on http://{args.host}:{args.port}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
