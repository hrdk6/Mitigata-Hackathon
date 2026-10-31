"""Scoped tool primitives.

These are the only ways the engine touches the outside world. Each one asks the
Scope Guard for permission *first*; if the target is out of scope the call
returns nothing and the block is already logged. Agents never open sockets
directly — they go through here, so the safety guarantee holds everywhere.
"""
from __future__ import annotations

import socket
from urllib import error, request

from nighttrace.safety.scope_guard import ScopeGuard

USER_AGENT = "NightTrace/0.1 (authorized-scan; non-destructive)"

# A focused default port list (web/dev/db/admin services). Non-destructive connect scan.
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3000, 3306, 3389, 5000, 5432, 5900, 6379,
    8000, 8008, 8080, 8081, 8443, 8888, 9000, 9200, 11211, 27017,
]

# Ports we treat as HTTP(S) for the web agent.
HTTP_PORTS = {80, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000}
HTTPS_PORTS = {443, 8443, 9443}


class _NoRedirect(request.HTTPRedirectHandler):
    """Do not auto-follow redirects — a redirect could point out of scope.
    The crawler re-checks scope and follows deliberately instead."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


_opener = request.build_opener(_NoRedirect)


def tcp_scan(guard: ScopeGuard, host: str, ports: list[int] | None = None,
             timeout: float = 0.5) -> list[tuple[int, str]]:
    """Non-destructive TCP connect scan. Returns [(port, banner), ...]."""
    ports = ports or DEFAULT_PORTS
    found: list[tuple[int, str]] = []
    for port in ports:
        if not guard.check_network(host, port).allowed:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((host, port)) == 0:
                    found.append((port, _banner(s)))
        except OSError:
            pass
    return found


def _banner(s: socket.socket) -> str:
    try:
        s.settimeout(0.5)
        return s.recv(128).decode("latin-1", "replace").strip()
    except OSError:
        return ""


def http_request(guard: ScopeGuard, url: str, method: str = "GET",
                 data: str | bytes | None = None, headers: dict | None = None,
                 timeout: float = 6.0) -> dict | None:
    """Single scoped HTTP request. Returns a dict or None if blocked/failed."""
    if not guard.check_url(url).allowed:
        return None
    body = data.encode() if isinstance(data, str) else data
    req = request.Request(url, data=body, method=method)
    req.add_header("User-Agent", USER_AGENT)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        return _wrap(_opener.open(req, timeout=timeout))
    except error.HTTPError as e:  # 3xx (no-redirect) and 4xx/5xx arrive here
        return _wrap(e)
    except (error.URLError, OSError, ValueError):
        return None


def _wrap(resp) -> dict:
    raw = resp.read(200_000)
    headers = {}
    try:
        headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception:
        pass
    return {
        "status": getattr(resp, "status", None) or getattr(resp, "code", 0) or 0,
        "headers": headers,
        "body": raw.decode("utf-8", "replace"),
        "url": resp.geturl() if hasattr(resp, "geturl") else "",
    }


def read_binary(guard: ScopeGuard, path: str, max_bytes: int = 20_000_000) -> bytes | None:
    """Read a provided binary (read-only, non-destructive) if it is in scope."""
    if not guard.check_binary(path).allowed:
        return None
    try:
        with open(path, "rb") as f:
            return f.read(max_bytes)
    except OSError:
        return None


def base_url_for(host: str, port: int) -> str:
    scheme = "https" if port in HTTPS_PORTS else "http"
    return f"{scheme}://{host}:{port}"
