"""Scoped tool primitives.

These are the only ways the engine touches the outside world. Each one asks the
Scope Guard for permission *first*; if the target is out of scope the call
returns nothing and the block is already logged. Agents never open sockets
directly — they go through here, so the safety guarantee holds everywhere.
"""
from __future__ import annotations

import http.client
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from urllib import error, request

from nighttrace import osfp
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

# Ports that speak TLS directly (for certificate/protocol auditing).
TLS_PORTS = HTTPS_PORTS | {465, 636, 989, 990, 992, 993, 995, 5061, 5986}


class _NoRedirect(request.HTTPRedirectHandler):
    """Do not auto-follow redirects — a redirect could point out of scope.
    The crawler re-checks scope and follows deliberately instead."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


_opener = request.build_opener(_NoRedirect)


def tcp_scan(guard: ScopeGuard, host: str, ports: list[int] | None = None,
             timeout: float = 1.5, workers: int = 32) -> list[dict]:
    """Non-destructive TCP connect scan. Returns [{port, service, product, banner}, ...].

    Ports are probed concurrently (the Scope Guard is thread-safe and still gates
    and paces every connection), so a tolerant per-port timeout — needed so real
    WiFi/LAN latency does not hide slow-to-answer open ports — stays fast.
    """
    ports = ports or DEFAULT_PORTS

    def _probe(port: int) -> dict | None:
        if not guard.check_network(host, port).allowed:
            return None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((host, port)) == 0:
                    return {"port": port, "service": None, "product": None, "banner": _banner(s)}
        except OSError:
            return None
        return None

    with ThreadPoolExecutor(max_workers=min(workers, len(ports) or 1)) as ex:
        found = [r for r in ex.map(_probe, ports) if r]
    found.sort(key=lambda d: d["port"])
    return found


def ping_ttl(guard: ScopeGuard, host: str, timeout: float = 1.0) -> int | None:
    """Scope-checked ICMP echo used for OS fingerprinting. One packet to an
    in-scope host; returns the reply TTL (128/64/255-class) or None."""
    if not guard.check_network(host).allowed:
        return None
    return osfp.ttl_ping(host, timeout)


def has_nmap() -> bool:
    return shutil.which("nmap") is not None


def nmap_scan(guard: ScopeGuard, host: str, ports: list[int] | None = None) -> list[dict]:
    """Discovery via nmap when available — richer service/version detection.

    Non-destructive: a TCP connect scan (-sT) with version detection (-sV). The
    host is scope-checked before nmap runs, and only our port list is scanned.
    """
    if not guard.check_network(host).allowed:
        return []
    port_arg = ",".join(str(p) for p in (ports or DEFAULT_PORTS))
    rate = max(guard.config.limits.rate_limit_pps, 10)
    cmd = ["nmap", "-Pn", "-sT", "-sV", "--open", "-oG", "-",
           "--max-rate", str(rate), "-p", port_arg, host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        return []
    out: list[dict] = []
    for line in proc.stdout.splitlines():
        if "Ports:" not in line:
            continue
        for entry in line.split("Ports:", 1)[1].split(","):
            f = entry.strip().split("/")
            if len(f) < 5 or f[1] != "open":
                continue
            try:
                port = int(f[0])
            except ValueError:
                continue
            product = f[6].strip() if len(f) > 6 and f[6].strip() else None
            out.append({"port": port, "service": f[4] or None, "product": product, "banner": ""})
    return out


def discover(guard: ScopeGuard, host: str, ports: list[int] | None = None,
             timeout: float = 1.5) -> list[dict]:
    """Pick the best available discovery method: nmap if present, else connect scan."""
    if has_nmap():
        res = nmap_scan(guard, host, ports)
        if res:
            return res
    return tcp_scan(guard, host, ports, timeout=timeout)


# A short port list used only to answer "is this host up?" before a full scan.
# A connect that succeeds (open) OR is actively refused (RST) proves the host
# exists; only a timeout leaves it unproven — so a mostly-empty range is cleared
# cheaply instead of paying a full port scan per dead address.
_ALIVE_PORTS = (80, 443, 22, 445, 3389)
_HOST_UP_ERRNOS = {111, 104, 10061, 10054}  # ECONNREFUSED / ECONNRESET (POSIX + WSA)


def host_is_live(guard: ScopeGuard, host: str, timeout: float = 0.5,
                 ports: tuple[int, ...] = _ALIVE_PORTS) -> bool:
    """Fast, scope-checked liveness probe: True as soon as any port is open or
    actively refuses the connection. Returns on the first proof."""
    for port in ports:
        if not guard.check_network(host, port).allowed:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                rc = s.connect_ex((host, port))
                if rc == 0 or rc in _HOST_UP_ERRNOS:
                    return True
        except OSError:
            continue
    return False


def filter_live(guard: ScopeGuard, hosts: list[str], timeout: float = 0.5,
                workers: int = 64) -> list[str]:
    """Keep only the hosts that answer a quick liveness probe, checked in
    parallel (the Scope Guard still gates and paces every probe). Order preserved."""
    if not hosts:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as ex:
        live = set(ex.map(lambda h: h if host_is_live(guard, h, timeout) else None, hosts))
    return [h for h in hosts if h in live]


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
    except (error.URLError, OSError, ValueError, http.client.HTTPException):
        # HTTPException (e.g. BadStatusLine) happens when a non-HTTP service — SSH,
        # FTP, a database — is probed as HTTP. Treat it as "not a web server".
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
