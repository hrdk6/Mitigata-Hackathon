"""Scoped tool primitives.

These are the only ways the engine touches the outside world. Each one asks the
Scope Guard for permission *first*; if the target is out of scope the call
returns nothing and the block is already logged. Agents never open sockets
directly — they go through here, so the safety guarantee holds everywhere.
"""
from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from urllib import error, request

from nighttrace import osfp
from nighttrace.safety.scope_guard import ScopeGuard

USER_AGENT = "NightTrace/0.1 (authorized-scan; non-destructive)"

# A focused default port list (web/dev/db/admin services). Non-destructive connect scan.
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3000, 3306, 3389, 5000, 5432, 5900, 6379,
    8000, 8008, 8080, 8081, 8443, 8833, 8888, 9000, 9200, 11211, 27017,
]

# A broad sweep used for network ranges and as the default per host: the common
# service ports plus the ones CTF/lab/app targets habitually hide on (e.g. an
# HTTP admin panel on :1111, :1337 or :8834). Wide enough to stop missing a
# non-standard service without paying a full 65535-port scan on every host.
COMMON_PORTS = sorted(set(DEFAULT_PORTS) | {
    81, 88, 123, 389, 465, 514, 587, 636, 873, 990, 1080, 1111, 1194, 1234,
    1337, 1723, 1883, 2082, 2083, 2181, 2375, 2376, 3001, 3128, 3268, 3690,
    4000, 4040, 4200, 4280, 4443, 4567, 4848, 5001, 5044, 5060, 5601, 5672,
    5985, 6000, 6443, 6667, 7000, 7001, 7077, 7443, 7777, 8001, 8009, 8010,
    8069, 8086, 8088, 8090, 8161, 8333, 8500, 8530, 8834, 8983, 9001, 9002,
    9042, 9080, 9090, 9091, 9300, 9443, 9999, 10000, 10250, 15672, 27018,
    50000, 61616,
})

# Full scan: every application port. nmap does all 65535 fast with -p-; the
# built-in connect scanner covers 1-10000, where essentially all services live.
FULL_PORTS = list(range(1, 10001))

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
             timeout: float = 1.5, workers: int = 100) -> list[dict]:
    """Non-destructive TCP connect scan. Returns [{port, service, product, banner}, ...].

    Ports are probed concurrently (the Scope Guard is thread-safe and still gates
    and paces every connection), so a tolerant per-port timeout — needed so real
    WiFi/LAN latency does not hide slow-to-answer open ports — stays fast even over
    a wide range.
    """
    ports = ports or COMMON_PORTS

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


def nmap_scan(guard: ScopeGuard, host: str, ports: list[int] | None = None,
              full: bool = False) -> list[dict]:
    """Discovery via nmap when available — richer service/version detection.

    Non-destructive: a TCP connect scan (-sT) with version detection (-sV). The
    host is scope-checked before nmap runs. `full` scans all 65535 ports (-p-),
    which is how non-standard services (an admin panel on :1111) get found;
    otherwise only the given port list is scanned.
    """
    if not guard.check_network(host).allowed:
        return []
    rate = max(guard.config.limits.rate_limit_pps, 10)
    cmd = ["nmap", "-Pn", "-sT", "-sV", "--open", "-oG", "-", "--max-rate", str(rate)]
    cmd += ["-p-"] if full else ["-p", ",".join(str(p) for p in (ports or COMMON_PORTS))]
    cmd.append(host)
    try:
        # A full -p- sweep needs a longer budget than a focused port list.
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900 if full else 300)
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
             timeout: float = 1.5, full: bool = False) -> list[dict]:
    """Pick the best available discovery method: nmap if present, else connect scan.

    `ports` pins an exact list; otherwise `full` scans everything (all ports via
    nmap -p-, or 1-10000 built-in) and the default is the broad COMMON_PORTS sweep.
    """
    scan_ports = ports or (FULL_PORTS if full else COMMON_PORTS)
    if has_nmap():
        res = nmap_scan(guard, host, ports=ports, full=full)
        if res:
            return res
    return tcp_scan(guard, host, scan_ports, timeout=timeout)


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
                 timeout: float = 10.0, retries: int = 1) -> dict | None:
    """Single scoped HTTP request with retries. Returns a dict or None if blocked/failed."""
    if not guard.check_url(url).allowed:
        return None
    body = data.encode() if isinstance(data, str) else data
    req = request.Request(url, data=body, method=method)
    req.add_header("User-Agent", USER_AGENT)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    for attempt in range(1 + max(0, retries)):
        try:
            return _wrap(_opener.open(req, timeout=timeout))
        except error.HTTPError as e:  # 3xx (no-redirect) and 4xx/5xx arrive here
            return _wrap(e)
        except (error.URLError, OSError, ValueError, http.client.HTTPException):
            if attempt < retries:
                time.sleep(0.3)
                continue
            return None
        except Exception:
            return None
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


def base_url_for(host: str, port: int, scheme: str | None = None) -> str:
    scheme = scheme or ("https" if port in HTTPS_PORTS else "http")
    return f"{scheme}://{host}:{port}"


# -- external engine: nuclei (community vulnerability templates) --------------
def has_nuclei() -> bool:
    return shutil.which("nuclei") is not None


def _nuclei_templates_present() -> bool:
    """True only if nuclei's templates are already installed. Without this guard,
    nuclei would try to download ~9000 templates mid-scan and stall the web task
    until its timeout — so we skip nuclei entirely until templates exist."""
    dirs = [os.environ.get("NUCLEI_TEMPLATES_DIR", ""),
            os.path.expanduser("~/.config/nuclei-templates"),
            os.path.expanduser("~/nuclei-templates")]
    return any(d and os.path.isdir(d) and os.listdir(d) for d in dirs)


def nuclei_scan(guard: ScopeGuard, base_url: str, timeout_s: int = 300) -> list[dict]:
    """Run nuclei's template engine against one in-scope URL and return parsed
    findings. Non-destructive templates only (dos/intrusive/fuzz excluded). The
    URL is scope-checked before nuclei is pointed at it. Returns [] when nuclei
    is unavailable, its templates are not installed, the target is out of scope,
    or nothing matched.
    """
    if not has_nuclei() or not _nuclei_templates_present() or not guard.check_url(base_url).allowed:
        return []
    rate = max(guard.config.limits.rate_limit_pps, 10)
    cmd = ["nuclei", "-u", base_url, "-jsonl", "-silent", "-nc",
           "-timeout", "8", "-retries", "1", "-rate-limit", str(rate),
           "-exclude-tags", "dos,intrusive,fuzz", "-disable-update-check"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except (OSError, subprocess.TimeoutExpired):
        return []
    results, seen = [], set()
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except ValueError:
            continue
        info = j.get("info") or {}
        tid = j.get("template-id") or j.get("templateID") or "nuclei"
        matched = j.get("matched-at") or j.get("matched_at") or j.get("host") or base_url
        key = (tid, matched)
        if key in seen:
            continue
        seen.add(key)
        results.append({
            "template": tid,
            "name": (info.get("name") or tid).strip(),
            "severity": (info.get("severity") or "info").lower(),
            "matched_at": matched,
            "description": (info.get("description") or "").strip(),
            "reference": info.get("reference") or [],
            "tags": info.get("tags") or [],
        })
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    results.sort(key=lambda r: -order.get(r["severity"], 0))
    return results[:60]  # cap so an info-heavy run cannot flood the report
