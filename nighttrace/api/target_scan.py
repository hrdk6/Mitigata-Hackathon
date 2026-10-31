"""One-host web scans started from the live dashboard.

The dashboard accepts only a literal private/loopback IPv4 HTTP(S) target.  It
turns that value into a fresh, exact-host scope before starting the existing
orchestrator; no broader network is ever inferred from user input.
"""
from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass
from urllib.parse import urlsplit

from nighttrace.blackboard import Blackboard
from nighttrace.config import Config, Limits, Scope
from nighttrace.orchestrator import Orchestrator


class TargetValidationError(ValueError):
    """The submitted dashboard target is not safe or unambiguous."""


@dataclass(frozen=True)
class WebTarget:
    """A normalised, exact HTTP(S) target supplied by the operator."""

    host: str
    port: int
    scheme: str

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def as_dict(self) -> dict:
        return {"host": self.host, "port": self.port, "scheme": self.scheme, "url": self.url}


def parse_web_target(value: object) -> WebTarget:
    """Validate a dashboard target without DNS resolution.

    Restricting this entry point to private/loopback IP literals makes the UI a
    local-lab feature and avoids a hostname changing destination after approval.
    The engine still performs a ScopeGuard check before every connection.
    """
    raw = str(value or "").strip()
    if not raw:
        raise TargetValidationError("Enter a target such as http://192.168.60.139/.")

    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError("The target URL has an invalid port.") from exc

    if parsed.scheme not in {"http", "https"}:
        raise TargetValidationError("Only http:// and https:// targets are supported.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise TargetValidationError("Use a bare IP address; credentials in the URL are not allowed.")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise TargetValidationError("Enter only the website origin, without a path, query, or fragment.")

    try:
        addr = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise TargetValidationError("Use a numeric IPv4 address, not a hostname.") from exc
    if addr.version != 4 or not (addr.is_private or addr.is_loopback):
        raise TargetValidationError("Dashboard scans are limited to private or loopback IPv4 targets.")
    if addr.is_unspecified or addr.is_multicast or addr.is_link_local:
        raise TargetValidationError("That IP address is not a valid web target.")

    chosen_port = port if port is not None else (443 if parsed.scheme == "https" else 80)
    if not 1 <= chosen_port <= 65535:
        raise TargetValidationError("The target port must be between 1 and 65535.")
    return WebTarget(host=str(addr), port=chosen_port, scheme=parsed.scheme)


class TargetScanManager:
    """Runs one operator-approved target scan at a time and exposes its state."""

    def __init__(self, bb: Blackboard, base_config: Config, checks: list[dict]):
        self._bb = bb
        self._base_config = base_config
        self._checks = checks
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._state: dict = {"status": "idle"}

    def status(self) -> dict:
        with self._lock:
            return dict(self._state)

    def start(self, target: WebTarget) -> tuple[bool, dict]:
        """Launch an isolated, exact-host run; return False while another runs."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False, dict(self._state)
            self._state = {"status": "running", "target": target.as_dict()}
            self._thread = threading.Thread(
                target=self._run, args=(target,), name="nighttrace-web-target", daemon=True
            )
            self._thread.start()
            return True, dict(self._state)

    def _scan_config(self, target: WebTarget) -> Config:
        limits = self._base_config.limits
        ports = [target.port]
        if 8833 not in ports:
            ports.append(8833)
        return Config(
            engagement=f"{self._base_config.engagement} — {target.url}",
            tier="recon",  # web + network only; no local binaries are inherited.
            scope=Scope(hosts=[target.host], ports=ports),
            limits=Limits(
                max_runtime_minutes=min(max(limits.max_runtime_minutes, 0.1), 5.0),
                rate_limit_pps=min(max(limits.rate_limit_pps, 1), 50),
                destructive=False,
                max_crawl_pages=min(max(limits.max_crawl_pages, 1), 50),
                connect_timeout=3.0,
            ),
            flag_pattern=self._base_config.flag_pattern,
        )

    def _run(self, target: WebTarget) -> None:
        try:
            Orchestrator(self._scan_config(target), self._checks, blackboard=self._bb).run()
            target_findings = self._bb.list_findings(asset_host=target.host)
            state = {
                "status": "complete",
                "target": target.as_dict(),
                "confirmed": sum(f["status"] == "Confirmed" for f in target_findings),
                "findings": len(target_findings),
            }
        except Exception as exc:  # keep an API worker failure visible to the operator
            state = {"status": "failed", "target": target.as_dict(), "error": type(exc).__name__}
        with self._lock:
            self._state = state
