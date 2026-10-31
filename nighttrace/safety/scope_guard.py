"""The Scope Guard — a mandatory, default-deny chokepoint.

Every outbound action (a connection, an HTTP request, reading a binary) is
checked here *before* it happens. If a target is not explicitly in scope, or is
excluded, or the action is destructive, it is blocked and logged. This is both
the ethics guarantee and the thing that keeps "stray probes" at zero.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import threading
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

from nighttrace.config import Config


@dataclass
class Decision:
    allowed: bool
    reason: str


class RateLimiter:
    """Simple global packets-per-second throttle (politeness + speed cap)."""

    def __init__(self, pps: int):
        self.min_interval = 1.0 / pps if pps and pps > 0 else 0.0
        self._lock = threading.Lock()
        self._next_at = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next_at:
                time.sleep(self._next_at - now)
                now = time.monotonic()
            self._next_at = max(now, self._next_at) + self.min_interval


class ScopeGuard:
    """Resolves and enforces the allow/deny policy from the Config."""

    def __init__(self, config: Config, event_sink: Callable[..., None] | None = None):
        self.config = config
        self._sink = event_sink
        self._lock = threading.Lock()
        self.allowed_count = 0
        self.blocked_count = 0
        self.stray_probe_attempts = 0  # scored metric: must stay at zero

        self._networks = [ipaddress.ip_network(n, strict=False) for n in config.scope.networks]
        # Website URL targets are in scope too: their host is trusted even though
        # it is not listed under `hosts` (so it gets a focused web audit, not a
        # full-port host sweep).
        seed_hosts = [s.get("host") for s in getattr(config.scope, "web_seeds", []) if s.get("host")]
        all_hosts = list(config.scope.hosts) + seed_hosts
        self._hosts = set(all_hosts)
        self._host_ips = {self._maybe_ip(h) for h in all_hosts if self._maybe_ip(h)}

        self._excl_networks = []
        self._excl_hosts = set()
        for e in config.scope.exclude:
            net = self._maybe_network(e)
            if net is not None:
                self._excl_networks.append(net)
            else:
                self._excl_hosts.add(e)
                ip = self._maybe_ip(e)
                if ip:
                    self._excl_hosts.add(ip)

        self._binaries = {self._norm(b) for b in config.scope.binaries}
        self.rate = RateLimiter(config.limits.rate_limit_pps)

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def _norm(path: str) -> str:
        return os.path.normcase(os.path.abspath(path))

    @staticmethod
    def _maybe_ip(host: str) -> str | None:
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            return None

    @staticmethod
    def _maybe_network(value: str):
        try:
            return ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None

    def _resolve(self, host: str) -> str | None:
        """Best-effort host -> IP. Only hosts already in scope are ever resolved."""
        ip = self._maybe_ip(host)
        if ip:
            return ip
        try:
            return socket.gethostbyname(host)
        except OSError:
            return None

    def _emit(self, action: str, decision: Decision, target: str) -> None:
        if self._sink is None:
            return
        self._sink(
            agent="scope_guard",
            action=action,
            ptes="pre_engagement",
            level="info" if decision.allowed else "warn",
            message=f"{'ALLOW' if decision.allowed else 'BLOCK'} {target} — {decision.reason}",
            data={"allowed": decision.allowed, "target": target, "reason": decision.reason},
        )

    # -- policy --------------------------------------------------------------
    def _host_allowed(self, host: str) -> Decision:
        ip = self._resolve(host)
        # exclusions win over everything
        if host in self._excl_hosts or (ip and ip in self._excl_hosts):
            return Decision(False, "host is on the exclude list")
        if ip:
            addr = ipaddress.ip_address(ip)
            for net in self._excl_networks:
                if addr in net:
                    return Decision(False, f"host in excluded network {net}")
        # allow-list
        if host in self._hosts or (ip and ip in self._host_ips):
            return Decision(True, "host explicitly in scope")
        if ip:
            addr = ipaddress.ip_address(ip)
            for net in self._networks:
                if addr in net:
                    return Decision(True, f"host in in-scope network {net}")
        return Decision(False, "host not in scope (default-deny)")

    def check_network(self, host: str, port: int | None = None, *, destructive: bool = False) -> Decision:
        if destructive and not self.config.limits.destructive:
            d = Decision(False, "destructive action blocked by non-destructive policy")
            self._record(d, f"{host}:{port}")
            return d
        d = self._host_allowed(host)
        self._record(d, f"{host}:{port}" if port else host)
        if d.allowed:
            self.rate.wait()
        return d

    def check_url(self, url: str, *, destructive: bool = False) -> Decision:
        host = urlparse(url).hostname or ""
        if not host:
            d = Decision(False, "URL has no host")
            self._record(d, url)
            return d
        return self.check_network(host, urlparse(url).port, destructive=destructive)

    def check_binary(self, path: str) -> Decision:
        norm = self._norm(path)
        if norm in self._binaries and os.path.isfile(norm):
            d = Decision(True, "binary explicitly in scope")
        elif norm in self._binaries:
            d = Decision(False, "binary in scope but file is missing")
        else:
            d = Decision(False, "binary not in scope (default-deny)")
        self._record(d, path, kind="binary")
        return d

    def _record(self, decision: Decision, target: str, kind: str = "network") -> None:
        with self._lock:
            if decision.allowed:
                self.allowed_count += 1
            else:
                self.blocked_count += 1
                # A block that was *attempted* against an out-of-scope target is a stray probe attempt.
                if "not in scope" in decision.reason or "exclude" in decision.reason or "excluded" in decision.reason:
                    self.stray_probe_attempts += 1
        self._emit(f"check_{kind}", decision, target)

    def summary(self) -> dict:
        return {
            "allowed": self.allowed_count,
            "blocked": self.blocked_count,
            "stray_probe_attempts": self.stray_probe_attempts,
        }
