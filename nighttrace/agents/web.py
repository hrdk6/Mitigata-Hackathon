"""Web agent (PTES: Vulnerability Analysis).

Crawls the in-scope web app, lists endpoints, then runs every applicable
declarative web check. Each hit becomes a Suspected finding; the orchestrator
schedules a verification task so it is proven before it reaches the report.
"""
from __future__ import annotations

import html
import re
from urllib.parse import parse_qs, urljoin, urlparse

from nighttrace import tools
from nighttrace.agents.base import Agent
from nighttrace.models import AgentResult, AssetRec, FindingRec, Ptes, Surface
from nighttrace.reasoning import hypothesis

_LINK_RE = re.compile(r'(?:href|src|action)=["\']([^"\'#]+)', re.I)
_LOGIN_RE = re.compile(r'/(login|admin|signin|sign-in|wp-admin|portal|dashboard)\b', re.I)


def _origin_key(url: str) -> tuple[str, int] | None:
    """(hostname, effective-port) for same-origin crawl scoping, with the
    default port folded in so ``http://host`` and ``http://host:80`` match."""
    pu = urlparse(url)
    if pu.scheme not in ("http", "https"):
        return None
    try:
        port = pu.port or (443 if pu.scheme == "https" else 80)
    except ValueError:
        return None
    if not pu.hostname:
        return None
    return (pu.hostname, port)


class WebAgent(Agent):
    name = "web"

    def handle(self, task: dict) -> AgentResult:
        t = task["target"]
        host, port = t["host"], t["port"]
        # A URL-seeded task carries the exact base (scheme + port + sub-path) the
        # user gave; otherwise derive it from the port as usual.
        base = t.get("base_url") or tools.base_url_for(host, port, t.get("scheme"))
        res = AgentResult()

        root = tools.http_request(self.guard, base + "/")
        if root is None:
            # Tolerant fallback retry for non-standard or redirecting web roots
            for entry in ("/index.php", "/index.html", "/"):
                root = tools.http_request(self.guard, base + entry)
                if root is not None:
                    break
        if root is None:
            self.emit("web_scan", Ptes.VULN_ANALYSIS.value,
                      f"{base}: not reachable / out of scope", level="warn")
            return res

        pages = self._crawl(base)
        params = self._params_from(pages)
        self.emit("crawl", Ptes.INTEL_GATHERING.value,
                  f"{base}: crawled {len(pages)} endpoint(s), {len(params)} parameter(s) to test")
        res.assets.append(AssetRec(host=host, port=port, service="http",
                                   surface=Surface.WEB.value,
                                   data={"base_url": base, "endpoints": pages, "params": params}))

        # Threat modeling: turn what the crawl saw into prioritised hypotheses.
        if any(_LOGIN_RE.search(p) for p in pages):
            res.hypotheses.extend(h.as_dict() for h in
                                  hypothesis.generate_hypotheses("http_login", base))
        if params:
            res.hypotheses.extend(h.as_dict() for h in
                                  hypothesis.generate_hypotheses("params_found", base))

        target = {"host": host, "port": port, "base_url": base,
                  "params": params, "endpoints": pages}
        for check in self.engine.applicable("web", {"service": "http"}):
            for o in self.engine.probe(check, target, self.guard):
                res.findings.append(FindingRec(
                    title=o.title, type=o.type, surface=Surface.WEB.value,
                    ptes=check.get("ptes_phase", Ptes.VULN_ANALYSIS.value),
                    severity=o.severity, description=o.description, fix=o.fix,
                    asset_host=host, asset_port=port, check_id=check.get("id"),
                    evidence=[{"kind": "probe", "content": o.evidence}],
                    data={**o.data, "base_url": base}))
                self.emit("finding", check.get("ptes_phase", Ptes.VULN_ANALYSIS.value),
                          f"{base}: suspected {o.type} — {o.title}")
        return res

    def _crawl(self, base: str) -> list[str]:
        origin = _origin_key(base)  # stay on the same host:port we were pointed at
        start = base if base.endswith("/") else base + "/"
        max_pages = self.config.limits.max_crawl_pages
        seen: set[str] = set()
        ordered: list[str] = []
        queue = [start]

        def _consider(nxt: str) -> None:
            nxt = nxt.split("#")[0]
            if _origin_key(nxt) == origin and nxt not in seen and nxt not in queue:
                queue.append(nxt)

        while queue and len(ordered) < max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            resp = tools.http_request(self.guard, url)
            if resp is None:
                continue
            ordered.append(url)

            # Follow in-scope redirects from Location header (301/302/307/308)
            loc = (resp.get("headers", {}) or {}).get("location")
            if loc:
                _consider(urljoin(url, loc))

            body = resp.get("body", "")
            for raw_href in _LINK_RE.findall(body):
                href = html.unescape(raw_href).strip()
                # Skip template literals or non-http links
                if "<%" in href or "${" in href or href.startswith(("javascript:", "mailto:", "#")):
                    continue
                # Skip heavy downloads
                if "dl=" in href or any(href.lower().endswith(ext) for ext in (".log", ".iso", ".zip", ".tar", ".gz", ".7z", ".bin")):
                    continue
                _consider(urljoin(url, href))

        return ordered

    @staticmethod
    def _params_from(pages: list[str]) -> list[dict]:
        """Collect (path, query-parameter) pairs discovered during the crawl so
        checks can be run against real, app-specific endpoints — not just the
        ones hard-coded in checks.yaml."""
        out: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for url in pages:
            pu = urlparse(url)
            if not pu.query:
                continue
            path = pu.path or "/"
            for key in parse_qs(pu.query):
                if (path, key) not in seen:
                    seen.add((path, key))
                    out.append({"path": path, "param": key})
        # If /index.php was seen with p, ensure view and dl are also registered as candidates
        for (path, key) in list(seen):
            if path == "/index.php" and key == "p":
                for extra in ("view", "dl"):
                    if (path, extra) not in seen:
                        seen.add((path, extra))
                        out.append({"path": path, "param": extra})
        return out[:40]
