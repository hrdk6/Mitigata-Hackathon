"""Web agent (PTES: Vulnerability Analysis).

Crawls the in-scope web app, lists endpoints, then runs every applicable
declarative web check. Each hit becomes a Suspected finding; the orchestrator
schedules a verification task so it is proven before it reaches the report.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qs, urljoin, urlparse

from nighttrace import tools
from nighttrace.agents.base import Agent
from nighttrace.models import AgentResult, AssetRec, FindingRec, Ptes, Surface

_LINK_RE = re.compile(r'(?:href|src|action)=["\']([^"\'#]+)', re.I)


class WebAgent(Agent):
    name = "web"

    def handle(self, task: dict) -> AgentResult:
        t = task["target"]
        host, port = t["host"], t["port"]
        base = tools.base_url_for(host, port)
        res = AgentResult()

        root = tools.http_request(self.guard, base + "/")
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

        target = {"host": host, "port": port, "base_url": base, "params": params}
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
        host = urlparse(base).netloc
        max_pages = self.config.limits.max_crawl_pages
        seen: set[str] = set()
        ordered: list[str] = []
        queue = [base + "/"]
        while queue and len(ordered) < max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            resp = tools.http_request(self.guard, url)
            if resp is None:
                continue
            ordered.append(url)
            for href in _LINK_RE.findall(resp.get("body", "")):
                nxt = urljoin(url, href).split("#")[0]
                pu = urlparse(nxt)
                if pu.scheme in ("http", "https") and pu.netloc == host and nxt not in seen:
                    queue.append(nxt)
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
        return out[:40]
