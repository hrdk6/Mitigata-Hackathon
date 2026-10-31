"""Recon agent (PTES: Intelligence Gathering).

Non-destructive TCP connect scan to find live hosts, open ports and a service
guess. Each web port it finds becomes a web task handed to the Web agent —
that hand-off is the coordination the PRD asks for.
"""
from __future__ import annotations

import ipaddress

from nighttrace import netdiscover, osfp, tools
from nighttrace.agents.base import Agent
from nighttrace.models import AgentResult, AssetRec, Ptes, Surface, TaskSpec
from nighttrace.reasoning import hypothesis

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 139: "smb", 143: "imap", 443: "https", 445: "smb",
    1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgres", 6379: "redis",
    8000: "http", 8008: "http", 8080: "http", 8081: "http", 8443: "https",
    8888: "http", 9000: "http", 9200: "elasticsearch", 11211: "memcached",
    27017: "mongodb",
}


def guess_service(port: int, banner: str) -> str:
    if port in SERVICES:
        return SERVICES[port]
    if banner and "HTTP" in banner.upper():
        return "http"
    return "unknown"


class ReconAgent(Agent):
    name = "recon"

    def handle(self, task: dict) -> AgentResult:
        target = task.get("target", {})
        res = AgentResult()
        hosts: list[str] = []
        if target.get("host"):
            hosts = [target["host"]]
        elif target.get("network"):
            try:
                net = ipaddress.ip_network(target["network"], strict=False)
                hosts = [str(h) for h in list(net.hosts())[:256]]
            except ValueError:
                hosts = []

        ports = self.config.scope.ports or None
        via = "nmap" if tools.has_nmap() else "connect-scan"
        arp = netdiscover.arp_table()  # best-effort MAC map for OS fingerprinting
        for host in hosts:
            open_ports = tools.discover(self.guard, host, ports,
                                        timeout=self.config.limits.connect_timeout)
            if open_ports:
                listing = ", ".join(str(d["port"]) for d in open_ports)
                self.emit("port_scan", Ptes.INTEL_GATHERING.value,
                          f"{host}: {len(open_ports)} open port(s) via {via}: {listing}")
            else:
                self.emit("port_scan", Ptes.INTEL_GATHERING.value,
                          f"{host}: no open ports found in scope")

            # Resolve the service per port first, so we can read an HTTP Server
            # header (one signal into OS fingerprinting) and reuse the result.
            resolved: list[dict] = []
            http_server = None
            for d in open_ports:
                port = d["port"]
                banner = d.get("banner") or ""
                svc = d.get("service") or guess_service(port, banner)
                if not svc or svc == "unknown":  # actively confirm HTTP on non-standard ports
                    if tools.http_request(self.guard, f"http://{host}:{port}/") is not None:
                        svc = "http"
                if http_server is None and svc in ("http", "https"):
                    resp = tools.http_request(self.guard, tools.base_url_for(host, port))
                    if resp:
                        http_server = resp.get("headers", {}).get("server")
                resolved.append({"port": port, "banner": banner, "svc": svc,
                                 "product": d.get("product")})

            # Fingerprint the OS once per host from the signals gathered above.
            ttl = tools.ping_ttl(self.guard, host)
            os_guess = osfp.fingerprint(ttl=ttl, open_ports=[r["port"] for r in resolved],
                                        http_server=http_server, mac=arp.get(host))
            host_os = {"os": os_guess["os"], "os_family": os_guess["family"],
                       "os_confidence": os_guess["confidence"],
                       "os_reasons": os_guess["reasons"], "ttl": ttl,
                       "os_tactics": osfp.suggested_tactics(os_guess["family"])}
            if os_guess["family"] != "unknown":
                self.emit("os_fingerprint", Ptes.INTEL_GATHERING.value,
                          f"{host}: OS guess {os_guess['os']} "
                          f"({int(os_guess['confidence'] * 100)}% confidence) — "
                          f"{'; '.join(os_guess['reasons'][:2])}")

            for r in resolved:
                port, banner, svc = r["port"], r["banner"], r["svc"]
                product = r["product"] or (banner or None)
                res.assets.append(AssetRec(
                    host=host, port=port, service=svc, product=product,
                    surface=Surface.NETWORK.value,
                    data={"banner": banner, "product": product, **host_os}))
                if (svc and "http" in svc) or svc == "https":
                    res.followups.append(TaskSpec(
                        type="web", ptes=Ptes.VULN_ANALYSIS.value,
                        target={"host": host, "port": port},
                        dedupe_key=f"web:{host}:{port}"))
                    # A live web root is a strong signal for exposed config/VCS
                    # secrets — formulate the hypothesis so the web pass prioritises it.
                    res.hypotheses.extend(
                        h.as_dict() for h in
                        hypothesis.generate_hypotheses("http_alive", f"{host}:{port}"))
        return res
