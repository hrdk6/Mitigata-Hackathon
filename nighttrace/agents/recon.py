"""Recon agent (PTES: Intelligence Gathering).

Non-destructive TCP connect scan to find live hosts, open ports and a service
guess. Each web port it finds becomes a web task handed to the Web agent —
that hand-off is the coordination the PRD asks for.
"""
from __future__ import annotations

import ipaddress

from nighttrace import tools
from nighttrace.agents.base import Agent
from nighttrace.models import AgentResult, AssetRec, Ptes, Surface, TaskSpec

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
        for host in hosts:
            open_ports = tools.tcp_scan(self.guard, host, ports)
            if open_ports:
                listing = ", ".join(str(p) for p, _ in open_ports)
                self.emit("port_scan", Ptes.INTEL_GATHERING.value,
                          f"{host}: {len(open_ports)} open port(s): {listing}")
            else:
                self.emit("port_scan", Ptes.INTEL_GATHERING.value,
                          f"{host}: no open ports found in scope")
            for port, banner in open_ports:
                svc = guess_service(port, banner)
                if svc == "unknown":  # actively confirm HTTP on non-standard ports
                    if tools.http_request(self.guard, f"http://{host}:{port}/") is not None:
                        svc = "http"
                res.assets.append(AssetRec(host=host, port=port, service=svc,
                                           product=banner or None, surface=Surface.NETWORK.value,
                                           data={"banner": banner}))
                if svc in ("http", "https"):
                    res.followups.append(TaskSpec(
                        type="web", ptes=Ptes.VULN_ANALYSIS.value,
                        target={"host": host, "port": port},
                        dedupe_key=f"web:{host}:{port}"))
        return res
